<#
.SYNOPSIS
    Shared helper functions for AD Discovery toolkit

.DESCRIPTION
    Provides common utilities for LDAP queries, platform detection,
    data conversion, and progress reporting. All functions follow
    error-safe patterns with proper resource disposal.

.NOTES
    Compatible with PowerShell 5.1 and PowerShell 7+
    No RSAT or administrative privileges required
#>

function Test-IsWindowsPlatform {
    <#
    .SYNOPSIS
        Detects if running on Windows platform

    .DESCRIPTION
        Compatible detection for both PS 5.1 (Desktop) and PS 7+ (Core)

    .OUTPUTS
        Boolean indicating Windows platform
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    # PowerShell 5.1 is always Windows (Desktop edition)
    if ($PSVersionTable.PSEdition -eq 'Desktop') {
        return $true
    }

    # PowerShell 7+ uses OS property
    if ($PSVersionTable.PSEdition -eq 'Core') {
        return ($PSVersionTable.OS -like '*Windows*')
    }

    # Fallback (should never reach here)
    return $false
}
# ---------------------------------------------------------------------------
# Shim layer over ADLdap.ps1
# ---------------------------------------------------------------------------
# The public helpers below (Get-RootDSE, New-LdapSearcher, Invoke-LdapQuery)
# keep their original signatures so the 8 consumer modules don't need to
# change, but their internals now run on the modern
# System.DirectoryServices.Protocols.LdapConnection stack via ADLdap.ps1.
# That stack works against DCs enforcing LDAP Channel Binding / Signing
# (the hardened modern default), which the legacy DirectoryEntry / ADSI
# path cannot do.
#
# When a per-run connection pool is installed by the orchestrator as
# $script:AdLdapPool, the shim acquires contexts from the pool (one
# LdapConnection per server, reused). When no pool is present, each helper
# opens a one-shot connection and disposes it. This keeps existing callers
# (and unit tests) working with zero changes.
#
# Automatic post-processing applied to every entry returned by the shim:
#   - Generalized Time attrs (whenCreated, whenChanged, currentTime,
#     dSCorePropagationData) converted to [datetime] so legacy callers
#     doing $x.whenCreated.ToString('...') keep working.
#   - Binary attrs (objectSid, objectGUID, schemaIDGUID, etc.) returned as
#     byte[] so New-Object SecurityIdentifier works as before.
#   - ADSPath synthetic key in 'LDAP://<server>/<dn>' form preserved.
#   - Lowercase 'distinguishedName' alias preserved.

$script:AdLdapBinaryAttrs = @(
    'objectSid','objectGUID','schemaIDGUID','attributeSecurityGUID',
    'mS-DS-ConsistencyGuid','msExchMailboxGuid','sIDHistory','tokenGroups',
    'tokenGroupsGlobalAndUniversal','tokenGroupsNoGCAcceptable','userCertificate',
    'userSMIMECertificate','cACertificate','thumbnailPhoto','thumbnailLogo'
)
$script:AdLdapGeneralizedTimeAttrs = @(
    'whenCreated','whenChanged','currentTime','dSCorePropagationData'
)

function script:ConvertFrom-LdapGeneralizedTime {
    <#
    .SYNOPSIS
        Private: converts a Generalized Time string (YYYYMMDDHHMMSS[.f][Z|±HHMM])
        to a [datetime] in UTC. Returns $null for null/empty/unparseable.
    #>
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { return $Value }
    if ($Value -is [array]) {
        if ($Value.Count -eq 0) { return $null }
        $Value = $Value[0]
    }
    $s = [string]$Value
    if ([string]::IsNullOrWhiteSpace($s)) { return $null }
    if ($s -match '^(\d{14})') {
        try {
            return [datetime]::ParseExact(
                $matches[1], 'yyyyMMddHHmmss',
                [System.Globalization.CultureInfo]::InvariantCulture,
                [System.Globalization.DateTimeStyles]::AssumeUniversal -bor `
                [System.Globalization.DateTimeStyles]::AdjustToUniversal)
        } catch { return $null }
    }
    return $null
}

function Get-RootDSE {
    <#
    .SYNOPSIS
        Reads fundamental AD directory information from the RootDSE.

    .DESCRIPTION
        Returns a hashtable of RootDSE attributes used by downstream modules
        (naming contexts, functional levels, DC hostname, etc.). When a
        script-scope connection pool ($script:AdLdapPool) exists, the
        connection is acquired from the pool; otherwise a one-shot connection
        is opened and disposed.

    .PARAMETER Server
        Domain controller FQDN or domain name.

    .PARAMETER Credential
        Optional credentials for authentication.

    .OUTPUTS
        Hashtable with RootDSE attributes.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Server,

        [Parameter(Mandatory = $false)]
        [PSCredential]$Credential
    )

    $ctx = $null
    $ownCtx = $false
    try {
        if ($script:AdLdapPool) {
            $ctx = Get-AdLdapPooledContext -Pool $script:AdLdapPool -Domain $Server
        } else {
            $connParams = @{ Server = $Server }
            if ($Credential) { $connParams.Credential = $Credential }
            $ctx = New-AdLdapConnection @connParams
            $ownCtx = $true
        }

        $dse = Get-AdLdapRootDse -Context $ctx -Attributes @(
            'defaultNamingContext','schemaNamingContext','configurationNamingContext',
            'rootDomainNamingContext','forestFunctionality','domainFunctionality',
            'domainControllerFunctionality','dnsHostName','currentTime','supportedLDAPVersion'
        )

        $toInt = {
            param($v)
            if ($null -eq $v -or $v -eq '') { return 0 }
            try { return [int]$v } catch { return 0 }
        }

        return @{
            defaultNamingContext          = [string]$dse.defaultNamingContext
            schemaNamingContext           = [string]$dse.schemaNamingContext
            configurationNamingContext    = [string]$dse.configurationNamingContext
            rootDomainNamingContext       = [string]$dse.rootDomainNamingContext
            forestFunctionality           = & $toInt $dse.forestFunctionality
            domainFunctionality           = & $toInt $dse.domainFunctionality
            domainControllerFunctionality = & $toInt $dse.domainControllerFunctionality
            dnsHostName                   = [string]$dse.dnsHostName
            currentTime                   = ConvertFrom-LdapGeneralizedTime $dse.currentTime
            supportedLDAPVersion          = $dse.supportedLDAPVersion
        }

    } catch {
        throw "Failed to connect to RootDSE on ${Server}: $_"
    } finally {
        if ($ownCtx) { Close-AdLdapConnection $ctx }
    }
}

function New-LdapSearcher {
    <#
    .SYNOPSIS
        Builds a shim searcher context for use with Invoke-LdapQuery.

    .DESCRIPTION
        Returns a PSCustomObject carrying the search parameters. The shim
        searcher has a no-op Dispose() method so existing modules that call
        $searcher.Dispose() continue to work unchanged.

    .PARAMETER SearchRoot
        LDAP path: 'LDAP://<server>' or 'LDAP://<server>/<baseDN>'.

    .PARAMETER Filter
        LDAP filter string.

    .PARAMETER Properties
        Array of attribute names to retrieve. '*' returns all attributes.

    .PARAMETER Credential
        Optional credentials. Used only when no connection pool is installed.

    .PARAMETER Config
        Hashtable with LdapPageSize, LdapTimeout, and optional AllowInsecure.

    .OUTPUTS
        PSCustomObject shim searcher.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SearchRoot,

        [Parameter(Mandatory = $true)]
        [string]$Filter,

        [Parameter(Mandatory = $false)]
        [string[]]$Properties = @('*'),

        [Parameter(Mandatory = $false)]
        [PSCredential]$Credential,

        [Parameter(Mandatory = $false)]
        [hashtable]$Config = @{}
    )

    # Parse SearchRoot: LDAP://<server>[/<baseDN>]
    $server = $null
    $baseDN = $null
    if ($SearchRoot -match '^LDAP://([^/]+?)(?:/(.*))?$') {
        $server = $matches[1]
        if ($matches[2]) { $baseDN = $matches[2] }
    } else {
        throw "New-LdapSearcher: SearchRoot must be in 'LDAP://<server>[/<baseDN>]' form; got '$SearchRoot'"
    }

    $searcher = [pscustomobject]@{
        _IsAdLdapShim = $true
        Server        = $server
        BaseDN        = $baseDN
        Filter        = $Filter
        Properties    = $Properties
        Credential    = $Credential
        Config        = $Config
        # Writable by consumers; default Subtree. Accepts either a string
        # ('Base' / 'OneLevel' / 'Subtree') or a
        # [System.DirectoryServices.SearchScope] enum value -- PowerShell
        # coerces the enum to its string name on assignment, which matches
        # what Invoke-LdapQuery expects below.
        SearchScope   = 'Subtree'
    }

    # Backward-compat: legacy callers do $searcher.Dispose(). No-op in the shim.
    Add-Member -InputObject $searcher -MemberType ScriptMethod -Name Dispose -Value { } -Force

    return $searcher
}

function Invoke-LdapQuery {
    <#
    .SYNOPSIS
        Executes the search described by a shim searcher and returns hashtables.

    .DESCRIPTION
        Runs via Invoke-AdLdapSearch under the hood. Attribute values come
        back as strings (single-valued) or string arrays (multi-valued), with
        the following automatic post-processing:
          - Generalized Time attributes converted to [datetime] (UTC).
          - Binary attributes (SID, GUID, certs, etc.) returned as byte[].
          - 'ADSPath' synthetic key added in 'LDAP://<server>/<dn>' form.
          - 'distinguishedName' lowercase alias preserved alongside
            'DistinguishedName'.

    .PARAMETER Searcher
        Shim searcher returned by New-LdapSearcher.

    .OUTPUTS
        Array of hashtables, one per matched LDAP entry.
    #>
    [CmdletBinding()]
    [OutputType([array])]
    param(
        [Parameter(Mandatory = $true)]
        $Searcher
    )

    if (-not $Searcher -or -not $Searcher._IsAdLdapShim) {
        throw "Invoke-LdapQuery: expected a shim searcher from New-LdapSearcher."
    }

    $timeoutSeconds = if ($Searcher.Config.LdapTimeout)  { [int]$Searcher.Config.LdapTimeout }  else { 120 }
    $pageSize       = if ($Searcher.Config.LdapPageSize) { [int]$Searcher.Config.LdapPageSize } else { 1000 }
    $allowInsecure  = [bool]$Searcher.Config.AllowInsecure

    $ctx = $null
    $ownCtx = $false
    try {
        if ($script:AdLdapPool) {
            $ctx = Get-AdLdapPooledContext -Pool $script:AdLdapPool -Domain $Searcher.Server
        } else {
            $connParams = @{
                Server         = $Searcher.Server
                TimeoutSeconds = $timeoutSeconds
            }
            if ($Searcher.Credential) { $connParams.Credential    = $Searcher.Credential }
            if ($allowInsecure)       { $connParams.AllowInsecure = $true }
            $ctx = New-AdLdapConnection @connParams
            $ownCtx = $true
        }

        $effBase = if ($Searcher.BaseDN) { $Searcher.BaseDN } else { $ctx.BaseDN }

        # Which requested attributes are binary?
        $requestedBinary = @()
        $hasExplicitProps = ($Searcher.Properties -and $Searcher.Properties.Count -gt 0 -and $Searcher.Properties[0] -ne '*')
        if ($hasExplicitProps) {
            $reqLower = $Searcher.Properties | ForEach-Object { $_.ToLowerInvariant() }
            foreach ($b in $script:AdLdapBinaryAttrs) {
                if ($reqLower -contains $b.ToLowerInvariant()) {
                    $requestedBinary += $b
                }
            }
        }

        # Translate the shim's SearchScope (string or .NET enum) to the
        # canonical string Invoke-AdLdapSearch accepts.
        $scopeStr = [string]$Searcher.SearchScope
        if ($scopeStr -notin @('Base','OneLevel','Subtree')) { $scopeStr = 'Subtree' }

        $searchParams = @{
            Context        = $ctx
            BaseDN         = $effBase
            Filter         = $Searcher.Filter
            Scope          = $scopeStr
            PageSize       = $pageSize
            TimeoutSeconds = $timeoutSeconds
        }
        if ($hasExplicitProps)              { $searchParams.Attributes       = $Searcher.Properties }
        if ($requestedBinary.Count -gt 0)   { $searchParams.BinaryAttributes = $requestedBinary }

        $raw = Invoke-AdLdapSearch @searchParams

        # Post-process each entry
        $output = New-Object System.Collections.Generic.List[hashtable]
        foreach ($entry in $raw) {
            foreach ($gt in $script:AdLdapGeneralizedTimeAttrs) {
                if ($entry.ContainsKey($gt)) {
                    $entry[$gt] = ConvertFrom-LdapGeneralizedTime $entry[$gt]
                }
            }
            if (-not $entry.ContainsKey('ADSPath')) {
                $entry['ADSPath'] = "LDAP://$($Searcher.Server)/$($entry.DistinguishedName)"
            }
            if (-not $entry.ContainsKey('distinguishedName') -and $entry.ContainsKey('DistinguishedName')) {
                $entry['distinguishedName'] = $entry['DistinguishedName']
            }
            $output.Add($entry) | Out-Null
        }
        return ,$output.ToArray()

    } catch {
        throw "LDAP query failed: $_"
    } finally {
        if ($ownCtx) { Close-AdLdapConnection $ctx }
    }
}

function ConvertTo-ReadableTimestamp {
    <#
    .SYNOPSIS
        Converts AD FileTime to readable DateTime

    .DESCRIPTION
        Handles AD large integer timestamps (100-nanosecond intervals since 1601)
        Returns formatted string or $null for invalid/never values

    .PARAMETER FileTime
        Int64 FileTime value from AD

    .OUTPUTS
        String formatted DateTime or $null
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false)]
        [long]$FileTime
    )

    # Handle null, 0, or "never" values
    if (-not $FileTime -or $FileTime -eq 0 -or $FileTime -eq 9223372036854775807) {
        return $null
    }

    try {
        $datetime = [DateTime]::FromFileTime($FileTime)
        return $datetime.ToString('yyyy-MM-dd HH:mm:ss')
    } catch {
        return $null
    }
}

function Write-ProgressStep {
    <#
    .SYNOPSIS
        Standardized progress output

    .DESCRIPTION
        Consistent formatting for multi-step operations

    .PARAMETER StepNumber
        Current step number

    .PARAMETER TotalSteps
        Total number of steps

    .PARAMETER Message
        Progress message
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [int]$StepNumber,

        [Parameter(Mandatory = $true)]
        [int]$TotalSteps,

        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    Write-Host "[$StepNumber/$TotalSteps] $Message" -ForegroundColor Cyan
}
