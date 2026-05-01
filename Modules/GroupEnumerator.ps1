<#
.SYNOPSIS
    Cross-domain group membership enumeration module

.DESCRIPTION
    Enumerates Active Directory group members across multiple domains via LDAPS.
    Supports CSV input in Domain,GroupName or DOMAIN\GroupName backslash format.
    Returns standardized @{ Data = ...; Errors = @() } hashtables throughout.

.NOTES
    Requires the ADLdap.ps1 module (dot-sourced from the same directory).
    ADLdap wraps System.DirectoryServices.Protocols.LdapConnection so this tool
    works against DCs that enforce LDAP Channel Binding / Signing.

    Connection strategy is delegated to New-AdLdapConnection: LDAPS-Verified
    first, then optional fallbacks (LDAPS cert-bypass, LDAP 389 sign+seal)
    controlled by Config.AllowInsecure.

    Uses objectCategory (indexed) for all LDAP group/user filters.
    Compatible with PowerShell 5.1 and 7+.
#>

function New-GroupEnumConfig {
    <#
    .SYNOPSIS
        Loads group-enum-config.json with defaults fallback

    .DESCRIPTION
        Reads config JSON file and merges values over a built-in defaults hashtable.
        Any key absent from the file will use the default value.

    .PARAMETER ConfigPath
        Path to group-enum-config.json. If omitted or file not found, all defaults apply.

    .OUTPUTS
        Hashtable of merged config values
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $false)]
        [string]$ConfigPath
    )

    # Built-in defaults -- every key the tool needs
    $defaults = @{
        LdapPageSize         = 1000
        LdapTimeout          = 120
        MaxMemberCount       = 5000
        SkipLargeGroups      = $true
        LargeGroupThreshold  = 5000
        SkipGroups           = @('Domain Users', 'Domain Computers', 'Authenticated Users')
        FuzzyPrefixes        = @('GG_', 'USV_', 'SG_', 'DL_', 'GL_')
        FuzzyMinScore        = 0.7
        OutputDirectory      = 'Output'
        DefaultTheme         = 'dark'
        CachePath            = 'Cache'
        CacheEnabled         = $true
        AllowInsecure        = $false
        LogEnabled           = $true
        LogPath              = 'Logs'
        LogLevel             = 'INFO'
    }

    if (-not $ConfigPath -or -not (Test-Path $ConfigPath)) {
        Write-Verbose "Group enum config file not found at '$ConfigPath'. Using defaults."
        return $defaults
    }

    try {
        $json = Get-Content -Path $ConfigPath -Raw -ErrorAction Stop
        $parsed = $json | ConvertFrom-Json -ErrorAction Stop

        # Merge parsed values over defaults
        $config = $defaults.Clone()

        foreach ($property in $parsed.PSObject.Properties) {
            $key   = $property.Name
            $value = $property.Value

            # PSCustomObject arrays come through as PSCustomObject or Object[] -- convert to PS array
            if ($value -is [System.Collections.IEnumerable] -and $value -isnot [string]) {
                $config[$key] = @($value)
            } else {
                $config[$key] = $value
            }
        }

        return $config

    } catch {
        Write-Warning "Failed to parse config file '$ConfigPath': $_. Using defaults."
        return $defaults
    }
}

function Import-GroupList {
    <#
    .SYNOPSIS
        Parses a CSV file into an array of domain/group pairs

    .DESCRIPTION
        Supports two CSV formats:
          1. Standard:   headers Domain,GroupName  -- one row per group
          2. Backslash:  header Group              -- values like DOMAIN\GroupName

        Format is auto-detected by inspecting the header row.
        A -DefaultDomain is used when the CSV contains no domain information.

    .PARAMETER CsvPath
        Full path to the input CSV file

    .PARAMETER DefaultDomain
        Domain to assign when no domain is present in the CSV row

    .OUTPUTS
        Array of hashtables: @{ Domain = "X"; GroupName = "Y" }
    #>
    [CmdletBinding()]
    [OutputType([array])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$CsvPath,

        [Parameter(Mandatory = $false)]
        [string]$DefaultDomain = ''
    )

    if (-not (Test-Path $CsvPath)) {
        throw "CSV file not found: $CsvPath"
    }

    try {
        $rows = Import-Csv -Path $CsvPath -ErrorAction Stop
    } catch {
        throw "Failed to read CSV '$CsvPath': $_"
    }

    if (-not $rows -or $rows.Count -eq 0) {
        return @()
    }

    # Detect format by inspecting the property names of the first row
    $headers = $rows[0].PSObject.Properties.Name

    # Normalise header names for comparison (case-insensitive)
    $headerLower = $headers | ForEach-Object { $_.ToLower() }

    $isStandard   = ($headerLower -contains 'domain') -and ($headerLower -contains 'groupname')
    $isBackslash  = ($headerLower -contains 'group') -and -not $isStandard

    if (-not $isStandard -and -not $isBackslash) {
        $msg = @(
            "Unrecognised CSV format in '$CsvPath'."
            "  Found headers: $($headers -join ', ')"
            ''
            '  Two formats are supported:'
            ''
            '  [1] Two-column format -- headers must be exactly: Domain,GroupName'
            '      Domain,GroupName'
            '      CORP,Domain Admins'
            '      CORP,Enterprise Admins'
            '      EUROPE,Helpdesk'
            ''
            '  [2] Single-column format -- header must be exactly: Group'
            '      Group'
            '      CORP\Domain Admins'
            '      CORP\Enterprise Admins'
            '      EUROPE\Helpdesk'
            ''
            '  Headers are case-insensitive. Sample files: Templates\groups-example-*.csv'
        ) -join [Environment]::NewLine
        throw $msg
    }

    $results = @()

    foreach ($row in $rows) {
        $domain    = ''
        $groupName = ''

        if ($isStandard) {
            $domain    = $row.Domain.Trim()
            $groupName = $row.GroupName.Trim()
        } else {
            # Backslash format: "DOMAIN\GroupName"
            $raw = $row.Group.Trim()
            if ($raw -match '^([^\\]+)\\(.+)$') {
                $domain    = $matches[1].Trim()
                $groupName = $matches[2].Trim()
            } else {
                # No backslash -- treat entire value as group name
                $domain    = $DefaultDomain
                $groupName = $raw
            }
        }

        # Fall back to DefaultDomain if domain still empty
        if (-not $domain) {
            $domain = $DefaultDomain
        }

        if (-not $groupName) {
            continue  # Skip blank rows
        }

        $results += @{
            Domain    = $domain
            GroupName = $groupName
        }
    }

    return , $results
}


# ---------------------------------------------------------------------------
# Private helper: Resolve-MemberDnToRecord
# Given a member DN, pick the right pooled context (cross-forest aware),
# handle ForeignSecurityPrincipal indirection, and return a member record
# hashtable in the standard shape expected by Get-GroupMembersDirect.
# ---------------------------------------------------------------------------
function script:Resolve-MemberDnToRecord {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]  [string]$MemberDN,
        [Parameter(Mandatory = $true)]  [hashtable]$LocalContext,
        [Parameter(Mandatory = $true)]  [string]$LocalDomain,
        [Parameter(Mandatory = $false)] [hashtable]$Pool,
        [Parameter(Mandatory = $false)] [int]$TimeoutSeconds = 120,
        [Parameter(Mandatory = $false)] [string[]]$IncludeAttributes = @()
    )

    $userAttrs = @('sAMAccountName','displayName','mail','userAccountControl','distinguishedName')
    $extraAttrs = @($IncludeAttributes | Where-Object { $_ } | ForEach-Object { $_.Trim() })
    if ($extraAttrs.Count -gt 0) {
        $userAttrs = $userAttrs + $extraAttrs
    }

    # Helper: build member hashtable from search result, including extra attributes
    $buildMemberRecord = {
        param([hashtable]$m, [string]$domain)
        $uac = if ($m.ContainsKey('userAccountControl')) { [int]$m.userAccountControl } else { 0 }
        $record = @{
            SamAccountName    = if ($m.ContainsKey('sAMAccountName')) { $m.sAMAccountName } else { $null }
            DisplayName       = if ($m.ContainsKey('displayName'))    { $m.displayName }    else { $null }
            Email             = if ($m.ContainsKey('mail'))           { $m.mail }           else { $null }
            Enabled           = (($uac -band 2) -eq 0)
            Domain            = $domain
            DistinguishedName = $m.DistinguishedName
        }
        # Add extra requested attributes
        foreach ($attr in $extraAttrs) {
            $attrLower = $attr.ToLower()
            $attrVal = if ($m.ContainsKey($attrLower)) { $m.$attrLower } elseif ($m.ContainsKey($attr)) { $m.$attr } else { $null }
            # Special handling: manager is a DN -- resolve to display name
            if ($attrLower -eq 'manager' -and $attrVal -and $queryCtx) {
                $mgrName = $null
                try {
                    $mgrHit = Invoke-AdLdapSearch -Context $queryCtx -BaseDN $attrVal `
                        -Filter '(objectCategory=person)' -Scope Base `
                        -Attributes @('displayName','sAMAccountName') -TimeoutSeconds $TimeoutSeconds
                    if ($mgrHit.Count -gt 0) {
                        $mgrName = if ($mgrHit[0].ContainsKey('displayName')) { $mgrHit[0].displayName } else { $mgrHit[0].sAMAccountName }
                    }
                } catch { }
                $record['Manager']   = $(if ($mgrName) { $mgrName } else { $attrVal })
                $record['ManagerDN'] = $attrVal
            } else {
                $record[$attr] = $attrVal
            }
        }
        return $record
    }

    $partial = @{
        SamAccountName    = $null
        DisplayName       = $null
        Email             = $null
        Enabled           = $null
        Domain            = $LocalDomain
        DistinguishedName = $MemberDN
    }

    # --- FSP indirection: resolve SID via foreign pooled context ---
    if ($MemberDN -match 'CN=ForeignSecurityPrincipals') {
        if (-not $Pool) { return $partial }
        try {
            $fspHit = Invoke-AdLdapSearch -Context $LocalContext -BaseDN $MemberDN -Scope Base `
                -Filter '(objectClass=*)' `
                -Attributes @('objectSid','distinguishedName') `
                -BinaryAttributes @('objectSid') `
                -TimeoutSeconds $TimeoutSeconds
        } catch { return $partial }
        if ($fspHit.Count -eq 0 -or -not $fspHit[0].ContainsKey('objectSid')) { return $partial }

        $sidBytes = [byte[]]$fspHit[0].objectSid
        $userSid  = ConvertTo-AdLdapSidString -SidBytes $sidBytes
        # Foreign domain SID = user SID minus the trailing RID
        $foreignDomainSid = $userSid -replace '-\d+$', ''

        # Find pooled context whose domain SID matches
        $target = $null
        $targetDomain = $null
        foreach ($entry in $Pool.Domains.GetEnumerator()) {
            $ctx = $entry.Value
            $poolSid = Get-AdLdapDomainSid -Pool $Pool -Context $ctx
            if ($poolSid -and ($poolSid -eq $foreignDomainSid)) {
                $target = $ctx
                $targetDomain = $entry.Key
                break
            }
        }
        if (-not $target) { return $partial }

        # Lookup in the foreign context by SID (binary filter)
        $sidFilter = ConvertTo-AdLdapSidFilter -SidBytes $sidBytes
        try {
            $userHit = Invoke-AdLdapSearch -Context $target -BaseDN $target.BaseDN -Scope Subtree `
                -Filter "(&(objectCategory=person)(objectSid=$sidFilter))" `
                -Attributes $userAttrs `
                -TimeoutSeconds $TimeoutSeconds
        } catch { return $partial }
        if ($userHit.Count -eq 0) { return $partial }

        $m = $userHit[0]
        $queryCtx = $target  # Set for manager resolution in buildMemberRecord
        return (& $buildMemberRecord $m $targetDomain)
    }

    # --- Direct cross-domain DN routing ---
    # If the member DN lives in a different pooled domain, route to that context
    $queryCtx    = $LocalContext
    $queryDomain = $LocalDomain
    if ($Pool) {
        $routed = Get-AdLdapContextForDN -Pool $Pool -DistinguishedName $MemberDN
        if ($routed -and $routed.BaseDN -ne $LocalContext.BaseDN) {
            $queryCtx = $routed
            # Find the domain key for the routed context
            foreach ($entry in $Pool.Domains.GetEnumerator()) {
                if ($entry.Value -eq $routed) { $queryDomain = $entry.Key; break }
            }
        }
    }

    try {
        $hit = Invoke-AdLdapSearch -Context $queryCtx -BaseDN $MemberDN `
            -Filter '(objectCategory=person)' -Scope Base `
            -Attributes $userAttrs `
            -TimeoutSeconds $TimeoutSeconds
    } catch {
        return $partial
    }

    if ($hit.Count -eq 0) { return $partial }
    $m = $hit[0]
    return (& $buildMemberRecord $m $queryDomain)
}

function Get-GroupMembersDirect {
    <#
    .SYNOPSIS
        Low-level group enumerator on top of ADLdap helpers.

    .DESCRIPTION
        When a ConnectionPool is supplied, contexts are pulled from the pool
        (opened lazily, reused, disposed by the pool owner). When no pool is
        supplied, a one-shot connection is opened and closed for this call
        (backward-compatible with the single-call mode used by unit tests).

        Cross-forest member resolution is active when a pool is supplied:
        member DNs routed to the correct pooled domain, and
        ForeignSecurityPrincipal entries resolved by SID against the foreign
        pooled context.

    .OUTPUTS
        Hashtable: @{ Members; DistinguishedName; MemberCount; Skipped; SkipReason; Errors }
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]  [string]$Domain,
        [Parameter(Mandatory = $true)]  [string]$GroupName,
        [Parameter(Mandatory = $false)] [PSCredential]$Credential,
        [Parameter(Mandatory = $false)] [hashtable]$Config = @{},
        [Parameter(Mandatory = $false)] [hashtable]$ConnectionPool,
        [Parameter(Mandatory = $false)] [string[]]$IncludeAttributes = @()
    )

    $errors      = @()
    $members     = @()
    $groupDN     = $null
    $memberCount = 0

    $pageSize         = if ($Config.LdapPageSize)              { $Config.LdapPageSize }        else { 1000 }
    $timeoutSeconds   = if ($Config.LdapTimeout)               { $Config.LdapTimeout }         else { 120 }
    $maxMemberCount   = if ($Config.MaxMemberCount)            { $Config.MaxMemberCount }      else { 5000 }
    $skipLargeGroups  = if ($null -ne $Config.SkipLargeGroups) { $Config.SkipLargeGroups }     else { $true }
    $largeGroupThresh = if ($Config.LargeGroupThreshold)       { $Config.LargeGroupThreshold } else { 5000 }
    $skipGroupNames   = if ($Config.SkipGroups)                { $Config.SkipGroups }          else { @() }
    $allowInsecure    = if ($null -ne $Config.AllowInsecure)   { $Config.AllowInsecure }       else { $false }

    if ($skipGroupNames -contains $GroupName) {
        return @{
            Members = @(); DistinguishedName = $null; MemberCount = 0
            Skipped = $true
            SkipReason = "Group '$GroupName' is in the SkipGroups list"
            Errors = @()
        }
    }

    $ctx = $null
    $ownCtx = $false    # true when we opened the ctx ourselves (must close in finally)
    try {
        Write-GroupEnumLog -Level 'DEBUG' -Operation 'LdapConnect' `
            -Message "Obtaining LDAP connection to '$Domain'" `
            -Context @{ domain = $Domain; groupName = $GroupName; pooled = [bool]$ConnectionPool }

        try {
            if ($ConnectionPool) {
                $ctx = Get-AdLdapPooledContext -Pool $ConnectionPool -Domain $Domain
            } else {
                $connParams = @{
                    Server         = $Domain
                    TimeoutSeconds = $timeoutSeconds
                }
                if ($Credential)    { $connParams.Credential    = $Credential }
                if ($allowInsecure) { $connParams.AllowInsecure = $true }
                $ctx = New-AdLdapConnection @connParams
                $ownCtx = $true
            }
        } catch {
            Write-GroupEnumLog -Level 'ERROR' -Operation 'LdapConnect' `
                -Message "Could not connect to '$Domain'" `
                -Context @{ domain = $Domain; error = $_.ToString() }
            throw
        }

        Write-GroupEnumLog -Level 'INFO' -Operation 'LdapConnect' `
            -Message "Using connection to '$Domain' via $($ctx.Tier)" `
            -Context @{ domain = $Domain; tier = $ctx.Tier; port = $ctx.Port; baseDN = $ctx.BaseDN; pooled = (-not $ownCtx) }

        if ($ctx.Tier -ne 'LDAPS-Verified') {
            $errors += "WARNING: Using tier '$($ctx.Tier)' (port $($ctx.Port)) for domain '$Domain'. Verified LDAPS was not available."
        }

        # Find the group
        $groupHits = Invoke-AdLdapSearch -Context $ctx `
            -Filter "(&(objectCategory=group)(cn=$GroupName))" `
            -Attributes @('distinguishedName','cn','member') `
            -PageSize $pageSize -TimeoutSeconds $timeoutSeconds

        if ($groupHits.Count -eq 0) {
            return @{
                Members = @(); DistinguishedName = $null; MemberCount = 0
                Skipped = $true
                SkipReason = "Group '$GroupName' not found in domain '$Domain'"
                Errors = $errors + @("Group not found")
            }
        }

        $g = $groupHits[0]
        $groupDN = $g.DistinguishedName

        $rawMemberDNs = @()
        if ($g.ContainsKey('member')) {
            if ($g.member -is [array]) { $rawMemberDNs = @($g.member) }
            else                       { $rawMemberDNs = @([string]$g.member) }
        }
        $memberCount = $rawMemberDNs.Count

        if ($skipLargeGroups -and $memberCount -ge $largeGroupThresh) {
            return @{
                Members = @(); DistinguishedName = $groupDN; MemberCount = $memberCount
                Skipped = $true
                SkipReason = "Group '$GroupName' has $memberCount members (threshold: $largeGroupThresh)"
                Errors = $errors
            }
        }

        $memberDNsToQuery = if ($rawMemberDNs.Count -gt $maxMemberCount) {
            $errors += "Warning: Member count ($($rawMemberDNs.Count)) exceeds MaxMemberCount ($maxMemberCount). Results truncated."
            $rawMemberDNs[0..($maxMemberCount - 1)]
        } else {
            $rawMemberDNs
        }

        foreach ($memberDN in $memberDNsToQuery) {
            try {
                $record = Resolve-MemberDnToRecord -MemberDN $memberDN `
                    -LocalContext $ctx -LocalDomain $Domain `
                    -Pool $ConnectionPool -TimeoutSeconds $timeoutSeconds `
                    -IncludeAttributes $IncludeAttributes
                $members += $record
            } catch {
                $errors += "Failed to query member '$memberDN': $($_.Exception.Message.Trim())"
            }
        }

        return @{
            Members           = $members
            DistinguishedName = $groupDN
            MemberCount       = $memberCount
            Skipped           = $false
            SkipReason        = $null
            Errors            = $errors
        }

    } finally {
        if ($ctx -and $ownCtx) { Close-AdLdapConnection $ctx }
    }
}

function Get-GroupMembers {
    <#
    .SYNOPSIS
        Enumerates members of a single AD group via LDAPS

    .DESCRIPTION
        Top-level enumeration function. Validates parameters, applies SkipGroups
        and LargeGroupThreshold checks, then delegates to Get-GroupMembersDirect
        for the actual LDAP work.

        Returns the standard module return shape:
          @{ Data = @{ GroupName; Domain; DistinguishedName; MemberCount; Members;
                       Skipped; SkipReason }; Errors = @() }

    .PARAMETER Domain
        NetBIOS name or FQDN of the target domain

    .PARAMETER GroupName
        Common name (CN) of the group to enumerate

    .PARAMETER Credential
        Optional PSCredential. Omit to use current Windows identity (Kerberos).

    .PARAMETER Config
        Configuration hashtable from New-GroupEnumConfig (or raw hashtable with same keys)

    .OUTPUTS
        Hashtable: @{ Data = @{...}; Errors = @() }
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Domain,

        [Parameter(Mandatory = $true)]
        [string]$GroupName,

        [Parameter(Mandatory = $false)]
        [PSCredential]$Credential,

        [Parameter(Mandatory = $false)]
        [hashtable]$Config = @{},

        [Parameter(Mandatory = $false)]
        [hashtable]$ConnectionPool,

        [Parameter(Mandatory = $false)]
        [string[]]$IncludeAttributes = @()
    )

    $errors = @()

    if ([string]::IsNullOrWhiteSpace($Domain)) {
        return @{
            Data   = $null
            Errors = @("Domain parameter is required and cannot be empty")
        }
    }

    if ([string]::IsNullOrWhiteSpace($GroupName)) {
        return @{
            Data   = $null
            Errors = @("GroupName parameter is required and cannot be empty")
        }
    }

    try {
        $directParams = @{
            Domain     = $Domain
            GroupName  = $GroupName
            Credential = $Credential
            Config     = $Config
        }
        if ($ConnectionPool) { $directParams.ConnectionPool = $ConnectionPool }
        if ($IncludeAttributes.Count -gt 0) { $directParams.IncludeAttributes = $IncludeAttributes }
        $raw = Get-GroupMembersDirect @directParams

        if ($raw.Errors.Count -gt 0) {
            $errors += $raw.Errors
        }

        $data = @{
            GroupName         = $GroupName
            Domain            = $Domain
            DistinguishedName = $raw.DistinguishedName
            MemberCount       = $raw.MemberCount
            Members           = $raw.Members
            Skipped           = $raw.Skipped
            SkipReason        = $raw.SkipReason
        }

        return @{
            Data   = $data
            Errors = $errors
        }

    } catch {
        $errors += "Unexpected error enumerating group '$Domain\$GroupName': $_"
        return @{
            Data   = @{
                GroupName         = $GroupName
                Domain            = $Domain
                DistinguishedName = $null
                MemberCount       = 0
                Members           = @()
                Skipped           = $false
                SkipReason        = $null
            }
            Errors = $errors
        }
    }
}
