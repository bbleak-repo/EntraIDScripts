<#
.SYNOPSIS
    Modern Active Directory LDAP helper built on System.DirectoryServices.Protocols

.DESCRIPTION
    Self-contained LDAP connection and search helpers for Active Directory tools.
    Uses System.DirectoryServices.Protocols.LdapConnection (not legacy ADSI
    DirectoryEntry) so it works against DCs that enforce LDAP Channel Binding
    (CBT) and LDAP Signing -- the modern hardened default.

    Connection tiers (tried in order, highest security first):
      Tier 1: LDAPS 636, cert verification strict      (always attempted)
      Tier 2: LDAPS 636, cert verification bypassed    (requires -AllowInsecure)
      Tier 3: LDAP  389, SASL sign + seal (Kerberos)   (requires -AllowInsecure)
      Tier 4: LDAP  389, no signing/sealing            (requires -AllowInsecureUnsigned)

    Authentication: AuthType.Negotiate (Kerberos preferred, NTLM fallback).
    Credentials: optional PSCredential; when omitted the current Windows identity
    is used via SSPI.

.NOTES
    CANONICAL COPY: Group-Enumerator/Modules/ADLdap.ps1
    This file is intentionally self-contained. It has no dependencies on any
    other module in the repo so it can be dropped into any AD tool's Modules/
    directory and dot-sourced. When fixing bugs, update this canonical copy and
    sync any vendored copies in sibling tools (AD-Discovery, etc.).

    Compatible with PowerShell 5.1 and 7+. Windows only (requires the
    System.DirectoryServices.Protocols assembly).
#>

# Ensure the Protocols assembly is loaded (no-op if already loaded).
Add-Type -AssemblyName System.DirectoryServices.Protocols -ErrorAction SilentlyContinue

# ---------------------------------------------------------------------------
# Public: New-AdLdapConnection
# ---------------------------------------------------------------------------
function New-AdLdapConnection {
    <#
    .SYNOPSIS
        Opens an authenticated LdapConnection to an AD domain, trying tiers in
        order of decreasing security.

    .PARAMETER Server
        Target server. May be a DC hostname, a domain FQDN, or an IP address.
        When a domain FQDN is supplied, Windows will locate a DC via DC Locator
        (serverless binding) -- this is usually what you want for portability.

    .PARAMETER Credential
        Optional PSCredential. When omitted the current Windows identity is used.

    .PARAMETER AllowInsecure
        Enables fallback tiers: LDAPS with cert verification bypassed, and LDAP
        389 with SASL sign+seal (Kerberos-encrypted session). Defaults to $false.

    .PARAMETER AllowInsecureUnsigned
        Enables the lowest fallback: LDAP 389 with no signing or sealing. Only
        use when talking to legacy DCs that refuse modern auth. Off by default
        and ignored unless -AllowInsecure is also set.

    .PARAMETER TimeoutSeconds
        Bind + search timeout in seconds. Defaults to 120.

    .OUTPUTS
        Hashtable @{
            Connection = [System.DirectoryServices.Protocols.LdapConnection]
            BaseDN     = '<defaultNamingContext>'
            Tier       = 'LDAPS-Verified' | 'LDAPS-Unverified' | 'LDAP-SignSeal' | 'LDAP-Plain'
            Port       = 636 | 389
            Secure     = $true | $false
            Server     = '<server you passed in>'
            Errors     = @() # non-fatal warnings from skipped tiers
        }

    .NOTES
        Caller is responsible for disposing the returned Connection, either
        directly (.Dispose()) or via Close-AdLdapConnection.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Server,

        [Parameter(Mandatory = $false)]
        [PSCredential]$Credential,

        [Parameter(Mandatory = $false)]
        [switch]$AllowInsecure,

        [Parameter(Mandatory = $false)]
        [switch]$AllowInsecureUnsigned,

        [Parameter(Mandatory = $false)]
        [int]$TimeoutSeconds = 120
    )

    $tierErrors = @()

    # Build the list of tiers to try in descending security order.
    $tiers = New-Object System.Collections.Generic.List[hashtable]
    $tiers.Add(@{ Name = 'LDAPS-Verified';   Port = 636; Ssl = $true;  VerifyCert = $true;  SignSeal = $false }) | Out-Null
    if ($AllowInsecure) {
        $tiers.Add(@{ Name = 'LDAPS-Unverified'; Port = 636; Ssl = $true;  VerifyCert = $false; SignSeal = $false }) | Out-Null
        $tiers.Add(@{ Name = 'LDAP-SignSeal';    Port = 389; Ssl = $false; VerifyCert = $false; SignSeal = $true  }) | Out-Null
        if ($AllowInsecureUnsigned) {
            $tiers.Add(@{ Name = 'LDAP-Plain';   Port = 389; Ssl = $false; VerifyCert = $false; SignSeal = $false }) | Out-Null
        }
    }

    foreach ($tier in $tiers) {
        $conn = $null
        try {
            Write-Verbose "New-AdLdapConnection: trying tier '$($tier.Name)' on $Server`:$($tier.Port)"

            $id   = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier(
                        $Server, [int]$tier.Port, <# fullyQualifiedDnsHostName #> $false, <# connectionless #> $false)
            $conn = New-Object System.DirectoryServices.Protocols.LdapConnection($id)
            $conn.AuthType    = [System.DirectoryServices.Protocols.AuthType]::Negotiate
            $conn.Timeout     = [TimeSpan]::FromSeconds($TimeoutSeconds)
            $conn.SessionOptions.ProtocolVersion = 3
            $conn.SessionOptions.ReferralChasing = [System.DirectoryServices.Protocols.ReferralChasingOptions]::None

            if ($tier.Ssl) {
                $conn.SessionOptions.SecureSocketLayer = $true
                if (-not $tier.VerifyCert) {
                    # Accept any server cert. Channel is still encrypted; we're
                    # just trusting the server identity on faith.
                    $conn.SessionOptions.VerifyServerCertificate = {
                        param($connection, $certificate) $true
                    }
                }
            } elseif ($tier.SignSeal) {
                # SASL sign + seal (Kerberos-encrypted session over 389)
                $conn.SessionOptions.Signing = $true
                $conn.SessionOptions.Sealing = $true
            }

            if ($Credential) {
                $netCred = New-Object System.Net.NetworkCredential(
                    $Credential.UserName,
                    $Credential.GetNetworkCredential().Password,
                    $Credential.GetNetworkCredential().Domain)
                $conn.Bind($netCred)
            } else {
                $conn.Bind()  # current Windows identity via SSPI
            }

            # Discover the base DN from the RootDSE
            $rootReq = New-Object System.DirectoryServices.Protocols.SearchRequest(
                '', '(objectClass=*)',
                [System.DirectoryServices.Protocols.SearchScope]::Base,
                @('defaultNamingContext'))
            $rootResp = $conn.SendRequest($rootReq)
            if ($rootResp.Entries.Count -eq 0 -or -not $rootResp.Entries[0].Attributes['defaultNamingContext']) {
                throw "Connected but RootDSE did not return defaultNamingContext"
            }
            $baseDN = [string]$rootResp.Entries[0].Attributes['defaultNamingContext'][0]

            Write-Verbose "New-AdLdapConnection: tier '$($tier.Name)' succeeded, baseDN=$baseDN"

            return @{
                Connection = $conn
                BaseDN     = $baseDN
                Tier       = $tier.Name
                Port       = [int]$tier.Port
                Secure     = [bool]$tier.Ssl
                Server     = $Server
                Errors     = $tierErrors
            }

        } catch {
            $msg = "Tier '$($tier.Name)' on $Server`:$($tier.Port) failed: $($_.Exception.Message.Trim())"
            Write-Verbose "New-AdLdapConnection: $msg"
            $tierErrors += $msg
            if ($conn) { try { $conn.Dispose() } catch {} }
            # fall through to next tier
        }
    }

    # All tiers exhausted
    $summary = "Unable to establish an LDAP connection to '$Server'. Attempts:`n  - " + ($tierErrors -join "`n  - ")
    if (-not $AllowInsecure) {
        $summary += "`nNote: only LDAPS-Verified was tried. Pass -AllowInsecure to enable fallback tiers (LDAPS cert bypass, 389 sign+seal)."
    }
    throw $summary
}

# ---------------------------------------------------------------------------
# Public: Invoke-AdLdapSearch
# ---------------------------------------------------------------------------
function Invoke-AdLdapSearch {
    <#
    .SYNOPSIS
        Runs a paged LDAP search and returns entries as plain hashtables.

    .PARAMETER Context
        A connection context hashtable returned by New-AdLdapConnection.

    .PARAMETER BaseDN
        Base DN for the search. Defaults to $Context.BaseDN.

    .PARAMETER Filter
        LDAP filter string. Must be a valid LDAP filter (e.g.
        '(&(objectCategory=group)(cn=Domain Admins))').

    .PARAMETER Attributes
        Array of attribute names to load. Pass an empty array to return DN only.

    .PARAMETER Scope
        Subtree (default), OneLevel, or Base.

    .PARAMETER PageSize
        Paging page size. Defaults to 1000. Server-side paging handles large
        result sets without hitting the default 1000-row LDAP cap.

    .PARAMETER SizeLimit
        Soft maximum number of entries to return across all pages. 0 (default)
        means no cap.

    .PARAMETER TimeoutSeconds
        Per-request timeout. Defaults to 120.

    .OUTPUTS
        Array of hashtables. Each entry looks like:
            @{
                DistinguishedName = 'CN=...,DC=...'
                <attr1>           = <string or string[]>
                <attr2>           = <string or string[]>
                ...
            }
        Multi-valued attributes come back as string arrays; single-valued as
        scalar strings; missing attributes are absent from the hashtable.
    #>
    [CmdletBinding()]
    [OutputType([hashtable[]])]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Context,

        [Parameter(Mandatory = $false)]
        [string]$BaseDN,

        [Parameter(Mandatory = $true)]
        [string]$Filter,

        [Parameter(Mandatory = $false)]
        [string[]]$Attributes = @(),

        [Parameter(Mandatory = $false)]
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [string]$Scope = 'Subtree',

        [Parameter(Mandatory = $false)]
        [int]$PageSize = 1000,

        [Parameter(Mandatory = $false)]
        [int]$SizeLimit = 0,

        [Parameter(Mandatory = $false)]
        [int]$TimeoutSeconds = 120
    )

    if (-not $Context -or -not $Context.Connection) {
        throw "Invoke-AdLdapSearch: Context is null or missing a Connection"
    }

    $conn    = $Context.Connection
    $effBase = if ($BaseDN) { $BaseDN } else { $Context.BaseDN }

    $scopeEnum = switch ($Scope) {
        'Base'     { [System.DirectoryServices.Protocols.SearchScope]::Base }
        'OneLevel' { [System.DirectoryServices.Protocols.SearchScope]::OneLevel }
        default    { [System.DirectoryServices.Protocols.SearchScope]::Subtree }
    }

    $results = New-Object System.Collections.Generic.List[hashtable]
    $pagingControl = $null

    # Base-scope single-entry fetches don't need paging.
    $usePaging = ($scopeEnum -ne [System.DirectoryServices.Protocols.SearchScope]::Base)

    if ($usePaging) {
        $pagingControl = New-Object System.DirectoryServices.Protocols.PageResultRequestControl($PageSize)
        $pagingControl.IsCritical = $false
    }

    do {
        $req = New-Object System.DirectoryServices.Protocols.SearchRequest(
            $effBase, $Filter, $scopeEnum, $Attributes)
        $req.TimeLimit = [TimeSpan]::FromSeconds($TimeoutSeconds)
        if ($usePaging) { $null = $req.Controls.Add($pagingControl) }

        $resp = $conn.SendRequest($req)

        foreach ($entry in $resp.Entries) {
            # Entries with a null DN are referral responses; skip them.
            if (-not $entry.DistinguishedName) { continue }

            $h = @{ DistinguishedName = [string]$entry.DistinguishedName }
            foreach ($attrName in $entry.Attributes.AttributeNames) {
                $attr = $entry.Attributes[$attrName]
                if ($attr.Count -eq 0) { continue }
                if ($attr.Count -eq 1) {
                    $h[$attrName] = [string]$attr[0]
                } else {
                    $vals = New-Object System.Collections.Generic.List[string]
                    foreach ($v in $attr.GetValues([string])) { $vals.Add([string]$v) }
                    $h[$attrName] = $vals.ToArray()
                }
            }
            $results.Add($h) | Out-Null

            if ($SizeLimit -gt 0 -and $results.Count -ge $SizeLimit) { break }
        }

        if ($SizeLimit -gt 0 -and $results.Count -ge $SizeLimit) { break }

        # Paging continuation
        if ($usePaging) {
            $cookie = $null
            foreach ($c in $resp.Controls) {
                if ($c -is [System.DirectoryServices.Protocols.PageResultResponseControl]) {
                    $cookie = $c.Cookie
                    break
                }
            }
            if ($null -eq $cookie -or $cookie.Length -eq 0) { break }
            $pagingControl.Cookie = $cookie
        } else {
            break
        }
    } while ($true)

    return ,$results.ToArray()
}

# ---------------------------------------------------------------------------
# Public: Get-AdLdapRootDse
# ---------------------------------------------------------------------------
function Get-AdLdapRootDse {
    <#
    .SYNOPSIS
        Returns the RootDSE as a hashtable. Useful for discovering naming
        contexts, supported controls, and forest-wide metadata.

    .PARAMETER Context
        Connection context from New-AdLdapConnection.

    .PARAMETER Attributes
        Attributes to load. Defaults to the common set.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Context,

        [Parameter(Mandatory = $false)]
        [string[]]$Attributes = @(
            'defaultNamingContext',
            'configurationNamingContext',
            'schemaNamingContext',
            'rootDomainNamingContext',
            'dnsHostName',
            'serverName',
            'supportedLDAPVersion',
            'supportedControl'
        )
    )

    $entries = Invoke-AdLdapSearch -Context $Context -BaseDN '' `
        -Filter '(objectClass=*)' -Scope Base -Attributes $Attributes
    if ($entries.Count -eq 0) { return @{} }
    return $entries[0]
}

# ---------------------------------------------------------------------------
# Public: Close-AdLdapConnection
# ---------------------------------------------------------------------------
function Close-AdLdapConnection {
    <#
    .SYNOPSIS
        Disposes an LdapConnection context. Safe to call with $null.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
        [hashtable]$Context
    )
    if ($Context -and $Context.Connection) {
        try { $Context.Connection.Dispose() } catch { }
    }
}
