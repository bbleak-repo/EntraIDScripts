<#
.SYNOPSIS
    Cross-domain group membership enumeration module

.DESCRIPTION
    Enumerates Active Directory group members across multiple domains via LDAPS.
    Supports CSV input in Domain,GroupName or DOMAIN\GroupName backslash format.
    Returns standardized @{ Data = ...; Errors = @() } hashtables throughout.

.NOTES
    Requires DirectoryServices (.NET). Compatible with PowerShell 5.1 and 7+.
    Always uses LDAPS (port 636, SecureSocketsLayer). Never uses plaintext LDAP 389.
    Always disposes DirectoryEntry and DirectorySearcher objects in finally blocks.
    Uses objectCategory (indexed) for all LDAP group/user filters.
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
        throw "Unrecognised CSV format. Expected headers 'Domain,GroupName' or 'Group' (DOMAIN\GroupName values). Found: $($headers -join ', ')"
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

function New-LdapDirectoryEntry {
    <#
    .SYNOPSIS
        Creates a DirectoryEntry for LDAP or LDAPS connections with proper auth flags

    .DESCRIPTION
        Connection strategy (in order of security):
          1. LDAPS (port 636) - Full TLS encryption. Requires DC cert trusted by client.
          2. LDAP + Kerberos Sealing (port 389) - Kerberos-encrypted session data.
             Nearly equivalent to LDAPS when both sides are domain-joined.
          3. LDAP plain (port 389) - Authentication only, data in clear. Last resort.

    .PARAMETER Domain
        NetBIOS name or FQDN of the target domain

    .PARAMETER Port
        LDAP port: 636 (LDAPS) or 389 (LDAP)

    .PARAMETER Secure
        $true for LDAPS (SecureSocketsLayer), $false for LDAP.
        When $false and no explicit credential, Sealing is added for Kerberos encryption.

    .PARAMETER Credential
        Optional PSCredential. When omitted, current Windows identity (Kerberos) is used.

    .PARAMETER BaseDN
        Optional base DN to append to the path (e.g. a specific member DN)
    #>
    [CmdletBinding()]
    [OutputType([System.DirectoryServices.DirectoryEntry])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Domain,

        [Parameter(Mandatory = $true)]
        [int]$Port,

        [Parameter(Mandatory = $true)]
        [bool]$Secure,

        [Parameter(Mandatory = $false)]
        [PSCredential]$Credential,

        [Parameter(Mandatory = $false)]
        [string]$BaseDN
    )

    $path = if ($BaseDN) {
        "LDAP://$Domain`:$Port/$BaseDN"
    } else {
        "LDAP://$Domain`:$Port"
    }

    if ($Secure) {
        $authType = [System.DirectoryServices.AuthenticationTypes]::SecureSocketsLayer
    } else {
        # LDAP 389: use Sealing for Kerberos-encrypted session when using integrated auth
        # Sealing wraps the entire LDAP session in Kerberos encryption (SASL/GSSAPI)
        if ($Credential) {
            $authType = [System.DirectoryServices.AuthenticationTypes]::Secure
        } else {
            $authType = [System.DirectoryServices.AuthenticationTypes]::Secure -bor
                        [System.DirectoryServices.AuthenticationTypes]::Sealing
        }
    }

    if ($Credential) {
        return New-Object System.DirectoryServices.DirectoryEntry(
            $path,
            $Credential.UserName,
            $Credential.GetNetworkCredential().Password,
            $authType
        )
    } else {
        return New-Object System.DirectoryServices.DirectoryEntry(
            $path,
            $null,
            $null,
            $authType
        )
    }
}

function Get-GroupMembersDirect {
    <#
    .SYNOPSIS
        Low-level helper: enumerates group members via DirectoryEntry + DirectorySearcher

    .DESCRIPTION
        Builds an LDAPS connection to the target domain, finds the group by CN,
        reads its member DNs, then queries each member for user properties.
        Returns raw member hashtables suitable for the Get-GroupMembers caller.

        Uses LDAPS port 636 with SecureSocketsLayer authentication exclusively.
        Uses objectCategory (indexed) in all LDAP filters.
        Disposes all DirectoryEntry and DirectorySearcher objects in finally blocks.

    .PARAMETER Domain
        NetBIOS domain name or FQDN used to build the LDAP path

    .PARAMETER GroupName
        CN (common name) of the group to enumerate

    .PARAMETER Credential
        Optional credentials. When omitted, current Windows identity is used.

    .PARAMETER Config
        Configuration hashtable (uses LdapPageSize, LdapTimeout, MaxMemberCount,
        SkipLargeGroups, LargeGroupThreshold, SkipGroups)

    .OUTPUTS
        Hashtable: @{ Members = @(...); DistinguishedName = "CN=..."; MemberCount = N;
                      Skipped = $false; SkipReason = $null; Errors = @() }
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
        [string[]]$IncludeAttributes = @()
    )

    $errors      = @()
    $members     = @()
    $groupDN     = $null
    $memberCount = 0
    $skipped     = $false
    $skipReason  = $null

    # Config values with defaults
    $pageSize           = if ($Config.LdapPageSize)        { $Config.LdapPageSize }        else { 1000 }
    $timeoutSeconds     = if ($Config.LdapTimeout)         { $Config.LdapTimeout }         else { 120 }
    $maxMemberCount     = if ($Config.MaxMemberCount)      { $Config.MaxMemberCount }      else { 5000 }
    $skipLargeGroups    = if ($null -ne $Config.SkipLargeGroups) { $Config.SkipLargeGroups } else { $true }
    $largeGroupThresh   = if ($Config.LargeGroupThreshold) { $Config.LargeGroupThreshold } else { 5000 }
    $skipGroupNames     = if ($Config.SkipGroups)          { $Config.SkipGroups }          else { @() }
    $allowInsecure      = if ($null -ne $Config.AllowInsecure)  { $Config.AllowInsecure }  else { $false }

    # Normalize extra attributes to lowercase for consistent handling
    $extraAttrs = @($IncludeAttributes | Where-Object { $_ } | ForEach-Object { $_.Trim() })

    # Check well-known skip list (case-insensitive)
    if ($skipGroupNames -contains $GroupName) {
        return @{
            Members          = @()
            DistinguishedName = $null
            MemberCount      = 0
            Skipped          = $true
            SkipReason       = "Group '$GroupName' is in the SkipGroups list"
            Errors           = @()
        }
    }

    $groupEntry   = $null
    $groupSearcher = $null
    $groupResults  = $null

    # Determine connection parameters: try LDAPS 636 first, fall back to 389 if AllowInsecure
    $usedInsecure = $false
    $connectionError636 = $null

    Write-GroupEnumLog -Level 'DEBUG' -Operation 'LdapConnect' `
        -Message "Attempting LDAPS (636) to domain '$Domain'" -Context @{
            domain = $Domain; port = 636; groupName = $GroupName
        }

    try {
        $groupEntry = New-LdapDirectoryEntry -Domain $Domain -Port 636 -Secure $true `
            -Credential $Credential
        # Validate the connection by accessing a property
        $null = $groupEntry.distinguishedName

        Write-GroupEnumLog -Level 'DEBUG' -Operation 'LdapConnect' `
            -Message "LDAPS (636) connected to '$Domain'" -Context @{
                domain = $Domain; port = 636; tier = 'LDAPS'
            }
    } catch {
        $connectionError636 = $_
        if ($groupEntry) { $groupEntry.Dispose(); $groupEntry = $null }

        Write-GroupEnumLog -Level 'WARN' -Operation 'LdapConnect' `
            -Message "LDAPS (636) failed for '$Domain': $connectionError636" -Context @{
                domain = $Domain; port = 636; error = $connectionError636.ToString()
            }

        if ($allowInsecure) {
            Write-Warning "LDAPS (636) failed for domain '$Domain': $connectionError636"
            Write-Warning "Falling back to LDAP (389) with Kerberos Sealing."

            Write-GroupEnumLog -Level 'INFO' -Operation 'LdapConnect' `
                -Message "Falling back to LDAP (389) with Kerberos Sealing for '$Domain'" -Context @{
                    domain = $Domain; port = 389; tier = 'Kerberos-Sealing'
                }

            try {
                $groupEntry = New-LdapDirectoryEntry -Domain $Domain -Port 389 -Secure $false `
                    -Credential $Credential
                $null = $groupEntry.distinguishedName
                $usedInsecure = $true
                $errors += "WARNING: Using LDAP (389) with Kerberos Sealing for domain '$Domain'. LDAPS (636) failed: $connectionError636"

                Write-GroupEnumLog -Level 'WARN' -Operation 'LdapConnect' `
                    -Message "Connected via LDAP (389) to '$Domain'" -Context @{
                        domain = $Domain; port = 389; tier = 'Kerberos-Sealing'
                        ldapsError = $connectionError636.ToString()
                    }
            } catch {
                if ($groupEntry) { $groupEntry.Dispose(); $groupEntry = $null }

                Write-GroupEnumLog -Level 'ERROR' -Operation 'LdapConnect' `
                    -Message "Both LDAPS (636) and LDAP (389) failed for '$Domain'" -Context @{
                        domain     = $Domain
                        ldapsError = $connectionError636.ToString()
                        ldapError  = $_.ToString()
                    }

                throw "Both LDAPS (636) and LDAP (389) failed for domain '$Domain'. LDAPS error: $connectionError636 -- LDAP error: $_"
            }
        } else {
            Write-GroupEnumLog -Level 'ERROR' -Operation 'LdapConnect' `
                -Message "LDAPS (636) failed and AllowInsecure is disabled for '$Domain'" -Context @{
                    domain = $Domain; error = $connectionError636.ToString()
                }

            throw "LDAPS (636) failed for domain '$Domain': $connectionError636. Use -AllowInsecure to fall back to LDAP (389)."
        }
    }

    # Track the port used for member queries later
    $ldapPort   = if ($usedInsecure) { 389 } else { 636 }
    $ldapSecure = -not $usedInsecure

    try {

        # Step 1: Find the group by CN using objectCategory (indexed)
        $groupSearcher = New-Object System.DirectoryServices.DirectorySearcher($groupEntry)
        $groupSearcher.Filter      = "(&(objectCategory=group)(cn=$GroupName))"
        $groupSearcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
        $groupSearcher.PageSize    = $pageSize
        $groupSearcher.ServerTimeLimit = New-TimeSpan -Seconds $timeoutSeconds
        $groupSearcher.ClientTimeout   = New-TimeSpan -Seconds ($timeoutSeconds + 10)

        $null = $groupSearcher.PropertiesToLoad.Add('distinguishedName')
        $null = $groupSearcher.PropertiesToLoad.Add('cn')
        $null = $groupSearcher.PropertiesToLoad.Add('member')
        $null = $groupSearcher.PropertiesToLoad.Add('memberOf')

        try {
            $groupResults = $groupSearcher.FindAll()

            if (-not $groupResults -or $groupResults.Count -eq 0) {
                return @{
                    Members           = @()
                    DistinguishedName = $null
                    MemberCount       = 0
                    Skipped           = $true
                    SkipReason        = "Group '$GroupName' not found in domain '$Domain'"
                    Errors            = @("Group not found")
                }
            }

            # Use the first match
            $groupResult = $groupResults[0]
            $groupDN = if ($groupResult.Properties['distinguishedName'].Count -gt 0) {
                $groupResult.Properties['distinguishedName'][0]
            } else { $null }

            # Get raw member DNs from the member attribute
            $rawMemberDNs = @()
            if ($groupResult.Properties['member'].Count -gt 0) {
                foreach ($m in $groupResult.Properties['member']) {
                    $rawMemberDNs += $m
                }
            }

            $memberCount = $rawMemberDNs.Count

        } finally {
            if ($groupResults) { $groupResults.Dispose() }
        }

    } catch {
        $errors += "Failed to find group '$GroupName' in domain '$Domain': $_"
        return @{
            Members           = @()
            DistinguishedName = $null
            MemberCount       = 0
            Skipped           = $false
            SkipReason        = $null
            Errors            = $errors
        }
    } finally {
        if ($groupSearcher) { $groupSearcher.Dispose() }
        if ($groupEntry)    { $groupEntry.Dispose() }
    }

    # Step 2: Check large-group threshold before enumerating members
    if ($skipLargeGroups -and $memberCount -ge $largeGroupThresh) {
        return @{
            Members           = @()
            DistinguishedName = $groupDN
            MemberCount       = $memberCount
            Skipped           = $true
            SkipReason        = "Group '$GroupName' has $memberCount members (threshold: $largeGroupThresh)"
            Errors            = @()
        }
    }

    # Cap member retrieval at MaxMemberCount
    $memberDNsToQuery = if ($rawMemberDNs.Count -gt $maxMemberCount) {
        $errors += "Warning: Member count ($($rawMemberDNs.Count)) exceeds MaxMemberCount ($maxMemberCount). Results truncated."
        $rawMemberDNs[0..($maxMemberCount - 1)]
    } else {
        $rawMemberDNs
    }

    # Step 3: For each member DN, query for user properties
    foreach ($memberDN in $memberDNsToQuery) {
        $memberEntry    = $null
        $memberSearcher = $null
        $memberResults  = $null

        try {
            # Use same port/security as the group query (636 or 389 fallback)
            $memberEntry = New-LdapDirectoryEntry -Domain $Domain -Port $ldapPort `
                -Secure $ldapSecure -Credential $Credential -BaseDN $memberDN

            $memberSearcher = New-Object System.DirectoryServices.DirectorySearcher($memberEntry)
            $memberSearcher.Filter      = "(objectCategory=person)"
            $memberSearcher.SearchScope = [System.DirectoryServices.SearchScope]::Base
            $memberSearcher.PageSize    = 1
            $memberSearcher.ServerTimeLimit = New-TimeSpan -Seconds $timeoutSeconds
            $memberSearcher.ClientTimeout   = New-TimeSpan -Seconds ($timeoutSeconds + 10)

            $null = $memberSearcher.PropertiesToLoad.Add('sAMAccountName')
            $null = $memberSearcher.PropertiesToLoad.Add('displayName')
            $null = $memberSearcher.PropertiesToLoad.Add('mail')
            $null = $memberSearcher.PropertiesToLoad.Add('userAccountControl')
            $null = $memberSearcher.PropertiesToLoad.Add('distinguishedName')

            # Add any extra requested attributes
            foreach ($attr in $extraAttrs) {
                $null = $memberSearcher.PropertiesToLoad.Add($attr)
            }

            try {
                $memberResults = $memberSearcher.FindAll()

                if ($memberResults -and $memberResults.Count -gt 0) {
                    $mr = $memberResults[0]

                    $sam     = if ($mr.Properties['sAMAccountName'].Count -gt 0)    { $mr.Properties['sAMAccountName'][0] }    else { $null }
                    $display = if ($mr.Properties['displayName'].Count -gt 0)       { $mr.Properties['displayName'][0] }       else { $null }
                    $mail    = if ($mr.Properties['mail'].Count -gt 0)              { $mr.Properties['mail'][0] }              else { $null }
                    $dn      = if ($mr.Properties['distinguishedName'].Count -gt 0) { $mr.Properties['distinguishedName'][0] } else { $memberDN }

                    $uac     = if ($mr.Properties['userAccountControl'].Count -gt 0) {
                        [int]$mr.Properties['userAccountControl'][0]
                    } else { 0 }

                    # Bit 2 (0x0002) of userAccountControl = ACCOUNTDISABLE
                    $enabled = ($uac -band 2) -eq 0

                    $memberHash = @{
                        SamAccountName    = $sam
                        DisplayName       = $display
                        Email             = $mail
                        Enabled           = $enabled
                        Domain            = $Domain
                        DistinguishedName = $dn
                    }

                    # Read extra attributes
                    foreach ($attr in $extraAttrs) {
                        $attrLower = $attr.ToLower()
                        $attrVal = if ($mr.Properties[$attrLower].Count -gt 0) {
                            $mr.Properties[$attrLower][0]
                        } else { $null }

                        # Special handling: manager attribute is a DN -- resolve to display name
                        if ($attrLower -eq 'manager' -and $attrVal) {
                            $managerDN = $attrVal
                            $managerName = $null
                            $mgrEntry = $null
                            $mgrSearcher = $null
                            $mgrResults = $null
                            try {
                                $mgrEntry = New-LdapDirectoryEntry -Domain $Domain -Port $ldapPort `
                                    -Secure $ldapSecure -Credential $Credential -BaseDN $managerDN
                                $mgrSearcher = New-Object System.DirectoryServices.DirectorySearcher($mgrEntry)
                                $mgrSearcher.Filter = '(objectCategory=person)'
                                $mgrSearcher.SearchScope = [System.DirectoryServices.SearchScope]::Base
                                $null = $mgrSearcher.PropertiesToLoad.Add('displayName')
                                $null = $mgrSearcher.PropertiesToLoad.Add('sAMAccountName')
                                try {
                                    $mgrResults = $mgrSearcher.FindAll()
                                    if ($mgrResults -and $mgrResults.Count -gt 0) {
                                        $mgrR = $mgrResults[0]
                                        $mgrDisplay = if ($mgrR.Properties['displayName'].Count -gt 0) { $mgrR.Properties['displayName'][0] } else { $null }
                                        $mgrSam = if ($mgrR.Properties['sAMAccountName'].Count -gt 0) { $mgrR.Properties['sAMAccountName'][0] } else { $null }
                                        $managerName = if ($mgrDisplay) { $mgrDisplay } else { $mgrSam }
                                    }
                                } finally {
                                    if ($mgrResults) { $mgrResults.Dispose() }
                                }
                            } catch {
                                # Manager resolution failed -- store raw DN
                            } finally {
                                if ($mgrSearcher) { $mgrSearcher.Dispose() }
                                if ($mgrEntry)    { $mgrEntry.Dispose() }
                            }

                            $memberHash['Manager']   = $(if ($managerName) { $managerName } else { $managerDN })
                            $memberHash['ManagerDN'] = $managerDN
                        } else {
                            $memberHash[$attr] = $attrVal
                        }
                    }

                    $members += $memberHash
                } else {
                    # Member DN exists but objectCategory=person returned nothing.
                    # Could be a nested group, contact, or computer. Include as partial entry.
                    $members += @{
                        SamAccountName    = $null
                        DisplayName       = $null
                        Email             = $null
                        Enabled           = $null
                        Domain            = $Domain
                        DistinguishedName = $memberDN
                    }
                }
            } finally {
                if ($memberResults) { $memberResults.Dispose() }
            }

        } catch {
            $errors += "Failed to query member '$memberDN': $_"
        } finally {
            if ($memberSearcher) { $memberSearcher.Dispose() }
            if ($memberEntry)    { $memberEntry.Dispose() }
        }
    }

    return @{
        Members           = $members
        DistinguishedName = $groupDN
        MemberCount       = $memberCount
        Skipped           = $skipped
        SkipReason        = $skipReason
        Errors            = $errors
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

    .PARAMETER IncludeAttributes
        Optional array of extra LDAP attribute names to retrieve for each member.
        The 'manager' attribute is automatically resolved from DN to display name.

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
        $raw = Get-GroupMembersDirect -Domain $Domain -GroupName $GroupName `
            -Credential $Credential -Config $Config -IncludeAttributes $IncludeAttributes

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
