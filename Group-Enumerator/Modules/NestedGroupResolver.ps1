<#
.SYNOPSIS
    Recursively resolves AD group membership to flat user lists

.DESCRIPTION
    Traverses nested AD group membership trees via LDAPS, returning a de-duplicated
    flat list of all user objects regardless of how many levels deep they are nested.

    Key behaviours:
      - Circular reference detection via visited-DN tracking
      - Configurable maximum recursion depth (NestedGroupMaxDepth config key, default 10)
      - De-duplication by DistinguishedName when the same user appears via multiple paths
      - Structured logging at DEBUG/INFO/WARN/ERROR levels using Write-GroupEnumLog
      - Respects AllowInsecure config for LDAP (389) fallback when LDAPS (636) fails
      - All DirectoryEntry and DirectorySearcher objects disposed in finally blocks

.NOTES
    Requires GroupEnumerator.ps1 and GroupEnumLogger.ps1 to be dot-sourced first
    (New-LdapDirectoryEntry and Write-GroupEnumLog must be loaded in the session).
    Compatible with PowerShell 5.1 and 7+. Targets Windows Active Directory only.
    Uses objectCategory (indexed) for all LDAP filters; never uses objectClass.
#>

# ---------------------------------------------------------------------------
# Private helper: build LDAP connection parameters from Config
# ---------------------------------------------------------------------------
function script:Get-LdapConnectionParams {
    param(
        [string]$Domain,
        [hashtable]$Config
    )

    $allowInsecure = if ($null -ne $Config.AllowInsecure) { $Config.AllowInsecure } else { $false }

    # Return a hashtable so callers can unpack the negotiated port/secure flag
    return @{
        Port          = 636
        Secure        = $true
        AllowInsecure = $allowInsecure
    }
}

# ---------------------------------------------------------------------------
# Private helper: establish a working DirectoryEntry with fallback logic
# Returns @{ Entry = <DirectoryEntry>; Port = <int>; Secure = <bool>; Error = <string> }
# ---------------------------------------------------------------------------
function script:Connect-LdapDomain {
    param(
        [string]$Domain,
        [PSCredential]$Credential,
        [hashtable]$Config,
        [string]$BaseDN
    )

    $allowInsecure = if ($null -ne $Config.AllowInsecure) { $Config.AllowInsecure } else { $false }
    $entryParams = @{
        Domain     = $Domain
        Port       = 636
        Secure     = $true
        Credential = $Credential
    }
    if ($BaseDN) { $entryParams.BaseDN = $BaseDN }

    Write-GroupEnumLog -Level 'DEBUG' -Operation 'LdapConnect' `
        -Message "Attempting LDAPS (636) to domain '$Domain'" `
        -Context @{ domain = $Domain; port = 636; baseDn = $BaseDN }

    $entry = $null
    try {
        $entry = New-LdapDirectoryEntry @entryParams
        # Probe the connection
        $null = $entry.distinguishedName

        Write-GroupEnumLog -Level 'DEBUG' -Operation 'LdapConnect' `
            -Message "LDAPS (636) connected to '$Domain'" `
            -Context @{ domain = $Domain; port = 636; tier = 'LDAPS' }

        return @{ Entry = $entry; Port = 636; Secure = $true; Error = $null }

    } catch {
        $ldapsError = $_.ToString()
        if ($entry) { $entry.Dispose(); $entry = $null }

        Write-GroupEnumLog -Level 'WARN' -Operation 'LdapConnect' `
            -Message "LDAPS (636) failed for '$Domain': $ldapsError" `
            -Context @{ domain = $Domain; port = 636; error = $ldapsError }

        if (-not $allowInsecure) {
            Write-GroupEnumLog -Level 'ERROR' -Operation 'LdapConnect' `
                -Message "LDAPS (636) failed and AllowInsecure is disabled for '$Domain'" `
                -Context @{ domain = $Domain; error = $ldapsError }
            return @{ Entry = $null; Port = 0; Secure = $false; Error = $ldapsError }
        }

        # Fallback to LDAP 389 + Kerberos Sealing
        Write-Warning "LDAPS (636) failed for domain '$Domain': $ldapsError"
        Write-Warning "Falling back to LDAP (389) with Kerberos Sealing."

        Write-GroupEnumLog -Level 'INFO' -Operation 'LdapConnect' `
            -Message "Falling back to LDAP (389) with Kerberos Sealing for '$Domain'" `
            -Context @{ domain = $Domain; port = 389; tier = 'Kerberos-Sealing' }

        $entryParams389 = @{
            Domain     = $Domain
            Port       = 389
            Secure     = $false
            Credential = $Credential
        }
        if ($BaseDN) { $entryParams389.BaseDN = $BaseDN }

        try {
            $entry = New-LdapDirectoryEntry @entryParams389
            $null  = $entry.distinguishedName

            Write-GroupEnumLog -Level 'WARN' -Operation 'LdapConnect' `
                -Message "Connected via LDAP (389) to '$Domain'" `
                -Context @{ domain = $Domain; port = 389; tier = 'Kerberos-Sealing'; ldapsError = $ldapsError }

            return @{ Entry = $entry; Port = 389; Secure = $false; Error = "WARNING: Using LDAP (389) with Kerberos Sealing for domain '$Domain'. LDAPS (636) failed: $ldapsError" }

        } catch {
            if ($entry) { $entry.Dispose(); $entry = $null }
            $ldapError = $_.ToString()

            Write-GroupEnumLog -Level 'ERROR' -Operation 'LdapConnect' `
                -Message "Both LDAPS (636) and LDAP (389) failed for '$Domain'" `
                -Context @{ domain = $Domain; ldapsError = $ldapsError; ldapError = $ldapError }

            return @{ Entry = $null; Port = 0; Secure = $false; Error = "Both LDAPS (636) and LDAP (389) failed for domain '$Domain'. LDAPS error: $ldapsError -- LDAP error: $ldapError" }
        }
    }
}

# ---------------------------------------------------------------------------
# Private: recursive core
# $visitedGroups  - hashtable keyed by DN (tracks already-visited groups)
# $flatUsers      - hashtable keyed by DN (de-duplicated user accumulator)
# $nestedGroups   - accumulator array (ref via [ref] inside plain hashtable trick)
# ---------------------------------------------------------------------------
function script:Resolve-GroupMembersRecursive {
    param(
        [string]$GroupDN,
        [string]$GroupName,
        [string]$Domain,
        [PSCredential]$Credential,
        [hashtable]$Config,
        [int]$CurrentDepth,
        [int]$MaxDepth,
        [hashtable]$VisitedGroups,       # [string DN] -> $true
        [hashtable]$FlatUsers,           # [string DN] -> user hashtable
        [System.Collections.ArrayList]$NestedGroups,
        [System.Collections.ArrayList]$ErrorList
    )

    # Guard: circular reference
    if ($VisitedGroups.ContainsKey($GroupDN)) {
        Write-GroupEnumLog -Level 'DEBUG' -Operation 'ResolveNested' `
            -Message "Skipping already-visited group DN (circular reference avoided)" `
            -Context @{ groupDn = $GroupDN; depth = $CurrentDepth }
        return
    }
    $VisitedGroups[$GroupDN] = $true

    # Guard: max depth
    if ($CurrentDepth -gt $MaxDepth) {
        Write-GroupEnumLog -Level 'WARN' -Operation 'ResolveNested' `
            -Message "Max recursion depth $MaxDepth reached at group '$GroupName'" `
            -Context @{ groupDn = $GroupDN; depth = $CurrentDepth; maxDepth = $MaxDepth }
        return
    }

    Write-GroupEnumLog -Level 'DEBUG' -Operation 'ResolveNested' `
        -Message "Resolving nested group '$GroupName' at depth $CurrentDepth" `
        -Context @{ group = $GroupName; groupDn = $GroupDN; depth = $CurrentDepth }

    $timeoutSeconds = if ($Config.LdapTimeout)  { $Config.LdapTimeout }  else { 120 }
    $pageSize       = if ($Config.LdapPageSize) { $Config.LdapPageSize } else { 1000 }

    # Establish connection scoped to the group DN
    $conn = script:Connect-LdapDomain -Domain $Domain -Credential $Credential `
        -Config $Config -BaseDN $GroupDN

    if (-not $conn.Entry) {
        $null = $ErrorList.Add("Failed to connect to domain '$Domain' for group DN '$GroupDN': $($conn.Error)")
        return
    }

    if ($conn.Error) {
        $null = $ErrorList.Add($conn.Error)
    }

    $ldapPort   = $conn.Port
    $ldapSecure = $conn.Secure
    $groupEntry = $conn.Entry

    $groupSearcher = $null
    $groupResults  = $null

    try {
        # Read the member attribute from the group DN (Base scope -- we already have the DN)
        $groupSearcher = New-Object System.DirectoryServices.DirectorySearcher($groupEntry)
        $groupSearcher.Filter      = "(objectCategory=group)"
        $groupSearcher.SearchScope = [System.DirectoryServices.SearchScope]::Base
        $groupSearcher.PageSize    = 1
        $groupSearcher.ServerTimeLimit = New-TimeSpan -Seconds $timeoutSeconds
        $groupSearcher.ClientTimeout   = New-TimeSpan -Seconds ($timeoutSeconds + 10)
        $null = $groupSearcher.PropertiesToLoad.Add('member')
        $null = $groupSearcher.PropertiesToLoad.Add('cn')
        $null = $groupSearcher.PropertiesToLoad.Add('distinguishedName')

        try {
            $groupResults = $groupSearcher.FindAll()

            if (-not $groupResults -or $groupResults.Count -eq 0) {
                Write-GroupEnumLog -Level 'WARN' -Operation 'ResolveNested' `
                    -Message "Group DN '$GroupDN' returned no results with objectCategory=group" `
                    -Context @{ groupDn = $GroupDN; depth = $CurrentDepth }
                return
            }

            $gr = $groupResults[0]
            $rawMemberDNs = @()
            if ($gr.Properties['member'].Count -gt 0) {
                foreach ($m in $gr.Properties['member']) {
                    $rawMemberDNs += $m
                }
            }

            Write-GroupEnumLog -Level 'DEBUG' -Operation 'ResolveNested' `
                -Message "Group '$GroupName' at depth $CurrentDepth has $($rawMemberDNs.Count) direct member DN(s)" `
                -Context @{ group = $GroupName; depth = $CurrentDepth; directMemberCount = $rawMemberDNs.Count }

        } finally {
            if ($groupResults) { $groupResults.Dispose() }
        }

    } catch {
        $null = $ErrorList.Add("Failed to read members of group '$GroupName' (DN: $GroupDN) at depth $CurrentDepth`: $_")
        return
    } finally {
        if ($groupSearcher) { $groupSearcher.Dispose() }
        if ($groupEntry)    { $groupEntry.Dispose() }
    }

    # Process each member DN
    foreach ($memberDN in $rawMemberDNs) {
        # First: determine if user or group (or other) via a Base-scope search
        $memberEntry    = $null
        $memberSearcher = $null
        $memberResults  = $null

        try {
            $memberEntry = New-LdapDirectoryEntry -Domain $Domain -Port $ldapPort `
                -Secure $ldapSecure -Credential $Credential -BaseDN $memberDN

            $memberSearcher = New-Object System.DirectoryServices.DirectorySearcher($memberEntry)
            # Use a broad filter and check objectCategory in results to classify
            $memberSearcher.Filter      = "(|(objectCategory=person)(objectCategory=group))"
            $memberSearcher.SearchScope = [System.DirectoryServices.SearchScope]::Base
            $memberSearcher.PageSize    = 1
            $memberSearcher.ServerTimeLimit = New-TimeSpan -Seconds $timeoutSeconds
            $memberSearcher.ClientTimeout   = New-TimeSpan -Seconds ($timeoutSeconds + 10)

            $null = $memberSearcher.PropertiesToLoad.Add('objectCategory')
            $null = $memberSearcher.PropertiesToLoad.Add('sAMAccountName')
            $null = $memberSearcher.PropertiesToLoad.Add('displayName')
            $null = $memberSearcher.PropertiesToLoad.Add('mail')
            $null = $memberSearcher.PropertiesToLoad.Add('userAccountControl')
            $null = $memberSearcher.PropertiesToLoad.Add('distinguishedName')
            $null = $memberSearcher.PropertiesToLoad.Add('cn')

            try {
                $memberResults = $memberSearcher.FindAll()

                if (-not $memberResults -or $memberResults.Count -eq 0) {
                    Write-GroupEnumLog -Level 'DEBUG' -Operation 'ResolveNested' `
                        -Message "Member DN '$memberDN' returned no results (may be a contact or computer)" `
                        -Context @{ memberDn = $memberDN; depth = $CurrentDepth }
                    # Do not use continue inside a nested try -- outer finally would be skipped.
                    # Fall through; $mr remains $null and the if-blocks below are all skipped.
                }

                $mr = if ($memberResults -and $memberResults.Count -gt 0) { $memberResults[0] } else { $null }

                if ($mr) {
                    # objectCategory comes back as the full DN of the schema class,
                    # e.g. "CN=Person,CN=Schema,..." or "CN=Group,CN=Schema,..."
                    $objectCategoryRaw = if ($mr.Properties['objectCategory'].Count -gt 0) {
                        $mr.Properties['objectCategory'][0]
                    } else { '' }

                    $isUser  = $objectCategoryRaw -imatch '^CN=Person,'
                    $isGroup = $objectCategoryRaw -imatch '^CN=Group,'

                    if ($isUser) {
                        # Only add if not already seen (de-duplicate by DN)
                        $dn = if ($mr.Properties['distinguishedName'].Count -gt 0) {
                            $mr.Properties['distinguishedName'][0]
                        } else { $memberDN }

                        if (-not $FlatUsers.ContainsKey($dn)) {
                            $sam     = if ($mr.Properties['sAMAccountName'].Count -gt 0)  { $mr.Properties['sAMAccountName'][0] }  else { $null }
                            $display = if ($mr.Properties['displayName'].Count -gt 0)      { $mr.Properties['displayName'][0] }      else { $null }
                            $mail    = if ($mr.Properties['mail'].Count -gt 0)             { $mr.Properties['mail'][0] }             else { $null }
                            $uac     = if ($mr.Properties['userAccountControl'].Count -gt 0) {
                                [int]$mr.Properties['userAccountControl'][0]
                            } else { 0 }
                            $enabled = ($uac -band 2) -eq 0

                            $FlatUsers[$dn] = @{
                                SamAccountName    = $sam
                                DisplayName       = $display
                                Email             = $mail
                                Enabled           = $enabled
                                DistinguishedName = $dn
                                Domain            = $Domain
                            }

                            Write-GroupEnumLog -Level 'DEBUG' -Operation 'ResolveNested' `
                                -Message "Added user '$sam' from group '$GroupName' at depth $CurrentDepth" `
                                -Context @{ sam = $sam; dn = $dn; depth = $CurrentDepth; group = $GroupName }
                        }

                    } elseif ($isGroup) {
                        $subGroupCn = if ($mr.Properties['cn'].Count -gt 0) {
                            $mr.Properties['cn'][0]
                        } else { $memberDN }

                        $subGroupDn = if ($mr.Properties['distinguishedName'].Count -gt 0) {
                            $mr.Properties['distinguishedName'][0]
                        } else { $memberDN }

                        Write-GroupEnumLog -Level 'DEBUG' -Operation 'ResolveNested' `
                            -Message "Found nested group '$subGroupCn' at depth $CurrentDepth, recursing" `
                            -Context @{ subGroup = $subGroupCn; subGroupDn = $subGroupDn; depth = $CurrentDepth }

                        # Record this nested group in the traversal list
                        # (MemberCount placeholder filled after recursion)
                        $null = $NestedGroups.Add(@{
                            Name        = $subGroupCn
                            Depth       = $CurrentDepth + 1
                            DN          = $subGroupDn
                            ParentGroup = $GroupName
                            ParentDN    = $GroupDN
                        })

                        # Recurse
                        script:Resolve-GroupMembersRecursive `
                            -GroupDN        $subGroupDn `
                            -GroupName      $subGroupCn `
                            -Domain         $Domain `
                            -Credential     $Credential `
                            -Config         $Config `
                            -CurrentDepth   ($CurrentDepth + 1) `
                            -MaxDepth       $MaxDepth `
                            -VisitedGroups  $VisitedGroups `
                            -FlatUsers      $FlatUsers `
                            -NestedGroups   $NestedGroups `
                            -ErrorList      $ErrorList

                    } else {
                        Write-GroupEnumLog -Level 'DEBUG' -Operation 'ResolveNested' `
                            -Message "Member DN '$memberDN' is neither a person nor group (objectCategory: $objectCategoryRaw) -- skipping" `
                            -Context @{ memberDn = $memberDN; objectCategory = $objectCategoryRaw }
                    }
                }

            } finally {
                if ($memberResults) { $memberResults.Dispose() }
            }

        } catch {
            $null = $ErrorList.Add("Failed to classify member DN '$memberDN' in group '$GroupName': $_")

            Write-GroupEnumLog -Level 'ERROR' -Operation 'ResolveNested' `
                -Message "Failed to classify member DN '$memberDN': $_" `
                -Context @{ memberDn = $memberDN; group = $GroupName; depth = $CurrentDepth; error = $_.ToString() }

        } finally {
            if ($memberSearcher) { $memberSearcher.Dispose() }
            if ($memberEntry)    { $memberEntry.Dispose() }
        }
    }
}

# ---------------------------------------------------------------------------
# Public: Resolve-NestedGroupMembers
# ---------------------------------------------------------------------------
function Resolve-NestedGroupMembers {
    <#
    .SYNOPSIS
        Recursively resolves all members of an AD group to a flat, de-duplicated user list

    .DESCRIPTION
        Starting from the named group, traverses the full group membership tree via LDAPS.
        Users encountered through multiple nesting paths are de-duplicated by
        DistinguishedName. Circular group references are detected and skipped.

        The recursion depth limit is read from Config.NestedGroupMaxDepth (default 10).
        AllowInsecure in Config controls whether LDAP (389) with Kerberos Sealing is
        permitted when LDAPS (636) is unavailable.

        Requires New-LdapDirectoryEntry and Write-GroupEnumLog to be loaded in the session
        (dot-source GroupEnumerator.ps1 and GroupEnumLogger.ps1 before calling this).

    .PARAMETER Domain
        NetBIOS name or FQDN of the domain containing the group

    .PARAMETER GroupName
        CN (common name) of the root group to resolve

    .PARAMETER Credential
        Optional PSCredential for LDAP authentication. Omit for integrated Windows auth.

    .PARAMETER Config
        Configuration hashtable. Relevant keys:
          NestedGroupMaxDepth  - max recursion depth (default 10)
          LdapTimeout          - per-query timeout in seconds (default 120)
          LdapPageSize         - LDAP page size (default 1000)
          AllowInsecure        - allow LDAP (389) fallback (default $false)

    .PARAMETER MaxDepth
        Override for NestedGroupMaxDepth. If both are specified, this wins.

    .OUTPUTS
        Hashtable:
          FlatMembers     - array of user hashtables (SamAccountName, DisplayName, Email,
                            Enabled, DistinguishedName, Domain); de-duplicated
          NestedGroups    - array of group hashtables found during traversal
                            (Name, Depth, DN, ParentGroup, ParentDN)
          MaxDepthReached - $true if the depth limit was hit during traversal
          TotalUsersFound - count of unique users in FlatMembers
          Errors          - array of error strings (non-fatal issues accumulated)

    .EXAMPLE
        $result = Resolve-NestedGroupMembers -Domain 'CORP' -GroupName 'GG_AppTeam' -Config $cfg
        $result.FlatMembers | Select-Object SamAccountName, DisplayName, Enabled
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
        [int]$MaxDepth = 0
    )

    $errors = @()

    if ([string]::IsNullOrWhiteSpace($Domain)) {
        return @{
            FlatMembers     = @()
            NestedGroups    = @()
            MaxDepthReached = $false
            TotalUsersFound = 0
            Errors          = @("Domain parameter is required and cannot be empty")
        }
    }

    if ([string]::IsNullOrWhiteSpace($GroupName)) {
        return @{
            FlatMembers     = @()
            NestedGroups    = @()
            MaxDepthReached = $false
            TotalUsersFound = 0
            Errors          = @("GroupName parameter is required and cannot be empty")
        }
    }

    # Resolve max depth: explicit param > config key > hard default
    $resolvedMaxDepth = if ($MaxDepth -gt 0) {
        $MaxDepth
    } elseif ($Config.NestedGroupMaxDepth -and $Config.NestedGroupMaxDepth -gt 0) {
        $Config.NestedGroupMaxDepth
    } else {
        10
    }

    $timeoutSeconds = if ($Config.LdapTimeout)  { $Config.LdapTimeout }  else { 120 }
    $pageSize       = if ($Config.LdapPageSize) { $Config.LdapPageSize } else { 1000 }

    Write-GroupEnumLog -Level 'INFO' -Operation 'ResolveNested' `
        -Message "Starting nested group resolution for '$GroupName' in domain '$Domain'" `
        -Context @{ group = $GroupName; domain = $Domain; maxDepth = $resolvedMaxDepth }

    # Step 1: Find the root group DN
    $conn = script:Connect-LdapDomain -Domain $Domain -Credential $Credential -Config $Config

    if (-not $conn.Entry) {
        return @{
            FlatMembers     = @()
            NestedGroups    = @()
            MaxDepthReached = $false
            TotalUsersFound = 0
            Errors          = @("Failed to connect to domain '$Domain': $($conn.Error)")
        }
    }

    if ($conn.Error) { $errors += $conn.Error }

    $rootGroupDN   = $null
    $rootEntry     = $conn.Entry
    $rootSearcher  = $null
    $rootResults   = $null

    try {
        $rootSearcher = New-Object System.DirectoryServices.DirectorySearcher($rootEntry)
        $rootSearcher.Filter      = "(&(objectCategory=group)(cn=$GroupName))"
        $rootSearcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
        $rootSearcher.PageSize    = $pageSize
        $rootSearcher.ServerTimeLimit = New-TimeSpan -Seconds $timeoutSeconds
        $rootSearcher.ClientTimeout   = New-TimeSpan -Seconds ($timeoutSeconds + 10)
        $null = $rootSearcher.PropertiesToLoad.Add('distinguishedName')
        $null = $rootSearcher.PropertiesToLoad.Add('cn')

        try {
            $rootResults = $rootSearcher.FindAll()

            if (-not $rootResults -or $rootResults.Count -eq 0) {
                return @{
                    FlatMembers     = @()
                    NestedGroups    = @()
                    MaxDepthReached = $false
                    TotalUsersFound = 0
                    Errors          = @("Group '$GroupName' not found in domain '$Domain'")
                }
            }

            $rootGroupDN = if ($rootResults[0].Properties['distinguishedName'].Count -gt 0) {
                $rootResults[0].Properties['distinguishedName'][0]
            } else { $null }

        } finally {
            if ($rootResults) { $rootResults.Dispose() }
        }

    } catch {
        return @{
            FlatMembers     = @()
            NestedGroups    = @()
            MaxDepthReached = $false
            TotalUsersFound = 0
            Errors          = @("Failed to locate root group '$GroupName' in domain '$Domain': $_")
        }
    } finally {
        if ($rootSearcher) { $rootSearcher.Dispose() }
        if ($rootEntry)    { $rootEntry.Dispose() }
    }

    if (-not $rootGroupDN) {
        return @{
            FlatMembers     = @()
            NestedGroups    = @()
            MaxDepthReached = $false
            TotalUsersFound = 0
            Errors          = @("Group '$GroupName' found but DistinguishedName attribute was empty")
        }
    }

    Write-GroupEnumLog -Level 'DEBUG' -Operation 'ResolveNested' `
        -Message "Root group '$GroupName' resolved to DN '$rootGroupDN'" `
        -Context @{ group = $GroupName; dn = $rootGroupDN }

    # Step 2: Recursive traversal
    $visitedGroups = @{}
    $flatUsers     = @{}                  # keyed by DN
    $nestedGroups  = [System.Collections.ArrayList]::new()
    $errorList     = [System.Collections.ArrayList]::new()

    script:Resolve-GroupMembersRecursive `
        -GroupDN       $rootGroupDN `
        -GroupName     $GroupName `
        -Domain        $Domain `
        -Credential    $Credential `
        -Config        $Config `
        -CurrentDepth  1 `
        -MaxDepth      $resolvedMaxDepth `
        -VisitedGroups $visitedGroups `
        -FlatUsers     $flatUsers `
        -NestedGroups  $nestedGroups `
        -ErrorList     $errorList

    foreach ($e in $errorList) { $errors += $e }

    # Determine whether max depth was reached by checking if any nested group
    # was recorded at exactly maxDepth + 1 (which triggers the depth guard in recursion)
    $maxDepthReached = $false
    foreach ($ng in $nestedGroups) {
        if ($ng.Depth -gt $resolvedMaxDepth) {
            $maxDepthReached = $true
            break
        }
    }

    if ($maxDepthReached) {
        Write-GroupEnumLog -Level 'WARN' -Operation 'ResolveNested' `
            -Message "Max depth $resolvedMaxDepth reached during resolution of '$GroupName'. Some members may be missing." `
            -Context @{ group = $GroupName; domain = $Domain; maxDepth = $resolvedMaxDepth }
    }

    $flatMembersArray = @($flatUsers.Values)
    $totalUsers       = $flatMembersArray.Count

    Write-GroupEnumLog -Level 'INFO' -Operation 'ResolveNested' `
        -Message "Completed nested resolution for '$GroupName': $totalUsers unique user(s) found, $($nestedGroups.Count) nested group(s) traversed" `
        -Context @{
            group           = $GroupName
            domain          = $Domain
            uniqueUsers     = $totalUsers
            nestedGroupsHit = $nestedGroups.Count
            maxDepthReached = $maxDepthReached
            errorCount      = $errors.Count
        }

    return @{
        FlatMembers     = $flatMembersArray
        NestedGroups    = @($nestedGroups)
        MaxDepthReached = $maxDepthReached
        TotalUsersFound = $totalUsers
        Errors          = $errors
    }
}

# ---------------------------------------------------------------------------
# Public: Get-NestedGroupTree
# ---------------------------------------------------------------------------
function Get-NestedGroupTree {
    <#
    .SYNOPSIS
        Returns the nesting structure of an AD group as a tree for logging or display

    .DESCRIPTION
        Traverses the same group membership tree as Resolve-NestedGroupMembers but
        focuses on the group-to-group relationships rather than collecting users.
        Returns a tree node for each group encountered, including depth, parent, and
        direct member count.

        Useful for diagnosing complex nesting hierarchies before running a full
        member resolution, and for including group topology in reports.

    .PARAMETER Domain
        NetBIOS name or FQDN of the domain containing the root group

    .PARAMETER GroupName
        CN (common name) of the root group

    .PARAMETER Credential
        Optional PSCredential for LDAP authentication. Omit for integrated Windows auth.

    .PARAMETER Config
        Configuration hashtable (same keys as Resolve-NestedGroupMembers).

    .PARAMETER MaxDepth
        Override for recursion depth limit. If 0, Config.NestedGroupMaxDepth or 10 applies.

    .OUTPUTS
        Hashtable:
          RootGroup  - name and DN of the root group
          Nodes      - array of group node hashtables (Name, DN, Depth, ParentGroup,
                       ParentDN, DirectMemberCount, DirectGroupCount)
          MaxDepth   - the depth limit used
          Errors     - array of error strings

    .EXAMPLE
        $tree = Get-NestedGroupTree -Domain 'CORP' -GroupName 'GG_AppTeam' -Config $cfg
        $tree.Nodes | Sort-Object Depth | Format-Table Name, Depth, ParentGroup
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
        [int]$MaxDepth = 0
    )

    $errors = @()

    $resolvedMaxDepth = if ($MaxDepth -gt 0) {
        $MaxDepth
    } elseif ($Config.NestedGroupMaxDepth -and $Config.NestedGroupMaxDepth -gt 0) {
        $Config.NestedGroupMaxDepth
    } else {
        10
    }

    $timeoutSeconds = if ($Config.LdapTimeout)  { $Config.LdapTimeout }  else { 120 }
    $pageSize       = if ($Config.LdapPageSize) { $Config.LdapPageSize } else { 1000 }

    Write-GroupEnumLog -Level 'INFO' -Operation 'GroupTree' `
        -Message "Building group nesting tree for '$GroupName' in domain '$Domain'" `
        -Context @{ group = $GroupName; domain = $Domain; maxDepth = $resolvedMaxDepth }

    # Locate root group
    $conn = script:Connect-LdapDomain -Domain $Domain -Credential $Credential -Config $Config
    if (-not $conn.Entry) {
        return @{
            RootGroup = @{ Name = $GroupName; DN = $null }
            Nodes     = @()
            MaxDepth  = $resolvedMaxDepth
            Errors    = @("Failed to connect to domain '$Domain': $($conn.Error)")
        }
    }

    if ($conn.Error) { $errors += $conn.Error }

    $rootGroupDN  = $null
    $rootEntry    = $conn.Entry
    $rootSearcher = $null
    $rootResults  = $null

    try {
        $rootSearcher = New-Object System.DirectoryServices.DirectorySearcher($rootEntry)
        $rootSearcher.Filter      = "(&(objectCategory=group)(cn=$GroupName))"
        $rootSearcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
        $rootSearcher.PageSize    = $pageSize
        $rootSearcher.ServerTimeLimit = New-TimeSpan -Seconds $timeoutSeconds
        $rootSearcher.ClientTimeout   = New-TimeSpan -Seconds ($timeoutSeconds + 10)
        $null = $rootSearcher.PropertiesToLoad.Add('distinguishedName')

        try {
            $rootResults = $rootSearcher.FindAll()
            if ($rootResults -and $rootResults.Count -gt 0) {
                $rootGroupDN = if ($rootResults[0].Properties['distinguishedName'].Count -gt 0) {
                    $rootResults[0].Properties['distinguishedName'][0]
                } else { $null }
            }
        } finally {
            if ($rootResults) { $rootResults.Dispose() }
        }
    } catch {
        $errors += "Failed to locate root group '$GroupName': $_"
    } finally {
        if ($rootSearcher) { $rootSearcher.Dispose() }
        if ($rootEntry)    { $rootEntry.Dispose() }
    }

    if (-not $rootGroupDN) {
        return @{
            RootGroup = @{ Name = $GroupName; DN = $null }
            Nodes     = @()
            MaxDepth  = $resolvedMaxDepth
            Errors    = $errors + @("Group '$GroupName' not found in domain '$Domain'")
        }
    }

    # Walk the tree (breadth queue to avoid deep call stack on very flat wide trees)
    $nodes        = [System.Collections.ArrayList]::new()
    $visitedDNs   = @{}
    $queue        = [System.Collections.Queue]::new()

    $queue.Enqueue(@{ DN = $rootGroupDN; Name = $GroupName; Depth = 0; ParentGroup = $null; ParentDN = $null })

    while ($queue.Count -gt 0) {
        $current = $queue.Dequeue()

        if ($visitedDNs.ContainsKey($current.DN)) { continue }
        $visitedDNs[$current.DN] = $true

        if ($current.Depth -gt $resolvedMaxDepth) { continue }

        $conn2 = script:Connect-LdapDomain -Domain $Domain -Credential $Credential `
            -Config $Config -BaseDN $current.DN

        if (-not $conn2.Entry) {
            $errors += "Failed to connect for tree node '$($current.Name)': $($conn2.Error)"
            continue
        }
        if ($conn2.Error) { $errors += $conn2.Error }

        $nodeEntry    = $conn2.Entry
        $nodeSearcher = $null
        $nodeResults  = $null
        $directUsers  = 0
        $directGroups = 0

        try {
            $nodeSearcher = New-Object System.DirectoryServices.DirectorySearcher($nodeEntry)
            $nodeSearcher.Filter      = "(objectCategory=group)"
            $nodeSearcher.SearchScope = [System.DirectoryServices.SearchScope]::Base
            $nodeSearcher.PageSize    = 1
            $nodeSearcher.ServerTimeLimit = New-TimeSpan -Seconds $timeoutSeconds
            $nodeSearcher.ClientTimeout   = New-TimeSpan -Seconds ($timeoutSeconds + 10)
            $null = $nodeSearcher.PropertiesToLoad.Add('member')

            try {
                $nodeResults = $nodeSearcher.FindAll()

                if ($nodeResults -and $nodeResults.Count -gt 0) {
                    $nr = $nodeResults[0]
                    $memberDNs = @()
                    if ($nr.Properties['member'].Count -gt 0) {
                        foreach ($m in $nr.Properties['member']) { $memberDNs += $m }
                    }

                    # Classify child members (lightweight: check CN=Person or CN=Group prefix)
                    foreach ($mDN in $memberDNs) {
                        $mEntry    = $null
                        $mSearcher = $null
                        $mResults  = $null
                        try {
                            $mEntry = New-LdapDirectoryEntry -Domain $Domain -Port $conn2.Port `
                                -Secure $conn2.Secure -Credential $Credential -BaseDN $mDN
                            $mSearcher = New-Object System.DirectoryServices.DirectorySearcher($mEntry)
                            $mSearcher.Filter      = "(|(objectCategory=person)(objectCategory=group))"
                            $mSearcher.SearchScope = [System.DirectoryServices.SearchScope]::Base
                            $mSearcher.PageSize    = 1
                            $mSearcher.ServerTimeLimit = New-TimeSpan -Seconds $timeoutSeconds
                            $mSearcher.ClientTimeout   = New-TimeSpan -Seconds ($timeoutSeconds + 10)
                            $null = $mSearcher.PropertiesToLoad.Add('objectCategory')
                            $null = $mSearcher.PropertiesToLoad.Add('cn')
                            $null = $mSearcher.PropertiesToLoad.Add('distinguishedName')

                            try {
                                $mResults = $mSearcher.FindAll()
                                if ($mResults -and $mResults.Count -gt 0) {
                                    $mr2  = $mResults[0]
                                    $cat2 = if ($mr2.Properties['objectCategory'].Count -gt 0) {
                                        $mr2.Properties['objectCategory'][0]
                                    } else { '' }

                                    if ($cat2 -imatch '^CN=Person,') {
                                        $directUsers++
                                    } elseif ($cat2 -imatch '^CN=Group,') {
                                        $directGroups++
                                        $childCN = if ($mr2.Properties['cn'].Count -gt 0) { $mr2.Properties['cn'][0] } else { $mDN }
                                        $childDN = if ($mr2.Properties['distinguishedName'].Count -gt 0) { $mr2.Properties['distinguishedName'][0] } else { $mDN }
                                        if (-not $visitedDNs.ContainsKey($childDN) -and ($current.Depth + 1) -le $resolvedMaxDepth) {
                                            $queue.Enqueue(@{
                                                DN          = $childDN
                                                Name        = $childCN
                                                Depth       = $current.Depth + 1
                                                ParentGroup = $current.Name
                                                ParentDN    = $current.DN
                                            })
                                        }
                                    }
                                }
                            } finally {
                                if ($mResults) { $mResults.Dispose() }
                            }
                        } catch {
                            $errors += "Tree: failed to classify member '$mDN': $_"
                        } finally {
                            if ($mSearcher) { $mSearcher.Dispose() }
                            if ($mEntry)    { $mEntry.Dispose() }
                        }
                    }
                }
            } finally {
                if ($nodeResults) { $nodeResults.Dispose() }
            }
        } catch {
            $errors += "Tree: failed to read group '$($current.Name)': $_"
        } finally {
            if ($nodeSearcher) { $nodeSearcher.Dispose() }
            if ($nodeEntry)    { $nodeEntry.Dispose() }
        }

        $null = $nodes.Add(@{
            Name              = $current.Name
            DN                = $current.DN
            Depth             = $current.Depth
            ParentGroup       = $current.ParentGroup
            ParentDN          = $current.ParentDN
            DirectUserCount   = $directUsers
            DirectGroupCount  = $directGroups
        })
    }

    Write-GroupEnumLog -Level 'INFO' -Operation 'GroupTree' `
        -Message "Group tree complete for '$GroupName': $($nodes.Count) node(s)" `
        -Context @{ group = $GroupName; domain = $Domain; nodeCount = $nodes.Count; errorCount = $errors.Count }

    return @{
        RootGroup = @{ Name = $GroupName; DN = $rootGroupDN }
        Nodes     = @($nodes)
        MaxDepth  = $resolvedMaxDepth
        Errors    = $errors
    }
}
