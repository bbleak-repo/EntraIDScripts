<#
.SYNOPSIS
    Group inventory discovery module

.DESCRIPTION
    Retrieves Active Directory security and distribution groups with
    scope, type, member counts, and management information

.NOTES
    Returns standardized hashtable: @{ Data = ...; Errors = @() }
    Respects MaxGroupCount configuration limit for safety
#>

function Get-GroupsInfo {
    <#
    .SYNOPSIS
        Discovers AD groups with statistics

    .PARAMETER Server
        Domain controller FQDN or domain name

    .PARAMETER Credential
        Optional credentials for authentication

    .PARAMETER Config
        Configuration hashtable (respects MaxGroupCount limit)

    .OUTPUTS
        Hashtable with Data and Errors keys
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Server,

        [Parameter(Mandatory = $false)]
        [PSCredential]$Credential,

        [Parameter(Mandatory = $false)]
        [hashtable]$Config = @{}
    )

    $errors = @()
    $groups = @()
    $limitReached = $false

    try {
        # Get default naming context
        $rootDSE = Get-RootDSE -Server $Server -Credential $Credential
        $defaultNC = $rootDSE.defaultNamingContext
        $domainPath = "LDAP://$Server/$defaultNC"

        # Get safety limit from config
        $maxGroupCount = if ($Config.MaxGroupCount) { $Config.MaxGroupCount } else { 5000 }

        # Query groups
        $groupSearcher = New-LdapSearcher -SearchRoot $domainPath `
            -Filter "(objectCategory=group)" `
            -Properties @('name', 'distinguishedName', 'groupType', 'description', 'member', 'managedBy', 'whenCreated', 'whenChanged') `
            -Credential $Credential `
            -Config $Config

        $groupResults = Invoke-LdapQuery -Searcher $groupSearcher
        $groupSearcher.Dispose()

        if (-not $groupResults -or $groupResults.Count -eq 0) {
            return @{
                Data = @{
                    Groups = @()
                    TotalGroups = 0
                    GroupsByScope = @{}
                    GroupsByType = @{}
                    LimitReached = $false
                }
                Errors = @("No groups found in domain")
            }
        }

        # Check if we hit the limit
        if ($groupResults.Count -ge $maxGroupCount) {
            $limitReached = $true
            $errors += "Warning: Group count ($($groupResults.Count)) reached safety limit ($maxGroupCount). Results may be truncated."
            $groupResults = $groupResults[0..($maxGroupCount - 1)]
        }

        # Counters for statistics
        $groupsByScope = @{
            Global = 0
            DomainLocal = 0
            Universal = 0
            Unknown = 0
        }

        $groupsByType = @{
            Security = 0
            Distribution = 0
        }

        foreach ($group in $groupResults) {
            # Parse groupType bit flags
            $groupTypeValue = if ($group.groupType) { [int]$group.groupType } else { 0 }

            # Determine scope (bits 0-3)
            $scope = 'Unknown'
            if ($groupTypeValue -band 0x00000002) {
                $scope = 'Global'
                $groupsByScope.Global++
            } elseif ($groupTypeValue -band 0x00000004) {
                $scope = 'DomainLocal'
                $groupsByScope.DomainLocal++
            } elseif ($groupTypeValue -band 0x00000008) {
                $scope = 'Universal'
                $groupsByScope.Universal++
            } else {
                $groupsByScope.Unknown++
            }

            # Determine type (bit 31)
            $isSecurity = ($groupTypeValue -band 0x80000000) -ne 0
            $type = if ($isSecurity) { 'Security' } else { 'Distribution' }

            if ($isSecurity) {
                $groupsByType.Security++
            } else {
                $groupsByType.Distribution++
            }

            # Build readable group type string
            $groupTypeName = "$scope $type"

            # Get member count (without enumerating all members)
            $memberCount = 0
            $memberCountNote = $null
            if ($group.member) {
                if ($group.member -is [array]) {
                    $memberCount = $group.member.Count
                } else {
                    $memberCount = 1
                }

                # AD typically returns max 1500 values for multi-valued attributes
                # If we hit exactly 1500, it's likely there are more
                if ($memberCount -ge 1500) {
                    $memberCountNote = "1500+ (range retrieval required for exact count)"
                }
            }

            # Parse managedBy DN to get manager name
            $managedByName = $null
            if ($group.managedBy) {
                if ($group.managedBy -match 'CN=([^,]+)') {
                    $managedByName = $matches[1]
                }
            }

            $groupInfo = @{
                Name = $group.name
                DistinguishedName = $group.distinguishedName
                GroupType = $groupTypeName
                Scope = $scope
                Type = $type
                GroupTypeValue = $groupTypeValue
                Description = $group.description
                MemberCount = $memberCount
                MemberCountNote = $memberCountNote
                ManagedBy = $managedByName
                ManagedByDN = $group.managedBy
                WhenCreated = if ($group.whenCreated) { $group.whenCreated.ToString('yyyy-MM-dd HH:mm:ss') } else { $null }
                WhenChanged = if ($group.whenChanged) { $group.whenChanged.ToString('yyyy-MM-dd HH:mm:ss') } else { $null }
            }

            $groups += $groupInfo
        }

        # Build result data
        $data = @{
            Groups = $groups
            TotalGroups = $groups.Count
            GroupsByScope = $groupsByScope
            GroupsByType = $groupsByType
            LimitReached = $limitReached
            MaxGroupCount = $maxGroupCount
        }

    } catch {
        $errors += "Failed to retrieve group information: $_"
    }

    return @{
        Data = $data
        Errors = $errors
    }
}
