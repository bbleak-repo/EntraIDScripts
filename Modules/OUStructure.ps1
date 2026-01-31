<#
.SYNOPSIS
    Organizational Unit structure discovery module

.DESCRIPTION
    Retrieves OU hierarchy with depth analysis and object counts
    (users, computers, groups) per OU

.NOTES
    Returns standardized hashtable: @{ Data = ...; Errors = @() }
#>

function Get-OUStructure {
    <#
    .SYNOPSIS
        Discovers OU hierarchy and object distribution

    .PARAMETER Server
        Domain controller FQDN or domain name

    .PARAMETER Credential
        Optional credentials for authentication

    .PARAMETER Config
        Configuration hashtable

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
    $data = @{}
    $ous = @()

    try {
        # Get default naming context
        $rootDSE = Get-RootDSE -Server $Server -Credential $Credential
        $defaultNC = $rootDSE.defaultNamingContext
        $domainPath = "LDAP://$Server/$defaultNC"

        # Query all OUs
        $ouSearcher = New-LdapSearcher -SearchRoot $domainPath `
            -Filter "(objectCategory=organizationalUnit)" `
            -Properties @('name', 'distinguishedName', 'description', 'whenCreated', 'whenChanged') `
            -Credential $Credential `
            -Config $Config

        $ouResults = Invoke-LdapQuery -Searcher $ouSearcher
        $ouSearcher.Dispose()

        if (-not $ouResults -or $ouResults.Count -eq 0) {
            $errors += "No OUs found in domain"
            return @{
                Data = @{
                    TotalOUs = 0
                    MaxDepth = 0
                    OUs = @()
                }
                Errors = $errors
            }
        }

        # Process each OU
        $maxDepth = 0
        foreach ($ou in $ouResults) {
            $dn = $ou.distinguishedName

            # Calculate depth (count OU= occurrences)
            $depth = ([regex]::Matches($dn, 'OU=')).Count
            if ($depth -gt $maxDepth) {
                $maxDepth = $depth
            }

            # Count child objects (users, computers, groups)
            $userCount = 0
            $computerCount = 0
            $groupCount = 0

            try {
                # Count users (objectCategory=person excludes contacts)
                $userSearcher = New-LdapSearcher -SearchRoot "LDAP://$Server/$dn" `
                    -Filter "(objectCategory=person)" `
                    -Properties @('cn') `
                    -Credential $Credential `
                    -Config $Config
                $userSearcher.SearchScope = [System.DirectoryServices.SearchScope]::OneLevel
                $userResults = Invoke-LdapQuery -Searcher $userSearcher
                $userCount = $userResults.Count
                $userSearcher.Dispose()

                # Count computers
                $computerSearcher = New-LdapSearcher -SearchRoot "LDAP://$Server/$dn" `
                    -Filter "(objectCategory=computer)" `
                    -Properties @('cn') `
                    -Credential $Credential `
                    -Config $Config
                $computerSearcher.SearchScope = [System.DirectoryServices.SearchScope]::OneLevel
                $computerResults = Invoke-LdapQuery -Searcher $computerSearcher
                $computerCount = $computerResults.Count
                $computerSearcher.Dispose()

                # Count groups
                $groupSearcher = New-LdapSearcher -SearchRoot "LDAP://$Server/$dn" `
                    -Filter "(objectCategory=group)" `
                    -Properties @('cn') `
                    -Credential $Credential `
                    -Config $Config
                $groupSearcher.SearchScope = [System.DirectoryServices.SearchScope]::OneLevel
                $groupResults = Invoke-LdapQuery -Searcher $groupSearcher
                $groupCount = $groupResults.Count
                $groupSearcher.Dispose()

            } catch {
                $errors += "Warning: Could not count objects in OU $($ou.name): $_"
            }

            # Build OU info
            $ouInfo = @{
                Name = $ou.name
                DistinguishedName = $dn
                Description = $ou.description
                Depth = $depth
                UserCount = $userCount
                ComputerCount = $computerCount
                GroupCount = $groupCount
                WhenCreated = if ($ou.whenCreated) { $ou.whenCreated.ToString('yyyy-MM-dd HH:mm:ss') } else { $null }
                WhenChanged = if ($ou.whenChanged) { $ou.whenChanged.ToString('yyyy-MM-dd HH:mm:ss') } else { $null }
            }

            $ous += $ouInfo
        }

        # Sort OUs by distinguished name for hierarchical display
        $ous = $ous | Sort-Object -Property DistinguishedName

        $data = @{
            TotalOUs = $ous.Count
            MaxDepth = $maxDepth
            OUs = $ous
        }

    } catch {
        $errors += "Failed to retrieve OU structure: $_"
    }

    return @{
        Data = $data
        Errors = $errors
    }
}
