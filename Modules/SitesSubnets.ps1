<#
.SYNOPSIS
    Sites and subnets discovery module

.DESCRIPTION
    Retrieves Active Directory sites, subnets, and site link topology
    from the Configuration partition

.NOTES
    Returns standardized hashtable: @{ Data = ...; Errors = @() }
#>

function Get-SitesSubnetsInfo {
    <#
    .SYNOPSIS
        Discovers AD sites, subnets, and replication topology

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
    $sites = @()
    $subnets = @()
    $siteLinks = @()

    try {
        # Get Configuration naming context from RootDSE
        $rootDSE = Get-RootDSE -Server $Server -Credential $Credential
        $configNC = $rootDSE.configurationNamingContext

        # Query Sites container
        $sitesPath = "LDAP://$Server/CN=Sites,$configNC"

        # Get all sites
        try {
            $siteSearcher = New-LdapSearcher -SearchRoot $sitesPath `
                -Filter "(objectCategory=site)" `
                -Properties @('name', 'distinguishedName', 'description', 'location', 'whenCreated') `
                -Credential $Credential `
                -Config $Config

            $siteResults = Invoke-LdapQuery -Searcher $siteSearcher
            $siteSearcher.Dispose()

            foreach ($site in $siteResults) {
                $siteInfo = @{
                    Name = $site.name
                    DistinguishedName = $site.distinguishedName
                    Description = $site.description
                    Location = $site.location
                    WhenCreated = if ($site.whenCreated) { $site.whenCreated.ToString('yyyy-MM-dd HH:mm:ss') } else { $null }
                }
                $sites += $siteInfo
            }
        } catch {
            $errors += "Failed to enumerate sites: $_"
        }

        # Get all subnets
        try {
            $subnetsPath = "LDAP://$Server/CN=Subnets,CN=Sites,$configNC"
            $subnetSearcher = New-LdapSearcher -SearchRoot $subnetsPath `
                -Filter "(objectCategory=subnet)" `
                -Properties @('name', 'distinguishedName', 'description', 'location', 'siteObject') `
                -Credential $Credential `
                -Config $Config

            $subnetResults = Invoke-LdapQuery -Searcher $subnetSearcher
            $subnetSearcher.Dispose()

            foreach ($subnet in $subnetResults) {
                # Extract site name from siteObject DN
                $siteName = $null
                if ($subnet.siteObject) {
                    $siteObjectDN = $subnet.siteObject
                    if ($siteObjectDN -match 'CN=([^,]+)') {
                        $siteName = $matches[1]
                    }
                }

                $subnetInfo = @{
                    Name = $subnet.name  # This is the subnet CIDR (e.g., 10.10.10.0/24)
                    DistinguishedName = $subnet.distinguishedName
                    Description = $subnet.description
                    Location = $subnet.location
                    SiteName = $siteName
                }
                $subnets += $subnetInfo
            }
        } catch {
            $errors += "Failed to enumerate subnets: $_"
        }

        # Get site links (IP transport)
        try {
            $siteLinksPath = "LDAP://$Server/CN=IP,CN=Inter-Site Transports,CN=Sites,$configNC"
            $siteLinkSearcher = New-LdapSearcher -SearchRoot $siteLinksPath `
                -Filter "(objectCategory=siteLink)" `
                -Properties @('name', 'distinguishedName', 'cost', 'replInterval', 'siteList', 'description') `
                -Credential $Credential `
                -Config $Config

            $siteLinkResults = Invoke-LdapQuery -Searcher $siteLinkSearcher
            $siteLinkSearcher.Dispose()

            foreach ($siteLink in $siteLinkResults) {
                # Extract site names from siteList DNs
                $connectedSites = @()
                if ($siteLink.siteList) {
                    $siteListArray = if ($siteLink.siteList -is [array]) { $siteLink.siteList } else { @($siteLink.siteList) }
                    foreach ($siteDN in $siteListArray) {
                        if ($siteDN -match 'CN=([^,]+)') {
                            $connectedSites += $matches[1]
                        }
                    }
                }

                $siteLinkInfo = @{
                    Name = $siteLink.name
                    DistinguishedName = $siteLink.distinguishedName
                    Description = $siteLink.description
                    Cost = if ($siteLink.cost) { [int]$siteLink.cost } else { 100 }
                    ReplicationInterval = if ($siteLink.replInterval) { [int]$siteLink.replInterval } else { 180 }
                    ConnectedSites = $connectedSites
                }
                $siteLinks += $siteLinkInfo
            }
        } catch {
            $errors += "Failed to enumerate site links: $_"
        }

        # Build result data
        $data = @{
            Sites = $sites
            Subnets = $subnets
            SiteLinks = $siteLinks
            TotalSites = $sites.Count
            TotalSubnets = $subnets.Count
            TotalSiteLinks = $siteLinks.Count
        }

    } catch {
        $errors += "Failed to retrieve sites and subnets information: $_"
    }

    return @{
        Data = $data
        Errors = $errors
    }
}
