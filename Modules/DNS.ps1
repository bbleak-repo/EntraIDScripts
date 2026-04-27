<#
.SYNOPSIS
    DNS zones discovery module

.DESCRIPTION
    Retrieves Active Directory-integrated DNS zones from domain and
    forest DNS partitions with graceful degradation for access restrictions

.NOTES
    Returns standardized hashtable: @{ Data = ...; Errors = @() }
    DNS zones are often restricted - implements graceful degradation
#>

function Get-DNSInfo {
    <#
    .SYNOPSIS
        Discovers AD-integrated DNS zones

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
    $zones = @()
    $accessLevel = 'Unknown'
    $zonesFound = 0
    $zonesRestricted = 0

    try {
        # Get naming contexts from RootDSE
        $rootDSE = Get-RootDSE -Server $Server -Credential $Credential
        $defaultNC = $rootDSE.defaultNamingContext
        $rootDomainNC = $rootDSE.rootDomainNamingContext

        # Extract domain name components for DNS partition paths
        $domainDnsName = ($defaultNC -replace 'DC=', '' -replace ',', '.').Trim('.')

        # Try multiple DNS partition locations
        $dnsPartitions = @(
            @{
                Name = 'DomainDnsZones'
                Path = "LDAP://$Server/CN=MicrosoftDNS,DC=DomainDnsZones,$defaultNC"
                Description = 'Domain DNS Zones'
            },
            @{
                Name = 'ForestDnsZones'
                Path = "LDAP://$Server/CN=MicrosoftDNS,DC=ForestDnsZones,$rootDomainNC"
                Description = 'Forest DNS Zones'
            },
            @{
                Name = 'LegacyDNS'
                Path = "LDAP://$Server/CN=MicrosoftDNS,CN=System,$defaultNC"
                Description = 'Legacy DNS (System Container)'
            }
        )

        $totalAccessible = 0
        $totalZones = 0

        foreach ($partition in $dnsPartitions) {
            try {
                # Try to query DNS zones in this partition
                $zoneSearcher = New-LdapSearcher -SearchRoot $partition.Path `
                    -Filter "(objectCategory=dnsZone)" `
                    -Properties @('name', 'distinguishedName', 'whenCreated', 'whenChanged', 'dnsProperty') `
                    -Credential $Credential `
                    -Config $Config

                $zoneResults = Invoke-LdapQuery -Searcher $zoneSearcher
                $zoneSearcher.Dispose()

                $totalAccessible++

                if ($zoneResults -and $zoneResults.Count -gt 0) {
                    $totalZones += $zoneResults.Count

                    foreach ($zone in $zoneResults) {
                        # Skip internal zones like ..TrustAnchors
                        if ($zone.name -like '*..*') {
                            continue
                        }

                        # Count DNS records in this zone
                        $recordCount = 0
                        try {
                            $zonePath = "LDAP://$Server/$($zone.distinguishedName)"
                            $recordSearcher = New-LdapSearcher -SearchRoot $zonePath `
                                -Filter "(objectCategory=dnsNode)" `
                                -Properties @('name') `
                                -Credential $Credential `
                                -Config $Config

                            $recordResults = Invoke-LdapQuery -Searcher $recordSearcher
                            $recordCount = $recordResults.Count
                            $recordSearcher.Dispose()
                        } catch {
                            # Record enumeration may fail for some zones
                            $recordCount = -1
                        }

                        $zoneInfo = @{
                            Name = $zone.name
                            DistinguishedName = $zone.distinguishedName
                            Partition = $partition.Description
                            RecordCount = $recordCount
                            WhenCreated = if ($zone.whenCreated) { $zone.whenCreated.ToString('yyyy-MM-dd HH:mm:ss') } else { $null }
                            WhenChanged = if ($zone.whenChanged) { $zone.whenChanged.ToString('yyyy-MM-dd HH:mm:ss') } else { $null }
                        }

                        $zones += $zoneInfo
                        $zonesFound++
                    }
                }

            } catch {
                $zonesRestricted++
                $errors += "Warning: Cannot access DNS partition $($partition.Description): $_"
            }
        }

        # Determine access level
        if ($totalAccessible -eq $dnsPartitions.Count) {
            $accessLevel = 'Full'
        } elseif ($totalAccessible -gt 0) {
            $accessLevel = 'Partial'
        } else {
            $accessLevel = 'Denied'
            $errors += "All DNS partitions are inaccessible. This may be due to insufficient permissions or DNS not being AD-integrated."
        }

        # Build result data
        $data = @{
            Zones = $zones
            TotalZones = $zonesFound
            AccessLevel = $accessLevel
            PartitionsAccessible = $totalAccessible
            PartitionsRestricted = $zonesRestricted
            TotalPartitions = $dnsPartitions.Count
        }

    } catch {
        $errors += "Failed to retrieve DNS information: $_"
        $data = @{
            Zones = @()
            TotalZones = 0
            AccessLevel = 'Denied'
            PartitionsAccessible = 0
            PartitionsRestricted = 0
            TotalPartitions = 0
        }
    }

    return @{
        Data = $data
        Errors = $errors
    }
}
