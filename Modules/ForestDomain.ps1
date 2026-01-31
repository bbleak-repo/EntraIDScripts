<#
.SYNOPSIS
    Forest and domain discovery module

.DESCRIPTION
    Retrieves fundamental forest and domain information including
    functional levels, naming contexts, and domain identification

.NOTES
    Returns standardized hashtable: @{ Data = ...; Errors = @() }
#>

function Get-ForestDomainInfo {
    <#
    .SYNOPSIS
        Discovers forest and domain information

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

    try {
        # Connect to RootDSE
        $rootDSE = Get-RootDSE -Server $Server -Credential $Credential

        # Map functional levels to readable names
        $functionalLevelMap = @{
            0 = 'Windows2000'
            1 = 'Windows2003Interim'
            2 = 'Windows2003'
            3 = 'Windows2008'
            4 = 'Windows2008R2'
            5 = 'Windows2012'
            6 = 'Windows2012R2'
            7 = 'Windows2016'
            10 = 'Windows2025'
        }

        $forestLevel = $rootDSE.forestFunctionality
        $domainLevel = $rootDSE.domainFunctionality

        # Extract domain info from default naming context
        $defaultNC = $rootDSE.defaultNamingContext
        $domainDNSName = ($defaultNC -replace 'DC=', '' -replace ',', '.').Trim('.')

        # Get NetBIOS name from partitions container
        $netbiosName = $null
        try {
            $partitionsPath = "LDAP://$Server/CN=Partitions,$($rootDSE.configurationNamingContext)"
            $partitionSearcher = New-LdapSearcher -SearchRoot $partitionsPath `
                -Filter "(&(objectCategory=crossRef)(nCName=$defaultNC))" `
                -Properties @('nETBIOSName') `
                -Credential $Credential `
                -Config $Config

            $partitionResults = Invoke-LdapQuery -Searcher $partitionSearcher
            if ($partitionResults -and $partitionResults.Count -gt 0) {
                $netbiosName = $partitionResults[0].nETBIOSName
            }
            $partitionSearcher.Dispose()
        } catch {
            $errors += "Warning: Could not retrieve NetBIOS name: $_"
        }

        # Get domain SID from well-known object
        $domainSID = $null
        try {
            $domainPath = "LDAP://$Server/$defaultNC"
            $domainSearcher = New-LdapSearcher -SearchRoot $domainPath `
                -Filter "(objectCategory=domain)" `
                -Properties @('objectSid') `
                -Credential $Credential `
                -Config $Config

            $domainResults = Invoke-LdapQuery -Searcher $domainSearcher
            if ($domainResults -and $domainResults.Count -gt 0) {
                $sidBytes = $domainResults[0].objectSid
                if ($sidBytes) {
                    $domainSID = (New-Object System.Security.Principal.SecurityIdentifier($sidBytes, 0)).Value
                }
            }
            $domainSearcher.Dispose()
        } catch {
            $errors += "Warning: Could not retrieve domain SID: $_"
        }

        # Build result data
        $data = @{
            ForestName = $domainDNSName
            DomainName = $domainDNSName
            DomainDNSName = $domainDNSName
            ForestFunctionalLevel = if ($functionalLevelMap.ContainsKey($forestLevel)) { $functionalLevelMap[$forestLevel] } else { "Unknown ($forestLevel)" }
            DomainFunctionalLevel = if ($functionalLevelMap.ContainsKey($domainLevel)) { $functionalLevelMap[$domainLevel] } else { "Unknown ($domainLevel)" }
            ForestFunctionalLevelValue = $forestLevel
            DomainFunctionalLevelValue = $domainLevel
            SchemaNamingContext = $rootDSE.schemaNamingContext
            ConfigurationNamingContext = $rootDSE.configurationNamingContext
            DefaultNamingContext = $rootDSE.defaultNamingContext
            RootDomainNamingContext = $rootDSE.rootDomainNamingContext
            DomainControllerHostName = $rootDSE.dnsHostName
            CurrentTime = $rootDSE.currentTime
            SupportedLDAPVersion = $rootDSE.supportedLDAPVersion
            DomainSID = $domainSID
            NetBIOSName = $netbiosName
        }

    } catch {
        $errors += "Failed to retrieve forest/domain information: $_"
    }

    return @{
        Data = $data
        Errors = $errors
    }
}
