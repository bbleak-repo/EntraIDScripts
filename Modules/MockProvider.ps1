<#
.SYNOPSIS
    Mock data provider for cross-platform testing

.DESCRIPTION
    Provides realistic test data for two mock AD domains with deliberate
    differences to validate comparison engine. Returns identical structure
    to real discovery modules for transparent testing.

.NOTES
    Mock domains:
    - mock-prod.local: Windows Server 2022, 3 DCs, complex structure
    - mock-dev.local: Windows Server 2019, 2 DCs, simplified structure
#>

function Get-MockForestDomainInfo {
    <#
    .SYNOPSIS
        Returns mock forest and domain information
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DomainName
    )

    $mockData = @{
        'mock-prod.local' = @{
            ForestName = 'mock-prod.local'
            DomainName = 'mock-prod.local'
            ForestFunctionalLevel = 'Windows2016'
            DomainFunctionalLevel = 'Windows2016'
            ForestFunctionalLevelValue = 7
            DomainFunctionalLevelValue = 7
            SchemaNamingContext = 'CN=Schema,CN=Configuration,DC=mock-prod,DC=local'
            ConfigurationNamingContext = 'CN=Configuration,DC=mock-prod,DC=local'
            DefaultNamingContext = 'DC=mock-prod,DC=local'
            DomainSID = 'S-1-5-21-1234567890-1234567890-1234567890'
            NetBIOSName = 'MOCKPROD'
            DomainDNSName = 'mock-prod.local'
        }
        'mock-dev.local' = @{
            ForestName = 'mock-dev.local'
            DomainName = 'mock-dev.local'
            ForestFunctionalLevel = 'Windows2012R2'
            DomainFunctionalLevel = 'Windows2012R2'
            ForestFunctionalLevelValue = 6
            DomainFunctionalLevelValue = 6
            SchemaNamingContext = 'CN=Schema,CN=Configuration,DC=mock-dev,DC=local'
            ConfigurationNamingContext = 'CN=Configuration,DC=mock-dev,DC=local'
            DefaultNamingContext = 'DC=mock-dev,DC=local'
            DomainSID = 'S-1-5-21-9876543210-9876543210-9876543210'
            NetBIOSName = 'MOCKDEV'
            DomainDNSName = 'mock-dev.local'
        }
    }

    if (-not $mockData.ContainsKey($DomainName)) {
        return @{
            Data = $null
            Errors = @("Unknown mock domain: $DomainName. Available: mock-prod.local, mock-dev.local")
        }
    }

    return @{
        Data = $mockData[$DomainName]
        Errors = @()
    }
}

function Get-MockSchemaInfo {
    <#
    .SYNOPSIS
        Returns mock schema information
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DomainName
    )

    $mockData = @{
        'mock-prod.local' = @{
            SchemaVersion = 88
            WindowsServerVersion = 'Windows Server 2022'
            TotalAttributes = 1582
            TotalClasses = 351
            CustomAttributes = @(
                @{ Name = 'companyEmployeeID'; OID = '1.2.840.113556.1.8000.2554.12345'; Description = 'Custom employee identifier' }
                @{ Name = 'companyDivision'; OID = '1.2.840.113556.1.8000.2554.12346'; Description = 'Business division code' }
                @{ Name = 'companyCostCenter'; OID = '1.2.840.113556.1.8000.2554.12347'; Description = 'Cost center allocation' }
            )
            SchemaLastModified = '2025-01-15 14:32:18'
        }
        'mock-dev.local' = @{
            SchemaVersion = 87
            WindowsServerVersion = 'Windows Server 2019'
            TotalAttributes = 1528
            TotalClasses = 340
            CustomAttributes = @(
                @{ Name = 'companyEmployeeID'; OID = '1.2.840.113556.1.8000.2554.12345'; Description = 'Custom employee identifier' }
                @{ Name = 'companyDivision'; OID = '1.2.840.113556.1.8000.2554.12346'; Description = 'Business division code' }
            )
            SchemaLastModified = '2024-11-20 09:15:42'
        }
    }

    if (-not $mockData.ContainsKey($DomainName)) {
        return @{
            Data = $null
            Errors = @("Unknown mock domain: $DomainName")
        }
    }

    return @{
        Data = $mockData[$DomainName]
        Errors = @()
    }
}

function Get-MockOUStructure {
    <#
    .SYNOPSIS
        Returns mock OU hierarchy
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DomainName
    )

    $mockData = @{
        'mock-prod.local' = @{
            TotalOUs = 15
            MaxDepth = 3
            OUs = @(
                @{ Name = 'Corporate'; DistinguishedName = 'OU=Corporate,DC=mock-prod,DC=local'; Description = 'Corporate headquarters'; Depth = 1; UserCount = 125; ComputerCount = 145; GroupCount = 18 }
                @{ Name = 'IT'; DistinguishedName = 'OU=IT,OU=Corporate,DC=mock-prod,DC=local'; Description = 'IT Department'; Depth = 2; UserCount = 45; ComputerCount = 52; GroupCount = 12 }
                @{ Name = 'Servers'; DistinguishedName = 'OU=Servers,OU=IT,OU=Corporate,DC=mock-prod,DC=local'; Description = 'Production servers'; Depth = 3; UserCount = 0; ComputerCount = 28; GroupCount = 3 }
                @{ Name = 'Workstations'; DistinguishedName = 'OU=Workstations,OU=IT,OU=Corporate,DC=mock-prod,DC=local'; Description = 'IT workstations'; Depth = 3; UserCount = 0; ComputerCount = 24; GroupCount = 2 }
                @{ Name = 'Finance'; DistinguishedName = 'OU=Finance,OU=Corporate,DC=mock-prod,DC=local'; Description = 'Finance Department'; Depth = 2; UserCount = 32; ComputerCount = 35; GroupCount = 8 }
                @{ Name = 'HR'; DistinguishedName = 'OU=HR,OU=Corporate,DC=mock-prod,DC=local'; Description = 'Human Resources'; Depth = 2; UserCount = 18; ComputerCount = 20; GroupCount = 5 }
                @{ Name = 'Sales'; DistinguishedName = 'OU=Sales,OU=Corporate,DC=mock-prod,DC=local'; Description = 'Sales Department'; Depth = 2; UserCount = 30; ComputerCount = 33; GroupCount = 6 }
                @{ Name = 'Regional'; DistinguishedName = 'OU=Regional,DC=mock-prod,DC=local'; Description = 'Regional offices'; Depth = 1; UserCount = 85; ComputerCount = 92; GroupCount = 10 }
                @{ Name = 'US-East'; DistinguishedName = 'OU=US-East,OU=Regional,DC=mock-prod,DC=local'; Description = 'Eastern US region'; Depth = 2; UserCount = 42; ComputerCount = 45; GroupCount = 5 }
                @{ Name = 'US-West'; DistinguishedName = 'OU=US-West,OU=Regional,DC=mock-prod,DC=local'; Description = 'Western US region'; Depth = 2; UserCount = 43; ComputerCount = 47; GroupCount = 5 }
                @{ Name = 'Service Accounts'; DistinguishedName = 'OU=Service Accounts,DC=mock-prod,DC=local'; Description = 'Service and system accounts'; Depth = 1; UserCount = 28; ComputerCount = 0; GroupCount = 4 }
                @{ Name = 'Quarantine'; DistinguishedName = 'OU=Quarantine,DC=mock-prod,DC=local'; Description = 'Quarantined objects'; Depth = 1; UserCount = 3; ComputerCount = 5; GroupCount = 0 }
                @{ Name = 'Disabled'; DistinguishedName = 'OU=Disabled,DC=mock-prod,DC=local'; Description = 'Disabled accounts'; Depth = 1; UserCount = 12; ComputerCount = 8; GroupCount = 0 }
                @{ Name = 'Groups'; DistinguishedName = 'OU=Groups,DC=mock-prod,DC=local'; Description = 'Security and distribution groups'; Depth = 1; UserCount = 0; ComputerCount = 0; GroupCount = 22 }
                @{ Name = 'Contractors'; DistinguishedName = 'OU=Contractors,DC=mock-prod,DC=local'; Description = 'External contractors'; Depth = 1; UserCount = 15; ComputerCount = 12; GroupCount = 2 }
            )
        }
        'mock-dev.local' = @{
            TotalOUs = 12
            MaxDepth = 3
            OUs = @(
                @{ Name = 'Corporate'; DistinguishedName = 'OU=Corporate,DC=mock-dev,DC=local'; Description = 'Corporate headquarters'; Depth = 1; UserCount = 78; ComputerCount = 85; GroupCount = 12 }
                @{ Name = 'IT'; DistinguishedName = 'OU=IT,OU=Corporate,DC=mock-dev,DC=local'; Description = 'IT Department'; Depth = 2; UserCount = 28; ComputerCount = 32; GroupCount = 8 }
                @{ Name = 'Servers'; DistinguishedName = 'OU=Servers,OU=IT,OU=Corporate,DC=mock-dev,DC=local'; Description = 'Test servers'; Depth = 3; UserCount = 0; ComputerCount = 15; GroupCount = 2 }
                @{ Name = 'Finance'; DistinguishedName = 'OU=Finance,OU=Corporate,DC=mock-dev,DC=local'; Description = 'Finance Department'; Depth = 2; UserCount = 22; ComputerCount = 24; GroupCount = 5 }
                @{ Name = 'HR'; DistinguishedName = 'OU=HR,OU=Corporate,DC=mock-dev,DC=local'; Description = 'Human Resources'; Depth = 2; UserCount = 14; ComputerCount = 16; GroupCount = 4 }
                @{ Name = 'Sales'; DistinguishedName = 'OU=Sales,OU=Corporate,DC=mock-dev,DC=local'; Description = 'Sales Department'; Depth = 2; UserCount = 14; ComputerCount = 17; GroupCount = 3 }
                @{ Name = 'Regional'; DistinguishedName = 'OU=Regional,DC=mock-dev,DC=local'; Description = 'Regional offices'; Depth = 1; UserCount = 45; ComputerCount = 48; GroupCount = 6 }
                @{ Name = 'US-East'; DistinguishedName = 'OU=US-East,OU=Regional,DC=mock-dev,DC=local'; Description = 'Eastern US region'; Depth = 2; UserCount = 45; ComputerCount = 48; GroupCount = 6 }
                @{ Name = 'Service Accounts'; DistinguishedName = 'OU=Service Accounts,DC=mock-dev,DC=local'; Description = 'Service and system accounts'; Depth = 1; UserCount = 18; ComputerCount = 0; GroupCount = 3 }
                @{ Name = 'Quarantine'; DistinguishedName = 'OU=Quarantine,DC=mock-dev,DC=local'; Description = 'Quarantined objects'; Depth = 1; UserCount = 2; ComputerCount = 3; GroupCount = 0 }
                @{ Name = 'Disabled'; DistinguishedName = 'OU=Disabled,DC=mock-dev,DC=local'; Description = 'Disabled accounts'; Depth = 1; UserCount = 8; ComputerCount = 5; GroupCount = 0 }
                @{ Name = 'Groups'; DistinguishedName = 'OU=Groups,DC=mock-dev,DC=local'; Description = 'Security and distribution groups'; Depth = 1; UserCount = 0; ComputerCount = 0; GroupCount = 15 }
            )
        }
    }

    if (-not $mockData.ContainsKey($DomainName)) {
        return @{
            Data = $null
            Errors = @("Unknown mock domain: $DomainName")
        }
    }

    return @{
        Data = $mockData[$DomainName]
        Errors = @()
    }
}

function Get-MockSitesSubnetsInfo {
    <#
    .SYNOPSIS
        Returns mock sites and subnets information
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DomainName
    )

    $mockData = @{
        'mock-prod.local' = @{
            TotalSites = 2
            TotalSubnets = 5
            TotalSiteLinks = 1
            Sites = @(
                @{ Name = 'HQ-Site'; Location = 'New York, NY'; Description = 'Headquarters site'; SubnetCount = 3 }
                @{ Name = 'DR-Site'; Location = 'Chicago, IL'; Description = 'Disaster recovery site'; SubnetCount = 2 }
            )
            Subnets = @(
                @{ Name = '10.10.10.0/24'; Site = 'HQ-Site'; Location = 'HQ Corporate Network' }
                @{ Name = '10.10.20.0/24'; Site = 'HQ-Site'; Location = 'HQ Server Network' }
                @{ Name = '10.10.30.0/24'; Site = 'HQ-Site'; Location = 'HQ Guest Network' }
                @{ Name = '10.20.10.0/24'; Site = 'DR-Site'; Location = 'DR Production Network' }
                @{ Name = '10.20.20.0/24'; Site = 'DR-Site'; Location = 'DR Replication Network' }
            )
            SiteLinks = @(
                @{ Name = 'HQ-DR-Link'; Sites = @('HQ-Site', 'DR-Site'); Cost = 100; ReplicationInterval = 180 }
            )
        }
        'mock-dev.local' = @{
            TotalSites = 1
            TotalSubnets = 2
            TotalSiteLinks = 0
            Sites = @(
                @{ Name = 'Default-Site'; Location = 'Development Lab'; Description = 'Development environment'; SubnetCount = 2 }
            )
            Subnets = @(
                @{ Name = '192.168.10.0/24'; Site = 'Default-Site'; Location = 'Dev Network' }
                @{ Name = '192.168.20.0/24'; Site = 'Default-Site'; Location = 'Test Network' }
            )
            SiteLinks = @()
        }
    }

    if (-not $mockData.ContainsKey($DomainName)) {
        return @{
            Data = $null
            Errors = @("Unknown mock domain: $DomainName")
        }
    }

    return @{
        Data = $mockData[$DomainName]
        Errors = @()
    }
}

function Get-MockTrustsInfo {
    <#
    .SYNOPSIS
        Returns mock trust relationships
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DomainName
    )

    $mockData = @{
        'mock-prod.local' = @{
            TotalTrusts = 3
            Trusts = @(
                @{ TargetName = 'partner-corp.com'; TrustType = 'External'; TrustDirection = 'Bidirectional'; Status = 'Active'; Created = '2023-05-12' }
                @{ TargetName = 'vendor-systems.net'; TrustType = 'External'; TrustDirection = 'Outbound'; Status = 'Active'; Created = '2024-02-08' }
                @{ TargetName = 'subsidiary.local'; TrustType = 'Forest'; TrustDirection = 'Bidirectional'; Status = 'Active'; Created = '2022-11-20' }
            )
        }
        'mock-dev.local' = @{
            TotalTrusts = 1
            Trusts = @(
                @{ TargetName = 'mock-prod.local'; TrustType = 'External'; TrustDirection = 'Inbound'; Status = 'Active'; Created = '2024-06-15' }
            )
        }
    }

    if (-not $mockData.ContainsKey($DomainName)) {
        return @{
            Data = $null
            Errors = @("Unknown mock domain: $DomainName")
        }
    }

    return @{
        Data = $mockData[$DomainName]
        Errors = @()
    }
}

function Get-MockDomainControllersInfo {
    <#
    .SYNOPSIS
        Returns mock domain controller information
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DomainName
    )

    $mockData = @{
        'mock-prod.local' = @{
            TotalDCs = 3
            DomainControllers = @(
                @{ Name = 'DC01'; HostName = 'dc01.mock-prod.local'; Site = 'HQ-Site'; OSVersion = 'Windows Server 2022'; IsGlobalCatalog = $true; FSMORoles = @('PDCEmulator', 'RIDMaster', 'InfrastructureMaster'); IPAddress = '10.10.10.10' }
                @{ Name = 'DC02'; HostName = 'dc02.mock-prod.local'; Site = 'HQ-Site'; OSVersion = 'Windows Server 2022'; IsGlobalCatalog = $true; FSMORoles = @('SchemaMaster', 'DomainNamingMaster'); IPAddress = '10.10.10.11' }
                @{ Name = 'DC03'; HostName = 'dc03.mock-prod.local'; Site = 'DR-Site'; OSVersion = 'Windows Server 2019'; IsGlobalCatalog = $true; FSMORoles = @(); IPAddress = '10.20.10.10' }
            )
        }
        'mock-dev.local' = @{
            TotalDCs = 2
            DomainControllers = @(
                @{ Name = 'DEVDC01'; HostName = 'devdc01.mock-dev.local'; Site = 'Default-Site'; OSVersion = 'Windows Server 2019'; IsGlobalCatalog = $true; FSMORoles = @('PDCEmulator', 'RIDMaster', 'InfrastructureMaster', 'SchemaMaster', 'DomainNamingMaster'); IPAddress = '192.168.10.10' }
                @{ Name = 'DEVDC02'; HostName = 'devdc02.mock-dev.local'; Site = 'Default-Site'; OSVersion = 'Windows Server 2016'; IsGlobalCatalog = $false; FSMORoles = @(); IPAddress = '192.168.10.11' }
            )
        }
    }

    if (-not $mockData.ContainsKey($DomainName)) {
        return @{
            Data = $null
            Errors = @("Unknown mock domain: $DomainName")
        }
    }

    return @{
        Data = $mockData[$DomainName]
        Errors = @()
    }
}

function Get-MockGroupsInfo {
    <#
    .SYNOPSIS
        Returns mock group inventory
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DomainName
    )

    $mockData = @{
        'mock-prod.local' = @{
            TotalGroups = 50
            SecurityGroups = 38
            DistributionGroups = 12
            Groups = @(
                @{ Name = 'Domain Admins'; Scope = 'Global'; Type = 'Security'; MemberCount = 5; Description = 'Designated administrators of the domain' }
                @{ Name = 'IT-Administrators'; Scope = 'Global'; Type = 'Security'; MemberCount = 12; Description = 'IT department administrators' }
                @{ Name = 'Finance-Users'; Scope = 'Global'; Type = 'Security'; MemberCount = 32; Description = 'Finance department users' }
                @{ Name = 'HR-Managers'; Scope = 'Global'; Type = 'Security'; MemberCount = 8; Description = 'Human resources managers' }
                @{ Name = 'Sales-Team'; Scope = 'Global'; Type = 'Security'; MemberCount = 30; Description = 'Sales department team members' }
                @{ Name = 'VPN-Users'; Scope = 'DomainLocal'; Type = 'Security'; MemberCount = 145; Description = 'VPN access authorization' }
                @{ Name = 'All-Employees'; Scope = 'Universal'; Type = 'Distribution'; MemberCount = 368; Description = 'All company employees distribution list' }
            )
        }
        'mock-dev.local' = @{
            TotalGroups = 35
            SecurityGroups = 28
            DistributionGroups = 7
            Groups = @(
                @{ Name = 'Domain Admins'; Scope = 'Global'; Type = 'Security'; MemberCount = 3; Description = 'Designated administrators of the domain' }
                @{ Name = 'IT-Administrators'; Scope = 'Global'; Type = 'Security'; MemberCount = 8; Description = 'IT department administrators' }
                @{ Name = 'Finance-Users'; Scope = 'Global'; Type = 'Security'; MemberCount = 22; Description = 'Finance department users' }
                @{ Name = 'HR-Managers'; Scope = 'Global'; Type = 'Security'; MemberCount = 5; Description = 'Human resources managers' }
                @{ Name = 'Sales-Team'; Scope = 'Global'; Type = 'Security'; MemberCount = 14; Description = 'Sales department team members' }
                @{ Name = 'VPN-Users'; Scope = 'DomainLocal'; Type = 'Security'; MemberCount = 95; Description = 'VPN access authorization' }
                @{ Name = 'All-Employees'; Scope = 'Universal'; Type = 'Distribution'; MemberCount = 195; Description = 'All company employees distribution list' }
            )
        }
    }

    if (-not $mockData.ContainsKey($DomainName)) {
        return @{
            Data = $null
            Errors = @("Unknown mock domain: $DomainName")
        }
    }

    return @{
        Data = $mockData[$DomainName]
        Errors = @()
    }
}

function Get-MockDNSInfo {
    <#
    .SYNOPSIS
        Returns mock DNS zone information
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DomainName
    )

    $mockData = @{
        'mock-prod.local' = @{
            TotalZones = 4
            Zones = @(
                @{ Name = 'mock-prod.local'; Type = 'Primary'; DynamicUpdate = 'Secure'; RecordCount = 342 }
                @{ Name = '_msdcs.mock-prod.local'; Type = 'Primary'; DynamicUpdate = 'Secure'; RecordCount = 28 }
                @{ Name = '10.10.in-addr.arpa'; Type = 'Primary'; DynamicUpdate = 'Secure'; RecordCount = 156 }
                @{ Name = '10.20.in-addr.arpa'; Type = 'Primary'; DynamicUpdate = 'Secure'; RecordCount = 78 }
            )
        }
        'mock-dev.local' = @{
            TotalZones = 2
            Zones = @(
                @{ Name = 'mock-dev.local'; Type = 'Primary'; DynamicUpdate = 'Secure'; RecordCount = 185 }
                @{ Name = '168.192.in-addr.arpa'; Type = 'Primary'; DynamicUpdate = 'Secure'; RecordCount = 92 }
            )
        }
    }

    if (-not $mockData.ContainsKey($DomainName)) {
        return @{
            Data = $null
            Errors = @("Unknown mock domain: $DomainName")
        }
    }

    return @{
        Data = $mockData[$DomainName]
        Errors = @()
    }
}
