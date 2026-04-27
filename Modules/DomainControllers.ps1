<#
.SYNOPSIS
    Domain Controllers discovery module

.DESCRIPTION
    Retrieves Active Directory domain controller information including
    FSMO roles, Global Catalog status, and operating system details

.NOTES
    Returns standardized hashtable: @{ Data = ...; Errors = @() }
#>

function Get-DomainControllersInfo {
    <#
    .SYNOPSIS
        Discovers domain controllers and FSMO role holders

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
    $domainControllers = @()
    $fsmoRoles = @{}

    try {
        # Get naming contexts from RootDSE
        $rootDSE = Get-RootDSE -Server $Server -Credential $Credential
        $defaultNC = $rootDSE.defaultNamingContext
        $configNC = $rootDSE.configurationNamingContext
        $schemaNC = $rootDSE.schemaNamingContext

        # Query domain controllers using primaryGroupID=516 (Domain Controllers group)
        try {
            $dcSearcher = New-LdapSearcher -SearchRoot "LDAP://$Server/$defaultNC" `
                -Filter "(&(objectCategory=computer)(primaryGroupID=516))" `
                -Properties @('name', 'distinguishedName', 'dNSHostName', 'operatingSystem', 'operatingSystemVersion', 'whenCreated') `
                -Credential $Credential `
                -Config $Config

            $dcResults = Invoke-LdapQuery -Searcher $dcSearcher
            $dcSearcher.Dispose()

            foreach ($dc in $dcResults) {
                # Check if this DC is a Global Catalog by querying its NTDS Settings object
                $isGC = $false
                try {
                    $sitesPath = "LDAP://$Server/CN=Sites,$configNC"
                    $ntdsSearcher = New-LdapSearcher -SearchRoot $sitesPath `
                        -Filter "(&(objectCategory=nTDSDSA)(|(cn=NTDS Settings)))" `
                        -Properties @('distinguishedName', 'options') `
                        -Credential $Credential `
                        -Config $Config

                    $ntdsResults = Invoke-LdapQuery -Searcher $ntdsSearcher
                    $ntdsSearcher.Dispose()

                    # Find the NTDS Settings object for this DC
                    foreach ($ntds in $ntdsResults) {
                        if ($ntds.distinguishedName -like "*$($dc.name)*") {
                            $options = if ($ntds.options) { [int]$ntds.options } else { 0 }
                            # Bit 1 (value 1) indicates Global Catalog
                            if ($options -band 1) {
                                $isGC = $true
                                break
                            }
                        }
                    }
                } catch {
                    $errors += "Warning: Could not determine GC status for $($dc.name): $_"
                }

                $dcInfo = @{
                    Name = $dc.name
                    DistinguishedName = $dc.distinguishedName
                    DNSHostName = $dc.dNSHostName
                    OperatingSystem = $dc.operatingSystem
                    OperatingSystemVersion = $dc.operatingSystemVersion
                    IsGlobalCatalog = $isGC
                    WhenCreated = if ($dc.whenCreated) { $dc.whenCreated.ToString('yyyy-MM-dd HH:mm:ss') } else { $null }
                    FSMORoles = @()
                }

                $domainControllers += $dcInfo
            }
        } catch {
            $errors += "Failed to enumerate domain controllers: $_"
        }

        # Query FSMO role holders
        try {
            # Schema Master: fSMORoleOwner on Schema container
            $schemaMaster = $null
            try {
                $schemaSearcher = New-LdapSearcher -SearchRoot "LDAP://$Server/$schemaNC" `
                    -Filter "(objectClass=dMD)" `
                    -Properties @('fSMORoleOwner') `
                    -Credential $Credential `
                    -Config $Config
                $schemaSearcher.SearchScope = [System.DirectoryServices.SearchScope]::Base
                $schemaResults = Invoke-LdapQuery -Searcher $schemaSearcher
                $schemaSearcher.Dispose()

                if ($schemaResults -and $schemaResults[0].fSMORoleOwner) {
                    $schemaMaster = Get-DCNameFromNTDSDN -NTDSDN $schemaResults[0].fSMORoleOwner
                }
            } catch {
                $errors += "Warning: Could not retrieve Schema Master: $_"
            }

            # Domain Naming Master: fSMORoleOwner on Partitions container
            $domainNamingMaster = $null
            try {
                $partitionsSearcher = New-LdapSearcher -SearchRoot "LDAP://$Server/CN=Partitions,$configNC" `
                    -Filter "(objectClass=crossRefContainer)" `
                    -Properties @('fSMORoleOwner') `
                    -Credential $Credential `
                    -Config $Config
                $partitionsSearcher.SearchScope = [System.DirectoryServices.SearchScope]::Base
                $partitionsResults = Invoke-LdapQuery -Searcher $partitionsSearcher
                $partitionsSearcher.Dispose()

                if ($partitionsResults -and $partitionsResults[0].fSMORoleOwner) {
                    $domainNamingMaster = Get-DCNameFromNTDSDN -NTDSDN $partitionsResults[0].fSMORoleOwner
                }
            } catch {
                $errors += "Warning: Could not retrieve Domain Naming Master: $_"
            }

            # PDC Emulator: fSMORoleOwner on domain object
            $pdcEmulator = $null
            try {
                $domainSearcher = New-LdapSearcher -SearchRoot "LDAP://$Server/$defaultNC" `
                    -Filter "(objectCategory=domain)" `
                    -Properties @('fSMORoleOwner') `
                    -Credential $Credential `
                    -Config $Config
                $domainSearcher.SearchScope = [System.DirectoryServices.SearchScope]::Base
                $domainResults = Invoke-LdapQuery -Searcher $domainSearcher
                $domainSearcher.Dispose()

                if ($domainResults -and $domainResults[0].fSMORoleOwner) {
                    $pdcEmulator = Get-DCNameFromNTDSDN -NTDSDN $domainResults[0].fSMORoleOwner
                }
            } catch {
                $errors += "Warning: Could not retrieve PDC Emulator: $_"
            }

            # RID Master: fSMORoleOwner on RID Manager object
            $ridMaster = $null
            try {
                $ridSearcher = New-LdapSearcher -SearchRoot "LDAP://$Server/CN=RID Manager$,CN=System,$defaultNC" `
                    -Filter "(objectClass=rIDManager)" `
                    -Properties @('fSMORoleOwner') `
                    -Credential $Credential `
                    -Config $Config
                $ridSearcher.SearchScope = [System.DirectoryServices.SearchScope]::Base
                $ridResults = Invoke-LdapQuery -Searcher $ridSearcher
                $ridSearcher.Dispose()

                if ($ridResults -and $ridResults[0].fSMORoleOwner) {
                    $ridMaster = Get-DCNameFromNTDSDN -NTDSDN $ridResults[0].fSMORoleOwner
                }
            } catch {
                $errors += "Warning: Could not retrieve RID Master: $_"
            }

            # Infrastructure Master: fSMORoleOwner on Infrastructure object
            $infraMaster = $null
            try {
                $infraSearcher = New-LdapSearcher -SearchRoot "LDAP://$Server/CN=Infrastructure,$defaultNC" `
                    -Filter "(objectClass=infrastructureUpdate)" `
                    -Properties @('fSMORoleOwner') `
                    -Credential $Credential `
                    -Config $Config
                $infraSearcher.SearchScope = [System.DirectoryServices.SearchScope]::Base
                $infraResults = Invoke-LdapQuery -Searcher $infraSearcher
                $infraSearcher.Dispose()

                if ($infraResults -and $infraResults[0].fSMORoleOwner) {
                    $infraMaster = Get-DCNameFromNTDSDN -NTDSDN $infraResults[0].fSMORoleOwner
                }
            } catch {
                $errors += "Warning: Could not retrieve Infrastructure Master: $_"
            }

            # Build FSMO roles hashtable
            $fsmoRoles = @{
                SchemaMaster = $schemaMaster
                DomainNamingMaster = $domainNamingMaster
                PDCEmulator = $pdcEmulator
                RIDMaster = $ridMaster
                InfrastructureMaster = $infraMaster
            }

            # Add FSMO roles to corresponding DC entries
            foreach ($dc in $domainControllers) {
                $roles = @()
                if ($dc.Name -eq $schemaMaster) { $roles += 'SchemaMaster' }
                if ($dc.Name -eq $domainNamingMaster) { $roles += 'DomainNamingMaster' }
                if ($dc.Name -eq $pdcEmulator) { $roles += 'PDCEmulator' }
                if ($dc.Name -eq $ridMaster) { $roles += 'RIDMaster' }
                if ($dc.Name -eq $infraMaster) { $roles += 'InfrastructureMaster' }
                $dc.FSMORoles = $roles
            }

        } catch {
            $errors += "Failed to retrieve FSMO roles: $_"
        }

        # Count Global Catalog servers
        $gcCount = ($domainControllers | Where-Object { $_.IsGlobalCatalog }).Count

        # Build result data
        $data = @{
            DomainControllers = $domainControllers
            FSMORoles = $fsmoRoles
            TotalDCs = $domainControllers.Count
            GlobalCatalogCount = $gcCount
        }

    } catch {
        $errors += "Failed to retrieve domain controller information: $_"
    }

    return @{
        Data = $data
        Errors = $errors
    }
}

function Get-DCNameFromNTDSDN {
    <#
    .SYNOPSIS
        Extracts DC name from NTDS Settings distinguished name

    .PARAMETER NTDSDN
        Distinguished name of NTDS Settings object

    .OUTPUTS
        String containing DC name
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$NTDSDN
    )

    # NTDS DN format: CN=NTDS Settings,CN=DC01,CN=Servers,CN=Site-Name,CN=Sites,CN=Configuration,DC=...
    # We need to extract the CN= value that appears right before ",CN=Servers"
    if ($NTDSDN -match 'CN=NTDS Settings,CN=([^,]+),CN=Servers') {
        return $matches[1]
    }

    return $null
}
