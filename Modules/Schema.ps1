<#
.SYNOPSIS
    Schema discovery module

.DESCRIPTION
    Retrieves Active Directory schema information including version,
    attribute/class counts, and custom schema extensions

.NOTES
    Returns standardized hashtable: @{ Data = ...; Errors = @() }
#>

function Get-SchemaInfo {
    <#
    .SYNOPSIS
        Discovers Active Directory schema information

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
        # Get RootDSE for schema naming context
        $rootDSE = Get-RootDSE -Server $Server -Credential $Credential
        $schemaNamingContext = $rootDSE.schemaNamingContext

        # Schema version mapping
        $schemaVersionMap = @{
            13 = 'Windows 2000'
            30 = 'Windows Server 2003'
            31 = 'Windows Server 2003 R2'
            44 = 'Windows Server 2008'
            47 = 'Windows Server 2008 R2'
            56 = 'Windows Server 2012'
            69 = 'Windows Server 2012 R2'
            87 = 'Windows Server 2016/2019'
            88 = 'Windows Server 2022'
            90 = 'Windows Server 2025'
        }

        # Get schema version
        $schemaVersion = $null
        $schemaLastModified = $null
        try {
            $schemaPath = "LDAP://$Server/$schemaNamingContext"
            $schemaSearcher = New-LdapSearcher -SearchRoot $schemaPath `
                -Filter "(objectClass=dMD)" `
                -Properties @('objectVersion', 'whenChanged') `
                -Credential $Credential `
                -Config $Config

            $schemaSearcher.SearchScope = [System.DirectoryServices.SearchScope]::Base
            $schemaResults = Invoke-LdapQuery -Searcher $schemaSearcher

            if ($schemaResults -and $schemaResults.Count -gt 0) {
                $schemaVersion = [int]$schemaResults[0].objectVersion
                $schemaLastModified = $schemaResults[0].whenChanged
            }
            $schemaSearcher.Dispose()
        } catch {
            $errors += "Failed to get schema version: $_"
        }

        # Count total attributes
        $totalAttributes = 0
        try {
            $attributeSearcher = New-LdapSearcher -SearchRoot "LDAP://$Server/$schemaNamingContext" `
                -Filter "(objectCategory=attributeSchema)" `
                -Properties @('cn') `
                -Credential $Credential `
                -Config $Config

            $attributeResults = Invoke-LdapQuery -Searcher $attributeSearcher
            $totalAttributes = $attributeResults.Count
            $attributeSearcher.Dispose()
        } catch {
            $errors += "Failed to count attributes: $_"
        }

        # Count total classes
        $totalClasses = 0
        try {
            $classSearcher = New-LdapSearcher -SearchRoot "LDAP://$Server/$schemaNamingContext" `
                -Filter "(objectCategory=classSchema)" `
                -Properties @('cn') `
                -Credential $Credential `
                -Config $Config

            $classResults = Invoke-LdapQuery -Searcher $classSearcher
            $totalClasses = $classResults.Count
            $classSearcher.Dispose()
        } catch {
            $errors += "Failed to count classes: $_"
        }

        # Find custom/extended attributes
        $customAttributes = @()
        try {
            # Custom attributes typically have adminDescription or non-Microsoft OIDs
            $customAttrSearcher = New-LdapSearcher -SearchRoot "LDAP://$Server/$schemaNamingContext" `
                -Filter "(&(objectCategory=attributeSchema)(adminDescription=*))" `
                -Properties @('cn', 'lDAPDisplayName', 'attributeID', 'adminDescription') `
                -Credential $Credential `
                -Config $Config

            $customAttrResults = Invoke-LdapQuery -Searcher $customAttrSearcher

            foreach ($attr in $customAttrResults) {
                $oid = $attr.attributeID
                # Filter out Microsoft OIDs (1.2.840.113556.1.*)
                if ($oid -and $oid -notlike '1.2.840.113556.1.*') {
                    $customAttributes += @{
                        Name = $attr.lDAPDisplayName
                        CommonName = $attr.cn
                        OID = $oid
                        Description = $attr.adminDescription
                    }
                }
            }
            $customAttrSearcher.Dispose()
        } catch {
            $errors += "Warning: Could not enumerate custom attributes: $_"
        }

        # Build result data
        $windowsVersion = if ($schemaVersionMap.ContainsKey($schemaVersion)) {
            $schemaVersionMap[$schemaVersion]
        } else {
            "Unknown"
        }

        $data = @{
            SchemaVersion = $schemaVersion
            WindowsServerVersion = $windowsVersion
            TotalAttributes = $totalAttributes
            TotalClasses = $totalClasses
            CustomAttributes = $customAttributes
            SchemaLastModified = if ($schemaLastModified) { $schemaLastModified.ToString('yyyy-MM-dd HH:mm:ss') } else { $null }
            SchemaNamingContext = $schemaNamingContext
        }

    } catch {
        $errors += "Failed to retrieve schema information: $_"
    }

    return @{
        Data = $data
        Errors = $errors
    }
}
