<#
.SYNOPSIS
    Trust relationships discovery module

.DESCRIPTION
    Retrieves Active Directory trust relationships including type,
    direction, attributes, and partner domain information

.NOTES
    Returns standardized hashtable: @{ Data = ...; Errors = @() }
#>

function Get-TrustsInfo {
    <#
    .SYNOPSIS
        Discovers domain trust relationships

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
    $trusts = @()

    try {
        # Get default naming context
        $rootDSE = Get-RootDSE -Server $Server -Credential $Credential
        $defaultNC = $rootDSE.defaultNamingContext
        $systemPath = "LDAP://$Server/CN=System,$defaultNC"

        # Query trusted domain objects
        $trustSearcher = New-LdapSearcher -SearchRoot $systemPath `
            -Filter "(objectCategory=trustedDomain)" `
            -Properties @('name', 'distinguishedName', 'trustPartner', 'trustType', 'trustDirection', 'trustAttributes', 'flatName', 'whenCreated', 'whenChanged') `
            -Credential $Credential `
            -Config $Config

        $trustResults = Invoke-LdapQuery -Searcher $trustSearcher
        $trustSearcher.Dispose()

        if ($trustResults -and $trustResults.Count -gt 0) {
            # Trust type mappings
            $trustTypeMap = @{
                1 = 'Windows NT (Downlevel)'
                2 = 'Active Directory'
                3 = 'MIT Kerberos'
                4 = 'DCE'
            }

            # Trust direction mappings
            $trustDirectionMap = @{
                0 = 'Disabled'
                1 = 'Inbound'
                2 = 'Outbound'
                3 = 'Bidirectional'
            }

            foreach ($trust in $trustResults) {
                # Parse trust type
                $trustTypeValue = if ($trust.trustType) { [int]$trust.trustType } else { 0 }
                $trustType = if ($trustTypeMap.ContainsKey($trustTypeValue)) {
                    $trustTypeMap[$trustTypeValue]
                } else {
                    "Unknown ($trustTypeValue)"
                }

                # Parse trust direction
                $trustDirectionValue = if ($trust.trustDirection) { [int]$trust.trustDirection } else { 0 }
                $trustDirection = if ($trustDirectionMap.ContainsKey($trustDirectionValue)) {
                    $trustDirectionMap[$trustDirectionValue]
                } else {
                    "Unknown ($trustDirectionValue)"
                }

                # Parse trust attributes (bit flags)
                $trustAttributesValue = if ($trust.trustAttributes) { [int]$trust.trustAttributes } else { 0 }
                $trustAttributesList = @()

                if ($trustAttributesValue -band 0x00000001) { $trustAttributesList += 'Non-Transitive' }
                if ($trustAttributesValue -band 0x00000002) { $trustAttributesList += 'Uplevel-Only' }
                if ($trustAttributesValue -band 0x00000004) { $trustAttributesList += 'SID-Filtering' }
                if ($trustAttributesValue -band 0x00000008) { $trustAttributesList += 'Forest-Trust' }
                if ($trustAttributesValue -band 0x00000010) { $trustAttributesList += 'Cross-Organization' }
                if ($trustAttributesValue -band 0x00000020) { $trustAttributesList += 'Within-Forest' }
                if ($trustAttributesValue -band 0x00000040) { $trustAttributesList += 'Treat-As-External' }
                if ($trustAttributesValue -band 0x00000080) { $trustAttributesList += 'Uses-RC4-Encryption' }
                if ($trustAttributesValue -band 0x00000100) { $trustAttributesList += 'Cross-Organization-No-TGT' }
                if ($trustAttributesValue -band 0x00000200) { $trustAttributesList += 'PIM-Trust' }

                if ($trustAttributesList.Count -eq 0) {
                    $trustAttributesList += 'Transitive'
                }

                $trustInfo = @{
                    Name = $trust.name
                    DistinguishedName = $trust.distinguishedName
                    TrustPartner = $trust.trustPartner
                    TrustType = $trustType
                    TrustTypeValue = $trustTypeValue
                    TrustDirection = $trustDirection
                    TrustDirectionValue = $trustDirectionValue
                    TrustAttributes = $trustAttributesList -join ', '
                    TrustAttributesValue = $trustAttributesValue
                    FlatName = $trust.flatName
                    WhenCreated = if ($trust.whenCreated) { $trust.whenCreated.ToString('yyyy-MM-dd HH:mm:ss') } else { $null }
                    WhenChanged = if ($trust.whenChanged) { $trust.whenChanged.ToString('yyyy-MM-dd HH:mm:ss') } else { $null }
                }

                $trusts += $trustInfo
            }
        }

        # Build result data
        $data = @{
            Trusts = $trusts
            TotalTrusts = $trusts.Count
        }

    } catch {
        $errors += "Failed to retrieve trust information: $_"
    }

    return @{
        Data = $data
        Errors = $errors
    }
}
