<#
.SYNOPSIS
    Shared helper functions for AD Discovery toolkit

.DESCRIPTION
    Provides common utilities for LDAP queries, platform detection,
    data conversion, and progress reporting. All functions follow
    error-safe patterns with proper resource disposal.

.NOTES
    Compatible with PowerShell 5.1 and PowerShell 7+
    No RSAT or administrative privileges required
#>

function Test-IsWindowsPlatform {
    <#
    .SYNOPSIS
        Detects if running on Windows platform

    .DESCRIPTION
        Compatible detection for both PS 5.1 (Desktop) and PS 7+ (Core)

    .OUTPUTS
        Boolean indicating Windows platform
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    # PowerShell 5.1 is always Windows (Desktop edition)
    if ($PSVersionTable.PSEdition -eq 'Desktop') {
        return $true
    }

    # PowerShell 7+ uses OS property
    if ($PSVersionTable.PSEdition -eq 'Core') {
        return ($PSVersionTable.OS -like '*Windows*')
    }

    # Fallback (should never reach here)
    return $false
}

function Get-RootDSE {
    <#
    .SYNOPSIS
        Connects to Active Directory RootDSE

    .DESCRIPTION
        Retrieves fundamental directory information from RootDSE including
        naming contexts, functional levels, and domain controller details

    .PARAMETER Server
        Domain controller FQDN or domain name

    .PARAMETER Credential
        Optional credentials for authentication

    .OUTPUTS
        Hashtable with RootDSE attributes
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Server,

        [Parameter(Mandatory = $false)]
        [PSCredential]$Credential
    )

    try {
        # Build LDAP path to RootDSE
        $ldapPath = "LDAP://$Server/RootDSE"

        # Create directory entry
        if ($Credential) {
            $rootDSE = New-Object System.DirectoryServices.DirectoryEntry(
                $ldapPath,
                $Credential.UserName,
                $Credential.GetNetworkCredential().Password
            )
        } else {
            $rootDSE = New-Object System.DirectoryServices.DirectoryEntry($ldapPath)
        }

        # Force connection by accessing a property
        $null = $rootDSE.distinguishedName

        # Extract key attributes
        $result = @{
            defaultNamingContext = $rootDSE.defaultNamingContext.Value
            schemaNamingContext = $rootDSE.schemaNamingContext.Value
            configurationNamingContext = $rootDSE.configurationNamingContext.Value
            rootDomainNamingContext = $rootDSE.rootDomainNamingContext.Value
            forestFunctionality = if ($rootDSE.forestFunctionality.Value) { [int]$rootDSE.forestFunctionality.Value } else { 0 }
            domainFunctionality = if ($rootDSE.domainFunctionality.Value) { [int]$rootDSE.domainFunctionality.Value } else { 0 }
            domainControllerFunctionality = if ($rootDSE.domainControllerFunctionality.Value) { [int]$rootDSE.domainControllerFunctionality.Value } else { 0 }
            dnsHostName = $rootDSE.dnsHostName.Value
            currentTime = $rootDSE.currentTime.Value
            supportedLDAPVersion = $rootDSE.supportedLDAPVersion.Value
        }

        $rootDSE.Dispose()
        return $result

    } catch {
        throw "Failed to connect to RootDSE on $Server : $_"
    }
}

function New-LdapSearcher {
    <#
    .SYNOPSIS
        Creates configured DirectorySearcher object

    .DESCRIPTION
        Constructs LDAP searcher with proper paging, timeout, and property loading
        Uses objectCategory (indexed) over objectClass for performance

    .PARAMETER SearchRoot
        LDAP path to search base (e.g., LDAP://DC=contoso,DC=com)

    .PARAMETER Filter
        LDAP filter string (e.g., (objectCategory=person))

    .PARAMETER Properties
        Array of attribute names to retrieve

    .PARAMETER Credential
        Optional credentials for authentication

    .PARAMETER Config
        Configuration hashtable with LdapPageSize and LdapTimeout

    .OUTPUTS
        System.DirectoryServices.DirectorySearcher
    #>
    [CmdletBinding()]
    [OutputType([System.DirectoryServices.DirectorySearcher])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SearchRoot,

        [Parameter(Mandatory = $true)]
        [string]$Filter,

        [Parameter(Mandatory = $false)]
        [string[]]$Properties = @('*'),

        [Parameter(Mandatory = $false)]
        [PSCredential]$Credential,

        [Parameter(Mandatory = $false)]
        [hashtable]$Config = @{}
    )

    try {
        # Create directory entry for search root
        if ($Credential) {
            $directoryEntry = New-Object System.DirectoryServices.DirectoryEntry(
                $SearchRoot,
                $Credential.UserName,
                $Credential.GetNetworkCredential().Password
            )
        } else {
            $directoryEntry = New-Object System.DirectoryServices.DirectoryEntry($SearchRoot)
        }

        # Create searcher
        $searcher = New-Object System.DirectoryServices.DirectorySearcher($directoryEntry)
        $searcher.Filter = $Filter
        $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree

        # Configure paging (critical for large result sets)
        $pageSize = if ($Config.LdapPageSize) { $Config.LdapPageSize } else { 1000 }
        $searcher.PageSize = $pageSize

        # Configure timeout
        $timeoutSeconds = if ($Config.LdapTimeout) { $Config.LdapTimeout } else { 120 }
        $searcher.ServerTimeLimit = New-TimeSpan -Seconds $timeoutSeconds
        $searcher.ClientTimeout = New-TimeSpan -Seconds ($timeoutSeconds + 10)

        # Load requested properties
        if ($Properties -and $Properties.Count -gt 0 -and $Properties[0] -ne '*') {
            $searcher.PropertiesToLoad.Clear()
            foreach ($prop in $Properties) {
                $null = $searcher.PropertiesToLoad.Add($prop)
            }
        }

        return $searcher

    } catch {
        if ($directoryEntry) { $directoryEntry.Dispose() }
        throw "Failed to create LDAP searcher: $_"
    }
}

function Invoke-LdapQuery {
    <#
    .SYNOPSIS
        Executes LDAP query with proper resource cleanup

    .DESCRIPTION
        Wraps DirectorySearcher.FindAll() with try/catch/finally
        to ensure SearchResultCollection is always disposed

    .PARAMETER Searcher
        Configured DirectorySearcher object

    .OUTPUTS
        Array of hashtables (converted from SearchResult objects)
    #>
    [CmdletBinding()]
    [OutputType([array])]
    param(
        [Parameter(Mandatory = $true)]
        [System.DirectoryServices.DirectorySearcher]$Searcher
    )

    $results = $null
    $output = @()

    try {
        # Execute query
        $results = $Searcher.FindAll()

        # Get property names from searcher
        $propertyNames = if ($Searcher.PropertiesToLoad.Count -gt 0) {
            $Searcher.PropertiesToLoad
        } else {
            @()  # Will be populated from first result
        }

        # Convert each result to hashtable
        foreach ($result in $results) {
            # If no specific properties requested, get them from first result
            if ($propertyNames.Count -eq 0) {
                $propertyNames = $result.Properties.PropertyNames
            }

            $hashtable = ConvertTo-HashtableFromResult -Result $result -Properties $propertyNames
            $output += $hashtable
        }

        return $output

    } catch {
        throw "LDAP query failed: $_"

    } finally {
        # Critical: always dispose SearchResultCollection
        if ($results) {
            $results.Dispose()
        }
    }
}

function ConvertTo-HashtableFromResult {
    <#
    .SYNOPSIS
        Converts SearchResult to hashtable

    .DESCRIPTION
        Extracts properties from SearchResult object into clean hashtable
        Handles multi-value properties and common AD attribute types

    .PARAMETER Result
        Single SearchResult object

    .PARAMETER Properties
        Array of property names to extract

    .OUTPUTS
        Hashtable with property values
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        $Result,

        [Parameter(Mandatory = $true)]
        [array]$Properties
    )

    $hashtable = @{}

    foreach ($propName in $Properties) {
        if ($Result.Properties.Contains($propName)) {
            $propValue = $Result.Properties[$propName]

            # Handle multi-value properties
            if ($propValue.Count -eq 1) {
                $hashtable[$propName] = $propValue[0]
            } elseif ($propValue.Count -gt 1) {
                $hashtable[$propName] = @($propValue)
            } else {
                $hashtable[$propName] = $null
            }
        } else {
            $hashtable[$propName] = $null
        }
    }

    # Always include DN if available
    if ($Result.Properties.Contains('distinguishedName') -and -not $hashtable.ContainsKey('distinguishedName')) {
        $hashtable['distinguishedName'] = $Result.Properties['distinguishedName'][0]
    }

    # Always include path
    $hashtable['ADSPath'] = $Result.Path

    return $hashtable
}

function ConvertTo-ReadableTimestamp {
    <#
    .SYNOPSIS
        Converts AD FileTime to readable DateTime

    .DESCRIPTION
        Handles AD large integer timestamps (100-nanosecond intervals since 1601)
        Returns formatted string or $null for invalid/never values

    .PARAMETER FileTime
        Int64 FileTime value from AD

    .OUTPUTS
        String formatted DateTime or $null
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false)]
        [long]$FileTime
    )

    # Handle null, 0, or "never" values
    if (-not $FileTime -or $FileTime -eq 0 -or $FileTime -eq 9223372036854775807) {
        return $null
    }

    try {
        $datetime = [DateTime]::FromFileTime($FileTime)
        return $datetime.ToString('yyyy-MM-dd HH:mm:ss')
    } catch {
        return $null
    }
}

function Write-ProgressStep {
    <#
    .SYNOPSIS
        Standardized progress output

    .DESCRIPTION
        Consistent formatting for multi-step operations

    .PARAMETER StepNumber
        Current step number

    .PARAMETER TotalSteps
        Total number of steps

    .PARAMETER Message
        Progress message
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [int]$StepNumber,

        [Parameter(Mandatory = $true)]
        [int]$TotalSteps,

        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    Write-Host "[$StepNumber/$TotalSteps] $Message" -ForegroundColor Cyan
}
