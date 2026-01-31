<#
.SYNOPSIS
    Domain comparison engine for AD Discovery toolkit

.DESCRIPTION
    Deep recursive comparison of two Active Directory discovery result sets.
    Identifies additions, removals, changes, and unchanged items across all
    discovery modules with detailed property-level differences.

.NOTES
    Returns standardized structure with summary statistics and detailed
    module-by-module comparisons. Handles scalar properties, collections,
    and nested objects.
#>

function Compare-ADDomains {
    <#
    .SYNOPSIS
        Compares two AD domain discovery result sets

    .DESCRIPTION
        Performs comprehensive comparison of discovery data from two domains,
        identifying all differences with categorization (Added, Removed, Changed, Unchanged)

    .PARAMETER PrimaryResults
        Discovery results hashtable from primary domain

    .PARAMETER CompareResults
        Discovery results hashtable from comparison domain

    .PARAMETER PrimaryName
        Display name for primary domain

    .PARAMETER CompareName
        Display name for comparison domain

    .OUTPUTS
        Hashtable with Summary, ModuleComparisons, and Errors
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$PrimaryResults,

        [Parameter(Mandatory = $true)]
        [hashtable]$CompareResults,

        [Parameter(Mandatory = $true)]
        [string]$PrimaryName,

        [Parameter(Mandatory = $true)]
        [string]$CompareName
    )

    $errors = @()
    $moduleComparisons = @{}
    $totalDifferences = 0
    $totalAdded = 0
    $totalRemoved = 0
    $totalChanged = 0
    $totalUnchanged = 0

    Write-Verbose "Starting comparison: $PrimaryName vs $CompareName"

    try {
        # Get all module names from both result sets
        $allModules = @($PrimaryResults.Keys) + @($CompareResults.Keys) | Select-Object -Unique

        foreach ($moduleName in $allModules) {
            Write-Verbose "Comparing module: $moduleName"

            # Check if module exists in both results
            $primaryData = if ($PrimaryResults.ContainsKey($moduleName)) { $PrimaryResults[$moduleName].Data } else { $null }
            $compareData = if ($CompareResults.ContainsKey($moduleName)) { $CompareResults[$moduleName].Data } else { $null }

            # Handle missing modules
            if (-not $primaryData -and -not $compareData) {
                $errors += "Module $moduleName has no data in either domain"
                continue
            }

            if (-not $primaryData) {
                $errors += "Module $moduleName missing from primary domain ($PrimaryName)"
                continue
            }

            if (-not $compareData) {
                $errors += "Module $moduleName missing from comparison domain ($CompareName)"
                continue
            }

            # Compare the module data
            $moduleComparison = Compare-ModuleData -ModuleName $moduleName `
                -PrimaryData $primaryData `
                -CompareData $compareData

            $moduleComparisons[$moduleName] = $moduleComparison

            # Aggregate statistics
            if ($moduleComparison.Summary) {
                $totalDifferences += $moduleComparison.Summary.TotalDifferences
                $totalAdded += $moduleComparison.Summary.AddedCount
                $totalRemoved += $moduleComparison.Summary.RemovedCount
                $totalChanged += $moduleComparison.Summary.ChangedCount
                $totalUnchanged += $moduleComparison.Summary.UnchangedCount
            }
        }

    } catch {
        $errors += "Comparison engine failed: $_"
    }

    return @{
        Summary = @{
            TotalDifferences = $totalDifferences
            AddedCount = $totalAdded
            RemovedCount = $totalRemoved
            ChangedCount = $totalChanged
            UnchangedCount = $totalUnchanged
            ModulesCompared = $moduleComparisons.Count
            PrimaryDomain = $PrimaryName
            CompareDomain = $CompareName
            ComparisonTimestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        }
        ModuleComparisons = $moduleComparisons
        Errors = $errors
    }
}

function Compare-ModuleData {
    <#
    .SYNOPSIS
        Compares data from a single discovery module

    .DESCRIPTION
        Handles both scalar properties and collections within module data

    .PARAMETER ModuleName
        Name of the module being compared

    .PARAMETER PrimaryData
        Primary domain data for this module

    .PARAMETER CompareData
        Comparison domain data for this module

    .OUTPUTS
        Hashtable with differences categorized by type
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ModuleName,

        [Parameter(Mandatory = $true)]
        $PrimaryData,

        [Parameter(Mandatory = $true)]
        $CompareData
    )

    $result = @{
        ScalarDifferences = @()
        CollectionDifferences = @{}
        Summary = @{
            TotalDifferences = 0
            AddedCount = 0
            RemovedCount = 0
            ChangedCount = 0
            UnchangedCount = 0
        }
    }

    # Separate scalar properties from collections
    $primaryKeys = @($PrimaryData.Keys)
    $compareKeys = @($CompareData.Keys)
    $allKeys = @($primaryKeys) + @($compareKeys) | Select-Object -Unique

    foreach ($key in $allKeys) {
        $primaryValue = if ($PrimaryData.ContainsKey($key)) { $PrimaryData[$key] } else { $null }
        $compareValue = if ($CompareData.ContainsKey($key)) { $CompareData[$key] } else { $null }

        # Determine if this is a collection (array of hashtables)
        $isPrimaryCollection = ($primaryValue -is [array]) -and ($primaryValue.Count -gt 0) -and ($primaryValue[0] -is [hashtable])
        $isCompareCollection = ($compareValue -is [array]) -and ($compareValue.Count -gt 0) -and ($compareValue[0] -is [hashtable])

        if ($isPrimaryCollection -or $isCompareCollection) {
            # Handle as collection
            $keyField = Get-CollectionKeyField -ModuleName $ModuleName -CollectionName $key
            $collectionComparison = Compare-Collections -CollectionName $key `
                -PrimaryCollection $primaryValue `
                -CompareCollection $compareValue `
                -KeyField $keyField

            $result.CollectionDifferences[$key] = $collectionComparison

            # Update summary counts
            $result.Summary.AddedCount += $collectionComparison.Added.Count
            $result.Summary.RemovedCount += $collectionComparison.Removed.Count
            $result.Summary.ChangedCount += $collectionComparison.Changed.Count
            $result.Summary.UnchangedCount += $collectionComparison.Unchanged.Count

        } else {
            # Handle as scalar property
            $comparison = Compare-ScalarValue -PropertyName $key `
                -PrimaryValue $primaryValue `
                -CompareValue $compareValue

            $result.ScalarDifferences += $comparison

            if ($comparison.Status -eq 'Changed') {
                $result.Summary.TotalDifferences++
            }
        }
    }

    # Calculate total differences
    $result.Summary.TotalDifferences = $result.Summary.AddedCount + $result.Summary.RemovedCount + $result.Summary.ChangedCount

    return $result
}

function Compare-ScalarValue {
    <#
    .SYNOPSIS
        Compares two scalar property values

    .PARAMETER PropertyName
        Name of the property being compared

    .PARAMETER PrimaryValue
        Value from primary domain

    .PARAMETER CompareValue
        Value from comparison domain

    .OUTPUTS
        Hashtable with comparison result
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PropertyName,

        [Parameter(Mandatory = $false)]
        $PrimaryValue,

        [Parameter(Mandatory = $false)]
        $CompareValue
    )

    # Convert values to strings for comparison
    $primaryStr = if ($null -eq $PrimaryValue) { '' } else { $PrimaryValue.ToString() }
    $compareStr = if ($null -eq $CompareValue) { '' } else { $CompareValue.ToString() }

    $status = if ($primaryStr -eq $compareStr) { 'Unchanged' } else { 'Changed' }

    return @{
        Property = $PropertyName
        PrimaryValue = $PrimaryValue
        CompareValue = $CompareValue
        Status = $status
    }
}

function Compare-Collections {
    <#
    .SYNOPSIS
        Compares two collections (arrays of hashtables)

    .DESCRIPTION
        Matches items by key field and compares properties within matched items

    .PARAMETER CollectionName
        Name of the collection being compared

    .PARAMETER PrimaryCollection
        Collection from primary domain

    .PARAMETER CompareCollection
        Collection from comparison domain

    .PARAMETER KeyField
        Field name to use for matching items between collections

    .OUTPUTS
        Hashtable with Added, Removed, Changed, and Unchanged arrays
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$CollectionName,

        [Parameter(Mandatory = $false)]
        [array]$PrimaryCollection = @(),

        [Parameter(Mandatory = $false)]
        [array]$CompareCollection = @(),

        [Parameter(Mandatory = $true)]
        [string]$KeyField
    )

    $added = @()
    $removed = @()
    $changed = @()
    $unchanged = @()

    # Ensure collections are arrays
    if ($null -eq $PrimaryCollection) { $PrimaryCollection = @() }
    if ($null -eq $CompareCollection) { $CompareCollection = @() }

    # Build lookup tables by key field
    $primaryLookup = @{}
    $compareLookup = @{}

    foreach ($item in $PrimaryCollection) {
        if ($item -is [hashtable] -and $item.ContainsKey($KeyField)) {
            $key = $item[$KeyField]
            $primaryLookup[$key] = $item
        }
    }

    foreach ($item in $CompareCollection) {
        if ($item -is [hashtable] -and $item.ContainsKey($KeyField)) {
            $key = $item[$KeyField]
            $compareLookup[$key] = $item
        }
    }

    # Find added items (in compare but not in primary)
    foreach ($key in $compareLookup.Keys) {
        if (-not $primaryLookup.ContainsKey($key)) {
            $added += @{
                KeyField = $KeyField
                KeyValue = $key
                Item = $compareLookup[$key]
            }
        }
    }

    # Find removed items (in primary but not in compare)
    foreach ($key in $primaryLookup.Keys) {
        if (-not $compareLookup.ContainsKey($key)) {
            $removed += @{
                KeyField = $KeyField
                KeyValue = $key
                Item = $primaryLookup[$key]
            }
        }
    }

    # Find changed and unchanged items (in both)
    foreach ($key in $primaryLookup.Keys) {
        if ($compareLookup.ContainsKey($key)) {
            $primaryItem = $primaryLookup[$key]
            $compareItem = $compareLookup[$key]

            # Compare all properties in the items
            $itemDifferences = @()
            $allItemKeys = @($primaryItem.Keys) + @($compareItem.Keys) | Select-Object -Unique

            foreach ($propKey in $allItemKeys) {
                $primaryProp = if ($primaryItem.ContainsKey($propKey)) { $primaryItem[$propKey] } else { $null }
                $compareProp = if ($compareItem.ContainsKey($propKey)) { $compareItem[$propKey] } else { $null }

                # Handle array properties specially
                if ($primaryProp -is [array] -or $compareProp -is [array]) {
                    $primaryArray = if ($primaryProp -is [array]) { $primaryProp } else { @($primaryProp) }
                    $compareArray = if ($compareProp -is [array]) { $compareProp } else { @($compareProp) }

                    $primarySorted = ($primaryArray | Sort-Object) -join ','
                    $compareSorted = ($compareArray | Sort-Object) -join ','

                    if ($primarySorted -ne $compareSorted) {
                        $itemDifferences += @{
                            Property = $propKey
                            PrimaryValue = $primaryProp
                            CompareValue = $compareProp
                        }
                    }
                } else {
                    # Scalar comparison
                    $primaryStr = if ($null -eq $primaryProp) { '' } else { $primaryProp.ToString() }
                    $compareStr = if ($null -eq $compareProp) { '' } else { $compareProp.ToString() }

                    if ($primaryStr -ne $compareStr) {
                        $itemDifferences += @{
                            Property = $propKey
                            PrimaryValue = $primaryProp
                            CompareValue = $compareProp
                        }
                    }
                }
            }

            if ($itemDifferences.Count -gt 0) {
                $changed += @{
                    KeyField = $KeyField
                    KeyValue = $key
                    Differences = $itemDifferences
                    PrimaryItem = $primaryItem
                    CompareItem = $compareItem
                }
            } else {
                $unchanged += @{
                    KeyField = $KeyField
                    KeyValue = $key
                    Item = $primaryItem
                }
            }
        }
    }

    return @{
        Added = $added
        Removed = $removed
        Changed = $changed
        Unchanged = $unchanged
    }
}

function Get-CollectionKeyField {
    <#
    .SYNOPSIS
        Determines the key field for matching items in a collection

    .DESCRIPTION
        Returns appropriate key field based on module and collection name

    .PARAMETER ModuleName
        Name of the discovery module

    .PARAMETER CollectionName
        Name of the collection within the module

    .OUTPUTS
        String key field name
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ModuleName,

        [Parameter(Mandatory = $true)]
        [string]$CollectionName
    )

    # Define key field mappings
    $keyFieldMap = @{
        'OUStructure' = @{
            'OUs' = 'DistinguishedName'
        }
        'SitesSubnets' = @{
            'Sites' = 'Name'
            'Subnets' = 'Name'
            'SiteLinks' = 'Name'
        }
        'Trusts' = @{
            'Trusts' = 'TargetName'
        }
        'DomainControllers' = @{
            'DomainControllers' = 'Name'
        }
        'Groups' = @{
            'Groups' = 'Name'
        }
        'DNS' = @{
            'Zones' = 'Name'
        }
        'Schema' = @{
            'CustomAttributes' = 'Name'
        }
    }

    # Try to find specific mapping
    if ($keyFieldMap.ContainsKey($ModuleName) -and $keyFieldMap[$ModuleName].ContainsKey($CollectionName)) {
        return $keyFieldMap[$ModuleName][$CollectionName]
    }

    # Default fallbacks
    if ($CollectionName -like '*OU*') {
        return 'DistinguishedName'
    }

    # Generic fallback
    return 'Name'
}
