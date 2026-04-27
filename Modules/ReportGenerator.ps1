<#
.SYNOPSIS
    Report generation module for AD Discovery toolkit

.DESCRIPTION
    Generates professional HTML, JSON, and CSV reports from discovery data.
    Supports both single-domain discovery and two-domain comparison modes.

.NOTES
    HTML reports use dark mode theme with collapsible sections
    JSON reports include full metadata and structured data
    CSV exports create separate files per category
#>

function Export-HTMLReport {
    <#
    .SYNOPSIS
        Generates professional HTML report with optional comparison

    .PARAMETER PrimaryResults
        Discovery results from primary domain

    .PARAMETER CompareResults
        Optional discovery results from comparison domain

    .PARAMETER ComparisonData
        Optional comparison analysis data

    .PARAMETER PrimaryName
        Display name for primary domain

    .PARAMETER CompareName
        Display name for comparison domain

    .PARAMETER OutputPath
        Full path for output HTML file

    .PARAMETER TemplatePath
        Path to HTML template file

    .OUTPUTS
        String path to generated HTML file
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$PrimaryResults,

        [Parameter(Mandatory = $false)]
        [hashtable]$CompareResults = $null,

        [Parameter(Mandatory = $false)]
        [hashtable]$ComparisonData = $null,

        [Parameter(Mandatory = $true)]
        [string]$PrimaryName,

        [Parameter(Mandatory = $false)]
        [string]$CompareName = '',

        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $false)]
        [string]$TemplatePath = ''
    )

    try {
        $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        $toolVersion = '1.0.0'

        # Build executive summary
        $executiveSummary = Build-ExecutiveSummary -PrimaryResults $PrimaryResults `
            -CompareResults $CompareResults `
            -ComparisonData $ComparisonData `
            -PrimaryName $PrimaryName `
            -CompareName $CompareName

        # Build content sections
        $contentSections = Build-ContentSections -PrimaryResults $PrimaryResults `
            -CompareResults $CompareResults `
            -ComparisonData $ComparisonData `
            -PrimaryName $PrimaryName `
            -CompareName $CompareName

        # Build errors section
        $errorsSection = Build-ErrorsSection -PrimaryResults $PrimaryResults `
            -CompareResults $CompareResults

        # Generate HTML (using inline template if none provided)
        if (-not $TemplatePath -or -not (Test-Path $TemplatePath)) {
            $htmlContent = Get-InlineHTMLTemplate
        } else {
            $htmlContent = Get-Content $TemplatePath -Raw
        }

        # Replace placeholders
        $title = if ($CompareResults) { "AD Comparison Report: $PrimaryName vs $CompareName" } else { "AD Discovery Report: $PrimaryName" }

        $htmlContent = $htmlContent -replace '{{TITLE}}', $title
        $htmlContent = $htmlContent -replace '{{TIMESTAMP}}', $timestamp
        $htmlContent = $htmlContent -replace '{{TOOL_VERSION}}', $toolVersion
        $htmlContent = $htmlContent -replace '{{PRIMARY_DOMAIN}}', $PrimaryName
        $htmlContent = $htmlContent -replace '{{COMPARE_DOMAIN}}', $CompareName
        $htmlContent = $htmlContent -replace '{{EXECUTIVE_SUMMARY}}', $executiveSummary
        $htmlContent = $htmlContent -replace '{{CONTENT}}', $contentSections
        $htmlContent = $htmlContent -replace '{{ERRORS}}', $errorsSection

        # Write to file
        $htmlContent | Out-File -FilePath $OutputPath -Encoding utf8

        Write-Verbose "HTML report generated: $OutputPath"
        return $OutputPath

    } catch {
        throw "Failed to generate HTML report: $_"
    }
}

function Export-JSONReport {
    <#
    .SYNOPSIS
        Exports discovery data to structured JSON

    .PARAMETER PrimaryResults
        Discovery results from primary domain

    .PARAMETER CompareResults
        Optional discovery results from comparison domain

    .PARAMETER ComparisonData
        Optional comparison analysis data

    .PARAMETER PrimaryName
        Display name for primary domain

    .PARAMETER CompareName
        Display name for comparison domain

    .PARAMETER OutputPath
        Full path for output JSON file

    .OUTPUTS
        String path to generated JSON file
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$PrimaryResults,

        [Parameter(Mandatory = $false)]
        [hashtable]$CompareResults = $null,

        [Parameter(Mandatory = $false)]
        [hashtable]$ComparisonData = $null,

        [Parameter(Mandatory = $true)]
        [string]$PrimaryName,

        [Parameter(Mandatory = $false)]
        [string]$CompareName = '',

        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    try {
        $jsonData = @{
            Metadata = @{
                GeneratedTimestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
                ToolVersion = '1.0.0'
                ComparisonMode = ($null -ne $CompareResults)
                PrimaryDomain = $PrimaryName
                CompareDomain = if ($CompareName) { $CompareName } else { $null }
            }
            PrimaryDomain = @{
                Name = $PrimaryName
                DiscoveryResults = $PrimaryResults
            }
        }

        if ($CompareResults) {
            $jsonData.CompareDomain = @{
                Name = $CompareName
                DiscoveryResults = $CompareResults
            }
        }

        if ($ComparisonData) {
            $jsonData.ComparisonAnalysis = $ComparisonData
        }

        # Convert to JSON with proper depth
        $jsonContent = $jsonData | ConvertTo-Json -Depth 20

        # Write to file
        $jsonContent | Out-File -FilePath $OutputPath -Encoding utf8

        Write-Verbose "JSON report generated: $OutputPath"
        return $OutputPath

    } catch {
        throw "Failed to generate JSON report: $_"
    }
}

function Export-CSVReports {
    <#
    .SYNOPSIS
        Exports discovery data to category-specific CSV files

    .PARAMETER Results
        Discovery results hashtable

    .PARAMETER DomainName
        Domain name for file naming

    .PARAMETER OutputPath
        Output directory path

    .OUTPUTS
        Array of generated CSV file paths
    #>
    [CmdletBinding()]
    [OutputType([array])]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Results,

        [Parameter(Mandatory = $true)]
        [string]$DomainName,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    try {
        $outputFiles = @()
        $safeDomainName = $DomainName -replace '[^a-zA-Z0-9]', '-'

        # Define CSV export mappings
        $csvMappings = @{
            'OUStructure' = @{ CollectionKey = 'OUs'; FileName = 'OUs.csv' }
            'Groups' = @{ CollectionKey = 'Groups'; FileName = 'Groups.csv' }
            'DomainControllers' = @{ CollectionKey = 'DomainControllers'; FileName = 'DomainControllers.csv' }
            'Trusts' = @{ CollectionKey = 'Trusts'; FileName = 'Trusts.csv' }
            'SitesSubnets' = @{ CollectionKey = 'Sites'; FileName = 'Sites.csv' }
            'DNS' = @{ CollectionKey = 'Zones'; FileName = 'DNSZones.csv' }
        }

        foreach ($moduleName in $csvMappings.Keys) {
            if (-not $Results.ContainsKey($moduleName)) {
                continue
            }

            $moduleData = $Results[$moduleName].Data
            if (-not $moduleData) {
                continue
            }

            $mapping = $csvMappings[$moduleName]
            $collection = $moduleData[$mapping.CollectionKey]

            if ($collection -and $collection.Count -gt 0) {
                $fileName = "$safeDomainName-$($mapping.FileName)"
                $filePath = Join-Path $OutputPath $fileName

                # Flatten hashtables for CSV export
                $flattenedData = @()
                foreach ($item in $collection) {
                    $flatItem = @{}
                    foreach ($key in $item.Keys) {
                        $value = $item[$key]
                        if ($value -is [array]) {
                            $flatItem[$key] = ($value -join '; ')
                        } elseif ($value -is [hashtable]) {
                            $flatItem[$key] = ($value | ConvertTo-Json -Compress)
                        } else {
                            $flatItem[$key] = $value
                        }
                    }
                    $flattenedData += [PSCustomObject]$flatItem
                }

                $flattenedData | Export-Csv -Path $filePath -NoTypeInformation -Encoding UTF8
                $outputFiles += $filePath
                Write-Verbose "CSV exported: $filePath"
            }
        }

        # Export subnets separately if present
        if ($Results.ContainsKey('SitesSubnets') -and $Results.SitesSubnets.Data.Subnets) {
            $subnets = $Results.SitesSubnets.Data.Subnets
            if ($subnets.Count -gt 0) {
                $fileName = "$safeDomainName-Subnets.csv"
                $filePath = Join-Path $OutputPath $fileName

                $flattenedData = @()
                foreach ($item in $subnets) {
                    $flatItem = @{}
                    foreach ($key in $item.Keys) {
                        $flatItem[$key] = $item[$key]
                    }
                    $flattenedData += [PSCustomObject]$flatItem
                }

                $flattenedData | Export-Csv -Path $filePath -NoTypeInformation -Encoding UTF8
                $outputFiles += $filePath
                Write-Verbose "CSV exported: $filePath"
            }
        }

        return $outputFiles

    } catch {
        throw "Failed to generate CSV reports: $_"
    }
}

function Build-ExecutiveSummary {
    <#
    .SYNOPSIS
        Builds executive summary HTML section
    #>
    [CmdletBinding()]
    param(
        [hashtable]$PrimaryResults,
        [hashtable]$CompareResults,
        [hashtable]$ComparisonData,
        [string]$PrimaryName,
        [string]$CompareName
    )

    $html = @"
<div class="executive-summary">
    <h2>Executive Summary</h2>
    <div class="summary-cards">
"@

    # Primary domain stats
    $primaryStats = Get-DomainStats -Results $PrimaryResults
    $html += @"
        <div class="summary-card">
            <h3>$PrimaryName</h3>
            <div class="stat-row"><span class="stat-label">Organizational Units:</span> <span class="stat-value">$($primaryStats.OUCount)</span></div>
            <div class="stat-row"><span class="stat-label">Groups:</span> <span class="stat-value">$($primaryStats.GroupCount)</span></div>
            <div class="stat-row"><span class="stat-label">Domain Controllers:</span> <span class="stat-value">$($primaryStats.DCCount)</span></div>
            <div class="stat-row"><span class="stat-label">Sites:</span> <span class="stat-value">$($primaryStats.SiteCount)</span></div>
            <div class="stat-row"><span class="stat-label">DNS Zones:</span> <span class="stat-value">$($primaryStats.ZoneCount)</span></div>
        </div>
"@

    # Comparison domain stats
    if ($CompareResults) {
        $compareStats = Get-DomainStats -Results $CompareResults
        $html += @"
        <div class="summary-card">
            <h3>$CompareName</h3>
            <div class="stat-row"><span class="stat-label">Organizational Units:</span> <span class="stat-value">$($compareStats.OUCount)</span></div>
            <div class="stat-row"><span class="stat-label">Groups:</span> <span class="stat-value">$($compareStats.GroupCount)</span></div>
            <div class="stat-row"><span class="stat-label">Domain Controllers:</span> <span class="stat-value">$($compareStats.DCCount)</span></div>
            <div class="stat-row"><span class="stat-label">Sites:</span> <span class="stat-value">$($compareStats.SiteCount)</span></div>
            <div class="stat-row"><span class="stat-label">DNS Zones:</span> <span class="stat-value">$($compareStats.ZoneCount)</span></div>
        </div>
"@
    }

    # Comparison summary
    if ($ComparisonData -and $ComparisonData.Summary) {
        $summary = $ComparisonData.Summary
        $html += @"
        <div class="summary-card comparison-summary">
            <h3>Comparison Results</h3>
            <div class="stat-row"><span class="stat-label">Total Differences:</span> <span class="stat-value">$($summary.TotalDifferences)</span></div>
            <div class="stat-row added"><span class="stat-label">Added:</span> <span class="stat-value">$($summary.AddedCount)</span></div>
            <div class="stat-row removed"><span class="stat-label">Removed:</span> <span class="stat-value">$($summary.RemovedCount)</span></div>
            <div class="stat-row changed"><span class="stat-label">Changed:</span> <span class="stat-value">$($summary.ChangedCount)</span></div>
            <div class="stat-row unchanged"><span class="stat-label">Unchanged:</span> <span class="stat-value">$($summary.UnchangedCount)</span></div>
        </div>
"@
    }

    $html += @"
    </div>
</div>
"@

    return $html
}

function Build-ContentSections {
    <#
    .SYNOPSIS
        Builds main content sections HTML
    #>
    [CmdletBinding()]
    param(
        [hashtable]$PrimaryResults,
        [hashtable]$CompareResults,
        [hashtable]$ComparisonData,
        [string]$PrimaryName,
        [string]$CompareName
    )

    $html = '<div class="content-sections">'

    # Module display order
    $moduleOrder = @('ForestDomain', 'Schema', 'OUStructure', 'SitesSubnets', 'Trusts', 'DomainControllers', 'Groups', 'DNS')

    foreach ($moduleName in $moduleOrder) {
        if (-not $PrimaryResults.ContainsKey($moduleName)) {
            continue
        }

        $html += @"
<details class="module-section" open>
    <summary>
        <h2>$moduleName</h2>
    </summary>
    <div class="module-content">
"@

        # Get module data
        $primaryData = $PrimaryResults[$moduleName].Data
        $compareData = if ($CompareResults -and $CompareResults.ContainsKey($moduleName)) { $CompareResults[$moduleName].Data } else { $null }
        $comparisonModuleData = if ($ComparisonData -and $ComparisonData.ModuleComparisons.ContainsKey($moduleName)) { $ComparisonData.ModuleComparisons[$moduleName] } else { $null }

        # Render module content
        $html += Build-ModuleContent -ModuleName $moduleName `
            -PrimaryData $primaryData `
            -CompareData $compareData `
            -ComparisonData $comparisonModuleData `
            -PrimaryName $PrimaryName `
            -CompareName $CompareName

        $html += @"
    </div>
</details>
"@
    }

    $html += '</div>'
    return $html
}

function Build-ModuleContent {
    <#
    .SYNOPSIS
        Builds content for a single module
    #>
    [CmdletBinding()]
    param(
        [string]$ModuleName,
        $PrimaryData,
        $CompareData,
        $ComparisonData,
        [string]$PrimaryName,
        [string]$CompareName
    )

    $html = ''

    # Render scalar properties as key-value table
    $scalarKeys = $PrimaryData.Keys | Where-Object {
        $value = $PrimaryData[$_]
        -not ($value -is [array] -and $value.Count -gt 0 -and $value[0] -is [hashtable])
    }

    if ($scalarKeys.Count -gt 0) {
        $html += '<h3>Properties</h3><table class="properties-table">'
        $html += '<thead><tr><th>Property</th><th>' + $PrimaryName + '</th>'
        if ($CompareData) {
            $html += '<th>' + $CompareName + '</th><th>Status</th>'
        }
        $html += '</tr></thead><tbody>'

        foreach ($key in $scalarKeys) {
            $primaryValue = if ($PrimaryData[$key]) { $PrimaryData[$key] } else { '-' }

            $html += "<tr><td>$key</td><td>$primaryValue</td>"

            if ($CompareData) {
                $compareValue = if ($CompareData[$key]) { $CompareData[$key] } else { '-' }
                $status = if ($primaryValue -eq $compareValue) { 'unchanged' } else { 'changed' }
                $html += "<td>$compareValue</td><td class='$status'>$status</td>"
            }

            $html += '</tr>'
        }

        $html += '</tbody></table>'
    }

    # Render collections
    $collectionKeys = $PrimaryData.Keys | Where-Object {
        $value = $PrimaryData[$_]
        ($value -is [array] -and $value.Count -gt 0 -and $value[0] -is [hashtable])
    }

    foreach ($collectionKey in $collectionKeys) {
        $html += "<h3>$collectionKey</h3>"

        if ($ComparisonData -and $ComparisonData.CollectionDifferences.ContainsKey($collectionKey)) {
            $collectionComparison = $ComparisonData.CollectionDifferences[$collectionKey]
            $html += Build-CollectionComparisonTable -CollectionName $collectionKey `
                -ComparisonData $collectionComparison `
                -PrimaryName $PrimaryName `
                -CompareName $CompareName
        } else {
            $collection = $PrimaryData[$collectionKey]
            $html += Build-SimpleCollectionTable -Collection $collection
        }
    }

    return $html
}

function Build-SimpleCollectionTable {
    <#
    .SYNOPSIS
        Builds simple table for collection without comparison
    #>
    [CmdletBinding()]
    param([array]$Collection)

    if ($Collection.Count -eq 0) {
        return '<p class="no-data">No items found</p>'
    }

    $html = '<table class="collection-table"><thead><tr>'

    # Get columns from first item
    $columns = $Collection[0].Keys | Sort-Object
    foreach ($col in $columns) {
        $html += "<th>$col</th>"
    }
    $html += '</tr></thead><tbody>'

    foreach ($item in $Collection) {
        $html += '<tr>'
        foreach ($col in $columns) {
            $value = if ($item[$col]) {
                if ($item[$col] -is [array]) { ($item[$col] -join ', ') } else { $item[$col] }
            } else { '-' }
            $html += "<td>$value</td>"
        }
        $html += '</tr>'
    }

    $html += '</tbody></table>'
    return $html
}

function Build-CollectionComparisonTable {
    <#
    .SYNOPSIS
        Builds comparison table for collection with diff highlighting
    #>
    [CmdletBinding()]
    param(
        [string]$CollectionName,
        $ComparisonData,
        [string]$PrimaryName,
        [string]$CompareName
    )

    $html = ''

    # Added items
    if ($ComparisonData.Added.Count -gt 0) {
        $html += '<h4 class="added">Added in ' + $CompareName + ' (' + $ComparisonData.Added.Count + ')</h4>'
        $html += '<table class="collection-table added-items"><thead><tr>'

        $firstItem = $ComparisonData.Added[0].Item
        $columns = $firstItem.Keys | Sort-Object
        foreach ($col in $columns) {
            $html += "<th>$col</th>"
        }
        $html += '</tr></thead><tbody>'

        foreach ($item in $ComparisonData.Added) {
            $html += '<tr>'
            foreach ($col in $columns) {
                $value = if ($item.Item[$col]) {
                    if ($item.Item[$col] -is [array]) { ($item.Item[$col] -join ', ') } else { $item.Item[$col] }
                } else { '-' }
                $html += "<td>$value</td>"
            }
            $html += '</tr>'
        }

        $html += '</tbody></table>'
    }

    # Removed items
    if ($ComparisonData.Removed.Count -gt 0) {
        $html += '<h4 class="removed">Removed from ' + $PrimaryName + ' (' + $ComparisonData.Removed.Count + ')</h4>'
        $html += '<table class="collection-table removed-items"><thead><tr>'

        $firstItem = $ComparisonData.Removed[0].Item
        $columns = $firstItem.Keys | Sort-Object
        foreach ($col in $columns) {
            $html += "<th>$col</th>"
        }
        $html += '</tr></thead><tbody>'

        foreach ($item in $ComparisonData.Removed) {
            $html += '<tr>'
            foreach ($col in $columns) {
                $value = if ($item.Item[$col]) {
                    if ($item.Item[$col] -is [array]) { ($item.Item[$col] -join ', ') } else { $item.Item[$col] }
                } else { '-' }
                $html += "<td>$value</td>"
            }
            $html += '</tr>'
        }

        $html += '</tbody></table>'
    }

    # Changed items
    if ($ComparisonData.Changed.Count -gt 0) {
        $html += '<h4 class="changed">Changed Items (' + $ComparisonData.Changed.Count + ')</h4>'

        foreach ($item in $ComparisonData.Changed) {
            $html += '<details class="changed-item"><summary>' + $item.KeyValue + ' (' + $item.Differences.Count + ' differences)</summary>'
            $html += '<table class="diff-table"><thead><tr><th>Property</th><th>' + $PrimaryName + '</th><th>' + $CompareName + '</th></tr></thead><tbody>'

            foreach ($diff in $item.Differences) {
                $primaryValue = if ($diff.PrimaryValue) {
                    if ($diff.PrimaryValue -is [array]) { ($diff.PrimaryValue -join ', ') } else { $diff.PrimaryValue }
                } else { '-' }
                $compareValue = if ($diff.CompareValue) {
                    if ($diff.CompareValue -is [array]) { ($diff.CompareValue -join ', ') } else { $diff.CompareValue }
                } else { '-' }

                $html += "<tr><td>$($diff.Property)</td><td>$primaryValue</td><td>$compareValue</td></tr>"
            }

            $html += '</tbody></table></details>'
        }
    }

    # Unchanged summary
    if ($ComparisonData.Unchanged.Count -gt 0) {
        $html += '<p class="unchanged-summary">Unchanged items: ' + $ComparisonData.Unchanged.Count + '</p>'
    }

    return $html
}

function Build-ErrorsSection {
    <#
    .SYNOPSIS
        Builds errors and warnings section
    #>
    [CmdletBinding()]
    param(
        [hashtable]$PrimaryResults,
        [hashtable]$CompareResults
    )

    $allErrors = @()

    foreach ($moduleName in $PrimaryResults.Keys) {
        $moduleErrors = $PrimaryResults[$moduleName].Errors
        if ($moduleErrors -and $moduleErrors.Count -gt 0) {
            foreach ($err in $moduleErrors) {
                $allErrors += @{
                    Domain = 'Primary'
                    Module = $moduleName
                    Error = $err
                }
            }
        }
    }

    if ($CompareResults) {
        foreach ($moduleName in $CompareResults.Keys) {
            $moduleErrors = $CompareResults[$moduleName].Errors
            if ($moduleErrors -and $moduleErrors.Count -gt 0) {
                foreach ($err in $moduleErrors) {
                    $allErrors += @{
                        Domain = 'Compare'
                        Module = $moduleName
                        Error = $err
                    }
                }
            }
        }
    }

    if ($allErrors.Count -eq 0) {
        return '<div class="errors-section"><h2>Errors & Warnings</h2><p class="no-errors">No errors or warnings reported.</p></div>'
    }

    $html = '<div class="errors-section"><h2>Errors & Warnings</h2><table class="errors-table">'
    $html += '<thead><tr><th>Domain</th><th>Module</th><th>Message</th></tr></thead><tbody>'

    foreach ($err in $allErrors) {
        $html += '<tr><td>' + $err.Domain + '</td><td>' + $err.Module + '</td><td>' + $err.Error + '</td></tr>'
    }

    $html += '</tbody></table></div>'
    return $html
}

function Get-DomainStats {
    <#
    .SYNOPSIS
        Extracts summary statistics from discovery results
    #>
    [CmdletBinding()]
    param([hashtable]$Results)

    $stats = @{
        OUCount = 0
        GroupCount = 0
        DCCount = 0
        SiteCount = 0
        ZoneCount = 0
    }

    if ($Results.ContainsKey('OUStructure') -and $Results.OUStructure.Data) {
        $stats.OUCount = if ($Results.OUStructure.Data.TotalOUs) { $Results.OUStructure.Data.TotalOUs } else { 0 }
    }

    if ($Results.ContainsKey('Groups') -and $Results.Groups.Data) {
        $stats.GroupCount = if ($Results.Groups.Data.TotalGroups) { $Results.Groups.Data.TotalGroups } else { 0 }
    }

    if ($Results.ContainsKey('DomainControllers') -and $Results.DomainControllers.Data) {
        $stats.DCCount = if ($Results.DomainControllers.Data.TotalDCs) { $Results.DomainControllers.Data.TotalDCs } else { 0 }
    }

    if ($Results.ContainsKey('SitesSubnets') -and $Results.SitesSubnets.Data) {
        $stats.SiteCount = if ($Results.SitesSubnets.Data.TotalSites) { $Results.SitesSubnets.Data.TotalSites } else { 0 }
    }

    if ($Results.ContainsKey('DNS') -and $Results.DNS.Data) {
        $stats.ZoneCount = if ($Results.DNS.Data.TotalZones) { $Results.DNS.Data.TotalZones } else { 0 }
    }

    return $stats
}

function Get-InlineHTMLTemplate {
    <#
    .SYNOPSIS
        Returns inline HTML template when external template not available
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    return @'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{TITLE}}</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, 'Segoe UI', system-ui, sans-serif;
            background: #1a1a2e;
            color: #e0e0e0;
            padding: 20px;
            line-height: 1.6;
        }
        .container { max-width: 1400px; margin: 0 auto; }
        header {
            background: linear-gradient(135deg, #2c3e50 0%, #3498db 100%);
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.3);
        }
        header h1 { font-size: 2.5em; margin-bottom: 10px; }
        header .meta { opacity: 0.9; font-size: 0.95em; }
        .executive-summary {
            background: #16213e;
            padding: 25px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.3);
        }
        .executive-summary h2 {
            color: #3498db;
            margin-bottom: 20px;
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
        }
        .summary-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
        }
        .summary-card {
            background: #0f1620;
            padding: 20px;
            border-radius: 8px;
            border: 1px solid #2c3e50;
        }
        .summary-card h3 {
            color: #3498db;
            margin-bottom: 15px;
            font-size: 1.3em;
        }
        .stat-row {
            display: flex;
            justify-content: space-between;
            padding: 8px 0;
            border-bottom: 1px solid #2c3e50;
        }
        .stat-row:last-child { border-bottom: none; }
        .stat-label { font-weight: 500; }
        .stat-value { font-weight: bold; color: #3498db; }
        .module-section {
            background: #16213e;
            margin-bottom: 20px;
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 4px 6px rgba(0,0,0,0.3);
        }
        .module-section summary {
            background: #0f1620;
            padding: 20px;
            cursor: pointer;
            list-style: none;
            border-bottom: 2px solid #3498db;
        }
        .module-section summary::-webkit-details-marker { display: none; }
        .module-section summary h2 {
            color: #3498db;
            display: inline-block;
        }
        .module-section summary:hover { background: #1a2332; }
        .module-content { padding: 25px; }
        .module-content h3 {
            color: #52b788;
            margin: 25px 0 15px 0;
            font-size: 1.3em;
        }
        .module-content h4 {
            margin: 20px 0 10px 0;
            font-size: 1.1em;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
            background: #0f1620;
            border-radius: 8px;
            overflow: hidden;
        }
        thead th {
            background: #2c3e50;
            color: #fff;
            padding: 12px;
            text-align: left;
            font-weight: 600;
        }
        tbody tr { border-bottom: 1px solid #2c3e50; }
        tbody tr:last-child { border-bottom: none; }
        tbody tr:hover { background: #1a2332; }
        tbody td { padding: 12px; }
        .added { color: #52b788; }
        .removed { color: #e63946; }
        .changed { color: #ffd60a; }
        .unchanged { color: #94a3b8; }
        .added-items { border-left: 4px solid #52b788; }
        .removed-items { border-left: 4px solid #e63946; }
        .changed-item {
            background: #0f1620;
            padding: 15px;
            margin: 10px 0;
            border-radius: 6px;
            border-left: 4px solid #ffd60a;
        }
        .changed-item summary {
            cursor: pointer;
            font-weight: 600;
            color: #ffd60a;
        }
        .diff-table { margin-top: 15px; }
        .no-data, .no-errors, .unchanged-summary {
            padding: 15px;
            color: #94a3b8;
            font-style: italic;
        }
        .errors-section {
            background: #16213e;
            padding: 25px;
            border-radius: 10px;
            margin-top: 30px;
            border-left: 4px solid #e63946;
        }
        .errors-section h2 {
            color: #e63946;
            margin-bottom: 20px;
        }
        .errors-table td { color: #e0e0e0; }
        footer {
            text-align: center;
            padding: 30px 0;
            color: #94a3b8;
            font-size: 0.9em;
        }
        @media print {
            body { background: #fff; color: #000; }
            .module-section { page-break-inside: avoid; }
            details { display: block; }
            summary { display: none; }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>{{TITLE}}</h1>
            <div class="meta">
                <p><strong>Generated:</strong> {{TIMESTAMP}} | <strong>Tool Version:</strong> {{TOOL_VERSION}}</p>
                <p><strong>Primary Domain:</strong> {{PRIMARY_DOMAIN}}</p>
                <p><strong>Comparison Domain:</strong> {{COMPARE_DOMAIN}}</p>
            </div>
        </header>

        {{EXECUTIVE_SUMMARY}}

        {{CONTENT}}

        {{ERRORS}}

        <footer>
            <p>Active Directory Discovery & Comparison Tool | Generated on {{TIMESTAMP}}</p>
        </footer>
    </div>
</body>
</html>
'@
}
