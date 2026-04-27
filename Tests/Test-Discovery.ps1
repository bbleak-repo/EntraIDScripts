<#
.SYNOPSIS
    Comprehensive test harness for AD Discovery toolkit

.DESCRIPTION
    Tests all modules, comparison engine, and report generation using mock data.
    Works on macOS/Linux without Active Directory dependencies.

.NOTES
    Simple test framework with no external dependencies
    Tests run against mock-prod.local and mock-dev.local
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [switch]$VerboseLogging
)

$ErrorActionPreference = 'Stop'
$scriptRoot = Split-Path -Parent $PSScriptRoot

$script:TestsPassed = 0
$script:TestsFailed = 0
$script:TestErrors = @()
$script:TestStartTime = Get-Date

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "AD Discovery Toolkit - Test Suite" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

function Assert-True {
    param(
        [Parameter(Mandatory = $true)]
        [bool]$Condition,

        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    if ($Condition) {
        $script:TestsPassed++
        Write-Host "  [PASS] $Message" -ForegroundColor Green
        return $true
    } else {
        $script:TestsFailed++
        $script:TestErrors += $Message
        Write-Host "  [FAIL] $Message" -ForegroundColor Red
        return $false
    }
}

function Assert-Equal {
    param(
        [Parameter(Mandatory = $true)]
        $Expected,

        [Parameter(Mandatory = $true)]
        $Actual,

        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    if ($Expected -eq $Actual) {
        $script:TestsPassed++
        Write-Host "  [PASS] $Message" -ForegroundColor Green
        return $true
    } else {
        $script:TestsFailed++
        $errorMsg = "$Message (Expected: $Expected, Actual: $Actual)"
        $script:TestErrors += $errorMsg
        Write-Host "  [FAIL] $errorMsg" -ForegroundColor Red
        return $false
    }
}

function Assert-NotNull {
    param(
        [Parameter(Mandatory = $false)]
        $Value,

        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    if ($null -ne $Value) {
        $script:TestsPassed++
        Write-Host "  [PASS] $Message" -ForegroundColor Green
        return $true
    } else {
        $script:TestsFailed++
        $script:TestErrors += $Message
        Write-Host "  [FAIL] $Message (Value was null)" -ForegroundColor Red
        return $false
    }
}

function Assert-GreaterThan {
    param(
        [Parameter(Mandatory = $true)]
        $Value,

        [Parameter(Mandatory = $true)]
        $Threshold,

        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    if ($Value -gt $Threshold) {
        $script:TestsPassed++
        Write-Host "  [PASS] $Message" -ForegroundColor Green
        return $true
    } else {
        $script:TestsFailed++
        $errorMsg = "$Message (Value: $Value, Threshold: $Threshold)"
        $script:TestErrors += $errorMsg
        Write-Host "  [FAIL] $errorMsg" -ForegroundColor Red
        return $false
    }
}

function Assert-Contains {
    param(
        [Parameter(Mandatory = $true)]
        [array]$Collection,

        [Parameter(Mandatory = $true)]
        $Item,

        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    if ($Collection -contains $Item) {
        $script:TestsPassed++
        Write-Host "  [PASS] $Message" -ForegroundColor Green
        return $true
    } else {
        $script:TestsFailed++
        $errorMsg = "$Message (Item not found: $Item)"
        $script:TestErrors += $errorMsg
        Write-Host "  [FAIL] $errorMsg" -ForegroundColor Red
        return $false
    }
}

Write-Host "Loading modules..." -ForegroundColor Yellow
Write-Host ""

try {
    . (Join-Path $scriptRoot 'Modules\Helpers.ps1')
    . (Join-Path $scriptRoot 'Modules\MockProvider.ps1')
    . (Join-Path $scriptRoot 'Modules\ComparisonEngine.ps1')
    . (Join-Path $scriptRoot 'Modules\ReportGenerator.ps1')
    Write-Host "  All modules loaded successfully" -ForegroundColor Green
    Write-Host ""
} catch {
    Write-Host "  Failed to load modules: $_" -ForegroundColor Red
    exit 1
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Test Category 1: Platform Detection" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$platformCheck = Test-IsWindowsPlatform
Assert-NotNull -Value $platformCheck -Message "Test-IsWindowsPlatform returns a value"

if ($PSVersionTable.PSEdition -eq 'Desktop') {
    Assert-True -Condition $platformCheck -Message "Desktop edition correctly detected as Windows"
} elseif ($PSVersionTable.OS -like '*Darwin*' -or $PSVersionTable.OS -like '*Linux*') {
    Assert-True -Condition (-not $platformCheck) -Message "Unix platform correctly detected as non-Windows"
}

Write-Host ""

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Test Category 2: Mock Data Structure" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$mockFunctions = @(
    'Get-MockForestDomainInfo',
    'Get-MockSchemaInfo',
    'Get-MockOUStructure',
    'Get-MockSitesSubnetsInfo',
    'Get-MockTrustsInfo',
    'Get-MockDomainControllersInfo',
    'Get-MockGroupsInfo',
    'Get-MockDNSInfo'
)

foreach ($funcName in $mockFunctions) {
    $result = & $funcName -DomainName 'mock-prod.local'

    Assert-NotNull -Value $result -Message "$funcName returns a result"
    Assert-True -Condition ($result -is [hashtable]) -Message "$funcName returns hashtable"
    Assert-True -Condition ($result.ContainsKey('Data')) -Message "$funcName has Data key"
    Assert-True -Condition ($result.ContainsKey('Errors')) -Message "$funcName has Errors key"
    Assert-True -Condition ($result.Errors -is [array]) -Message "$funcName Errors is array"
}

Write-Host ""

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Test Category 3: Mock Data Content" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$forestResult = Get-MockForestDomainInfo -DomainName 'mock-prod.local'
Assert-NotNull -Value $forestResult.Data.ForestName -Message "ForestDomain mock has ForestName"
Assert-Equal -Expected 'mock-prod.local' -Actual $forestResult.Data.ForestName -Message "ForestName is correct"
Assert-NotNull -Value $forestResult.Data.ForestFunctionalLevel -Message "ForestDomain mock has ForestFunctionalLevel"

$schemaResult = Get-MockSchemaInfo -DomainName 'mock-prod.local'
Assert-NotNull -Value $schemaResult.Data.SchemaVersion -Message "Schema mock has SchemaVersion"
Assert-Equal -Expected 88 -Actual $schemaResult.Data.SchemaVersion -Message "Schema version is correct for mock-prod"
Assert-NotNull -Value $schemaResult.Data.CustomAttributes -Message "Schema mock has CustomAttributes"
Assert-True -Condition ($schemaResult.Data.CustomAttributes.Count -gt 0) -Message "CustomAttributes has items"

$ouResult = Get-MockOUStructure -DomainName 'mock-prod.local'
Assert-NotNull -Value $ouResult.Data.TotalOUs -Message "OUStructure mock has TotalOUs"
Assert-Equal -Expected 15 -Actual $ouResult.Data.TotalOUs -Message "TotalOUs is correct for mock-prod"
Assert-NotNull -Value $ouResult.Data.OUs -Message "OUStructure mock has OUs array"
Assert-True -Condition ($ouResult.Data.OUs.Count -eq 15) -Message "OUs array has correct count"

$sitesResult = Get-MockSitesSubnetsInfo -DomainName 'mock-prod.local'
Assert-NotNull -Value $sitesResult.Data.Sites -Message "SitesSubnets mock has Sites"
Assert-Equal -Expected 2 -Actual $sitesResult.Data.TotalSites -Message "TotalSites is correct"

$trustsResult = Get-MockTrustsInfo -DomainName 'mock-prod.local'
Assert-NotNull -Value $trustsResult.Data.Trusts -Message "Trusts mock has Trusts array"
Assert-Equal -Expected 3 -Actual $trustsResult.Data.TotalTrusts -Message "TotalTrusts is correct"

$dcsResult = Get-MockDomainControllersInfo -DomainName 'mock-prod.local'
Assert-NotNull -Value $dcsResult.Data.DomainControllers -Message "DCs mock has DomainControllers"
Assert-Equal -Expected 3 -Actual $dcsResult.Data.TotalDCs -Message "TotalDCs is correct"

$groupsResult = Get-MockGroupsInfo -DomainName 'mock-prod.local'
Assert-NotNull -Value $groupsResult.Data.Groups -Message "Groups mock has Groups array"
Assert-GreaterThan -Value $groupsResult.Data.TotalGroups -Threshold 0 -Message "TotalGroups is greater than 0"

$dnsResult = Get-MockDNSInfo -DomainName 'mock-prod.local'
Assert-NotNull -Value $dnsResult.Data.Zones -Message "DNS mock has Zones array"
Assert-Equal -Expected 4 -Actual $dnsResult.Data.TotalZones -Message "TotalZones is correct"

Write-Host ""

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Test Category 4: Mock Domain Differences" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$prodForest = Get-MockForestDomainInfo -DomainName 'mock-prod.local'
$devForest = Get-MockForestDomainInfo -DomainName 'mock-dev.local'
Assert-True -Condition ($prodForest.Data.ForestFunctionalLevel -ne $devForest.Data.ForestFunctionalLevel) -Message "Forest functional levels differ between mock domains"

$prodSchema = Get-MockSchemaInfo -DomainName 'mock-prod.local'
$devSchema = Get-MockSchemaInfo -DomainName 'mock-dev.local'
Assert-True -Condition ($prodSchema.Data.SchemaVersion -ne $devSchema.Data.SchemaVersion) -Message "Schema versions differ (88 vs 87)"
Assert-True -Condition ($prodSchema.Data.CustomAttributes.Count -ne $devSchema.Data.CustomAttributes.Count) -Message "CustomAttributes count differs"

$prodOUs = Get-MockOUStructure -DomainName 'mock-prod.local'
$devOUs = Get-MockOUStructure -DomainName 'mock-dev.local'
Assert-True -Condition ($prodOUs.Data.TotalOUs -ne $devOUs.Data.TotalOUs) -Message "OU counts differ (15 vs 12)"

$prodDCs = Get-MockDomainControllersInfo -DomainName 'mock-prod.local'
$devDCs = Get-MockDomainControllersInfo -DomainName 'mock-dev.local'
Assert-True -Condition ($prodDCs.Data.TotalDCs -ne $devDCs.Data.TotalDCs) -Message "DC counts differ (3 vs 2)"

Write-Host ""

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Test Category 5: Comparison Engine" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$primaryResults = @{
    ForestDomain = Get-MockForestDomainInfo -DomainName 'mock-prod.local'
    Schema = Get-MockSchemaInfo -DomainName 'mock-prod.local'
    OUStructure = Get-MockOUStructure -DomainName 'mock-prod.local'
    SitesSubnets = Get-MockSitesSubnetsInfo -DomainName 'mock-prod.local'
    Trusts = Get-MockTrustsInfo -DomainName 'mock-prod.local'
    DomainControllers = Get-MockDomainControllersInfo -DomainName 'mock-prod.local'
    Groups = Get-MockGroupsInfo -DomainName 'mock-prod.local'
    DNS = Get-MockDNSInfo -DomainName 'mock-prod.local'
}

$compareResults = @{
    ForestDomain = Get-MockForestDomainInfo -DomainName 'mock-dev.local'
    Schema = Get-MockSchemaInfo -DomainName 'mock-dev.local'
    OUStructure = Get-MockOUStructure -DomainName 'mock-dev.local'
    SitesSubnets = Get-MockSitesSubnetsInfo -DomainName 'mock-dev.local'
    Trusts = Get-MockTrustsInfo -DomainName 'mock-dev.local'
    DomainControllers = Get-MockDomainControllersInfo -DomainName 'mock-dev.local'
    Groups = Get-MockGroupsInfo -DomainName 'mock-dev.local'
    DNS = Get-MockDNSInfo -DomainName 'mock-dev.local'
}

$comparisonResult = Compare-ADDomains -PrimaryResults $primaryResults `
    -CompareResults $compareResults `
    -PrimaryName 'mock-prod.local' `
    -CompareName 'mock-dev.local'

Assert-NotNull -Value $comparisonResult -Message "Compare-ADDomains returns result"
Assert-True -Condition ($comparisonResult -is [hashtable]) -Message "Comparison result is hashtable"
Assert-True -Condition ($comparisonResult.ContainsKey('Summary')) -Message "Comparison has Summary"
Assert-True -Condition ($comparisonResult.ContainsKey('ModuleComparisons')) -Message "Comparison has ModuleComparisons"
Assert-True -Condition ($comparisonResult.ContainsKey('Errors')) -Message "Comparison has Errors"

$summary = $comparisonResult.Summary
Assert-NotNull -Value $summary.TotalDifferences -Message "Summary has TotalDifferences"
Assert-NotNull -Value $summary.AddedCount -Message "Summary has AddedCount"
Assert-NotNull -Value $summary.RemovedCount -Message "Summary has RemovedCount"
Assert-NotNull -Value $summary.ChangedCount -Message "Summary has ChangedCount"
Assert-Equal -Expected 8 -Actual $summary.ModulesCompared -Message "8 modules compared"

Assert-GreaterThan -Value $summary.TotalDifferences -Threshold 0 -Message "Differences detected between mock domains"

$ouComparison = $comparisonResult.ModuleComparisons.OUStructure
Assert-NotNull -Value $ouComparison -Message "OUStructure comparison exists"
Assert-True -Condition ($ouComparison.ContainsKey('CollectionDifferences')) -Message "OUStructure has CollectionDifferences"

$ouDiff = $ouComparison.CollectionDifferences.OUs
Assert-NotNull -Value $ouDiff -Message "OUs collection differences exist"
Assert-True -Condition ($ouDiff.Removed.Count -gt 0) -Message "OUs removed detected (mock-prod has more OUs)"

$dcComparison = $comparisonResult.ModuleComparisons.DomainControllers
$dcDiff = $dcComparison.CollectionDifferences.DomainControllers
Assert-True -Condition ($dcDiff.Removed.Count -gt 0) -Message "DCs removed detected (mock-prod has 3, mock-dev has 2)"

Write-Host ""

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Test Category 6: Report Generation" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$testOutputDir = Join-Path $scriptRoot 'Tests\Output'
if (-not (Test-Path $testOutputDir)) {
    New-Item -ItemType Directory -Path $testOutputDir -Force | Out-Null
}

$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'

try {
    $htmlPath = Join-Path $testOutputDir "test-report-$timestamp.html"
    $result = Export-HTMLReport -PrimaryResults $primaryResults `
        -CompareResults $compareResults `
        -ComparisonData $comparisonResult `
        -PrimaryName 'mock-prod.local' `
        -CompareName 'mock-dev.local' `
        -OutputPath $htmlPath

    Assert-True -Condition (Test-Path $htmlPath) -Message "HTML report file created"
    $htmlContent = Get-Content $htmlPath -Raw
    Assert-True -Condition ($htmlContent.Length -gt 1000) -Message "HTML report has substantial content"
    Assert-True -Condition ($htmlContent.Contains('mock-prod.local')) -Message "HTML contains primary domain name"
    Assert-True -Condition ($htmlContent.Contains('mock-dev.local')) -Message "HTML contains comparison domain name"
    Assert-True -Condition ($htmlContent.Contains('Executive Summary')) -Message "HTML contains executive summary section"

    Write-Host "  HTML report generated at: $htmlPath" -ForegroundColor Gray
} catch {
    Assert-True -Condition $false -Message "HTML report generation failed: $_"
}

try {
    $jsonPath = Join-Path $testOutputDir "test-report-$timestamp.json"
    $result = Export-JSONReport -PrimaryResults $primaryResults `
        -CompareResults $compareResults `
        -ComparisonData $comparisonResult `
        -PrimaryName 'mock-prod.local' `
        -CompareName 'mock-dev.local' `
        -OutputPath $jsonPath

    Assert-True -Condition (Test-Path $jsonPath) -Message "JSON report file created"
    $jsonContent = Get-Content $jsonPath -Raw
    $parsedJson = $jsonContent | ConvertFrom-Json
    Assert-NotNull -Value $parsedJson -Message "JSON is valid and parseable"
    Assert-NotNull -Value $parsedJson.Metadata -Message "JSON has Metadata section"
    Assert-NotNull -Value $parsedJson.PrimaryDomain -Message "JSON has PrimaryDomain section"
    Assert-NotNull -Value $parsedJson.CompareDomain -Message "JSON has CompareDomain section"
    Assert-NotNull -Value $parsedJson.ComparisonAnalysis -Message "JSON has ComparisonAnalysis section"

    Write-Host "  JSON report generated at: $jsonPath" -ForegroundColor Gray
} catch {
    Assert-True -Condition $false -Message "JSON report generation failed: $_"
}

try {
    $csvFiles = Export-CSVReports -Results $primaryResults `
        -DomainName 'mock-prod.local' `
        -OutputPath $testOutputDir

    Assert-True -Condition ($csvFiles.Count -gt 0) -Message "CSV reports generated"
    Assert-True -Condition ($csvFiles.Count -ge 4) -Message "At least 4 CSV files created"

    foreach ($csvFile in $csvFiles) {
        Assert-True -Condition (Test-Path $csvFile) -Message "CSV file exists: $(Split-Path $csvFile -Leaf)"
    }

    Write-Host "  CSV reports generated: $($csvFiles.Count) files" -ForegroundColor Gray
} catch {
    Assert-True -Condition $false -Message "CSV report generation failed: $_"
}

Write-Host ""

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Test Category 7: Error Handling" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$invalidResult = Get-MockForestDomainInfo -DomainName 'invalid-domain.local'
Assert-NotNull -Value $invalidResult -Message "Invalid domain returns result object"
Assert-True -Condition ($invalidResult.Errors.Count -gt 0) -Message "Invalid domain returns errors"
Assert-True -Condition ($null -eq $invalidResult.Data) -Message "Invalid domain returns null data"

Write-Host ""

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Test Summary" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$testDuration = (Get-Date) - $script:TestStartTime
$totalTests = $script:TestsPassed + $script:TestsFailed

Write-Host ""
Write-Host "Total Tests: $totalTests" -ForegroundColor White
Write-Host "Passed: $script:TestsPassed" -ForegroundColor Green
Write-Host "Failed: $script:TestsFailed" -ForegroundColor $(if ($script:TestsFailed -gt 0) { 'Red' } else { 'Green' })
Write-Host "Duration: $($testDuration.TotalSeconds) seconds" -ForegroundColor White
Write-Host ""

if ($script:TestsFailed -gt 0) {
    Write-Host "Failed Tests:" -ForegroundColor Red
    foreach ($error in $script:TestErrors) {
        Write-Host "  - $error" -ForegroundColor Red
    }
    Write-Host ""
    exit 1
} else {
    Write-Host "All tests passed!" -ForegroundColor Green
    Write-Host ""
    exit 0
}
