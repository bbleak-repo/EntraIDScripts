<#
.SYNOPSIS
    Active Directory Discovery and Comparison Tool

.DESCRIPTION
    Enterprise-grade AD discovery tool for environments without RSAT or admin rights.
    Supports cross-platform testing with mock data provider.

    Features:
    - Comprehensive AD structure discovery
    - Two-domain comparison with delta reporting
    - HTML and JSON output formats
    - Mock data provider for macOS/Linux testing
    - Modular architecture for easy extension

.PARAMETER Server
    Primary domain controller FQDN or domain name

.PARAMETER CompareServer
    Second domain for comparison (optional)

.PARAMETER UseMock
    Use mock data provider for cross-platform testing

.PARAMETER Format
    Output formats: HTML, JSON (default from config)

.PARAMETER SkipModules
    Modules to skip during discovery

.PARAMETER Credential
    Credentials for primary domain

.PARAMETER CompareCredential
    Credentials for comparison domain

.PARAMETER OutputPath
    Output directory (default from config)

.EXAMPLE
    .\AD-Discovery.ps1 -UseMock -Server mock-prod.local -CompareServer mock-dev.local

.EXAMPLE
    .\AD-Discovery.ps1 -Server dc01.contoso.com -Credential $cred -Format HTML,JSON

.NOTES
    Author: AD Discovery Team
    Requires: PowerShell 5.1 or PowerShell 7+
    Compatible: Windows (native), macOS/Linux (mock mode)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$Server,

    [Parameter(Mandatory = $false)]
    [string]$CompareServer,

    [Parameter(Mandatory = $false)]
    [switch]$UseMock,

    [Parameter(Mandatory = $false)]
    [ValidateSet('HTML', 'JSON', 'CSV')]
    [string[]]$Format,

    [Parameter(Mandatory = $false)]
    [string[]]$SkipModules = @(),

    [Parameter(Mandatory = $false)]
    [PSCredential]$Credential,

    [Parameter(Mandatory = $false)]
    [PSCredential]$CompareCredential,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath
)

# Script configuration
$ErrorActionPreference = 'Stop'
$scriptRoot = $PSScriptRoot
$configPath = Join-Path $scriptRoot 'Config\discovery-config.json'

# Load configuration
Write-Host "Loading configuration..." -ForegroundColor Cyan
if (-not (Test-Path $configPath)) {
    Write-Error "Configuration file not found: $configPath"
    exit 1
}

try {
    $configJson = Get-Content $configPath -Raw
    $config = $configJson | ConvertFrom-Json

    # Convert to hashtable for easier manipulation
    $configHash = @{}
    $config.PSObject.Properties | ForEach-Object {
        $configHash[$_.Name] = $_.Value
    }
} catch {
    Write-Error "Failed to load configuration: $_"
    exit 1
}

# Apply parameter overrides
if ($Format) {
    $configHash.DefaultOutputFormats = $Format
}
if ($SkipModules) {
    $configHash.SkipModules = $SkipModules
}
if ($OutputPath) {
    $configHash.OutputDirectory = $OutputPath
}

# Create output directory
$outputDir = Join-Path $scriptRoot $configHash.OutputDirectory
if (-not (Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
}

# Dot-source all modules
Write-Host "Loading modules..." -ForegroundColor Cyan
$moduleFiles = @(
    'Helpers.ps1',
    'MockProvider.ps1',
    'ForestDomain.ps1',
    'Schema.ps1',
    'OUStructure.ps1',
    'SitesSubnets.ps1',
    'Trusts.ps1',
    'DomainControllers.ps1',
    'Groups.ps1',
    'DNS.ps1',
    'ComparisonEngine.ps1',
    'ReportGenerator.ps1'
)

foreach ($moduleFile in $moduleFiles) {
    $modulePath = Join-Path $scriptRoot "Modules\$moduleFile"
    if (Test-Path $modulePath) {
        . $modulePath
        Write-Host "  Loaded: $moduleFile" -ForegroundColor Gray
    } else {
        Write-Warning "Module not found: $modulePath"
    }
}

# Platform detection
Write-Host "`nDetecting platform..." -ForegroundColor Cyan
$isWindowsPlatform = Test-IsWindowsPlatform
Write-Host "  Platform: $(if ($isWindowsPlatform) { 'Windows' } else { 'Non-Windows' })" -ForegroundColor Gray
Write-Host "  PowerShell: $($PSVersionTable.PSEdition) $($PSVersionTable.PSVersion)" -ForegroundColor Gray

# Validate platform and mode
if (-not $isWindowsPlatform -and -not $UseMock) {
    Write-Error @"
Non-Windows platform detected without -UseMock flag.

This tool requires Windows for live AD queries. On macOS/Linux, use:
    .\AD-Discovery.ps1 -UseMock -Server mock-prod.local -CompareServer mock-dev.local

Available mock domains:
    - mock-prod.local (Win2022, 3 DCs, complex structure)
    - mock-dev.local (Win2019, 2 DCs, simplified structure)
"@
    exit 1
}

# Validate server parameter
if (-not $Server -and -not $UseMock) {
    Write-Error "The -Server parameter is required unless -UseMock is specified"
    exit 1
}

if ($UseMock -and -not $Server) {
    $Server = 'mock-prod.local'
    Write-Host "  Using default mock domain: $Server" -ForegroundColor Yellow
}

# Define discovery modules
$discoveryModules = @(
    @{ Name = 'ForestDomain'; Function = 'Get-ForestDomainInfo'; MockFunction = 'Get-MockForestDomainInfo' }
    @{ Name = 'Schema'; Function = 'Get-SchemaInfo'; MockFunction = 'Get-MockSchemaInfo' }
    @{ Name = 'OUStructure'; Function = 'Get-OUStructure'; MockFunction = 'Get-MockOUStructure' }
    @{ Name = 'SitesSubnets'; Function = 'Get-SitesSubnetsInfo'; MockFunction = 'Get-MockSitesSubnetsInfo' }
    @{ Name = 'Trusts'; Function = 'Get-TrustsInfo'; MockFunction = 'Get-MockTrustsInfo' }
    @{ Name = 'DomainControllers'; Function = 'Get-DomainControllersInfo'; MockFunction = 'Get-MockDomainControllersInfo' }
    @{ Name = 'Groups'; Function = 'Get-GroupsInfo'; MockFunction = 'Get-MockGroupsInfo' }
    @{ Name = 'DNS'; Function = 'Get-DNSInfo'; MockFunction = 'Get-MockDNSInfo' }
)

# Filter out skipped modules
$activeModules = $discoveryModules | Where-Object { $_.Name -notin $configHash.SkipModules }

# Discovery function
function Invoke-Discovery {
    param(
        [string]$DomainServer,
        [PSCredential]$DomainCredential,
        [string]$Label
    )

    Write-Host "`n$('=' * 70)" -ForegroundColor Cyan
    Write-Host "Starting discovery: $Label" -ForegroundColor Cyan
    Write-Host "$('=' * 70)" -ForegroundColor Cyan

    $results = @{}
    $totalSteps = $activeModules.Count
    $currentStep = 0

    foreach ($module in $activeModules) {
        $currentStep++
        Write-ProgressStep -StepNumber $currentStep -TotalSteps $totalSteps -Message "Running $($module.Name) module"

        try {
            if ($UseMock) {
                # Use mock function
                $functionName = $module.MockFunction
                if (Get-Command $functionName -ErrorAction SilentlyContinue) {
                    $result = & $functionName -DomainName $DomainServer
                } else {
                    Write-Warning "Mock function not found: $functionName"
                    $result = @{ Data = $null; Errors = @("Mock function not implemented") }
                }
            } else {
                # Use real function
                $functionName = $module.Function
                if (Get-Command $functionName -ErrorAction SilentlyContinue) {
                    $params = @{
                        Server = $DomainServer
                        Config = $configHash
                    }
                    if ($DomainCredential) {
                        $params.Credential = $DomainCredential
                    }
                    $result = & $functionName @params
                } else {
                    Write-Warning "Function not found: $functionName"
                    $result = @{ Data = $null; Errors = @("Function not implemented") }
                }
            }

            $results[$module.Name] = $result

            # Display errors if any
            if ($result.Errors -and $result.Errors.Count -gt 0) {
                foreach ($err in $result.Errors) {
                    Write-Host "    $err" -ForegroundColor Yellow
                }
            } else {
                Write-Host "    Success" -ForegroundColor Green
            }

        } catch {
            Write-Host "    Failed: $_" -ForegroundColor Red
            $results[$module.Name] = @{
                Data = $null
                Errors = @("Module execution failed: $_")
            }
        }
    }

    return $results
}

# Run primary discovery
$primaryResults = Invoke-Discovery -DomainServer $Server -DomainCredential $Credential -Label $Server

# Run comparison discovery if requested
$compareResults = $null
if ($CompareServer) {
    $compareResults = Invoke-Discovery -DomainServer $CompareServer -DomainCredential $CompareCredential -Label $CompareServer
}

# Run comparison if two domains
$comparisonData = $null
if ($compareResults) {
    Write-Host "`n$('=' * 70)" -ForegroundColor Cyan
    Write-Host "Running comparison engine..." -ForegroundColor Cyan
    Write-Host "$('=' * 70)" -ForegroundColor Cyan

    try {
        $comparisonData = Compare-ADDomains -PrimaryResults $primaryResults `
            -CompareResults $compareResults `
            -PrimaryName $Server `
            -CompareName $CompareServer

        Write-Host "  Total differences: $($comparisonData.Summary.TotalDifferences)" -ForegroundColor White
        Write-Host "  Added: $($comparisonData.Summary.AddedCount)" -ForegroundColor Green
        Write-Host "  Removed: $($comparisonData.Summary.RemovedCount)" -ForegroundColor Red
        Write-Host "  Changed: $($comparisonData.Summary.ChangedCount)" -ForegroundColor Yellow
    } catch {
        Write-Host "  Comparison failed: $_" -ForegroundColor Red
    }
}

# Generate reports
Write-Host "`n$('=' * 70)" -ForegroundColor Cyan
Write-Host "Generating reports..." -ForegroundColor Cyan
Write-Host "$('=' * 70)" -ForegroundColor Cyan

$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$generatedFiles = @()

# HTML output
if ('HTML' -in $configHash.DefaultOutputFormats) {
    $htmlOutputPath = Join-Path $outputDir "discovery-$timestamp.html"
    $templatePath = Join-Path $scriptRoot 'Templates' 'report-template.html'

    try {
        $htmlFile = Export-HTMLReport -PrimaryResults $primaryResults `
            -CompareResults $compareResults `
            -ComparisonData $comparisonData `
            -PrimaryName $Server `
            -CompareName $CompareServer `
            -OutputPath $htmlOutputPath `
            -TemplatePath $templatePath

        $generatedFiles += $htmlFile
        Write-Host "  Generated: $htmlFile" -ForegroundColor Green
    } catch {
        Write-Host "  HTML report failed: $_" -ForegroundColor Red
    }
}

# JSON output
if ('JSON' -in $configHash.DefaultOutputFormats) {
    $jsonOutputPath = Join-Path $outputDir "discovery-$timestamp.json"

    try {
        $jsonFile = Export-JSONReport -PrimaryResults $primaryResults `
            -CompareResults $compareResults `
            -ComparisonData $comparisonData `
            -PrimaryName $Server `
            -CompareName $CompareServer `
            -OutputPath $jsonOutputPath

        $generatedFiles += $jsonFile
        Write-Host "  Generated: $jsonFile" -ForegroundColor Green
    } catch {
        Write-Host "  JSON report failed: $_" -ForegroundColor Red
    }
}

# CSV output
if ('CSV' -in $configHash.DefaultOutputFormats) {
    try {
        $csvFiles = Export-CSVReports -Results $primaryResults `
            -DomainName $Server `
            -OutputPath $outputDir

        $generatedFiles += $csvFiles
        Write-Host "  Generated: $($csvFiles.Count) CSV files" -ForegroundColor Green
    } catch {
        Write-Host "  CSV export failed: $_" -ForegroundColor Red
    }
}

# Summary
Write-Host "`n$('=' * 70)" -ForegroundColor Cyan
Write-Host "Discovery Complete" -ForegroundColor Cyan
Write-Host "$('=' * 70)" -ForegroundColor Cyan
Write-Host "  Primary domain: $Server" -ForegroundColor White
if ($CompareServer) {
    Write-Host "  Comparison domain: $CompareServer" -ForegroundColor White
}
Write-Host "  Modules executed: $($activeModules.Count)" -ForegroundColor White
Write-Host "  Output files: $($generatedFiles.Count)" -ForegroundColor White
Write-Host ""
foreach ($file in $generatedFiles) {
    Write-Host "    $file" -ForegroundColor Gray
}
Write-Host ""

# Return results object for pipeline usage
return @{
    PrimaryDomain = $Server
    PrimaryResults = $primaryResults
    CompareDomain = $CompareServer
    CompareResults = $compareResults
    OutputFiles = $generatedFiles
    Timestamp = $timestamp
}
