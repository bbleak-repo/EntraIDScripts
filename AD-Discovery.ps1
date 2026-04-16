<#
.SYNOPSIS
    Active Directory Discovery and Comparison Tool

.DESCRIPTION
    Enterprise-grade AD discovery tool for environments without RSAT or admin rights.
    Runs on the modern System.DirectoryServices.Protocols.LdapConnection stack
    (via ADLdap.ps1), so it works against DCs enforcing LDAP Channel Binding
    and LDAP Signing -- the hardened modern default.

    Discovery modules: ForestDomain, Schema, OUStructure, SitesSubnets, Trusts,
    DomainControllers, Groups, DNS. A connection pool is installed at startup
    so every module reuses the same LdapConnection per server.

    Features:
    - Comprehensive AD structure discovery
    - Two-domain comparison with delta reporting
    - HTML, JSON, and CSV output formats
    - Mock data provider for macOS/Linux testing (-UseMock)
    - Tiered connection strategy (-AllowInsecure for fallback tiers)
    - Modular architecture for easy extension

.PARAMETER Server
    Primary domain controller FQDN or domain name. Required unless -UseMock.

.PARAMETER CompareServer
    Second domain for comparison (optional).

.PARAMETER UseMock
    Use mock data provider for cross-platform testing. Skips all LDAP work.

.PARAMETER Format
    Output formats: HTML, JSON, CSV (default from config).

.PARAMETER SkipModules
    Discovery modules to skip by name.

.PARAMETER Credential
    Credentials for primary domain. Defaults to current Windows identity (Kerberos).

.PARAMETER CompareCredential
    Credentials for the comparison domain.

.PARAMETER OutputPath
    Output directory override (default from config).

.PARAMETER AllowInsecure
    Enable fallback tiers when verified LDAPS fails. Tier order:
      Tier 1: LDAPS 636, cert verified           (always attempted)
      Tier 2: LDAPS 636, cert bypass             (this switch)
      Tier 3: LDAP  389, SASL sign+seal          (this switch)
    Required when the workstation cannot validate the DC's TLS certificate
    (cross-forest, lab environments, or rotated certs).

.PARAMETER Help
    Show a usage summary with examples and exit. Also shown when the script
    is invoked with no arguments.

.EXAMPLE
    .\AD-Discovery.ps1 -Server delusionalsecurity.review
    Simplest live discovery against a single domain.

.EXAMPLE
    .\AD-Discovery.ps1 -Server delusionalsecurity.review -AllowInsecure
    Live discovery with fallback tiers enabled (lab/cross-forest/cert mismatch).

.EXAMPLE
    .\AD-Discovery.ps1 -Server dc01.contoso.com -CompareServer dc01.fabrikam.com -AllowInsecure
    Two-domain comparison for migration or drift analysis.

.EXAMPLE
    $cred = Get-Credential
    .\AD-Discovery.ps1 -Server delusionalsecurity.review -Credential $cred -AllowInsecure
    Pass explicit credentials instead of using Kerberos integrated auth.

.EXAMPLE
    .\AD-Discovery.ps1 -UseMock -Server mock-prod.local -CompareServer mock-dev.local
    Mock mode -- no AD access required, runs anywhere.

.NOTES
    Author: AD Discovery Team
    Requires: PowerShell 5.1 or PowerShell 7+
    Compatible: Windows (native), macOS/Linux (mock mode)

    Run with no arguments or -Help for a usage summary with examples.
    Run 'Get-Help .\AD-Discovery.ps1 -Detailed' for full parameter docs.
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
    [string]$OutputPath,

    [Parameter(Mandatory = $false)]
    [switch]$AllowInsecure,

    [Parameter(Mandatory = $false)]
    [switch]$Help
)

# Script configuration
$ErrorActionPreference = 'Stop'
$scriptRoot = $PSScriptRoot
$configPath = Join-Path $scriptRoot 'Config\discovery-config.json'

# ---------------------------------------------------------------------------
# Usage / help output when invoked with no args or -Help
# ---------------------------------------------------------------------------
function Show-Usage {
    $self = Split-Path -Leaf $PSCommandPath
    $lines = @(
        ''
        'Active Directory Discovery and Comparison Tool'
        '=============================================='
        'Discovers AD structure (forest, domain, DCs, OUs, groups, sites, trusts,'
        'schema, DNS) and produces HTML / JSON / CSV reports. Can compare two'
        'domains for migration or drift analysis. Uses the modern LdapConnection'
        'stack via ADLdap.ps1, so it works against DCs enforcing LDAP Channel'
        'Binding / Signing.'
        ''
        'USAGE'
        "  .\$self -Server <dc-or-domain> [options]"
        "  .\$self -UseMock [options]"
        "  .\$self -Help"
        ''
        'REQUIRED (one of)'
        '  -Server <name>           DC hostname or domain FQDN to discover'
        '  -UseMock                 Run against the built-in mock provider (no AD needed)'
        ''
        'COMPARISON'
        '  -CompareServer <name>    Second DC/domain to compare against'
        '  -CompareCredential <c>   Credentials for the compare target'
        ''
        'CONNECTIVITY'
        '  -Credential <pscred>     Explicit credentials (default = current user via Kerberos)'
        '  -AllowInsecure           Enable fallback tiers when Tier 1 (verified LDAPS) fails:'
        '                             Tier 2: LDAPS 636 with cert bypass'
        '                             Tier 3: LDAP  389 with Kerberos sign+seal'
        ''
        'OUTPUT'
        '  -Format HTML,JSON,CSV    Output formats (defaults from config)'
        '  -OutputPath <dir>        Override output directory'
        '  -SkipModules <names>     Skip specific discovery modules by name'
        ''
        'EXAMPLES'
        ''
        '  # Simplest live discovery against a domain'
        "  .\$self -Server delusionalsecurity.review"
        ''
        '  # Live discovery against a DC with an untrusted cert (lab / cross-forest)'
        "  .\$self -Server delusionalsecurity.review -AllowInsecure"
        ''
        '  # Two-domain comparison for migration / drift'
        "  .\$self -Server dc01.contoso.com -CompareServer dc01.fabrikam.com -AllowInsecure"
        ''
        '  # With explicit credentials'
        '  $cred = Get-Credential'
        "  .\$self -Server delusionalsecurity.review -Credential `$cred -AllowInsecure"
        ''
        '  # Specific output formats'
        "  .\$self -Server delusionalsecurity.review -Format HTML,JSON -AllowInsecure"
        ''
        '  # Mock mode for testing on macOS / Linux or without AD access'
        "  .\$self -UseMock -Server mock-prod.local -CompareServer mock-dev.local"
        ''
        '  # Skip slower / unwanted modules'
        "  .\$self -Server delusionalsecurity.review -SkipModules Schema,DNS -AllowInsecure"
        ''
        'MORE'
        "  Full parameter docs:  Get-Help .\$self -Detailed"
        '  Discovery modules:    ForestDomain, Schema, OUStructure, SitesSubnets,'
        '                        Trusts, DomainControllers, Groups, DNS'
        ''
    )
    $lines | ForEach-Object { Write-Host $_ }
}

if ($Help -or (-not $Server -and -not $UseMock)) {
    Show-Usage
    if (-not $Help -and -not $Server -and -not $UseMock) {
        Write-Host 'ERROR: -Server or -UseMock is required.' -ForegroundColor Red
        exit 2
    }
    exit 0
}

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
    'ADLdap.ps1',
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

# Surface -AllowInsecure into the config hash so downstream LDAP calls
# (Invoke-LdapQuery, New-AdLdapConnection) see it via $Searcher.Config.
if ($AllowInsecure) {
    $configHash.AllowInsecure = $true
}

# Per-run LDAP connection pool. Lives in script scope so the ADLdap shim
# in Helpers.ps1 can pick it up transparently. Only installed for live-AD
# runs; mock mode skips LDAP entirely.
$script:AdLdapPool = $null
if (-not $UseMock) {
    $poolParams = @{
        AllowInsecure  = [bool]$AllowInsecure
        TimeoutSeconds = if ($configHash.LdapTimeout) { [int]$configHash.LdapTimeout } else { 120 }
    }
    if ($Credential) { $poolParams.Credential = $Credential }
    $script:AdLdapPool = New-AdLdapConnectionPool @poolParams
    Write-Host "  LDAP connection pool installed (AllowInsecure=$AllowInsecure)" -ForegroundColor Gray
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

# Run primary discovery (wrapped so the pool is disposed on any exit path)
try {
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
    # PS 5.1's Join-Path only accepts 2 path components; chain for compat.
    $templatePath = Join-Path (Join-Path $scriptRoot 'Templates') 'report-template.html'

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

} finally {
    if ($script:AdLdapPool) {
        try { Close-AdLdapConnectionPool $script:AdLdapPool } catch { }
        $script:AdLdapPool = $null
    }
}
