<#
.SYNOPSIS
    Cross-domain group membership enumeration orchestrator

.DESCRIPTION
    Reads a CSV of domain/group pairs, enumerates members from each AD domain via
    System.DirectoryServices.Protocols.LdapConnection (the modern LDAP stack that
    works against DCs enforcing LDAP Channel Binding / Signing), optionally runs
    fuzzy cross-domain name matching, and produces an HTML report and/or JSON cache.

    Works equally well for single-domain inventory and multi-forest migration
    readiness. Cross-domain and cross-forest features are opt-in switches.

    Core features:
    - CSV input in Domain,GroupName or DOMAIN\GroupName backslash format
    - Per-domain connection pooling (one LdapConnection reused across all groups)
    - Tiered connection strategy with optional cert-verification bypass and
      Kerberos sign+seal fallback on 389 (-AllowInsecure)
    - Dark/light HTML reports, JSON cache for offline report regeneration
    - Structured JSON Lines logs with per-tier LdapConnect events

    V2 features (enabled by switches):
    - Nested group resolution to flat user lists (-ResolveNested)
    - Stale/disabled account detection (-DetectStale)
    - Fuzzy cross-domain group name matching via Levenshtein (-FuzzyMatch)
    - Cross-domain user correlation and gap analysis (-AnalyzeGaps)
    - Cross-forest member resolution when multiple domains are pooled:
      direct foreign DN routing and ForeignSecurityPrincipal SID lookup
    - Application-level readiness from CSV mapping (-AppMappingCsv)
    - SMTP delivery of migration readiness report (-SendEmail)

.PARAMETER CsvPath
    Full path to the CSV file containing groups to enumerate.
    Supports Domain,GroupName column format or DOMAIN\GroupName single-column format.

.PARAMETER Credential
    Optional PSCredential used for all LDAP binds.
    When omitted, the current Windows identity (Kerberos) is used.

.PARAMETER FuzzyMatch
    Enable fuzzy cross-domain group name matching using Levenshtein similarity.

.PARAMETER ConfigPath
    Path to group-enum-config.json. Defaults to .\Config\group-enum-config.json.
    If the file is missing, built-in defaults are used.

.PARAMETER OutputPath
    Output directory for generated files. Overrides config OutputDirectory setting.

.PARAMETER FromCache
    Skip LDAP enumeration and load previously saved JSON data for report regeneration.

.PARAMETER CachePath
    Path to the JSON cache file when using -FromCache.
    Also controls where the cache file is written when not using -FromCache.
    Defaults to config CachePath directory.

.PARAMETER Theme
    Initial HTML report theme: "dark" (default) or "light".
    The user can toggle in-browser after opening the report.

.PARAMETER JsonOnly
    Generate only the JSON cache file. Skip HTML report generation.

.PARAMETER NoCache
    Skip saving the JSON cache file after enumeration.

.PARAMETER ResolveNested
    Flatten nested group memberships to a single-level user list for each group.
    Requires LDAPS connectivity to resolve child groups.

.PARAMETER AnalyzeGaps
    Run migration gap analysis against matched group pairs.
    Implies user correlation. Requires -FuzzyMatch to have produced matched pairs.

.PARAMETER DetectStale
    Flag stale and disabled accounts in enumerated group membership.
    Stale threshold is controlled by -StaleDays or config StaleAccountDays (default 90).

.PARAMETER AppMappingCsv
    Optional path to a CSV mapping application names to AD group pairs.
    Columns: AppName,SourceGroup,TargetGroup,Notes

.PARAMETER SendEmail
    Send the migration readiness summary email after report generation.
    Requires Email section in config to be populated and Enabled = true.

.PARAMETER StaleDays
    Override the StaleAccountDays config value. 0 = use config value.

.EXAMPLE
    .\Invoke-GroupEnumerator.ps1 -CsvPath .\groups.csv
    Simplest single-domain inventory. Produces V1 HTML + JSON cache.

.EXAMPLE
    .\Invoke-GroupEnumerator.ps1 -CsvPath .\groups.csv -ResolveNested -DetectStale
    Single-domain inventory with nested group flattening and stale account flagging.

.EXAMPLE
    .\Invoke-GroupEnumerator.ps1 -CsvPath .\groups.csv -FuzzyMatch
    Cross-domain fuzzy match. Verified LDAPS only (Tier 1).

.EXAMPLE
    .\Invoke-GroupEnumerator.ps1 -CsvPath .\groups.csv -FuzzyMatch -AnalyzeGaps -DetectStale -ResolveNested -AllowInsecure
    Full two-forest migration readiness pipeline with all fallback tiers enabled.

.EXAMPLE
    .\Invoke-GroupEnumerator.ps1 -CsvPath .\groups.csv -FromCache -CachePath .\Cache\groups-20260415-103821.json
    Offline re-render of an HTML report from a saved JSON cache. No AD access.

.EXAMPLE
    $cred = Get-Credential
    .\Invoke-GroupEnumerator.ps1 -CsvPath .\groups.csv -FuzzyMatch -Credential $cred
    Pass explicit credentials (Kerberos integrated auth otherwise).

.NOTES
    Author: EntraID Team
    Requires: PowerShell 5.1 or PowerShell 7+

    Connection tiers (tried in order, highest security first):
      Tier 1: LDAPS 636, cert verification strict       (always attempted)
      Tier 2: LDAPS 636, cert verification bypassed     (requires -AllowInsecure)
      Tier 3: LDAP  389, SASL sign + seal (Kerberos)    (requires -AllowInsecure)
      Tier 4: LDAP  389, no signing/sealing             (not reachable via switches)

    Run with no arguments or -Help for a usage summary with examples.
    Run 'Get-Help .\Invoke-GroupEnumerator.ps1 -Detailed' for full parameter docs.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$CsvPath,

    [Parameter(Mandatory = $false)]
    [switch]$Help,

    [Parameter(Mandatory = $false)]
    [PSCredential]$Credential,

    [Parameter(Mandatory = $false)]
    [switch]$FuzzyMatch,

    [Parameter(Mandatory = $false)]
    [string]$ConfigPath,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath,

    [Parameter(Mandatory = $false)]
    [switch]$FromCache,

    [Parameter(Mandatory = $false)]
    [string]$CachePath,

    [Parameter(Mandatory = $false)]
    [ValidateSet('dark', 'light')]
    [string]$Theme = 'dark',

    [Parameter(Mandatory = $false)]
    [switch]$JsonOnly,

    [Parameter(Mandatory = $false)]
    [switch]$NoCache,

    [Parameter(Mandatory = $false)]
    [switch]$AllowInsecure,

    [Parameter(Mandatory = $false)]
    [switch]$ResolveNested,

    [Parameter(Mandatory = $false)]
    [switch]$AnalyzeGaps,

    [Parameter(Mandatory = $false)]
    [switch]$DetectStale,

    [Parameter(Mandatory = $false)]
    [string]$AppMappingCsv,

    [Parameter(Mandatory = $false)]
    [switch]$SendEmail,

    [Parameter(Mandatory = $false)]
    [int]$StaleDays = 0,

    [Parameter(Mandatory = $false)]
    [string]$MigratingTo,

    [Parameter(Mandatory = $false)]
    [string]$TargetSearchBase,

    [Parameter(Mandatory = $false)]
    [string[]]$IncludeAttributes = @(),

    [Parameter(Mandatory = $false)]
    [string]$BaselinePath,

    [Parameter(Mandatory = $false)]
    [string]$PreviousRunPath
)

$ErrorActionPreference = 'Stop'
$scriptRoot = $PSScriptRoot

# ---------------------------------------------------------------------------
# Usage / help output when invoked with no args or -Help
# ---------------------------------------------------------------------------
function Show-Usage {
    $self = Split-Path -Leaf $PSCommandPath
    $lines = @(
        ''
        'Cross-Domain Group Enumerator'
        '============================='
        'Enumerates Active Directory group membership via LdapConnection.'
        'Works for single-domain inventory and cross-forest migration readiness.'
        ''
        'USAGE'
        "  .\$self -CsvPath <file> [options]"
        "  .\$self -Help"
        ''
        'REQUIRED'
        '  -CsvPath <path>          CSV of groups to enumerate'
        '                             Format 1: headers Domain,GroupName  (e.g. CORP,Domain Admins)'
        '                             Format 2: header  Group             (e.g. CORP\Domain Admins)'
        '                             Samples:  Templates\groups-example-standard.csv'
        '                                       Templates\groups-example-backslash.csv'
        ''
        'CONNECTIVITY'
        '  -Credential <pscred>     Pass explicit creds (default = current user via Kerberos)'
        '  -AllowInsecure           Enable fallback tiers when Tier 1 (verified LDAPS) fails:'
        '                             Tier 2: LDAPS 636 with cert bypass'
        '                             Tier 3: LDAP  389 with Kerberos sign+seal'
        ''
        'ANALYSIS SWITCHES'
        '  -ResolveNested           Flatten nested group memberships (recursive)'
        '  -DetectStale             Flag disabled and inactive accounts'
        '  -FuzzyMatch              Cross-domain fuzzy group name matching (Levenshtein)'
        '  -AnalyzeGaps             Migration gap analysis + Change Requests (needs -FuzzyMatch)'
        '  -AppMappingCsv <path>    Optional app-to-group readiness mapping'
        '  -StaleDays <n>           Override stale threshold (default: config value, 90)'
        ''
        'OUTPUT / CACHE'
        '  -OutputPath <dir>        Output directory for reports (default: ./Output)'
        '  -CachePath <path>        Cache file (for -FromCache) or directory (for writes)'
        '  -FromCache               Skip LDAP; regenerate reports from a saved cache'
        '  -JsonOnly                Write JSON cache only, skip HTML report'
        '  -NoCache                 Skip writing the JSON cache'
        '  -Theme dark|light        Initial HTML theme (default: dark)'
        '  -ConfigPath <path>       Override config file location'
        '  -SendEmail               Send the migration report via SMTP (config must enable this)'
        ''
        'EXAMPLES'
        ''
        '  # Simplest single-domain inventory (V1 report)'
        "  .\$self -CsvPath .\groups.csv"
        ''
        '  # Single-domain with nested resolution + stale detection'
        "  .\$self -CsvPath .\groups.csv -ResolveNested -DetectStale"
        ''
        '  # Cross-domain fuzzy match, verified LDAPS only'
        "  .\$self -CsvPath .\groups.csv -FuzzyMatch"
        ''
        '  # Full two-forest migration readiness pipeline with fallback tiers'
        "  .\$self -CsvPath .\groups.csv -FuzzyMatch -AnalyzeGaps -DetectStale -ResolveNested -AllowInsecure"
        ''
        '  # Offline re-render from a saved cache (no AD access)'
        "  .\$self -CsvPath .\groups.csv -FromCache -CachePath .\Cache\groups-20260415-103821.json"
        ''
        '  # With explicit credentials'
        '  $cred = Get-Credential'
        "  .\$self -CsvPath .\groups.csv -FuzzyMatch -Credential `$cred"
        ''
        'MORE'
        "  Full parameter docs:  Get-Help .\$self -Detailed"
        '  Quick start:          docs/QUICKSTART.md'
        '  Developer notes:      docs/DEV-GUIDE.md'
        ''
    )
    $lines | ForEach-Object { Write-Host $_ }
}

if ($Help -or -not $CsvPath) {
    Show-Usage
    if (-not $Help -and -not $CsvPath) {
        Write-Host 'ERROR: -CsvPath is required.' -ForegroundColor Red
        exit 2
    }
    exit 0
}

# ---------------------------------------------------------------------------
# Resolve config path default
# ---------------------------------------------------------------------------
if (-not $ConfigPath) {
    $ConfigPath = Join-Path $scriptRoot 'Config\group-enum-config.json'
}

# ---------------------------------------------------------------------------
# Dot-source required modules
# ---------------------------------------------------------------------------
Write-Host 'Loading modules...' -ForegroundColor Cyan

$moduleFiles = @(
    'ADLdap.ps1',
    'GroupEnumLogger.ps1',
    'GroupEnumerator.ps1',
    'FuzzyMatcher.ps1',
    'GroupReportGenerator.ps1',
    'NestedGroupResolver.ps1',
    'UserCorrelation.ps1',
    'GapAnalysis.ps1',
    'StaleAccountDetector.ps1',
    'AppMapping.ps1',
    'MigrationReportGenerator.ps1',
    'EmailSummary.ps1',
    'DomainUserLookup.ps1',
    'MembershipDrift.ps1'
)

foreach ($moduleFile in $moduleFiles) {
    $modulePath = Join-Path $scriptRoot "Modules\$moduleFile"
    if (Test-Path $modulePath) {
        . $modulePath
        Write-Host "  Loaded: $moduleFile" -ForegroundColor Gray
    } else {
        Write-Error "Required module not found: $modulePath"
        exit 1
    }
}

Write-Host ''

# ---------------------------------------------------------------------------
# Main execution
# ---------------------------------------------------------------------------
$connectionPool = $null
try {
    # ---- Load configuration ----
    Write-Host 'Loading configuration...' -ForegroundColor Cyan
    $config = New-GroupEnumConfig -ConfigPath $ConfigPath

    # -AllowInsecure switch overrides config (switch takes precedence)
    if ($AllowInsecure) {
        $config.AllowInsecure = $true
    }

    Write-Host "  Config source: $(if (Test-Path $ConfigPath) { $ConfigPath } else { 'built-in defaults' })" -ForegroundColor Gray
    if ($config.AllowInsecure) {
        Write-Host '  ** AllowInsecure: LDAP 389 fallback enabled (tries LDAPS 636 first) **' -ForegroundColor Yellow
    }
    Write-Host ''

    # ---- Resolve stale threshold (v2 -- before logging so it appears in context) ----
    $staleDays = if ($StaleDays -gt 0) {
        $StaleDays
    } elseif ($config.StaleAccountDays) {
        $config.StaleAccountDays
    } else {
        90
    }

    # ---- Initialize logging ----
    $logState = Initialize-GroupEnumLog -Config $config -ScriptRoot $scriptRoot
    if ($logState.Enabled) {
        Write-Host "  Log file: $($logState.LogFilePath)" -ForegroundColor Gray
        Write-Host "  Log level: $($logState.LogLevel)" -ForegroundColor Gray
    } else {
        Write-Host '  Logging: disabled' -ForegroundColor Gray
    }
    Write-Host ''

    Write-GroupEnumLog -Level 'INFO' -Operation 'Config' `
        -Message "Configuration loaded" -Context @{
            configPath      = $ConfigPath
            allowInsecure   = $config.AllowInsecure
            fuzzyMatch      = [bool]$FuzzyMatch
            theme           = $Theme
            resolveNested   = [bool]$ResolveNested
            analyzeGaps     = [bool]$AnalyzeGaps
            detectStale     = [bool]$DetectStale
            staleDays       = $staleDays
            appMappingCsv   = $(if ($AppMappingCsv) { $AppMappingCsv } else { '' })
            sendEmail       = [bool]$SendEmail
        }

    # ---- Resolve output directory ----
    $resolvedOutputDir = if ($OutputPath) {
        $OutputPath
    } elseif ($config.OutputDirectory) {
        if ([System.IO.Path]::IsPathRooted($config.OutputDirectory)) {
            $config.OutputDirectory
        } else {
            Join-Path $scriptRoot $config.OutputDirectory
        }
    } else {
        Join-Path $scriptRoot 'Output'
    }

    if (-not (Test-Path $resolvedOutputDir)) {
        New-Item -ItemType Directory -Path $resolvedOutputDir -Force | Out-Null
        Write-Host "  Created output directory: $resolvedOutputDir" -ForegroundColor Gray
    }

    # ---- Resolve cache directory / path ----
    $cacheDir = if ($config.CachePath) {
        if ([System.IO.Path]::IsPathRooted($config.CachePath)) {
            $config.CachePath
        } else {
            Join-Path $scriptRoot $config.CachePath
        }
    } else {
        Join-Path $scriptRoot 'Cache'
    }

    if (-not (Test-Path $cacheDir)) {
        New-Item -ItemType Directory -Path $cacheDir -Force | Out-Null
    }

    $timestamp   = Get-Date -Format 'yyyyMMdd-HHmmss'
    $csvLeaf     = [System.IO.Path]::GetFileNameWithoutExtension($CsvPath)

    # ---- Timestamps for output file names ----
    $jsonFileName = "${csvLeaf}-${timestamp}.json"
    $htmlFileName = "${csvLeaf}-${timestamp}.html"

    $resolvedCachePath = if ($CachePath) {
        $CachePath
    } else {
        Join-Path $cacheDir $jsonFileName
    }

    $resolvedHtmlPath = Join-Path $resolvedOutputDir $htmlFileName

    # =========================================================================
    # BRANCH A: Load from JSON cache (skip LDAP)
    # =========================================================================
    if ($FromCache) {
        Write-Host 'Loading data from cache...' -ForegroundColor Cyan

        if (-not $CachePath) {
            Write-Error '-CachePath is required when using -FromCache'
            exit 1
        }

        if (-not (Test-Path $CachePath)) {
            Write-Error "Cache file not found: $CachePath"
            exit 1
        }

        $cacheData   = Import-GroupDataJson -JsonPath $CachePath
        $groupResults = $cacheData.Groups
        $matchResults = $cacheData.MatchResults

        $totalGroups = $groupResults.Count
        $domains     = @($groupResults | ForEach-Object { $_.Data.Domain } | Sort-Object -Unique)

        Write-Host "  Loaded $totalGroups groups from cache ($($domains -join ', '))" -ForegroundColor Gray
        Write-Host ''

        # Optionally re-run fuzzy matching on cached data
        if ($FuzzyMatch -and -not $matchResults) {
            Write-Host 'Running fuzzy match on cached data...' -ForegroundColor Cyan
            $prefixes  = if ($config.FuzzyPrefixes) { @($config.FuzzyPrefixes) } else { @() }
            $minScore  = if ($config.FuzzyMinScore)  { [double]$config.FuzzyMinScore }  else { 0.7 }
            $matchResults = Find-MatchingGroups -GroupResults $groupResults `
                -Prefixes $prefixes -MinScore $minScore
            Write-Host "  Matched: $($matchResults.Matched.Count) pairs, Unmatched: $($matchResults.Unmatched.Count)" -ForegroundColor Gray
            Write-Host ''
        }

    # =========================================================================
    # BRANCH B: Live LDAP enumeration
    # =========================================================================
    } else {
        # ---- Validate CSV ----
        if (-not (Test-Path $CsvPath)) {
            Write-Error "CSV file not found: $CsvPath"
            exit 1
        }

        # ---- Import group list ----
        Write-Host "Importing group list from: $CsvPath" -ForegroundColor Cyan
        $groupList = Import-GroupList -CsvPath $CsvPath

        if (-not $groupList -or $groupList.Count -eq 0) {
            Write-Warning @"
No groups found in CSV '$CsvPath'. Nothing to enumerate.

Check that the file:
  - has a header row (Domain,GroupName  OR  Group)
  - has at least one non-blank data row
  - uses DOMAIN\GroupName values if using the single-column 'Group' format

Sample files: Templates\groups-example-standard.csv
              Templates\groups-example-backslash.csv
"@
            exit 0
        }

        $domains      = @($groupList | ForEach-Object { $_.Domain } | Sort-Object -Unique)
        $domainCount  = ($domains | Where-Object { $_ -ne '' }).Count

        Write-Host "  Found $($groupList.Count) groups across $domainCount domain(s): $($domains -join ', ')" -ForegroundColor Gray
        Write-Host ''

        Write-GroupEnumLog -Level 'INFO' -Operation 'CsvImport' `
            -Message "Imported $($groupList.Count) groups from CSV" -Context @{
                csvPath    = $CsvPath
                groupCount = $groupList.Count
                domains    = ($domains -join ', ')
            }

        # ---- Enumerate each group ----
        Write-Host 'Enumerating group members...' -ForegroundColor Cyan

        $groupResults   = @()
        $totalErrors    = 0
        $skippedCount   = 0
        $totalProcessed = 0
        $totalInList    = $groupList.Count

        # Shared connection pool: one LdapConnection per domain, reused across
        # all groups in that domain. Also enables cross-forest member routing
        # and ForeignSecurityPrincipal SID resolution between pooled domains.
        $poolParams = @{
            AllowInsecure  = [bool]$config.AllowInsecure
            TimeoutSeconds = [int]$config.LdapTimeout
        }
        if ($Credential) { $poolParams.Credential = $Credential }
        $connectionPool = New-AdLdapConnectionPool @poolParams

        foreach ($entry in $groupList) {
            $totalProcessed++
            $progressPct = [int](($totalProcessed / $totalInList) * 100)
            Write-Host "  [$totalProcessed/$totalInList] $($entry.Domain)\$($entry.GroupName)..." -NoNewline -ForegroundColor Gray

            try {
                $enumParams = @{
                    Domain         = $entry.Domain
                    GroupName      = $entry.GroupName
                    Config         = $config
                    ConnectionPool = $connectionPool
                }
                if ($Credential) {
                    $enumParams.Credential = $Credential
                }
                if ($IncludeAttributes.Count -gt 0) {
                    $enumParams.IncludeAttributes = $IncludeAttributes
                }

                $result = Get-GroupMembers @enumParams

                if ($result.Errors -and $result.Errors.Count -gt 0) {
                    $totalErrors += $result.Errors.Count
                    Write-Host " [ERRORS: $($result.Errors.Count)]" -ForegroundColor Yellow
                    Write-GroupEnumLog -Level 'WARN' -Operation 'EnumerateGroup' `
                        -Message "Errors enumerating $($entry.Domain)\$($entry.GroupName)" -Context @{
                            domain    = $entry.Domain
                            groupName = $entry.GroupName
                            errors    = ($result.Errors -join '; ')
                        }
                } elseif ($result.Data.Skipped) {
                    $skippedCount++
                    Write-Host " [SKIPPED: $($result.Data.SkipReason)]" -ForegroundColor DarkYellow
                    Write-GroupEnumLog -Level 'INFO' -Operation 'SkipGroup' `
                        -Message "Skipped $($entry.Domain)\$($entry.GroupName)" -Context @{
                            domain     = $entry.Domain
                            groupName  = $entry.GroupName
                            skipReason = $result.Data.SkipReason
                        }
                } else {
                    Write-Host " $($result.Data.MemberCount) members" -ForegroundColor Green
                    Write-GroupEnumLog -Level 'DEBUG' -Operation 'EnumerateGroup' `
                        -Message "Enumerated $($entry.Domain)\$($entry.GroupName)" -Context @{
                            domain      = $entry.Domain
                            groupName   = $entry.GroupName
                            memberCount = $result.Data.MemberCount
                        }
                }

                $groupResults += $result

            } catch {
                $totalErrors++
                Write-Host " [FAILED: $_]" -ForegroundColor Red
                Write-GroupEnumLog -Level 'ERROR' -Operation 'EnumerateGroup' `
                    -Message "Failed to enumerate $($entry.Domain)\$($entry.GroupName): $_" -Context @{
                        domain    = $entry.Domain
                        groupName = $entry.GroupName
                        error     = $_.ToString()
                        stack     = $_.ScriptStackTrace
                    }
                $groupResults += @{
                    Data   = @{
                        GroupName         = $entry.GroupName
                        Domain            = $entry.Domain
                        DistinguishedName = $null
                        MemberCount       = 0
                        Members           = @()
                        Skipped           = $false
                        SkipReason        = $null
                    }
                    Errors = @("Enumeration failed: $_")
                }
            }
        }

        Write-Host ''

        # ---- Fuzzy matching ----
        $matchResults = $null
        if ($FuzzyMatch) {
            Write-Host 'Running fuzzy cross-domain matching...' -ForegroundColor Cyan
            $prefixes = if ($config.FuzzyPrefixes) { @($config.FuzzyPrefixes) } else { @() }
            $minScore = if ($config.FuzzyMinScore)  { [double]$config.FuzzyMinScore }  else { 0.7 }

            $matchResults = Find-MatchingGroups -GroupResults $groupResults `
                -Prefixes $prefixes -MinScore $minScore

            Write-Host "  Matched: $($matchResults.Matched.Count) pairs, Unmatched: $($matchResults.Unmatched.Count)" -ForegroundColor Gray
            Write-Host ''

            Write-GroupEnumLog -Level 'INFO' -Operation 'FuzzyMatch' `
                -Message "Fuzzy matching complete" -Context @{
                    matchedPairs    = $matchResults.Matched.Count
                    unmatchedGroups = $matchResults.Unmatched.Count
                    minScore        = $minScore
                    prefixes        = ($prefixes -join ', ')
                }
        }

        # ---- Save JSON cache ----
        if (-not $NoCache) {
            Write-Host "Saving JSON cache to: $resolvedCachePath" -ForegroundColor Cyan
            try {
                $null = Export-GroupDataJson `
                    -GroupResults $groupResults `
                    -MatchResults $matchResults `
                    -OutputPath   $resolvedCachePath `
                    -CsvSource    $CsvPath
                Write-Host "  Saved: $resolvedCachePath" -ForegroundColor Gray
            } catch {
                Write-Warning "Failed to save JSON cache: $_"
            }
            Write-Host ''
        }
    }

    # =========================================================================
    # V2: Migration Readiness Analysis (when -AnalyzeGaps or -ResolveNested)
    # =========================================================================

    # V2 result containers -- all null/empty by default so v1 path is unchanged
    $staleResults       = $null
    $correlationResults = @{}
    $gapResults         = @()
    $overallReadiness   = $null
    $appReadiness       = $null
    $gapCsvPath         = $null
    $crSummaryPath      = $null
    $crText             = ''

    $runStale       = $DetectStale -or $AnalyzeGaps
    $runCorrelation = $AnalyzeGaps -and $matchResults -and $matchResults.Matched.Count -gt 0
    $runGaps        = $AnalyzeGaps -and $runCorrelation

    # ---- Step 1: Nested Group Resolution ----
    if ($ResolveNested) {
        Write-Host 'Resolving nested group memberships...' -ForegroundColor Cyan

        $nestedResolved   = 0
        $nestedUsersTotal = 0

        foreach ($groupResult in $groupResults) {
            # Filter out benign tier-downgrade warnings (string-prefixed
            # "WARNING: Using tier ...") before deciding whether to skip.
            # They indicate successful enumeration via a fallback tier, not a
            # real error, and downstream processing should still run.
            $fatalErrs = @($groupResult.Errors | Where-Object { $_ -notlike 'WARNING: Using tier*' })
            if ($groupResult.Data.Skipped -or $fatalErrs.Count -gt 0) { continue }

            $nestedParams = @{
                Domain         = $groupResult.Data.Domain
                GroupName      = $groupResult.Data.GroupName
                Config         = $config
                ConnectionPool = $connectionPool
            }
            if ($Credential) { $nestedParams.Credential = $Credential }

            try {
                $flatResult = Resolve-NestedGroupMembers @nestedParams

                if ($flatResult.FlatMembers.Count -gt 0) {
                    $groupResult.Data.Members     = $flatResult.FlatMembers
                    $groupResult.Data.MemberCount = $flatResult.TotalUsersFound
                    $nestedResolved++
                    $nestedUsersTotal += $flatResult.TotalUsersFound

                    if ($flatResult.MaxDepthReached) {
                        Write-Host "  $($groupResult.Data.Domain)\$($groupResult.Data.GroupName): $($flatResult.TotalUsersFound) users [max depth reached]" -ForegroundColor Yellow
                    }
                }

                if ($flatResult.Errors -and $flatResult.Errors.Count -gt 0) {
                    foreach ($e in $flatResult.Errors) {
                        Write-GroupEnumLog -Level 'WARN' -Operation 'NestedResolve' `
                            -Message "Nested resolve error for $($groupResult.Data.Domain)\$($groupResult.Data.GroupName): $e" `
                            -Context @{ domain = $groupResult.Data.Domain; groupName = $groupResult.Data.GroupName }
                    }
                }
            } catch {
                Write-Warning "Nested resolution failed for $($groupResult.Data.Domain)\$($groupResult.Data.GroupName): $_"
                Write-GroupEnumLog -Level 'ERROR' -Operation 'NestedResolve' `
                    -Message "Nested resolution failed: $_" `
                    -Context @{ domain = $groupResult.Data.Domain; groupName = $groupResult.Data.GroupName; error = $_.ToString() }
            }
        }

        Write-Host "  Resolved $nestedResolved group(s) -- $nestedUsersTotal total flat members" -ForegroundColor Gray
        Write-Host ''

        Write-GroupEnumLog -Level 'INFO' -Operation 'NestedResolve' `
            -Message "Nested group resolution complete: $nestedResolved groups, $nestedUsersTotal total users" `
            -Context @{ groupsResolved = $nestedResolved; totalUsers = $nestedUsersTotal }
    }

    # ---- Step 2: Stale Account Detection ----
    if ($runStale) {
        Write-Host 'Detecting stale and disabled accounts...' -ForegroundColor Cyan

        $staleResults   = @{}
        $staleTotalFlag = 0

        foreach ($groupResult in $groupResults) {
            # Filter out benign tier-downgrade warnings (string-prefixed
            # "WARNING: Using tier ...") before deciding whether to skip.
            # They indicate successful enumeration via a fallback tier, not a
            # real error, and downstream processing should still run.
            $fatalErrs = @($groupResult.Errors | Where-Object { $_ -notlike 'WARNING: Using tier*' })
            if ($groupResult.Data.Skipped -or $fatalErrs.Count -gt 0) { continue }
            if (-not $groupResult.Data.Members -or $groupResult.Data.Members.Count -eq 0) { continue }

            $staleKey = "$($groupResult.Data.Domain)|$($groupResult.Data.GroupName)"

            # Pass a copy of config with the resolved stale threshold
            $staleConfig = $config.Clone()
            $staleConfig.StaleAccountDays = $staleDays

            $staleParams = @{
                Members        = $groupResult.Data.Members
                Domain         = $groupResult.Data.Domain
                Config         = $staleConfig
                ConnectionPool = $connectionPool
            }
            if ($Credential) { $staleParams.Credential = $Credential }

            try {
                $staleResult = Get-AccountStaleness @staleParams
                $staleResults[$staleKey] = $staleResult

                $flagged = $staleResult.Summary.DisabledCount + $staleResult.Summary.StaleCount + $staleResult.Summary.NeverLoggedInCount
                $staleTotalFlag += $flagged

                Write-GroupEnumLog -Level 'DEBUG' -Operation 'StaleDetect' `
                    -Message "Staleness check: $($groupResult.Data.Domain)\$($groupResult.Data.GroupName)" `
                    -Context @{
                        domain    = $groupResult.Data.Domain
                        groupName = $groupResult.Data.GroupName
                        active    = $staleResult.Summary.ActiveCount
                        disabled  = $staleResult.Summary.DisabledCount
                        stale     = $staleResult.Summary.StaleCount
                        never     = $staleResult.Summary.NeverLoggedInCount
                    }
            } catch {
                Write-Warning "Stale detection failed for $($groupResult.Data.Domain)\$($groupResult.Data.GroupName): $_"
                Write-GroupEnumLog -Level 'ERROR' -Operation 'StaleDetect' `
                    -Message "Stale detection failed: $_" `
                    -Context @{ domain = $groupResult.Data.Domain; groupName = $groupResult.Data.GroupName; error = $_.ToString() }
            }
        }

        Write-Host "  $staleTotalFlag stale/disabled account(s) flagged across $($staleResults.Count) group(s)" -ForegroundColor Gray
        Write-Host ''

        Write-GroupEnumLog -Level 'INFO' -Operation 'StaleDetect' `
            -Message "Stale account detection complete: $staleTotalFlag accounts flagged" `
            -Context @{ totalFlagged = $staleTotalFlag; groupsChecked = $staleResults.Count }
    }

    # ---- Step 3: User Correlation ----
    if ($runCorrelation) {
        Write-Host 'Running cross-domain user correlation...' -ForegroundColor Cyan

        $totalCorrelated   = 0
        $totalHighConf     = 0
        $totalMediumConf   = 0
        $totalLowConf      = 0

        # Build a lookup of GroupName -> group result for member access
        $groupResultByKey = @{}
        foreach ($gr in $groupResults) {
            $k = "$($gr.Data.Domain)|$($gr.Data.GroupName)"
            $groupResultByKey[$k] = $gr
        }

        foreach ($pair in $matchResults.Matched) {
            $srcKey = "$($pair.SourceDomain)|$($pair.SourceGroup)"
            $tgtKey = "$($pair.TargetDomain)|$($pair.TargetGroup)"

            $srcResult = $groupResultByKey[$srcKey]
            $tgtResult = $groupResultByKey[$tgtKey]

            if (-not $srcResult -or -not $tgtResult) { continue }

            $srcMembers = if ($srcResult.Data.Members) { @($srcResult.Data.Members) } else { @() }
            $tgtMembers = if ($tgtResult.Data.Members) { @($tgtResult.Data.Members) } else { @() }

            $corrKey = "$($pair.SourceDomain)\$($pair.SourceGroup)|$($pair.TargetDomain)\$($pair.TargetGroup)"

            $corrParams = @{
                SourceMembers  = $srcMembers
                TargetMembers  = $tgtMembers
                Config         = $config
            }

            try {
                $corrResult = Find-UserCorrelations @corrParams
                $correlationResults[$corrKey] = $corrResult

                $totalCorrelated += $corrResult.Summary.CorrelatedCount
                $totalHighConf   += $corrResult.Summary.HighConfidence
                $totalMediumConf += $corrResult.Summary.MediumConfidence
                $totalLowConf    += $corrResult.Summary.LowConfidence

            } catch {
                Write-Warning "User correlation failed for pair ${corrKey}: $_"
                Write-GroupEnumLog -Level 'ERROR' -Operation 'UserCorrelation' `
                    -Message "User correlation failed for pair ${corrKey}: $_" `
                    -Context @{ corrKey = $corrKey; error = $_.ToString() }
            }
        }

        Write-Host "  $totalCorrelated correlation(s) found: High=$totalHighConf, Medium=$totalMediumConf, Low=$totalLowConf" -ForegroundColor Gray
        Write-Host ''

        Write-GroupEnumLog -Level 'INFO' -Operation 'UserCorrelation' `
            -Message "User correlation complete across $($correlationResults.Count) group pair(s)" `
            -Context @{
                pairs         = $correlationResults.Count
                correlated    = $totalCorrelated
                highConf      = $totalHighConf
                mediumConf    = $totalMediumConf
                lowConf       = $totalLowConf
            }
    }

    # ---- Step 4: Gap Analysis ----
    if ($runGaps) {
        Write-Host 'Running migration gap analysis...' -ForegroundColor Cyan

        $groupResultByKey = @{}
        foreach ($gr in $groupResults) {
            $k = "$($gr.Data.Domain)|$($gr.Data.GroupName)"
            $groupResultByKey[$k] = $gr
        }

        foreach ($pair in $matchResults.Matched) {
            $corrKey = "$($pair.SourceDomain)\$($pair.SourceGroup)|$($pair.TargetDomain)\$($pair.TargetGroup)"

            if (-not $correlationResults.ContainsKey($corrKey)) { continue }

            $srcKey = "$($pair.SourceDomain)|$($pair.SourceGroup)"
            $tgtKey = "$($pair.TargetDomain)|$($pair.TargetGroup)"

            $srcResult = $groupResultByKey[$srcKey]
            $tgtResult = $groupResultByKey[$tgtKey]

            if (-not $srcResult -or -not $tgtResult) { continue }

            $corrResult = $correlationResults[$corrKey]

            # Stale data for this source group (keyed by Domain|GroupName)
            $srcStaleKey   = "$($pair.SourceDomain)|$($pair.SourceGroup)"
            $staleForGroup = if ($staleResults -and $staleResults.ContainsKey($srcStaleKey)) {
                $staleResults[$srcStaleKey]
            } else { $null }

            $gapParams = @{
                SourceGroupResult = $srcResult
                TargetGroupResult = $tgtResult
                CorrelationResult = $corrResult
                StaleResult       = $staleForGroup
                Config            = $config
            }

            try {
                $gapResult   = Get-MigrationGapAnalysis @gapParams
                $gapResults += $gapResult
            } catch {
                Write-Warning "Gap analysis failed for pair ${corrKey}: $_"
                Write-GroupEnumLog -Level 'ERROR' -Operation 'GapAnalysis' `
                    -Message "Gap analysis failed for pair ${corrKey}: $_" `
                    -Context @{ corrKey = $corrKey; error = $_.ToString() }
            }
        }

        # Overall readiness summary
        if ($gapResults.Count -gt 0) {
            $appReadinessForOverall = $null

            $overallReadiness = Get-OverallMigrationReadiness -GapResults $gapResults `
                -AppReadiness $appReadinessForOverall

            Write-Host "  Overall readiness: $($overallReadiness.OverallPercent)% -- $($overallReadiness.TotalCRItems) CR item(s) across $($gapResults.Count) group pair(s)" -ForegroundColor Gray
        } else {
            Write-Host '  No gap results generated (no matched pairs with correlations)' -ForegroundColor Yellow
        }

        Write-Host ''

        Write-GroupEnumLog -Level 'INFO' -Operation 'GapAnalysis' `
            -Message "Gap analysis complete: $($gapResults.Count) group pairs analyzed" `
            -Context @{
                pairsAnalyzed    = $gapResults.Count
                overallPercent   = $(if ($overallReadiness) { $overallReadiness.OverallPercent } else { 0 })
                totalCRItems     = $(if ($overallReadiness) { $overallReadiness.TotalCRItems }   else { 0 })
            }
    }

    # ---- Step 4b: Domain Existence Resolution (-MigratingTo) ----
    if ($MigratingTo -and $gapResults.Count -gt 0) {
        Write-Host "Resolving domain existence in '$MigratingTo'..." -ForegroundColor Cyan

        $resolvedSearchBase = $TargetSearchBase

        if (-not $resolvedSearchBase) {
            Write-Host '  No -TargetSearchBase provided. Detecting current user OU...' -ForegroundColor Gray
            $ouDetect = Get-CurrentUserOU -Domain $MigratingTo -Credential $Credential -Config $config
            if ($ouDetect.Detected -and $ouDetect.ParentOU) {
                Write-Host "  Detected your OU: $($ouDetect.ParentOU)" -ForegroundColor Cyan
                $useDetected = Read-Host "  Use this OU as SearchBase? [Y/n]"
                if (-not $useDetected -or $useDetected -imatch '^y') {
                    $resolvedSearchBase = $ouDetect.ParentOU
                    Write-Host "  Using detected OU: $resolvedSearchBase" -ForegroundColor Green
                } else {
                    Write-Host '  Searching from domain root (may be slower)' -ForegroundColor Yellow
                }
            } else {
                Write-Host "  Could not detect user OU: $($ouDetect.Error)" -ForegroundColor Yellow
                Write-Host '  Searching from domain root' -ForegroundColor Yellow
            }
        }

        if ($resolvedSearchBase) {
            $sbCheck = Test-SearchBaseExists -Domain $MigratingTo -SearchBase $resolvedSearchBase `
                -Credential $Credential -Config $config
            if (-not $sbCheck.Exists) {
                Write-Host "  SearchBase NOT FOUND: $resolvedSearchBase" -ForegroundColor Red
                $continueChoice = Read-Host '  Continue searching from domain root instead? [Y/n]'
                if (-not $continueChoice -or $continueChoice -imatch '^y') {
                    $resolvedSearchBase = $null
                } else {
                    $MigratingTo = $null
                }
            } else {
                Write-Host '  SearchBase validated' -ForegroundColor Green
            }
        }

        if ($MigratingTo) {
            $notProvCount = @($gapResults | ForEach-Object { $_.Items } |
                Where-Object { $_.Status -eq 'NotProvisioned' }).Count
            if ($notProvCount -gt 0) {
                Write-Host "  Searching target domain for $notProvCount unmatched user(s)..." -ForegroundColor Gray
                $gapResults = Resolve-DomainExistence -GapResults $gapResults `
                    -TargetDomain $MigratingTo -TargetSearchBase $resolvedSearchBase `
                    -Credential $Credential -Config $config
                $existsCount = @($gapResults | ForEach-Object { $_.Items } | Where-Object { $_.Status -eq 'ExistsNotInGroup' }).Count
                $notInDomCount = @($gapResults | ForEach-Object { $_.Items } | Where-Object { $_.Status -eq 'NotInDomain' }).Count
                Write-Host "  Results: $existsCount exist in domain, $notInDomCount not in domain" -ForegroundColor Gray
                $overallReadiness = Get-OverallMigrationReadiness -GapResults $gapResults
                Write-Host "  Updated readiness: $($overallReadiness.OverallPercent)%" -ForegroundColor Gray
            } else {
                Write-Host '  No NotProvisioned users to search for' -ForegroundColor Gray
            }
            Write-Host ''
        }
    }

    # ---- Step 4c: Membership Drift Detection ----
    $driftResult = $null
    if (($BaselinePath -or $PreviousRunPath) -and $groupResults.Count -gt 0) {
        Write-Host 'Detecting membership drift...' -ForegroundColor Cyan
        $resolvedPreviousPath = $PreviousRunPath
        if (-not $resolvedPreviousPath -and -not $FromCache) {
            $resolvedPreviousPath = Get-LatestCacheFile -CacheDirectory $cacheDir -ExcludePath $resolvedCachePath
            if ($resolvedPreviousPath) {
                Write-Host "  Auto-detected previous run: $resolvedPreviousPath" -ForegroundColor Gray
            }
        }
        $driftResult = Get-MembershipDrift -CurrentGroupResults $groupResults `
            -BaselinePath $BaselinePath -PreviousRunPath $resolvedPreviousPath
        $blSummary = $driftResult.OverallSummary.BaselineComparison
        $prSummary = $driftResult.OverallSummary.PreviousComparison
        if ($BaselinePath -and $blSummary.GroupsCompared -gt 0) {
            Write-Host "  vs Baseline: +$($blSummary.TotalAdded) added, -$($blSummary.TotalRemoved) removed across $($blSummary.GroupsWithChanges) group(s)" -ForegroundColor $(if ($blSummary.GroupsWithChanges -gt 0) { 'Yellow' } else { 'Gray' })
        }
        if ($resolvedPreviousPath -and $prSummary.GroupsCompared -gt 0) {
            Write-Host "  vs Previous: +$($prSummary.TotalAdded) added, -$($prSummary.TotalRemoved) removed across $($prSummary.GroupsWithChanges) group(s)" -ForegroundColor $(if ($prSummary.GroupsWithChanges -gt 0) { 'Yellow' } else { 'Gray' })
        }
        if ($driftResult.FromPrevious.Count -gt 0) {
            $driftCsvPath = Join-Path $resolvedOutputDir "${csvLeaf}-drift-previous-${timestamp}.csv"
            $null = Export-DriftReportCsv -DriftResult $driftResult -OutputPath $driftCsvPath -ComparisonType 'Previous'
            Write-Host "  Drift CSV: $driftCsvPath" -ForegroundColor Gray
        }
        Write-Host ''
    }

    # ---- Step 5: App Mapping ----
    if ($AppMappingCsv) {
        Write-Host "Loading application mapping from: $AppMappingCsv" -ForegroundColor Cyan

        try {
            $appMappings = Import-AppMapping -CsvPath $AppMappingCsv

            if ($appMappings.Count -gt 0 -and $gapResults.Count -gt 0) {
                $appReadiness = Get-AppReadiness -AppMappings $appMappings -GapResults $gapResults

                Write-Host "  $($appReadiness.Summary.TotalApps) app(s): $($appReadiness.Summary.ReadyApps) ready, $($appReadiness.Summary.InProgressApps) in progress, $($appReadiness.Summary.BlockedApps) blocked" -ForegroundColor Gray

                Write-GroupEnumLog -Level 'INFO' -Operation 'AppMapping' `
                    -Message "App readiness calculated for $($appReadiness.Summary.TotalApps) application(s)" `
                    -Context @{
                        totalApps      = $appReadiness.Summary.TotalApps
                        readyApps      = $appReadiness.Summary.ReadyApps
                        inProgressApps = $appReadiness.Summary.InProgressApps
                        blockedApps    = $appReadiness.Summary.BlockedApps
                        notAnalyzed    = $appReadiness.Summary.NotAnalyzedApps
                    }
            } elseif ($appMappings.Count -gt 0) {
                Write-Host '  App mappings loaded but no gap results available -- skipping app readiness calculation' -ForegroundColor Yellow
                Write-GroupEnumLog -Level 'WARN' -Operation 'AppMapping' `
                    -Message 'App mappings loaded but no gap results available for readiness calculation'
            }
        } catch {
            Write-Warning "App mapping failed: $_"
            Write-GroupEnumLog -Level 'ERROR' -Operation 'AppMapping' `
                -Message "App mapping failed: $_" -Context @{ error = $_.ToString() }
        }

        Write-Host ''
    }

    # ---- Step 6: Export Gap Analysis CSV and CR Summary ----
    if ($AnalyzeGaps -and $gapResults.Count -gt 0) {
        Write-Host 'Exporting gap analysis artefacts...' -ForegroundColor Cyan

        $gapCsvFileName = "${csvLeaf}-gaps-${timestamp}.csv"
        $gapCsvPath     = Join-Path $resolvedOutputDir $gapCsvFileName

        try {
            $null = Export-GapAnalysisCsv -GapResults $gapResults -OutputPath $gapCsvPath
            Write-Host "  Gap analysis CSV: $gapCsvPath" -ForegroundColor Gray

            Write-GroupEnumLog -Level 'INFO' -Operation 'ExportCsv' `
                -Message "Gap analysis CSV exported" -Context @{ path = $gapCsvPath }
        } catch {
            Write-Warning "Failed to export gap analysis CSV: $_"
            Write-GroupEnumLog -Level 'ERROR' -Operation 'ExportCsv' `
                -Message "Gap analysis CSV export failed: $_" -Context @{ error = $_.ToString() }
        }

        if ($overallReadiness) {
            $crSummaryFileName = "${csvLeaf}-cr-summary-${timestamp}.txt"
            $crSummaryPath     = Join-Path $resolvedOutputDir $crSummaryFileName

            try {
                $crText = Export-ChangeRequestSummary -GapResults $gapResults `
                    -OverallReadiness $overallReadiness

                [System.IO.File]::WriteAllText(
                    $crSummaryPath,
                    $crText,
                    [System.Text.UTF8Encoding]::new($false)
                )
                Write-Host "  CR summary: $crSummaryPath" -ForegroundColor Gray

                Write-GroupEnumLog -Level 'INFO' -Operation 'ExportCR' `
                    -Message "CR summary exported" -Context @{ path = $crSummaryPath }
            } catch {
                Write-Warning "Failed to export CR summary: $_"
                Write-GroupEnumLog -Level 'ERROR' -Operation 'ExportCR' `
                    -Message "CR summary export failed: $_" -Context @{ error = $_.ToString() }
                $crText = ''
            }
        }

        Write-Host ''
    }

    # =========================================================================
    # Report generation (both branches converge here)
    # =========================================================================
    if (-not $JsonOnly) {
        Write-Host "Generating HTML report: $resolvedHtmlPath" -ForegroundColor Cyan

        if ($AnalyzeGaps -and $gapResults.Count -gt 0) {
            # V2: migration readiness report
            $null = Export-MigrationReport `
                -GroupResults      $groupResults `
                -MatchResults      $matchResults `
                -GapResults        $gapResults `
                -OverallReadiness  $overallReadiness `
                -CorrelationResults $correlationResults `
                -StaleResults      $staleResults `
                -AppReadiness      $appReadiness `
                -OutputPath        $resolvedHtmlPath `
                -Theme             $Theme `
                -Config            $config
        } else {
            # V1: standard group comparison report
            $null = Export-GroupReport `
                -GroupResults $groupResults `
                -MatchResults $matchResults `
                -OutputPath   $resolvedHtmlPath `
                -Theme        $Theme `
                -Config       $config
        }

        Write-Host "  Report: $resolvedHtmlPath" -ForegroundColor Gray
        Write-Host ''
    }

    # ---- Email (if -SendEmail) ----
    if ($SendEmail) {
        Write-Host 'Sending migration summary email...' -ForegroundColor Cyan

        $emailOverallReadiness = if ($overallReadiness) {
            $overallReadiness
        } else {
            # Supply empty readiness so Send-MigrationSummaryEmail can build a minimal subject
            @{
                OverallPercent   = 0
                GroupCount       = $groupResults.Count
                ReadyGroups      = 0
                InProgressGroups = 0
                BlockedGroups    = 0
                TotalCRItems     = 0
                CRByPriority     = @{ P1 = 0; P2 = 0; P3 = 0 }
            }
        }

        $emailParams = @{
            HtmlReportPath   = $resolvedHtmlPath
            Config           = $config
            OverallReadiness = $emailOverallReadiness
            CRSummaryText    = $crText
        }
        if ($Credential) { $emailParams.Credential = $Credential }

        try {
            $emailResult = Send-MigrationSummaryEmail @emailParams

            if ($emailResult.Sent) {
                Write-Host "  Email sent to: $($emailResult.Recipients -join ', ')" -ForegroundColor Gray
                Write-GroupEnumLog -Level 'INFO' -Operation 'Email' `
                    -Message "Migration summary email sent" `
                    -Context @{
                        recipients = ($emailResult.Recipients -join ', ')
                        subject    = $emailResult.Subject
                    }
            } else {
                Write-Warning "Email send failed: $($emailResult.Error)"
                Write-GroupEnumLog -Level 'WARN' -Operation 'Email' `
                    -Message "Email send failed: $($emailResult.Error)" `
                    -Context @{ error = $emailResult.Error }
            }
        } catch {
            Write-Warning "Email delivery error: $_"
            Write-GroupEnumLog -Level 'ERROR' -Operation 'Email' `
                -Message "Email delivery error: $_" -Context @{ error = $_.ToString() }
        }

        Write-Host ''
    }

    # =========================================================================
    # Summary
    # =========================================================================
    $enumerated   = @($groupResults | Where-Object { -not $_.Data.Skipped })
    $skippedFinal = @($groupResults | Where-Object { $_.Data.Skipped })
    $totalMembers = 0
    foreach ($e in $enumerated) { $totalMembers += [int]$e.Data.MemberCount }
    $errGroups    = @($groupResults | Where-Object { $_.Errors.Count -gt 0 })

    Write-Host '========================================' -ForegroundColor Cyan
    Write-Host 'Summary' -ForegroundColor Cyan
    Write-Host '========================================' -ForegroundColor Cyan
    Write-Host "  Groups processed : $($groupResults.Count)" -ForegroundColor White
    Write-Host "  Enumerated       : $($enumerated.Count)" -ForegroundColor White
    Write-Host "  Skipped          : $($skippedFinal.Count)" -ForegroundColor $(if ($skippedFinal.Count -gt 0) { 'Yellow' } else { 'White' })
    Write-Host "  Total members    : $totalMembers" -ForegroundColor White
    Write-Host "  Groups with errors: $($errGroups.Count)" -ForegroundColor $(if ($errGroups.Count -gt 0) { 'Red' } else { 'White' })

    if ($FuzzyMatch -and $matchResults) {
        Write-Host "  Matched pairs    : $($matchResults.Matched.Count)" -ForegroundColor White
        Write-Host "  Unmatched groups : $($matchResults.Unmatched.Count)" -ForegroundColor White
    }

    # V2 summary lines
    if ($ResolveNested) {
        $nestedCount = @($groupResults | Where-Object { -not $_.Data.Skipped }).Count
        Write-Host "  Nested resolved  : $nestedCount group(s)" -ForegroundColor White
    }

    if ($runStale -and $staleResults) {
        $totalFlagged = 0
        foreach ($sr in $staleResults.Values) {
            $totalFlagged += $sr.Summary.DisabledCount + $sr.Summary.StaleCount + $sr.Summary.NeverLoggedInCount
        }
        Write-Host "  Stale flagged    : $totalFlagged account(s)" -ForegroundColor $(if ($totalFlagged -gt 0) { 'Yellow' } else { 'White' })
    }

    if ($runCorrelation -and $correlationResults.Count -gt 0) {
        Write-Host "  Correlations     : $totalCorrelated (High=$totalHighConf Medium=$totalMediumConf Low=$totalLowConf)" -ForegroundColor White
    }

    if ($overallReadiness) {
        Write-Host "  Readiness        : $($overallReadiness.OverallPercent)%" -ForegroundColor $(
            if ($overallReadiness.OverallPercent -ge 80) { 'Green' }
            elseif ($overallReadiness.OverallPercent -ge 50) { 'Yellow' }
            else { 'Red' }
        )
        $p1 = $overallReadiness.CRByPriority.P1
        $p2 = $overallReadiness.CRByPriority.P2
        $p3 = $overallReadiness.CRByPriority.P3
        Write-Host "  Change Requests  : $($overallReadiness.TotalCRItems) total (P1=$p1 P2=$p2 P3=$p3)" -ForegroundColor White
    }

    if (-not $JsonOnly) {
        Write-Host "  HTML report      : $resolvedHtmlPath" -ForegroundColor Cyan
    }
    if (-not $NoCache -and -not $FromCache) {
        Write-Host "  JSON cache       : $resolvedCachePath" -ForegroundColor Cyan
    }
    if ($gapCsvPath) {
        Write-Host "  Gap analysis CSV : $gapCsvPath" -ForegroundColor Cyan
    }
    if ($crSummaryPath) {
        Write-Host "  CR summary       : $crSummaryPath" -ForegroundColor Cyan
    }

    # Close logger and show path
    $logPath = Close-GroupEnumLog -Summary @{
        groupsProcessed  = $groupResults.Count
        enumerated       = $enumerated.Count
        skipped          = $skippedFinal.Count
        totalMembers     = $totalMembers
        errorGroups      = $errGroups.Count
        matchedPairs     = if ($matchResults) { $matchResults.Matched.Count } else { 0 }
        overallReadiness = if ($overallReadiness) { $overallReadiness.OverallPercent } else { $null }
        totalCRItems     = if ($overallReadiness) { $overallReadiness.TotalCRItems }   else { 0 }
    }
    if ($logPath) {
        Write-Host "  Log file         : $logPath" -ForegroundColor Cyan
    }

    Write-Host ''

    if ($errGroups.Count -gt 0) {
        Write-Host 'Groups with errors:' -ForegroundColor Red
        foreach ($eg in $errGroups) {
            Write-Host "  $($eg.Data.Domain)\$($eg.Data.GroupName):" -ForegroundColor Red
            foreach ($e in $eg.Errors) {
                Write-Host "    - $e" -ForegroundColor Red
            }
        }
        Write-Host ''
    }

    # Return results object for pipeline use
    $pipelineResult = @{
        GroupResults        = $groupResults
        MatchResults        = $matchResults
        Config              = $config
        OutputPath          = if (-not $JsonOnly) { $resolvedHtmlPath } else { $null }
        CachePath           = if (-not $NoCache -and -not $FromCache) { $resolvedCachePath } else { $null }
        GapResults          = $gapResults
        OverallReadiness    = $overallReadiness
        CorrelationResults  = $correlationResults
        StaleResults        = $staleResults
        AppReadiness        = $appReadiness
        GapCsvPath          = $gapCsvPath
        CRSummaryPath       = $crSummaryPath
    }

    return $pipelineResult

} catch {
    Write-Host ''
    Write-Host "FATAL ERROR: $_" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor DarkRed
    Write-GroupEnumLog -Level 'ERROR' -Operation 'Fatal' `
        -Message "Fatal error: $_" -Context @{
            error = $_.ToString()
            stack = $_.ScriptStackTrace
        }
    $null = Close-GroupEnumLog -Summary @{ fatalError = $_.ToString() }
    exit 1
} finally {
    if ($connectionPool) {
        try { Close-AdLdapConnectionPool $connectionPool } catch { }
    }
}
