<#
.SYNOPSIS
    Cross-domain group membership enumeration orchestrator

.DESCRIPTION
    Reads a CSV of domain/group pairs, enumerates members from each AD domain via LDAPS,
    optionally runs fuzzy cross-domain name matching, and produces an HTML report and/or
    JSON cache file.

    Features:
    - CSV input in Domain,GroupName or DOMAIN\GroupName backslash format
    - LDAPS-only enumeration (port 636) via GroupEnumerator module
    - Levenshtein-based fuzzy cross-domain group matching
    - Professional dark/light-theme HTML report
    - JSON cache for offline report regeneration with -FromCache

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

.EXAMPLE
    .\Invoke-GroupEnumerator.ps1 -CsvPath .\groups.csv -FuzzyMatch

.EXAMPLE
    .\Invoke-GroupEnumerator.ps1 -CsvPath .\groups.csv -Credential $cred -Theme light -NoCache

.EXAMPLE
    .\Invoke-GroupEnumerator.ps1 -CsvPath .\groups.csv -FromCache -CachePath .\Cache\groups-20260408.json

.NOTES
    Author: EntraID Team
    Requires: PowerShell 5.1 or PowerShell 7+
    Always uses LDAPS (port 636). Never uses plaintext LDAP 389.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$CsvPath,

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
    [switch]$AllowInsecure
)

$ErrorActionPreference = 'Stop'
$scriptRoot = $PSScriptRoot

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
    'GroupEnumLogger.ps1',
    'GroupEnumerator.ps1',
    'FuzzyMatcher.ps1',
    'GroupReportGenerator.ps1'
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
            configPath    = $ConfigPath
            allowInsecure = $config.AllowInsecure
            fuzzyMatch    = [bool]$FuzzyMatch
            theme         = $Theme
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
            Write-Warning 'No groups found in CSV. Nothing to enumerate.'
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

        foreach ($entry in $groupList) {
            $totalProcessed++
            $progressPct = [int](($totalProcessed / $totalInList) * 100)
            Write-Host "  [$totalProcessed/$totalInList] $($entry.Domain)\$($entry.GroupName)..." -NoNewline -ForegroundColor Gray

            try {
                $enumParams = @{
                    Domain    = $entry.Domain
                    GroupName = $entry.GroupName
                    Config    = $config
                }
                if ($Credential) {
                    $enumParams.Credential = $Credential
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
    # Report generation (both branches converge here)
    # =========================================================================
    if (-not $JsonOnly) {
        Write-Host "Generating HTML report: $resolvedHtmlPath" -ForegroundColor Cyan
        $null = Export-GroupReport `
            -GroupResults $groupResults `
            -MatchResults $matchResults `
            -OutputPath   $resolvedHtmlPath `
            -Theme        $Theme `
            -Config       $config
        Write-Host "  Report: $resolvedHtmlPath" -ForegroundColor Gray
        Write-Host ''
    }

    # =========================================================================
    # Summary
    # =========================================================================
    $enumerated   = @($groupResults | Where-Object { -not $_.Data.Skipped })
    $skippedFinal = @($groupResults | Where-Object { $_.Data.Skipped })
    $totalMembers = ($enumerated | Measure-Object -Property { $_.Data.MemberCount } -Sum).Sum
    if (-not $totalMembers) { $totalMembers = 0 }
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

    if (-not $JsonOnly) {
        Write-Host "  HTML report      : $resolvedHtmlPath" -ForegroundColor Cyan
    }
    if (-not $NoCache -and -not $FromCache) {
        Write-Host "  JSON cache       : $resolvedCachePath" -ForegroundColor Cyan
    }

    # Close logger and show path
    $logPath = Close-GroupEnumLog -Summary @{
        groupsProcessed = $groupResults.Count
        enumerated      = $enumerated.Count
        skipped         = $skippedFinal.Count
        totalMembers    = $totalMembers
        errorGroups     = $errGroups.Count
        matchedPairs    = if ($matchResults) { $matchResults.Matched.Count } else { 0 }
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
        GroupResults = $groupResults
        MatchResults = $matchResults
        Config       = $config
        OutputPath   = if (-not $JsonOnly) { $resolvedHtmlPath } else { $null }
        CachePath    = if (-not $NoCache -and -not $FromCache) { $resolvedCachePath } else { $null }
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
}
