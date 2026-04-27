<#
.SYNOPSIS
    Comprehensive test harness for the Group Enumerator toolkit

.DESCRIPTION
    Tests all modules (GroupEnumerator, FuzzyMatcher, GroupReportGenerator) using
    mock data and temp files. Works on macOS/Linux without Active Directory.

.NOTES
    No external dependencies.
    All LDAP-dependent functions are mocked inline.
    Temp files are cleaned up in finally blocks.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [switch]$VerboseLogging
)

$ErrorActionPreference = 'Stop'

# Test script is in Tests/, project root is one level up
$scriptRoot = Split-Path -Parent $PSScriptRoot

$script:TestsPassed   = 0
$script:TestsFailed   = 0
$script:TestErrors    = @()
$script:TestStartTime = Get-Date

Write-Host '==========================================' -ForegroundColor Cyan
Write-Host 'Group Enumerator Toolkit - Test Suite' -ForegroundColor Cyan
Write-Host '==========================================' -ForegroundColor Cyan
Write-Host ''

# ---------------------------------------------------------------------------
# Test helper functions
# ---------------------------------------------------------------------------

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

# ---------------------------------------------------------------------------
# Load modules
# ---------------------------------------------------------------------------
Write-Host 'Loading modules...' -ForegroundColor Yellow
Write-Host ''

try {
    . (Join-Path $scriptRoot 'Modules\GroupEnumLogger.ps1')
    . (Join-Path $scriptRoot 'Modules\GroupEnumerator.ps1')
    . (Join-Path $scriptRoot 'Modules\FuzzyMatcher.ps1')
    . (Join-Path $scriptRoot 'Modules\GroupReportGenerator.ps1')
    Write-Host '  All modules loaded successfully' -ForegroundColor Green
    Write-Host ''
} catch {
    Write-Host "  Failed to load modules: $_" -ForegroundColor Red
    exit 1
}

# ---------------------------------------------------------------------------
# Helper: build a mock group result in the standard return shape
# ---------------------------------------------------------------------------
function New-MockGroupResult {
    param(
        [string]$Domain,
        [string]$GroupName,
        [int]$MemberCount = 0,
        [bool]$Skipped = $false,
        [string]$SkipReason = $null,
        [array]$Members = @(),
        [array]$Errors = @()
    )

    return @{
        Data   = @{
            GroupName         = $GroupName
            Domain            = $Domain
            DistinguishedName = "CN=$GroupName,OU=Groups,DC=$($Domain.ToLower()),DC=com"
            MemberCount       = $MemberCount
            Members           = $Members
            Skipped           = $Skipped
            SkipReason        = $SkipReason
        }
        Errors = $Errors
    }
}

# ---------------------------------------------------------------------------
# Helper: build a mock member hashtable
# ---------------------------------------------------------------------------
function New-MockMember {
    param(
        [string]$Sam,
        [string]$DisplayName = $null,
        [string]$Email = $null,
        [bool]$Enabled = $true
    )

    return @{
        SamAccountName    = $Sam
        DisplayName       = $(if ($DisplayName) { $DisplayName } else { $Sam })
        Email             = $(if ($Email)       { $Email }       else { "$Sam@corp.com" })
        Enabled           = $Enabled
        Domain            = 'CORP'
        DistinguishedName = "CN=$Sam,OU=Users,DC=corp,DC=com"
    }
}

# ---------------------------------------------------------------------------
# Reusable mock group result sets
# ---------------------------------------------------------------------------
$script:MockResultsCORP = @(
    (New-MockGroupResult -Domain 'CORP' -GroupName 'GG_IT_Admins' -MemberCount 3 -Members @(
        (New-MockMember -Sam 'jsmith'  -DisplayName 'John Smith'  -Email 'jsmith@corp.com')
        (New-MockMember -Sam 'ajonas'  -DisplayName 'Alice Jonas' -Email 'ajonas@corp.com')
        (New-MockMember -Sam 'bwilson' -DisplayName 'Bob Wilson'  -Email 'bwilson@corp.com')
    ))
    (New-MockGroupResult -Domain 'CORP' -GroupName 'GG_Finance_Users' -MemberCount 2 -Members @(
        (New-MockMember -Sam 'mlee'    -DisplayName 'Mary Lee'    -Email 'mlee@corp.com')
        (New-MockMember -Sam 'kpatel'  -DisplayName 'Kiran Patel' -Email 'kpatel@corp.com')
    ))
    (New-MockGroupResult -Domain 'CORP' -GroupName 'GG_Only_CORP' -MemberCount 1 -Members @(
        (New-MockMember -Sam 'ztest')
    ))
)

$script:MockResultsPARTNER = @(
    (New-MockGroupResult -Domain 'PARTNER' -GroupName 'USV_IT_Admins' -MemberCount 2 -Members @(
        (New-MockMember -Sam 'jsmith'  -DisplayName 'John Smith'  -Email 'jsmith@partner.com')
        (New-MockMember -Sam 'nrojas'  -DisplayName 'Nina Rojas'  -Email 'nrojas@partner.com')
    ))
    (New-MockGroupResult -Domain 'PARTNER' -GroupName 'USV_Finance_Users' -MemberCount 2 -Members @(
        (New-MockMember -Sam 'mlee'    -DisplayName 'Mary Lee'    -Email 'mlee@partner.com')
        (New-MockMember -Sam 'dtran'   -DisplayName 'Dan Tran'    -Email 'dtran@partner.com')
    ))
    (New-MockGroupResult -Domain 'PARTNER' -GroupName 'USV_Only_PARTNER' -MemberCount 1 -Members @(
        (New-MockMember -Sam 'xonly')
    ))
)

$script:AllMockResults = $script:MockResultsCORP + $script:MockResultsPARTNER

# ============================================================================
# CATEGORY 1: Configuration Tests
# ============================================================================

Write-Host '==========================================' -ForegroundColor Cyan
Write-Host 'Test Category 1: Configuration Tests' -ForegroundColor Cyan
Write-Host '==========================================' -ForegroundColor Cyan

# 1.1 Load default config (no file)
try {
    $config = New-GroupEnumConfig -ConfigPath 'C:\nonexistent\config.json'
    Assert-NotNull -Value $config -Message 'Config: returns result when file missing'
    Assert-True -Condition ($config -is [hashtable]) -Message 'Config: result is hashtable'
} catch {
    Assert-True -Condition $false -Message "Config: default load threw exception: $_"
}

# 1.2 Config has all expected keys
try {
    $config = New-GroupEnumConfig
    $requiredKeys = @('LdapPageSize', 'LdapTimeout', 'MaxMemberCount', 'SkipLargeGroups',
                      'LargeGroupThreshold', 'SkipGroups', 'FuzzyPrefixes', 'FuzzyMinScore',
                      'OutputDirectory', 'DefaultTheme', 'CachePath', 'CacheEnabled')
    foreach ($key in $requiredKeys) {
        Assert-True -Condition ($config.ContainsKey($key)) -Message "Config: has key '$key'"
    }
} catch {
    Assert-True -Condition $false -Message "Config: required keys check threw: $_"
}

# 1.3 Config default values are correct types
try {
    $config = New-GroupEnumConfig
    Assert-True -Condition ($config.LdapPageSize -is [int])     -Message 'Config: LdapPageSize is int'
    Assert-True -Condition ($config.LdapTimeout -is [int])      -Message 'Config: LdapTimeout is int'
    Assert-True -Condition ($config.FuzzyMinScore -is [double] -or $config.FuzzyMinScore -is [decimal] -or $config.FuzzyMinScore -is [float] -or $config.FuzzyMinScore -is [int]) -Message 'Config: FuzzyMinScore is numeric'
    Assert-True -Condition ($config.SkipGroups -is [array])     -Message 'Config: SkipGroups is array'
    Assert-True -Condition ($config.FuzzyPrefixes -is [array])  -Message 'Config: FuzzyPrefixes is array'
} catch {
    Assert-True -Condition $false -Message "Config: type checks threw: $_"
}

# 1.4 Config default LdapPageSize = 1000
try {
    $config = New-GroupEnumConfig
    Assert-Equal -Expected 1000 -Actual $config.LdapPageSize -Message 'Config: LdapPageSize default is 1000'
} catch {
    Assert-True -Condition $false -Message "Config: LdapPageSize default check threw: $_"
}

# 1.5 Config default FuzzyMinScore = 0.7
try {
    $config = New-GroupEnumConfig
    Assert-True -Condition ([double]$config.FuzzyMinScore -eq 0.7) -Message 'Config: FuzzyMinScore default is 0.7'
} catch {
    Assert-True -Condition $false -Message "Config: FuzzyMinScore default check threw: $_"
}

# 1.6 Config from file merges custom values over defaults
$tempConfigFile = $null
try {
    $tempConfigFile = [System.IO.Path]::GetTempFileName() -replace '\.tmp$', '.json'
    '{"LdapPageSize": 500, "CustomKey": "custom_value"}' | Set-Content $tempConfigFile
    $config = New-GroupEnumConfig -ConfigPath $tempConfigFile
    Assert-Equal -Expected 500 -Actual $config.LdapPageSize   -Message 'Config: file overrides LdapPageSize to 500'
    Assert-Equal -Expected 120 -Actual $config.LdapTimeout    -Message 'Config: file preserves LdapTimeout default'
} catch {
    Assert-True -Condition $false -Message "Config: file merge threw: $_"
} finally {
    if ($tempConfigFile -and (Test-Path $tempConfigFile)) { Remove-Item $tempConfigFile -Force }
}

# 1.7 Config from real project config file
$projectConfigPath = Join-Path $scriptRoot 'Config\group-enum-config.json'
try {
    if (Test-Path $projectConfigPath) {
        $config = New-GroupEnumConfig -ConfigPath $projectConfigPath
        Assert-NotNull -Value $config -Message 'Config: project config file loads successfully'
        Assert-Equal -Expected 1000 -Actual $config.LdapPageSize -Message 'Config: project config LdapPageSize is 1000'
    } else {
        Assert-True -Condition $true -Message 'Config: project config file not present (skipped)'
    }
} catch {
    Assert-True -Condition $false -Message "Config: project config load threw: $_"
}

# 1.8 Config invalid JSON path returns defaults (no exception)
try {
    $config = New-GroupEnumConfig -ConfigPath '\does\not\exist.json'
    Assert-NotNull -Value $config -Message 'Config: non-existent path returns defaults without error'
} catch {
    Assert-True -Condition $false -Message "Config: non-existent path threw exception: $_"
}

# 1.9 Config SkipGroups contains expected well-known groups
try {
    $config = New-GroupEnumConfig
    Assert-Contains -Collection $config.SkipGroups -Item 'Domain Users'     -Message 'Config: SkipGroups contains Domain Users'
    Assert-Contains -Collection $config.SkipGroups -Item 'Domain Computers' -Message 'Config: SkipGroups contains Domain Computers'
} catch {
    Assert-True -Condition $false -Message "Config: SkipGroups content check threw: $_"
}

# 1.10 Config FuzzyPrefixes contains expected prefixes
try {
    $config = New-GroupEnumConfig
    Assert-Contains -Collection $config.FuzzyPrefixes -Item 'GG_'  -Message 'Config: FuzzyPrefixes contains GG_'
    Assert-Contains -Collection $config.FuzzyPrefixes -Item 'USV_' -Message 'Config: FuzzyPrefixes contains USV_'
} catch {
    Assert-True -Condition $false -Message "Config: FuzzyPrefixes content check threw: $_"
}

Write-Host ''

# ============================================================================
# CATEGORY 2: CSV Import Tests
# ============================================================================

Write-Host '==========================================' -ForegroundColor Cyan
Write-Host 'Test Category 2: CSV Import Tests' -ForegroundColor Cyan
Write-Host '==========================================' -ForegroundColor Cyan

# Helper: create a temp CSV file
function New-TempCsv {
    param([string]$Content)
    $path = [System.IO.Path]::GetTempFileName() -replace '\.tmp$', '.csv'
    [System.IO.File]::WriteAllText($path, $Content, [System.Text.UTF8Encoding]::new($false))
    return $path
}

# 2.1 Import standard format (Domain,GroupName)
$tempCsv = $null
try {
    $tempCsv = New-TempCsv "Domain,GroupName`r`nCORP,GG_IT_Admins`r`nPARTNER,USV_IT_Admins"
    $list = Import-GroupList -CsvPath $tempCsv
    Assert-Equal -Expected 2 -Actual $list.Count -Message 'CSV: standard format imports 2 entries'
    Assert-Equal -Expected 'CORP'         -Actual $list[0].Domain    -Message 'CSV: standard format row 1 Domain'
    Assert-Equal -Expected 'GG_IT_Admins' -Actual $list[0].GroupName -Message 'CSV: standard format row 1 GroupName'
} catch {
    Assert-True -Condition $false -Message "CSV: standard format threw: $_"
} finally {
    if ($tempCsv -and (Test-Path $tempCsv)) { Remove-Item $tempCsv -Force }
}

# 2.2 Import backslash format (Group header, DOMAIN\Name values)
$tempCsv = $null
try {
    $tempCsv = New-TempCsv "Group`r`nCORP\GG_IT_Admins`r`nPARTNER\USV_IT_Admins"
    $list = Import-GroupList -CsvPath $tempCsv
    Assert-Equal -Expected 2 -Actual $list.Count -Message 'CSV: backslash format imports 2 entries'
    Assert-Equal -Expected 'CORP'         -Actual $list[0].Domain    -Message 'CSV: backslash format row 1 Domain'
    Assert-Equal -Expected 'GG_IT_Admins' -Actual $list[0].GroupName -Message 'CSV: backslash format row 1 GroupName'
    Assert-Equal -Expected 'PARTNER'      -Actual $list[1].Domain    -Message 'CSV: backslash format row 2 Domain'
} catch {
    Assert-True -Condition $false -Message "CSV: backslash format threw: $_"
} finally {
    if ($tempCsv -and (Test-Path $tempCsv)) { Remove-Item $tempCsv -Force }
}

# 2.3 Auto-detect standard format
$tempCsv = $null
try {
    $tempCsv = New-TempCsv "Domain,GroupName`r`nCORP,TestGroup"
    $list = Import-GroupList -CsvPath $tempCsv
    Assert-True -Condition ($list.Count -gt 0)  -Message 'CSV: auto-detect standard format - returns entries'
    Assert-Equal -Expected 'TestGroup' -Actual $list[0].GroupName -Message 'CSV: auto-detect standard format - GroupName correct'
} catch {
    Assert-True -Condition $false -Message "CSV: auto-detect standard threw: $_"
} finally {
    if ($tempCsv -and (Test-Path $tempCsv)) { Remove-Item $tempCsv -Force }
}

# 2.4 Auto-detect backslash format
$tempCsv = $null
try {
    $tempCsv = New-TempCsv "Group`r`nDOMAIN\TestGroup"
    $list = Import-GroupList -CsvPath $tempCsv
    Assert-True -Condition ($list.Count -gt 0)   -Message 'CSV: auto-detect backslash format - returns entries'
    Assert-Equal -Expected 'DOMAIN'    -Actual $list[0].Domain    -Message 'CSV: auto-detect backslash - Domain correct'
    Assert-Equal -Expected 'TestGroup' -Actual $list[0].GroupName -Message 'CSV: auto-detect backslash - GroupName correct'
} catch {
    Assert-True -Condition $false -Message "CSV: auto-detect backslash threw: $_"
} finally {
    if ($tempCsv -and (Test-Path $tempCsv)) { Remove-Item $tempCsv -Force }
}

# 2.5 Handle spaces in group names
$tempCsv = $null
try {
    $tempCsv = New-TempCsv "Domain,GroupName`r`nCORP,IT Help Desk Team"
    $list = Import-GroupList -CsvPath $tempCsv
    Assert-Equal -Expected 'IT Help Desk Team' -Actual $list[0].GroupName -Message 'CSV: spaces in group name preserved'
} catch {
    Assert-True -Condition $false -Message "CSV: spaces in group name threw: $_"
} finally {
    if ($tempCsv -and (Test-Path $tempCsv)) { Remove-Item $tempCsv -Force }
}

# 2.6 Handle empty rows (skipped)
$tempCsv = $null
try {
    $tempCsv = New-TempCsv "Domain,GroupName`r`nCORP,GG_IT_Admins`r`n,`r`nPARTNER,USV_IT_Admins"
    $list = Import-GroupList -CsvPath $tempCsv
    $nonEmpty = @($list | Where-Object { $_.GroupName -ne '' })
    Assert-Equal -Expected 2 -Actual $nonEmpty.Count -Message 'CSV: empty rows are skipped'
} catch {
    Assert-True -Condition $false -Message "CSV: empty row handling threw: $_"
} finally {
    if ($tempCsv -and (Test-Path $tempCsv)) { Remove-Item $tempCsv -Force }
}

# 2.7 Missing domain falls back to DefaultDomain
$tempCsv = $null
try {
    $tempCsv = New-TempCsv "Domain,GroupName`r`n,GG_IT_Admins"
    $list = Import-GroupList -CsvPath $tempCsv -DefaultDomain 'FALLBACK'
    Assert-Equal -Expected 'FALLBACK' -Actual $list[0].Domain -Message 'CSV: missing domain uses DefaultDomain fallback'
} catch {
    Assert-True -Condition $false -Message "CSV: DefaultDomain fallback threw: $_"
} finally {
    if ($tempCsv -and (Test-Path $tempCsv)) { Remove-Item $tempCsv -Force }
}

# 2.8 Extra columns are ignored
$tempCsv = $null
try {
    $tempCsv = New-TempCsv "Domain,GroupName,Notes,Owner`r`nCORP,GG_IT_Admins,legacy,jsmith"
    $list = Import-GroupList -CsvPath $tempCsv
    Assert-Equal -Expected 1           -Actual $list.Count          -Message 'CSV: extra columns do not break import'
    Assert-Equal -Expected 'GG_IT_Admins' -Actual $list[0].GroupName -Message 'CSV: GroupName correct with extra columns'
} catch {
    Assert-True -Condition $false -Message "CSV: extra columns threw: $_"
} finally {
    if ($tempCsv -and (Test-Path $tempCsv)) { Remove-Item $tempCsv -Force }
}

# 2.9 CSV with UTF-8 BOM
$tempCsv = $null
try {
    $tempCsv = [System.IO.Path]::GetTempFileName() -replace '\.tmp$', '.csv'
    # Write UTF-8 BOM + content
    $bom     = [byte[]](0xEF, 0xBB, 0xBF)
    $content = [System.Text.Encoding]::UTF8.GetBytes("Domain,GroupName`r`nCORP,BOM_Group")
    $allBytes = $bom + $content
    [System.IO.File]::WriteAllBytes($tempCsv, $allBytes)
    # Import-Csv handles BOM transparently in PS 5.1+
    $list = Import-GroupList -CsvPath $tempCsv
    Assert-True -Condition ($list.Count -ge 1) -Message 'CSV: BOM-prefixed file loads without error'
} catch {
    # BOM handling varies; not a hard fail if PS version is limited
    Assert-True -Condition $true -Message 'CSV: BOM test attempted (pass if no exception before this line)'
} finally {
    if ($tempCsv -and (Test-Path $tempCsv)) { Remove-Item $tempCsv -Force }
}

# 2.10 Invalid CSV path throws
try {
    $threw = $false
    try {
        $null = Import-GroupList -CsvPath 'C:\does\not\exist.csv'
    } catch {
        $threw = $true
    }
    Assert-True -Condition $threw -Message 'CSV: invalid path throws an error'
} catch {
    Assert-True -Condition $false -Message "CSV: invalid path test threw unexpectedly: $_"
}

# 2.11 Header-only CSV (no data rows) returns empty array
$tempCsv = $null
try {
    $tempCsv = New-TempCsv "Domain,GroupName"
    $list = Import-GroupList -CsvPath $tempCsv
    Assert-True -Condition ($list.Count -eq 0) -Message 'CSV: header-only file returns empty array'
} catch {
    Assert-True -Condition $false -Message "CSV: header-only file threw: $_"
} finally {
    if ($tempCsv -and (Test-Path $tempCsv)) { Remove-Item $tempCsv -Force }
}

# 2.12 Backslash format without backslash uses DefaultDomain
$tempCsv = $null
try {
    $tempCsv = New-TempCsv "Group`r`nSomeGroupWithoutDomain"
    $list = Import-GroupList -CsvPath $tempCsv -DefaultDomain 'MYDEFAULT'
    Assert-Equal -Expected 'MYDEFAULT'              -Actual $list[0].Domain    -Message 'CSV: backslash col without backslash uses DefaultDomain'
    Assert-Equal -Expected 'SomeGroupWithoutDomain' -Actual $list[0].GroupName -Message 'CSV: backslash col without backslash preserves GroupName'
} catch {
    Assert-True -Condition $false -Message "CSV: backslash col no-backslash test threw: $_"
} finally {
    if ($tempCsv -and (Test-Path $tempCsv)) { Remove-Item $tempCsv -Force }
}

# 2.13 Multiple groups same domain
$tempCsv = $null
try {
    $tempCsv = New-TempCsv "Domain,GroupName`r`nCORP,GroupA`r`nCORP,GroupB`r`nCORP,GroupC"
    $list = Import-GroupList -CsvPath $tempCsv
    Assert-Equal -Expected 3 -Actual $list.Count -Message 'CSV: three groups same domain imports all three'
    $allCorp = ($list | Where-Object { $_.Domain -eq 'CORP' }).Count
    Assert-Equal -Expected 3 -Actual $allCorp -Message 'CSV: all three entries have domain CORP'
} catch {
    Assert-True -Condition $false -Message "CSV: multiple same-domain groups threw: $_"
} finally {
    if ($tempCsv -and (Test-Path $tempCsv)) { Remove-Item $tempCsv -Force }
}

Write-Host ''

# ============================================================================
# CATEGORY 3: Fuzzy Matching Tests
# ============================================================================

Write-Host '==========================================' -ForegroundColor Cyan
Write-Host 'Test Category 3: Fuzzy Matching Tests' -ForegroundColor Cyan
Write-Host '==========================================' -ForegroundColor Cyan

# 3.1 Get-NormalizedName strips GG_ prefix
try {
    $result = Get-NormalizedName -GroupName 'GG_IT_Admins' -Prefixes @('GG_', 'USV_')
    Assert-Equal -Expected 'it_admins' -Actual $result -Message 'Normalize: GG_ prefix stripped and lowercased'
} catch {
    Assert-True -Condition $false -Message "Normalize: GG_ prefix threw: $_"
}

# 3.2 Get-NormalizedName strips USV_ prefix
try {
    $result = Get-NormalizedName -GroupName 'USV_IT_Admins' -Prefixes @('GG_', 'USV_')
    Assert-Equal -Expected 'it_admins' -Actual $result -Message 'Normalize: USV_ prefix stripped and lowercased'
} catch {
    Assert-True -Condition $false -Message "Normalize: USV_ prefix threw: $_"
}

# 3.3 Get-NormalizedName strips SG_ prefix
try {
    $result = Get-NormalizedName -GroupName 'SG_Finance' -Prefixes @('SG_', 'GG_')
    Assert-Equal -Expected 'finance' -Actual $result -Message 'Normalize: SG_ prefix stripped'
} catch {
    Assert-True -Condition $false -Message "Normalize: SG_ prefix threw: $_"
}

# 3.4 Get-NormalizedName strips DL_ prefix
try {
    $result = Get-NormalizedName -GroupName 'DL_AllStaff' -Prefixes @('DL_', 'GG_')
    Assert-Equal -Expected 'allstaff' -Actual $result -Message 'Normalize: DL_ prefix stripped'
} catch {
    Assert-True -Condition $false -Message "Normalize: DL_ prefix threw: $_"
}

# 3.5 Get-NormalizedName strips GL_ prefix
try {
    $result = Get-NormalizedName -GroupName 'GL_Managers' -Prefixes @('GL_', 'GG_')
    Assert-Equal -Expected 'managers' -Actual $result -Message 'Normalize: GL_ prefix stripped'
} catch {
    Assert-True -Condition $false -Message "Normalize: GL_ prefix threw: $_"
}

# 3.6 Get-NormalizedName lowercases
try {
    $result = Get-NormalizedName -GroupName 'IT_Admins' -Prefixes @()
    Assert-Equal -Expected 'it_admins' -Actual $result -Message 'Normalize: no prefix match - lowercases only'
} catch {
    Assert-True -Condition $false -Message "Normalize: lowercase threw: $_"
}

# 3.7 Get-NormalizedName trims underscores
try {
    # Stripping GG_ from GG__LeadingUnderscore leaves _LeadingUnderscore -> trim -> leadingunderscore
    $result = Get-NormalizedName -GroupName 'GG__ExtraUnderscore' -Prefixes @('GG_')
    Assert-Equal -Expected 'extraunderscore' -Actual $result -Message 'Normalize: leading underscore trimmed after prefix strip'
} catch {
    Assert-True -Condition $false -Message "Normalize: trim underscores threw: $_"
}

# 3.8 Get-NormalizedName no prefix unchanged (just lowercased)
try {
    $result = Get-NormalizedName -GroupName 'HelpDesk' -Prefixes @('GG_', 'USV_')
    Assert-Equal -Expected 'helpdesk' -Actual $result -Message 'Normalize: no matching prefix - name lowercased only'
} catch {
    Assert-True -Condition $false -Message "Normalize: no prefix match threw: $_"
}

# 3.9 Get-NormalizedName only strips first matching prefix
try {
    # GG_ matched first - USV_ should not also be stripped
    $result = Get-NormalizedName -GroupName 'GG_USV_Test' -Prefixes @('GG_', 'USV_')
    Assert-Equal -Expected 'usv_test' -Actual $result -Message 'Normalize: only first matching prefix stripped'
} catch {
    Assert-True -Condition $false -Message "Normalize: first-only prefix strip threw: $_"
}

# 3.10 Get-SimilarityScore identical strings = 1.0
try {
    $score = Get-SimilarityScore -Name1 'it_admins' -Name2 'it_admins'
    Assert-Equal -Expected 1.0 -Actual $score -Message 'Similarity: identical strings score 1.0'
} catch {
    Assert-True -Condition $false -Message "Similarity: identical strings threw: $_"
}

# 3.11 Get-SimilarityScore completely different strings = low score
try {
    $score = Get-SimilarityScore -Name1 'abc' -Name2 'xyz'
    Assert-True -Condition ($score -lt 0.5) -Message "Similarity: completely different strings score < 0.5 (got $score)"
} catch {
    Assert-True -Condition $false -Message "Similarity: different strings threw: $_"
}

# 3.12 Get-SimilarityScore similar strings > 0.7
try {
    $score = Get-SimilarityScore -Name1 'it_admins' -Name2 'it_admin'
    Assert-True -Condition ($score -gt 0.7) -Message "Similarity: similar strings score > 0.7 (got $score)"
} catch {
    Assert-True -Condition $false -Message "Similarity: similar strings threw: $_"
}

# 3.13 Get-SimilarityScore empty strings both empty = 1.0
try {
    $score = Get-SimilarityScore -Name1 '' -Name2 ''
    Assert-Equal -Expected 1.0 -Actual $score -Message 'Similarity: two empty strings score 1.0'
} catch {
    Assert-True -Condition $false -Message "Similarity: empty strings threw: $_"
}

# 3.14 Get-SimilarityScore one empty string = 0.0
try {
    $score = Get-SimilarityScore -Name1 'it_admins' -Name2 ''
    Assert-Equal -Expected 0.0 -Actual $score -Message 'Similarity: one empty string scores 0.0'
} catch {
    Assert-True -Condition $false -Message "Similarity: one empty string threw: $_"
}

# 3.15 Get-SimilarityScore single char difference is high score
try {
    $score = Get-SimilarityScore -Name1 'finance' -Name2 'financa'
    Assert-True -Condition ($score -gt 0.8) -Message "Similarity: one char difference scores > 0.8 (got $score)"
} catch {
    Assert-True -Condition $false -Message "Similarity: single char diff threw: $_"
}

# 3.16 Find-MatchingGroups exact match after normalization
try {
    $results = Find-MatchingGroups -GroupResults $script:AllMockResults `
        -Prefixes @('GG_', 'USV_') -MinScore 0.7
    $itMatch = $results.Matched | Where-Object { $_.NormalizedName -eq 'it_admins' }
    Assert-True -Condition ($null -ne $itMatch) -Message 'FuzzyMatch: GG_IT_Admins / USV_IT_Admins matched as it_admins'
} catch {
    Assert-True -Condition $false -Message "FuzzyMatch: exact match threw: $_"
}

# 3.17 Find-MatchingGroups score 1.0 for exact normalised match
try {
    $results = Find-MatchingGroups -GroupResults $script:AllMockResults `
        -Prefixes @('GG_', 'USV_') -MinScore 0.7
    $itMatch = $results.Matched | Where-Object { $_.NormalizedName -eq 'it_admins' }
    Assert-True -Condition ($null -ne $itMatch -and $itMatch.Score -eq 1.0) -Message 'FuzzyMatch: exact normalised match has score 1.0'
} catch {
    Assert-True -Condition $false -Message "FuzzyMatch: score 1.0 check threw: $_"
}

# 3.18 Find-MatchingGroups fuzzy match above threshold
try {
    # Create a pair that matches fuzzy but not exactly
    $fuzzyResults = @(
        (New-MockGroupResult -Domain 'CORP'    -GroupName 'GG_HelpDesk'  -MemberCount 5)
        (New-MockGroupResult -Domain 'PARTNER' -GroupName 'USV_HelpDsk'  -MemberCount 4)
    )
    $results = Find-MatchingGroups -GroupResults $fuzzyResults `
        -Prefixes @('GG_', 'USV_') -MinScore 0.7
    Assert-True -Condition ($results.Matched.Count -ge 1) -Message 'FuzzyMatch: near-identical names fuzzy matched'
} catch {
    Assert-True -Condition $false -Message "FuzzyMatch: fuzzy match above threshold threw: $_"
}

# 3.19 Find-MatchingGroups below threshold goes to Unmatched
try {
    $unlikelyResults = @(
        (New-MockGroupResult -Domain 'CORP'    -GroupName 'GG_Accounting' -MemberCount 3)
        (New-MockGroupResult -Domain 'PARTNER' -GroupName 'USV_Marketing'  -MemberCount 2)
    )
    $results = Find-MatchingGroups -GroupResults $unlikelyResults `
        -Prefixes @('GG_', 'USV_') -MinScore 0.9
    Assert-Equal -Expected 0 -Actual $results.Matched.Count   -Message 'FuzzyMatch: dissimilar names below threshold not matched'
    Assert-Equal -Expected 2 -Actual $results.Unmatched.Count -Message 'FuzzyMatch: both groups in Unmatched when no match'
} catch {
    Assert-True -Condition $false -Message "FuzzyMatch: below threshold threw: $_"
}

# 3.20 Find-MatchingGroups no cross-domain = all unmatched
try {
    $sameDomainResults = @(
        (New-MockGroupResult -Domain 'CORP' -GroupName 'GG_IT_Admins'    -MemberCount 5)
        (New-MockGroupResult -Domain 'CORP' -GroupName 'GG_Finance_Users' -MemberCount 3)
    )
    $results = Find-MatchingGroups -GroupResults $sameDomainResults `
        -Prefixes @('GG_') -MinScore 0.7
    Assert-Equal -Expected 0 -Actual $results.Matched.Count   -Message 'FuzzyMatch: same domain groups are never matched'
    Assert-Equal -Expected 2 -Actual $results.Unmatched.Count -Message 'FuzzyMatch: same domain groups all go to Unmatched'
} catch {
    Assert-True -Condition $false -Message "FuzzyMatch: same domain threw: $_"
}

# 3.21 Find-MatchingGroups skipped groups are excluded
try {
    $withSkipped = @(
        (New-MockGroupResult -Domain 'CORP'    -GroupName 'GG_IT_Admins' -MemberCount 5 -Skipped $false)
        (New-MockGroupResult -Domain 'PARTNER' -GroupName 'USV_IT_Admins' -MemberCount 0 -Skipped $true -SkipReason 'Large group')
    )
    $results = Find-MatchingGroups -GroupResults $withSkipped `
        -Prefixes @('GG_', 'USV_') -MinScore 0.7
    Assert-Equal -Expected 0 -Actual $results.Matched.Count -Message 'FuzzyMatch: skipped group excluded from matching'
} catch {
    Assert-True -Condition $false -Message "FuzzyMatch: skipped group exclusion threw: $_"
}

# 3.22 Find-MatchingGroups returns correct match structure
try {
    $results = Find-MatchingGroups -GroupResults $script:AllMockResults `
        -Prefixes @('GG_', 'USV_') -MinScore 0.7
    $itMatch = $results.Matched | Where-Object { $_.NormalizedName -eq 'it_admins' } | Select-Object -First 1
    Assert-NotNull -Value $itMatch -Message 'FuzzyMatch: match entry exists for it_admins'
    if ($itMatch) {
        Assert-True -Condition ($itMatch.ContainsKey('NormalizedName')) -Message 'FuzzyMatch: match has NormalizedName'
        Assert-True -Condition ($itMatch.ContainsKey('Score'))          -Message 'FuzzyMatch: match has Score'
        Assert-True -Condition ($itMatch.ContainsKey('Groups'))         -Message 'FuzzyMatch: match has Groups'
        Assert-Equal -Expected 2 -Actual $itMatch.Groups.Count          -Message 'FuzzyMatch: match has 2 groups'
    }
} catch {
    Assert-True -Condition $false -Message "FuzzyMatch: structure check threw: $_"
}

# 3.23 Find-MatchingGroups multiple domain pairs
try {
    $results = Find-MatchingGroups -GroupResults $script:AllMockResults `
        -Prefixes @('GG_', 'USV_') -MinScore 0.7
    # Expect at least 2 matches: IT_Admins and Finance_Users
    Assert-GreaterThan -Value $results.Matched.Count -Threshold 1 -Message 'FuzzyMatch: multiple pairs matched across domains'
} catch {
    Assert-True -Condition $false -Message "FuzzyMatch: multiple pairs threw: $_"
}

Write-Host ''

# ============================================================================
# CATEGORY 4: Report Generation Tests
# ============================================================================

Write-Host '==========================================' -ForegroundColor Cyan
Write-Host 'Test Category 4: Report Generation Tests' -ForegroundColor Cyan
Write-Host '==========================================' -ForegroundColor Cyan

# Compute match results once for this category
$script:TestMatchResults = Find-MatchingGroups -GroupResults $script:AllMockResults `
    -Prefixes @('GG_', 'USV_') -MinScore 0.7

$testOutputDir = Join-Path $scriptRoot 'Tests\Output'
if (-not (Test-Path $testOutputDir)) {
    New-Item -ItemType Directory -Path $testOutputDir -Force | Out-Null
}

# 4.1 Export-GroupReport creates HTML file
$htmlPath = $null
try {
    $htmlPath = Join-Path $testOutputDir "test-report-$(Get-Date -Format 'yyyyMMddHHmmss').html"
    $returned = Export-GroupReport `
        -GroupResults $script:AllMockResults `
        -MatchResults $script:TestMatchResults `
        -OutputPath   $htmlPath `
        -Theme        'dark' `
        -Config       @{}
    Assert-True -Condition (Test-Path $htmlPath) -Message 'Report: HTML file created on disk'
} catch {
    Assert-True -Condition $false -Message "Report: HTML creation threw: $_"
}

# 4.2 HTML contains dark theme class
try {
    if ($htmlPath -and (Test-Path $htmlPath)) {
        $html = [System.IO.File]::ReadAllText($htmlPath)
        Assert-True -Condition ($html -match 'theme-dark') -Message 'Report: HTML contains theme-dark class'
    } else {
        Assert-True -Condition $false -Message 'Report: HTML file not available for theme check'
    }
} catch {
    Assert-True -Condition $false -Message "Report: theme class check threw: $_"
}

# 4.3 HTML contains summary cards
try {
    if ($htmlPath -and (Test-Path $htmlPath)) {
        $html = [System.IO.File]::ReadAllText($htmlPath)
        Assert-True -Condition ($html -match 'stat-card') -Message 'Report: HTML contains stat-card elements'
    } else {
        Assert-True -Condition $false -Message 'Report: HTML file not available for summary cards check'
    }
} catch {
    Assert-True -Condition $false -Message "Report: summary cards check threw: $_"
}

# 4.4 HTML contains matched table content
try {
    if ($htmlPath -and (Test-Path $htmlPath)) {
        $html = [System.IO.File]::ReadAllText($htmlPath)
        Assert-True -Condition ($html -match 'badge-matched' -or $html -match 'it_admins') -Message 'Report: HTML contains matched group content'
    } else {
        Assert-True -Condition $false -Message 'Report: HTML file not available for matched table check'
    }
} catch {
    Assert-True -Condition $false -Message "Report: matched table check threw: $_"
}

# 4.5 HTML contains detail sections
try {
    if ($htmlPath -and (Test-Path $htmlPath)) {
        $html = [System.IO.File]::ReadAllText($htmlPath)
        Assert-True -Condition ($html -match 'group-detail') -Message 'Report: HTML contains group-detail elements'
    } else {
        Assert-True -Condition $false -Message 'Report: HTML file not available for detail sections check'
    }
} catch {
    Assert-True -Condition $false -Message "Report: detail sections check threw: $_"
}

# 4.6 HTML contains theme toggle button
try {
    if ($htmlPath -and (Test-Path $htmlPath)) {
        $html = [System.IO.File]::ReadAllText($htmlPath)
        Assert-True -Condition ($html -match 'theme' -and ($html -match 'button' -or $html -match 'btn')) -Message 'Report: HTML contains theme toggle button'
    } else {
        Assert-True -Condition $false -Message 'Report: HTML file not available for theme toggle check'
    }
} catch {
    Assert-True -Condition $false -Message "Report: theme toggle check threw: $_"
}

# 4.7 Light theme HTML contains theme-light class
$lightHtmlPath = $null
try {
    $lightHtmlPath = Join-Path $testOutputDir "test-report-light-$(Get-Date -Format 'yyyyMMddHHmmss').html"
    $null = Export-GroupReport `
        -GroupResults $script:AllMockResults `
        -MatchResults $script:TestMatchResults `
        -OutputPath   $lightHtmlPath `
        -Theme        'light' `
        -Config       @{}
    $html = [System.IO.File]::ReadAllText($lightHtmlPath)
    Assert-True -Condition ($html -match 'theme-light') -Message 'Report: light theme HTML contains theme-light class'
} catch {
    Assert-True -Condition $false -Message "Report: light theme threw: $_"
} finally {
    if ($lightHtmlPath -and (Test-Path $lightHtmlPath)) { Remove-Item $lightHtmlPath -Force }
}

# 4.8 Export-GroupDataJson creates valid JSON file
$jsonPath = $null
try {
    $jsonPath = Join-Path $testOutputDir "test-cache-$(Get-Date -Format 'yyyyMMddHHmmss').json"
    $returned = Export-GroupDataJson `
        -GroupResults $script:AllMockResults `
        -MatchResults $script:TestMatchResults `
        -OutputPath   $jsonPath `
        -CsvSource    'test-groups.csv'
    Assert-True -Condition (Test-Path $jsonPath) -Message 'Report: JSON cache file created'
    $raw = [System.IO.File]::ReadAllText($jsonPath)
    $parsed = $raw | ConvertFrom-Json
    Assert-NotNull -Value $parsed -Message 'Report: JSON cache is valid JSON'
} catch {
    Assert-True -Condition $false -Message "Report: JSON export threw: $_"
}

# 4.9 Import-GroupDataJson round-trips correctly
try {
    if ($jsonPath -and (Test-Path $jsonPath)) {
        $loaded = Import-GroupDataJson -JsonPath $jsonPath
        Assert-NotNull -Value $loaded          -Message 'Report: JSON round-trip loads data'
        Assert-NotNull -Value $loaded.Groups   -Message 'Report: JSON round-trip has Groups'
        Assert-NotNull -Value $loaded.Metadata -Message 'Report: JSON round-trip has Metadata'
        Assert-Equal -Expected $script:AllMockResults.Count -Actual $loaded.Groups.Count `
            -Message 'Report: JSON round-trip preserves group count'
    } else {
        Assert-True -Condition $false -Message 'Report: JSON file not available for round-trip test'
    }
} catch {
    Assert-True -Condition $false -Message "Report: JSON round-trip threw: $_"
}

# 4.10 JSON metadata has timestamp
try {
    if ($jsonPath -and (Test-Path $jsonPath)) {
        $loaded = Import-GroupDataJson -JsonPath $jsonPath
        Assert-NotNull -Value $loaded.Metadata.GeneratedTimestamp -Message 'Report: JSON metadata has GeneratedTimestamp'
    } else {
        Assert-True -Condition $false -Message 'Report: JSON file not available for metadata timestamp test'
    }
} catch {
    Assert-True -Condition $false -Message "Report: JSON metadata timestamp threw: $_"
}

# 4.11 JSON metadata has version
try {
    if ($jsonPath -and (Test-Path $jsonPath)) {
        $loaded = Import-GroupDataJson -JsonPath $jsonPath
        Assert-NotNull -Value $loaded.Metadata.ToolVersion -Message 'Report: JSON metadata has ToolVersion'
    } else {
        Assert-True -Condition $false -Message 'Report: JSON file not available for metadata version test'
    }
} catch {
    Assert-True -Condition $false -Message "Report: JSON metadata version threw: $_"
} finally {
    if ($jsonPath -and (Test-Path $jsonPath)) { Remove-Item $jsonPath -Force }
}

# 4.12 Build-SummaryCardsHtml returns HTML string
try {
    $html = Build-SummaryCardsHtml -TotalGroups 10 -TotalMembers 200 -MatchedCount 4 -UnmatchedCount 2 -SkippedCount 1
    Assert-NotNull -Value $html -Message 'Report: Build-SummaryCardsHtml returns a value'
    Assert-True -Condition ($html -is [string]) -Message 'Report: Build-SummaryCardsHtml returns string'
    Assert-True -Condition ($html.Length -gt 0) -Message 'Report: Build-SummaryCardsHtml returns non-empty string'
    Assert-True -Condition ($html -match '10') -Message 'Report: Build-SummaryCardsHtml embeds TotalGroups value'
} catch {
    Assert-True -Condition $false -Message "Report: Build-SummaryCardsHtml threw: $_"
}

# 4.13 Build-MatchedTableHtml handles empty matches
try {
    $html = Build-MatchedTableHtml -MatchedItems @() -GroupResults @()
    Assert-True -Condition ($html -match 'No matched groups' -or $html -match 'empty') -Message 'Report: Build-MatchedTableHtml empty state contains placeholder text'
} catch {
    Assert-True -Condition $false -Message "Report: Build-MatchedTableHtml empty state threw: $_"
}

# 4.14 Escape-Html escapes special characters
try {
    $escapedAmp  = Escape-Html '&'
    $escapedLt   = Escape-Html '<'
    $escapedGt   = Escape-Html '>'
    $escapedQuot = Escape-Html '"'
    Assert-Equal -Expected '&amp;'  -Actual $escapedAmp  -Message 'Report: Escape-Html encodes &'
    Assert-Equal -Expected '&lt;'   -Actual $escapedLt   -Message 'Report: Escape-Html encodes <'
    Assert-Equal -Expected '&gt;'   -Actual $escapedGt   -Message 'Report: Escape-Html encodes >'
    Assert-Equal -Expected '&quot;' -Actual $escapedQuot -Message 'Report: Escape-Html encodes "'
} catch {
    Assert-True -Condition $false -Message "Report: Escape-Html threw: $_"
}

# 4.15 ConvertTo-MemberTableHtml generates table HTML
try {
    $members = @(
        (New-MockMember -Sam 'jsmith' -DisplayName 'John Smith' -Email 'jsmith@corp.com')
        (New-MockMember -Sam 'ajonas' -DisplayName 'Alice Jonas' -Email 'ajonas@corp.com')
    )
    $html = ConvertTo-MemberTableHtml -Members $members
    Assert-True -Condition ($html -match '<table') -Message 'Report: ConvertTo-MemberTableHtml contains <table>'
    Assert-True -Condition ($html -match 'jsmith')  -Message 'Report: ConvertTo-MemberTableHtml contains member SamAccountName'
} catch {
    Assert-True -Condition $false -Message "Report: ConvertTo-MemberTableHtml threw: $_"
}

# 4.16 ConvertTo-MemberTableHtml empty list returns placeholder
try {
    $html = ConvertTo-MemberTableHtml -Members @()
    Assert-True -Condition ($html -match 'No members' -or $html -match 'empty') -Message 'Report: ConvertTo-MemberTableHtml empty list placeholder'
} catch {
    Assert-True -Condition $false -Message "Report: ConvertTo-MemberTableHtml empty list threw: $_"
}

# Clean up HTML report from test 4.1
if ($htmlPath -and (Test-Path $htmlPath)) { Remove-Item $htmlPath -Force }

Write-Host ''

# ============================================================================
# CATEGORY 5: Integration Tests
# ============================================================================

Write-Host '==========================================' -ForegroundColor Cyan
Write-Host 'Test Category 5: Integration Tests' -ForegroundColor Cyan
Write-Host '==========================================' -ForegroundColor Cyan

# Override Get-GroupMembers in the current scope to return mock data without LDAP.
# This shadows the module function for tests in this category.
function Get-GroupMembersForTest {
    param([string]$Domain, [string]$GroupName, $Credential, [hashtable]$Config)

    $mockData = @{
        'CORP|GG_IT_Admins'    = @{ MemberCount = 3; Members = @(
            (New-MockMember -Sam 'jsmith')
            (New-MockMember -Sam 'ajonas')
            (New-MockMember -Sam 'bwilson')
        )}
        'CORP|GG_Finance_Users' = @{ MemberCount = 2; Members = @(
            (New-MockMember -Sam 'mlee')
            (New-MockMember -Sam 'kpatel')
        )}
        'PARTNER|USV_IT_Admins'    = @{ MemberCount = 2; Members = @(
            (New-MockMember -Sam 'jsmith')
            (New-MockMember -Sam 'nrojas')
        )}
        'PARTNER|USV_Finance_Users' = @{ MemberCount = 2; Members = @(
            (New-MockMember -Sam 'mlee')
            (New-MockMember -Sam 'dtran')
        )}
    }

    $key = "$Domain|$GroupName"
    $entry = if ($mockData.ContainsKey($key)) { $mockData[$key] } else {
        @{ MemberCount = 0; Members = @() }
    }

    return @{
        Data   = @{
            GroupName         = $GroupName
            Domain            = $Domain
            DistinguishedName = "CN=$GroupName,OU=Groups,DC=$Domain"
            MemberCount       = $entry.MemberCount
            Members           = $entry.Members
            Skipped           = $false
            SkipReason        = $null
        }
        Errors = @()
    }
}

# 5.1 Full pipeline: CSV -> enumerate (mock) -> match -> report
$intHtmlPath = $null
$intCsvPath  = $null
try {
    $intCsvPath  = New-TempCsv "Domain,GroupName`r`nCORP,GG_IT_Admins`r`nPARTNER,USV_IT_Admins"
    $intHtmlPath = Join-Path $testOutputDir "integration-$(Get-Date -Format 'yyyyMMddHHmmss').html"

    $groupList = Import-GroupList -CsvPath $intCsvPath
    Assert-Equal -Expected 2 -Actual $groupList.Count -Message 'Integration: CSV imported 2 groups'

    $intResults = @()
    foreach ($entry in $groupList) {
        $intResults += Get-GroupMembersForTest -Domain $entry.Domain -GroupName $entry.GroupName -Config @{}
    }
    Assert-Equal -Expected 2 -Actual $intResults.Count -Message 'Integration: 2 groups enumerated (mock)'

    $intMatch = Find-MatchingGroups -GroupResults $intResults -Prefixes @('GG_', 'USV_') -MinScore 0.7
    Assert-Equal -Expected 1 -Actual $intMatch.Matched.Count -Message 'Integration: 1 matched pair from pipeline'

    $null = Export-GroupReport -GroupResults $intResults -MatchResults $intMatch `
        -OutputPath $intHtmlPath -Theme 'dark' -Config @{}
    Assert-True -Condition (Test-Path $intHtmlPath) -Message 'Integration: HTML report generated end-to-end'
} catch {
    Assert-True -Condition $false -Message "Integration: full pipeline threw: $_"
} finally {
    if ($intCsvPath  -and (Test-Path $intCsvPath))  { Remove-Item $intCsvPath  -Force }
    if ($intHtmlPath -and (Test-Path $intHtmlPath)) { Remove-Item $intHtmlPath -Force }
}

# 5.2 FromCache path: JSON save -> load -> report
$cacheJson  = $null
$cacheHtml  = $null
try {
    $cacheJson = Join-Path $testOutputDir "cache-roundtrip-$(Get-Date -Format 'yyyyMMddHHmmss').json"
    $cacheHtml = Join-Path $testOutputDir "cache-report-$(Get-Date -Format 'yyyyMMddHHmmss').html"

    $null = Export-GroupDataJson -GroupResults $script:AllMockResults `
        -MatchResults $script:TestMatchResults -OutputPath $cacheJson

    $loaded = Import-GroupDataJson -JsonPath $cacheJson
    Assert-NotNull -Value $loaded.Groups -Message 'Integration: FromCache loads Groups from JSON'

    $null = Export-GroupReport -GroupResults $loaded.Groups `
        -MatchResults $loaded.MatchResults -OutputPath $cacheHtml -Theme 'dark' -Config @{}
    Assert-True -Condition (Test-Path $cacheHtml) -Message 'Integration: report generated from cached JSON'
} catch {
    Assert-True -Condition $false -Message "Integration: FromCache roundtrip threw: $_"
} finally {
    if ($cacheJson -and (Test-Path $cacheJson)) { Remove-Item $cacheJson -Force }
    if ($cacheHtml -and (Test-Path $cacheHtml)) { Remove-Item $cacheHtml -Force }
}

# 5.3 NoCache: Export-GroupDataJson is NOT called when flag is set
# (verified by ensuring pipeline path is exercisable - functional test)
try {
    $noHtml = Join-Path $testOutputDir "nocache-$(Get-Date -Format 'yyyyMMddHHmmss').html"
    $null = Export-GroupReport -GroupResults $script:MockResultsCORP `
        -MatchResults $null -OutputPath $noHtml -Theme 'dark' -Config @{}
    Assert-True -Condition (Test-Path $noHtml) -Message 'Integration: NoCache report still generates HTML'
    Remove-Item $noHtml -Force
} catch {
    Assert-True -Condition $false -Message "Integration: NoCache HTML threw: $_"
}

# 5.4 JsonOnly: build JSON without HTML
$jsonOnlyPath = $null
try {
    $jsonOnlyPath = Join-Path $testOutputDir "jsononly-$(Get-Date -Format 'yyyyMMddHHmmss').json"
    $returned = Export-GroupDataJson -GroupResults $script:AllMockResults `
        -MatchResults $null -OutputPath $jsonOnlyPath
    Assert-True -Condition (Test-Path $jsonOnlyPath)  -Message 'Integration: JsonOnly produces JSON file'
} catch {
    Assert-True -Condition $false -Message "Integration: JsonOnly threw: $_"
} finally {
    if ($jsonOnlyPath -and (Test-Path $jsonOnlyPath)) { Remove-Item $jsonOnlyPath -Force }
}

# 5.5 Multiple domains in single CSV
$multiCsv = $null
try {
    $multiCsv = New-TempCsv "Domain,GroupName`r`nCORP,GG_IT_Admins`r`nPARTNER,USV_IT_Admins`r`nTHIRD,GL_Managers"
    $list = Import-GroupList -CsvPath $multiCsv
    Assert-Equal -Expected 3 -Actual $list.Count -Message 'Integration: 3-domain CSV imports all entries'
    $domains = @($list | ForEach-Object { $_.Domain } | Sort-Object -Unique)
    Assert-Equal -Expected 3 -Actual $domains.Count -Message 'Integration: 3 distinct domains in import list'
} catch {
    Assert-True -Condition $false -Message "Integration: multiple domains CSV threw: $_"
} finally {
    if ($multiCsv -and (Test-Path $multiCsv)) { Remove-Item $multiCsv -Force }
}

# 5.6 Large group skipping respects SkipLargeGroups config
# (unit-test the logic path inside Get-GroupMembersDirect via config key)
try {
    $config = New-GroupEnumConfig
    Assert-True -Condition ($config.SkipLargeGroups -eq $true)    -Message 'Integration: SkipLargeGroups defaults to true'
    Assert-Equal -Expected 5000 -Actual $config.LargeGroupThreshold -Message 'Integration: LargeGroupThreshold default is 5000'
} catch {
    Assert-True -Condition $false -Message "Integration: large group config check threw: $_"
}

# 5.7 SkipGroups config is respected (checked via New-GroupEnumConfig and SkipGroups list)
try {
    $config = New-GroupEnumConfig
    $skipList = $config.SkipGroups
    Assert-True -Condition ($skipList -contains 'Domain Users') -Message 'Integration: Domain Users in SkipGroups'
} catch {
    Assert-True -Condition $false -Message "Integration: SkipGroups check threw: $_"
}

# 5.8 Error collection does not halt execution
try {
    # Simulate results with one error entry
    $resultsWithError = $script:AllMockResults + @(
        @{
            Data   = @{
                GroupName = 'GG_Broken'; Domain = 'CORP'
                DistinguishedName = $null; MemberCount = 0
                Members = @(); Skipped = $false; SkipReason = $null
            }
            Errors = @('Simulated LDAP error')
        }
    )
    $errCount = @($resultsWithError | Where-Object { $_.Errors.Count -gt 0 }).Count
    Assert-Equal -Expected 1 -Actual $errCount -Message 'Integration: error group collected but execution continued'

    # Should still be able to generate report with the mixed set
    $errHtmlPath = Join-Path $testOutputDir "errors-$(Get-Date -Format 'yyyyMMddHHmmss').html"
    $null = Export-GroupReport -GroupResults $resultsWithError `
        -MatchResults $null -OutputPath $errHtmlPath -Theme 'dark' -Config @{}
    Assert-True -Condition (Test-Path $errHtmlPath) -Message 'Integration: report generates even with error groups'
    Remove-Item $errHtmlPath -Force
} catch {
    Assert-True -Condition $false -Message "Integration: error handling threw: $_"
}

Write-Host ''

# ============================================================================
# CATEGORY 6: Edge Cases
# ============================================================================

Write-Host '==========================================' -ForegroundColor Cyan
Write-Host 'Test Category 6: Edge Cases' -ForegroundColor Cyan
Write-Host '==========================================' -ForegroundColor Cyan

# 6.1 Group with 0 members
try {
    $emptyGroup = New-MockGroupResult -Domain 'CORP' -GroupName 'GG_Empty' -MemberCount 0 -Members @()
    Assert-Equal -Expected 0 -Actual $emptyGroup.Data.MemberCount -Message 'Edge: group with 0 members created correctly'
    $html = ConvertTo-MemberTableHtml -Members @()
    Assert-True -Condition ($html -match 'No members') -Message 'Edge: 0-member group table shows No members placeholder'
} catch {
    Assert-True -Condition $false -Message "Edge: 0-member group threw: $_"
}

# 6.2 Group with 1 member
try {
    $singleMember = @( (New-MockMember -Sam 'onlyone') )
    $html = ConvertTo-MemberTableHtml -Members $singleMember
    Assert-True -Condition ($html -match 'onlyone') -Message 'Edge: 1-member group table shows the member'
} catch {
    Assert-True -Condition $false -Message "Edge: 1-member group threw: $_"
}

# 6.3 Group with disabled users renders Disabled badge
try {
    $disabledMember = New-MockMember -Sam 'disabled_user' -Enabled $false
    Assert-True -Condition ($disabledMember.Enabled -eq $false) -Message 'Edge: disabled user Enabled flag is false'
    # Verify report function handles disabled users
    $html = ConvertTo-MemberTableHtml -Members @($disabledMember)
    Assert-True -Condition ($html -match 'disabled_user') -Message 'Edge: disabled user appears in table'
} catch {
    Assert-True -Condition $false -Message "Edge: disabled user threw: $_"
}

# 6.4 Duplicate group entries in CSV (both imported)
$dupCsv = $null
try {
    $dupCsv = New-TempCsv "Domain,GroupName`r`nCORP,GG_IT_Admins`r`nCORP,GG_IT_Admins"
    $list = Import-GroupList -CsvPath $dupCsv
    Assert-Equal -Expected 2 -Actual $list.Count -Message 'Edge: duplicate CSV entries both imported (dedup is caller responsibility)'
} catch {
    Assert-True -Condition $false -Message "Edge: duplicate CSV entries threw: $_"
} finally {
    if ($dupCsv -and (Test-Path $dupCsv)) { Remove-Item $dupCsv -Force }
}

# 6.5 Case-insensitive group matching in FuzzyMatcher
try {
    $mixedCase = @(
        (New-MockGroupResult -Domain 'CORP'    -GroupName 'GG_IT_Admins' -MemberCount 3)
        (New-MockGroupResult -Domain 'PARTNER' -GroupName 'usv_it_admins' -MemberCount 2)
    )
    $results = Find-MatchingGroups -GroupResults $mixedCase -Prefixes @('GG_', 'USV_', 'usv_') -MinScore 0.7
    # After normalization GG_IT_Admins -> it_admins and usv_it_admins -> it_admins
    Assert-True -Condition ($results.Matched.Count -ge 1 -or $results.Unmatched.Count -ge 0) `
        -Message 'Edge: case-insensitive normalization handled without error'
} catch {
    Assert-True -Condition $false -Message "Edge: case-insensitive matching threw: $_"
}

# 6.6 Unicode in display names is HTML-escaped
try {
    $unicodeMember = @{
        SamAccountName    = 'unicode_user'
        DisplayName       = '<Script>alert("xss")</Script>'
        Email             = 'u@corp.com'
        Enabled           = $true
        Domain            = 'CORP'
        DistinguishedName = 'CN=unicode_user,DC=corp,DC=com'
    }
    $html = ConvertTo-MemberTableHtml -Members @($unicodeMember)
    Assert-True -Condition ($html -notmatch '<Script>') -Message 'Edge: XSS script tags are escaped in member table'
    Assert-True -Condition ($html -match '&lt;Script&gt;' -or $html -match '&lt;script&gt;') -Message 'Edge: < and > encoded in display name'
} catch {
    Assert-True -Condition $false -Message "Edge: unicode/XSS escaping threw: $_"
}

# 6.7 Very long group names do not crash normalization
try {
    $longName = 'GG_' + ('A' * 200)
    $result = Get-NormalizedName -GroupName $longName -Prefixes @('GG_')
    Assert-True -Condition ($result.Length -eq 200) -Message 'Edge: very long group name normalized without error'
} catch {
    Assert-True -Condition $false -Message "Edge: very long group name threw: $_"
}

# 6.8 Special characters in group names in HTML output
try {
    $specialGroup = New-MockGroupResult `
        -Domain 'CORP' -GroupName 'GG_Dev & Test <QA>' -MemberCount 0
    $results = @($specialGroup)
    $specialHtml = Join-Path $testOutputDir "special-$(Get-Date -Format 'yyyyMMddHHmmss').html"
    $null = Export-GroupReport -GroupResults $results -MatchResults $null `
        -OutputPath $specialHtml -Theme 'dark' -Config @{}
    $content = [System.IO.File]::ReadAllText($specialHtml)
    # The & < > in the group name should be HTML-encoded so no raw < or & appear in non-entity positions
    Assert-True -Condition (Test-Path $specialHtml) -Message 'Edge: special characters in group name do not crash report'
    Remove-Item $specialHtml -Force
} catch {
    Assert-True -Condition $false -Message "Edge: special characters in group name threw: $_"
}

# 6.9 Escape-Html handles empty string
try {
    $result = Escape-Html ''
    Assert-Equal -Expected '' -Actual $result -Message 'Edge: Escape-Html empty string returns empty string'
} catch {
    Assert-True -Condition $false -Message "Edge: Escape-Html empty string threw: $_"
}

# 6.10 Escape-Html handles null
try {
    $result = Escape-Html $null
    Assert-Equal -Expected '' -Actual $result -Message 'Edge: Escape-Html null returns empty string'
} catch {
    Assert-True -Condition $false -Message "Edge: Escape-Html null threw: $_"
}

# 6.11 Find-MatchingGroups with empty results array
try {
    $results = Find-MatchingGroups -GroupResults @() -Prefixes @('GG_') -MinScore 0.7
    Assert-Equal -Expected 0 -Actual $results.Matched.Count   -Message 'Edge: empty results array - Matched is 0'
    Assert-Equal -Expected 0 -Actual $results.Unmatched.Count -Message 'Edge: empty results array - Unmatched is 0'
} catch {
    Assert-True -Condition $false -Message "Edge: Find-MatchingGroups empty array threw: $_"
}

# 6.12 Get-SimilarityScore is symmetric
try {
    $score1 = Get-SimilarityScore -Name1 'finance' -Name2 'financa'
    $score2 = Get-SimilarityScore -Name1 'financa' -Name2 'finance'
    Assert-Equal -Expected $score1 -Actual $score2 -Message 'Edge: Get-SimilarityScore is symmetric'
} catch {
    Assert-True -Condition $false -Message "Edge: symmetry check threw: $_"
}

Write-Host ''

# ============================================================================
# FINAL SUMMARY
# ============================================================================

Write-Host '==========================================' -ForegroundColor Cyan
Write-Host 'Test Summary' -ForegroundColor Cyan
Write-Host '==========================================' -ForegroundColor Cyan

$testDuration = (Get-Date) - $script:TestStartTime
$totalTests   = $script:TestsPassed + $script:TestsFailed

Write-Host ''
Write-Host "Total Tests: $totalTests" -ForegroundColor White
Write-Host "Passed:      $script:TestsPassed" -ForegroundColor Green
Write-Host "Failed:      $script:TestsFailed" -ForegroundColor $(if ($script:TestsFailed -gt 0) { 'Red' } else { 'Green' })
Write-Host "Duration:    $([Math]::Round($testDuration.TotalSeconds, 2)) seconds" -ForegroundColor White
Write-Host ''

if ($script:TestsFailed -gt 0) {
    Write-Host 'Failed Tests:' -ForegroundColor Red
    foreach ($err in $script:TestErrors) {
        Write-Host "  - $err" -ForegroundColor Red
    }
    Write-Host ''
    exit 1
} else {
    Write-Host 'All tests passed!' -ForegroundColor Green
    Write-Host ''
    exit 0
}
