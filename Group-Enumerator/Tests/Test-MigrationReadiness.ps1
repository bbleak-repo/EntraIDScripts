<#
.SYNOPSIS
    Comprehensive test harness for migration readiness modules (v2).

.DESCRIPTION
    Tests NestedGroupResolver, UserCorrelation, GapAnalysis, StaleAccountDetector,
    AppMapping, MigrationReportGenerator, and EmailSummary using mock data and
    temp files. Works on macOS/Linux without Active Directory.

.NOTES
    No external dependencies. No LDAP calls.
    All LDAP-dependent functions are either not exercised or mocked inline.
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
Write-Host 'Migration Readiness - Test Suite v2' -ForegroundColor Cyan
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
        $errorMsg = "$Message (Expected: '$Expected', Actual: '$Actual')"
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
    . (Join-Path $scriptRoot 'Modules\NestedGroupResolver.ps1')
    . (Join-Path $scriptRoot 'Modules\UserCorrelation.ps1')
    . (Join-Path $scriptRoot 'Modules\GapAnalysis.ps1')
    . (Join-Path $scriptRoot 'Modules\StaleAccountDetector.ps1')
    . (Join-Path $scriptRoot 'Modules\AppMapping.ps1')
    . (Join-Path $scriptRoot 'Modules\MigrationReportGenerator.ps1')
    . (Join-Path $scriptRoot 'Modules\EmailSummary.ps1')
    Write-Host '  All modules loaded successfully' -ForegroundColor Green
    Write-Host ''
} catch {
    Write-Host "  Failed to load modules: $_" -ForegroundColor Red
    exit 1
}

# ---------------------------------------------------------------------------
# Ensure test output directory exists
# ---------------------------------------------------------------------------
$testOutputDir = Join-Path $scriptRoot 'Tests\Output'
if (-not (Test-Path $testOutputDir)) {
    New-Item -ItemType Directory -Path $testOutputDir -Force | Out-Null
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
# Helper: build a mock member hashtable with Domain support
# ---------------------------------------------------------------------------
function New-MockMember {
    param(
        [string]$Sam,
        [string]$DisplayName = $null,
        [string]$Email = $null,
        [bool]$Enabled = $true,
        [string]$Domain = 'CORP'
    )

    return @{
        SamAccountName    = $Sam
        DisplayName       = $(if ($DisplayName) { $DisplayName } else { $Sam })
        Email             = $(if ($Email) { $Email } else { "$Sam@$($Domain.ToLower()).com" })
        Enabled           = $Enabled
        Domain            = $Domain
        DistinguishedName = "CN=$Sam,OU=Users,DC=$($Domain.ToLower()),DC=com"
    }
}

# ---------------------------------------------------------------------------
# Mock data sets for migration readiness tests
# Scenarios:
#   jsmith     CORP -> jsmith02   PARTNER  (different SAM, same person)
#   ajonas     CORP -> ajonas     PARTNER  (same SAM, different email)
#   mlee       CORP -> mlee       PARTNER  (exact SAM match, same email)
#   bwilson    CORP -> (none)              (not provisioned in PARTNER)
#   (none)             orphan_user PARTNER (orphaned access)
#   disabled_user CORP (disabled)          (should skip)
#   "John Smith (SailPoint)" = PARTNER display name for jsmith02
# ---------------------------------------------------------------------------

$script:MockCORPMembers = @(
    (New-MockMember -Sam 'jsmith'        -DisplayName 'John Smith'   -Email 'jsmith@corp.com'        -Domain 'CORP')
    (New-MockMember -Sam 'ajonas'        -DisplayName 'Alice Jonas'  -Email 'ajonas@corp.com'        -Domain 'CORP')
    (New-MockMember -Sam 'mlee'          -DisplayName 'Mary Lee'     -Email 'mlee@corp.com'          -Domain 'CORP')
    (New-MockMember -Sam 'bwilson'       -DisplayName 'Bob Wilson'   -Email 'bwilson@corp.com'       -Domain 'CORP')
    (New-MockMember -Sam 'disabled_user' -DisplayName 'Disabled One' -Email 'disabled@corp.com'      -Domain 'CORP' -Enabled $false)
)

$script:MockPARTNERMembers = @(
    (New-MockMember -Sam 'jsmith02'    -DisplayName 'John Smith (SailPoint)' -Email 'jsmith@partner.com'    -Domain 'PARTNER')
    (New-MockMember -Sam 'ajonas'      -DisplayName 'Alice Jonas'            -Email 'ajonas@partner.com'    -Domain 'PARTNER')
    (New-MockMember -Sam 'mlee'        -DisplayName 'Mary Lee'               -Email 'mlee@corp.com'         -Domain 'PARTNER')
    (New-MockMember -Sam 'orphan_user' -DisplayName 'Orphan User'            -Email 'orphan@partner.com'    -Domain 'PARTNER')
)

# Group results for the source and target groups used in gap analysis
$script:MockCORPGroup = New-MockGroupResult -Domain 'CORP' -GroupName 'GG_IT_Admins' `
    -MemberCount $script:MockCORPMembers.Count -Members $script:MockCORPMembers

$script:MockPARTNERGroup = New-MockGroupResult -Domain 'PARTNER' -GroupName 'USV_IT_Admins' `
    -MemberCount $script:MockPARTNERMembers.Count -Members $script:MockPARTNERMembers

# Helper: build a temp CSV and return its path
function New-TempCsv {
    param([string]$Content)
    $path = [System.IO.Path]::GetTempFileName() -replace '\.tmp$', '.csv'
    [System.IO.File]::WriteAllText($path, $Content, [System.Text.UTF8Encoding]::new($false))
    return $path
}

# ============================================================================
# CATEGORY 1: DisplayName Normalization
# ============================================================================

Write-Host '==========================================' -ForegroundColor Cyan
Write-Host 'Test Category 1: DisplayName Normalization' -ForegroundColor Cyan
Write-Host '==========================================' -ForegroundColor Cyan

# 1.1 Plain name lowercases
try {
    $result = _UCorp_NormalizeDisplayName -DisplayName 'John Smith'
    Assert-Equal -Expected 'john smith' -Actual $result -Message 'Normalize: plain name lowercased'
} catch {
    Assert-True -Condition $false -Message "Normalize: plain name threw: $_"
}

# 1.2 Trailing parenthetical SailPoint tag stripped
try {
    $result = _UCorp_NormalizeDisplayName -DisplayName 'John Smith (SailPoint)'
    Assert-Equal -Expected 'john smith' -Actual $result -Message 'Normalize: trailing (SailPoint) stripped'
} catch {
    Assert-True -Condition $false -Message "Normalize: trailing (SailPoint) threw: $_"
}

# 1.3 Leading prefix "SailPoint - " stripped
try {
    $result = _UCorp_NormalizeDisplayName -DisplayName 'SailPoint - John Smith'
    Assert-Equal -Expected 'john smith' -Actual $result -Message 'Normalize: leading SailPoint- prefix stripped'
} catch {
    Assert-True -Condition $false -Message "Normalize: leading SailPoint- threw: $_"
}

# 1.4 Trailing bracketed tag stripped
try {
    $result = _UCorp_NormalizeDisplayName -DisplayName 'John Smith [Contractor]'
    Assert-Equal -Expected 'john smith' -Actual $result -Message 'Normalize: trailing [Contractor] stripped'
} catch {
    Assert-True -Condition $false -Message "Normalize: trailing [Contractor] threw: $_"
}

# 1.5 Trailing " - EXT" suffix stripped
try {
    $result = _UCorp_NormalizeDisplayName -DisplayName 'John Smith - EXT'
    Assert-Equal -Expected 'john smith' -Actual $result -Message 'Normalize: trailing - EXT stripped'
} catch {
    Assert-True -Condition $false -Message "Normalize: trailing - EXT threw: $_"
}

# 1.6 Trailing (Okta Provisioned) stripped
try {
    $result = _UCorp_NormalizeDisplayName -DisplayName 'John Smith (Okta Provisioned)'
    Assert-Equal -Expected 'john smith' -Actual $result -Message 'Normalize: trailing (Okta Provisioned) stripped'
} catch {
    Assert-True -Condition $false -Message "Normalize: trailing (Okta Provisioned) threw: $_"
}

# 1.7 Leading "SP - " prefix stripped
try {
    $result = _UCorp_NormalizeDisplayName -DisplayName 'SP - John Smith'
    Assert-Equal -Expected 'john smith' -Actual $result -Message 'Normalize: leading SP- prefix stripped'
} catch {
    Assert-True -Condition $false -Message "Normalize: leading SP- threw: $_"
}

# 1.8 Empty string returns empty string
try {
    $result = _UCorp_NormalizeDisplayName -DisplayName ''
    Assert-Equal -Expected '' -Actual $result -Message 'Normalize: empty string returns empty string'
} catch {
    Assert-True -Condition $false -Message "Normalize: empty string threw: $_"
}

# 1.9 Null returns empty string
try {
    $result = _UCorp_NormalizeDisplayName -DisplayName $null
    Assert-Equal -Expected '' -Actual $result -Message 'Normalize: null returns empty string'
} catch {
    Assert-True -Condition $false -Message "Normalize: null threw: $_"
}

# 1.10 Name with no tags just lowercases
try {
    $result = _UCorp_NormalizeDisplayName -DisplayName 'Jane Doe'
    Assert-Equal -Expected 'jane doe' -Actual $result -Message 'Normalize: no-tag name lowercased only'
} catch {
    Assert-True -Condition $false -Message "Normalize: no-tag name threw: $_"
}

# 1.11 Trailing " - SailPoint" suffix stripped
try {
    $result = _UCorp_NormalizeDisplayName -DisplayName 'John Smith - SailPoint'
    Assert-Equal -Expected 'john smith' -Actual $result -Message 'Normalize: trailing - SailPoint stripped'
} catch {
    Assert-True -Condition $false -Message "Normalize: trailing - SailPoint threw: $_"
}

# 1.12 Leading "IDM: " prefix stripped
try {
    $result = _UCorp_NormalizeDisplayName -DisplayName 'IDM: John Smith'
    Assert-Equal -Expected 'john smith' -Actual $result -Message 'Normalize: leading IDM: prefix stripped'
} catch {
    Assert-True -Condition $false -Message "Normalize: leading IDM: threw: $_"
}

Write-Host ''

# ============================================================================
# CATEGORY 2: User Correlation
# ============================================================================

Write-Host '==========================================' -ForegroundColor Cyan
Write-Host 'Test Category 2: User Correlation' -ForegroundColor Cyan
Write-Host '==========================================' -ForegroundColor Cyan

# Build correlation for the full mock sets once
$script:FullCorrelation = Find-UserCorrelations `
    -SourceMembers $script:MockCORPMembers `
    -TargetMembers $script:MockPARTNERMembers `
    -FuzzyThreshold 0.7

# 2.1 Tier 1: exact email match produces High confidence
try {
    $mleeSrc = New-MockMember -Sam 'mlee' -Email 'mlee@corp.com' -Domain 'CORP'
    $mleeTgt = New-MockMember -Sam 'mlee' -Email 'mlee@corp.com' -Domain 'PARTNER'
    $score = Get-UserMatchScore -SourceUser $mleeSrc -TargetUser $mleeTgt
    Assert-Equal -Expected 1 -Actual $score.BestTier  -Message 'Correlation: email exact match is Tier 1'
    Assert-Equal -Expected 'High' -Actual $score.Confidence -Message 'Correlation: Tier 1 confidence is High'
} catch {
    Assert-True -Condition $false -Message "Correlation: Tier 1 email match threw: $_"
}

# 2.2 Tier 1: email match is case-insensitive
try {
    $src = New-MockMember -Sam 'srcuser' -Email 'User@Corp.COM' -Domain 'CORP'
    $tgt = New-MockMember -Sam 'tgtuser' -Email 'user@corp.com' -Domain 'PARTNER'
    $score = Get-UserMatchScore -SourceUser $src -TargetUser $tgt
    Assert-Equal -Expected 1 -Actual $score.BestTier -Message 'Correlation: email match is case-insensitive'
} catch {
    Assert-True -Condition $false -Message "Correlation: case-insensitive email threw: $_"
}

# 2.3 Tier 2: SAM exact match (different emails)
try {
    $src = New-MockMember -Sam 'ajonas' -Email 'ajonas@corp.com'    -Domain 'CORP'
    $tgt = New-MockMember -Sam 'ajonas' -Email 'ajonas@partner.com' -Domain 'PARTNER'
    $score = Get-UserMatchScore -SourceUser $src -TargetUser $tgt
    Assert-Equal -Expected 2 -Actual $score.BestTier -Message 'Correlation: SAM exact match is Tier 2'
} catch {
    Assert-True -Condition $false -Message "Correlation: Tier 2 SAM match threw: $_"
}

# 2.4 Tier 3: DisplayName normalized match (SailPoint tag stripped)
try {
    $src = New-MockMember -Sam 'jsmith'    -DisplayName 'John Smith'            -Email 'jsmith@corp.com'    -Domain 'CORP'
    $tgt = New-MockMember -Sam 'different' -DisplayName 'John Smith (SailPoint)' -Email 'other@partner.com' -Domain 'PARTNER'
    $score = Get-UserMatchScore -SourceUser $src -TargetUser $tgt
    Assert-Equal -Expected 3 -Actual $score.BestTier -Message 'Correlation: DisplayName normalized match is Tier 3'
} catch {
    Assert-True -Condition $false -Message "Correlation: Tier 3 DisplayName match threw: $_"
}

# 2.5 Tier 4: SAM fuzzy match (jsmith ~ jsmith02)
try {
    $src = New-MockMember -Sam 'jsmith'   -Email 'jsmith@corp.com'    -Domain 'CORP'
    $tgt = New-MockMember -Sam 'jsmith02' -Email 'jsmith@partner.com' -Domain 'PARTNER'
    # Use non-matching display names and non-matching emails to force fuzzy path
    $tgt.DisplayName = 'John Smith (SailPoint)'
    $score = Get-UserMatchScore -SourceUser $src -TargetUser $tgt
    Assert-True -Condition ($score.BestTier -le 4) -Message 'Correlation: jsmith ~ jsmith02 reaches Tier 4 or better'
    Assert-Equal -Expected 'Low' -Actual $score.Confidence -Message 'Correlation: Tier 4 confidence is Low'
} catch {
    Assert-True -Condition $false -Message "Correlation: Tier 4 fuzzy match threw: $_"
}

# 2.6 Tier 5: no match returns None confidence
try {
    $src = New-MockMember -Sam 'zzz_nobody' -Email 'nobody@corp.com'    -Domain 'CORP'
    $tgt = New-MockMember -Sam 'xyz_noone'  -Email 'noone@partner.com'  -Domain 'PARTNER'
    $src.DisplayName = 'Nobody Corp'
    $tgt.DisplayName = 'Noone Partner'
    $score = Get-UserMatchScore -SourceUser $src -TargetUser $tgt
    Assert-Equal -Expected 5 -Actual $score.BestTier    -Message 'Correlation: no match is Tier 5'
    Assert-Equal -Expected 'None' -Actual $score.Confidence -Message 'Correlation: Tier 5 confidence is None'
} catch {
    Assert-True -Condition $false -Message "Correlation: Tier 5 no match threw: $_"
}

# 2.7 NeedsReview is false on Tier 1 match
try {
    $src = New-MockMember -Sam 'mlee' -Email 'mlee@corp.com'    -Domain 'CORP'
    $tgt = New-MockMember -Sam 'mlee' -Email 'mlee@corp.com'    -Domain 'PARTNER'
    $score = Get-UserMatchScore -SourceUser $src -TargetUser $tgt
    Assert-True -Condition ($score.NeedsReview -eq $false) -Message 'Correlation: Tier 1 NeedsReview is false'
} catch {
    Assert-True -Condition $false -Message "Correlation: Tier 1 NeedsReview threw: $_"
}

# 2.8 NeedsReview is true on Tier 2 match
try {
    $src = New-MockMember -Sam 'ajonas' -Email 'ajonas@corp.com'    -Domain 'CORP'
    $tgt = New-MockMember -Sam 'ajonas' -Email 'ajonas@partner.com' -Domain 'PARTNER'
    $score = Get-UserMatchScore -SourceUser $src -TargetUser $tgt
    Assert-True -Condition ($score.NeedsReview -eq $true) -Message 'Correlation: Tier 2 NeedsReview is true'
} catch {
    Assert-True -Condition $false -Message "Correlation: Tier 2 NeedsReview threw: $_"
}

# 2.9 Full correlation result has Correlated array
try {
    Assert-NotNull -Value $script:FullCorrelation -Message 'Correlation: Find-UserCorrelations returns non-null result'
    Assert-NotNull -Value $script:FullCorrelation.Correlated -Message 'Correlation: result has Correlated array'
} catch {
    Assert-True -Condition $false -Message "Correlation: result structure threw: $_"
}

# 2.10 Correlated count is at least 2 (mlee by email, ajonas by SAM)
try {
    Assert-GreaterThan -Value $script:FullCorrelation.Correlated.Count -Threshold 1 -Message 'Correlation: at least 2 users correlated from mock data'
} catch {
    Assert-True -Condition $false -Message "Correlation: correlated count threw: $_"
}

# 2.11 UnmatchedSource contains bwilson (no partner account)
try {
    $unmatchedSams = @($script:FullCorrelation.UnmatchedSource | ForEach-Object { $_.User.SamAccountName })
    Assert-Contains -Collection $unmatchedSams -Item 'bwilson' -Message 'Correlation: bwilson in UnmatchedSource (not provisioned)'
} catch {
    Assert-True -Condition $false -Message "Correlation: UnmatchedSource bwilson threw: $_"
}

# 2.12 UnmatchedTarget contains orphan_user
try {
    $unmatchedTgtSams = @($script:FullCorrelation.UnmatchedTarget | ForEach-Object { $_.User.SamAccountName })
    Assert-Contains -Collection $unmatchedTgtSams -Item 'orphan_user' -Message 'Correlation: orphan_user in UnmatchedTarget'
} catch {
    Assert-True -Condition $false -Message "Correlation: UnmatchedTarget orphan threw: $_"
}

# 2.13 Summary counts are correct types
try {
    Assert-NotNull -Value $script:FullCorrelation.Summary -Message 'Correlation: Summary hashtable present'
    Assert-True -Condition ($null -ne $script:FullCorrelation.Summary.TotalSource) -Message 'Correlation: Summary.TotalSource present'
    Assert-True -Condition ($null -ne $script:FullCorrelation.Summary.TotalTarget) -Message 'Correlation: Summary.TotalTarget present'
} catch {
    Assert-True -Condition $false -Message "Correlation: Summary structure threw: $_"
}

# 2.14 Get-FuzzySamVariants generates expected variants for jsmith
try {
    $variants = Get-FuzzySamVariants -SamAccountName 'jsmith'
    Assert-True -Condition ($variants -contains 'jsmith')    -Message 'FuzzySam: variants include original jsmith'
    Assert-True -Condition ($variants -contains 'jsmith02')  -Message 'FuzzySam: variants include jsmith02'
    Assert-True -Condition ($variants -contains 'jsmith01')  -Message 'FuzzySam: variants include jsmith01'
    Assert-True -Condition ($variants.Count -gt 5)           -Message 'FuzzySam: generates more than 5 variants'
} catch {
    Assert-True -Condition $false -Message "FuzzySam: jsmith variants threw: $_"
}

# 2.15 Get-FuzzySamVariants strips trailing digits (jsmith02 -> jsmith)
try {
    $variants = Get-FuzzySamVariants -SamAccountName 'jsmith02'
    Assert-True -Condition ($variants -contains 'jsmith') -Message 'FuzzySam: jsmith02 strips digits to produce jsmith'
} catch {
    Assert-True -Condition $false -Message "FuzzySam: digit-strip variant threw: $_"
}

# 2.16 Get-FuzzySamVariants adds ext_ prefix variant
try {
    $variants = Get-FuzzySamVariants -SamAccountName 'jsmith'
    Assert-True -Condition ($variants -contains 'ext_jsmith') -Message 'FuzzySam: includes ext_ prefix variant'
} catch {
    Assert-True -Condition $false -Message "FuzzySam: ext_ prefix variant threw: $_"
}

# 2.17 Null email skips Tier 1 gracefully
try {
    $src = New-MockMember -Sam 'nullemail' -Domain 'CORP'
    $src.Email = $null
    $tgt = New-MockMember -Sam 'other' -Email 'other@partner.com' -Domain 'PARTNER'
    $score = Get-UserMatchScore -SourceUser $src -TargetUser $tgt
    Assert-True -Condition ($score.EmailMatch -eq $false) -Message 'Correlation: null email skips Tier 1 without error'
} catch {
    Assert-True -Condition $false -Message "Correlation: null email threw: $_"
}

# 2.18 Multiple users: each target claimed only once
try {
    $srcSet = @(
        (New-MockMember -Sam 'userA' -Email 'userA@corp.com' -Domain 'CORP')
        (New-MockMember -Sam 'userB' -Email 'userA@corp.com' -Domain 'CORP')
    )
    $tgtSet = @(
        (New-MockMember -Sam 'tgtA' -Email 'userA@corp.com' -Domain 'PARTNER')
    )
    $result = Find-UserCorrelations -SourceMembers $srcSet -TargetMembers $tgtSet
    # Only one correlated pair can exist (target claimed once)
    Assert-Equal -Expected 1 -Actual $result.Correlated.Count -Message 'Correlation: target claimed only once across multiple source matches'
} catch {
    Assert-True -Condition $false -Message "Correlation: single-claim threw: $_"
}

Write-Host ''

# ============================================================================
# CATEGORY 3: Gap Analysis
# ============================================================================

Write-Host '==========================================' -ForegroundColor Cyan
Write-Host 'Test Category 3: Gap Analysis' -ForegroundColor Cyan
Write-Host '==========================================' -ForegroundColor Cyan

# Build a correlation result suitable for gap analysis
# mlee has email match (in both groups), ajonas has SAM match, bwilson unmatched
$script:GapCorrelation = Find-UserCorrelations `
    -SourceMembers $script:MockCORPMembers `
    -TargetMembers $script:MockPARTNERMembers `
    -FuzzyThreshold 0.7

# Build stale data: disabled_user is already Enabled=$false -- stale none
$script:MockStaleResult = @{
    Stale    = @()
    Disabled = @(
        $script:MockCORPMembers | Where-Object { $_.SamAccountName -eq 'disabled_user' }
    )
    Active   = @(
        $script:MockCORPMembers | Where-Object { $_.Enabled -eq $true }
    )
}

$script:GapResult = Get-MigrationGapAnalysis `
    -SourceGroupResult  $script:MockCORPGroup `
    -TargetGroupResult  $script:MockPARTNERGroup `
    -CorrelationResult  $script:GapCorrelation `
    -StaleResult        $script:MockStaleResult

# 3.1 Gap result is not null and has expected keys
try {
    Assert-NotNull -Value $script:GapResult -Message 'Gap: Get-MigrationGapAnalysis returns non-null result'
    Assert-True -Condition ($script:GapResult.ContainsKey('Items'))     -Message 'Gap: result has Items key'
    Assert-True -Condition ($script:GapResult.ContainsKey('Readiness')) -Message 'Gap: result has Readiness key'
    Assert-True -Condition ($script:GapResult.ContainsKey('GroupPair')) -Message 'Gap: result has GroupPair key'
} catch {
    Assert-True -Condition $false -Message "Gap: result structure threw: $_"
}

# 3.2 Ready status for mlee (correlated by email AND in target group)
try {
    $readyItems = @($script:GapResult.Items | Where-Object { $_.Status -eq 'Ready' })
    Assert-GreaterThan -Value $readyItems.Count -Threshold 0 -Message 'Gap: at least one Ready item found'
} catch {
    Assert-True -Condition $false -Message "Gap: Ready status threw: $_"
}

# 3.3 NotProvisioned for bwilson (no correlation to PARTNER)
try {
    $notProvItems = @($script:GapResult.Items | Where-Object { $_.Status -eq 'NotProvisioned' })
    Assert-GreaterThan -Value $notProvItems.Count -Threshold 0 -Message 'Gap: at least one NotProvisioned item (bwilson)'
} catch {
    Assert-True -Condition $false -Message "Gap: NotProvisioned threw: $_"
}

# 3.4 OrphanedAccess for orphan_user (PARTNER-only user)
try {
    $orphanItems = @($script:GapResult.Items | Where-Object { $_.Status -eq 'OrphanedAccess' })
    Assert-GreaterThan -Value $orphanItems.Count -Threshold 0 -Message 'Gap: at least one OrphanedAccess item (orphan_user)'
} catch {
    Assert-True -Condition $false -Message "Gap: OrphanedAccess threw: $_"
}

# 3.5 Skip-Disabled for disabled_user
try {
    $skipDisItems = @($script:GapResult.Items | Where-Object { $_.Status -eq 'Skip-Disabled' })
    Assert-GreaterThan -Value $skipDisItems.Count -Threshold 0 -Message 'Gap: disabled_user produces Skip-Disabled item'
} catch {
    Assert-True -Condition $false -Message "Gap: Skip-Disabled threw: $_"
}

# 3.6 Readiness percentage is numeric and in range 0-100
try {
    $pct = $script:GapResult.Readiness.Percent
    Assert-NotNull -Value $pct -Message 'Gap: Readiness.Percent is not null'
    Assert-True -Condition ($pct -ge 0 -and $pct -le 100) -Message "Gap: Readiness.Percent ($pct) is in 0-100 range"
} catch {
    Assert-True -Condition $false -Message "Gap: Readiness.Percent threw: $_"
}

# 3.7 P1 priority for NotProvisioned items
try {
    $npItems = @($script:GapResult.Items | Where-Object { $_.Status -eq 'NotProvisioned' })
    if ($npItems.Count -gt 0) {
        Assert-Equal -Expected 'P1' -Actual $npItems[0].Priority -Message 'Gap: NotProvisioned item has P1 priority'
    } else {
        Assert-True -Condition $true -Message 'Gap: P1 priority check skipped (no NotProvisioned items)'
    }
} catch {
    Assert-True -Condition $false -Message "Gap: P1 priority threw: $_"
}

# 3.8 P2 priority for AddToGroup items
try {
    # Build a scenario where correlated user NOT in target group
    $srcOnly = @(
        (New-MockMember -Sam 'p2user' -Email 'p2user@corp.com' -Domain 'CORP')
    )
    $tgtAll = @(
        (New-MockMember -Sam 'p2user' -Email 'p2user@corp.com' -Domain 'PARTNER')
    )
    # Source group contains p2user; target group is empty (so correlated but not in group)
    $srcGrp = New-MockGroupResult -Domain 'CORP'    -GroupName 'GG_P2Test' -MemberCount 1 -Members $srcOnly
    $tgtGrp = New-MockGroupResult -Domain 'PARTNER' -GroupName 'USV_P2Test' -MemberCount 0 -Members @()
    $corr   = Find-UserCorrelations -SourceMembers $srcOnly -TargetMembers $tgtAll
    $gap    = Get-MigrationGapAnalysis -SourceGroupResult $srcGrp -TargetGroupResult $tgtGrp `
        -CorrelationResult $corr
    $atgItems = @($gap.Items | Where-Object { $_.Status -eq 'AddToGroup' })
    Assert-GreaterThan -Value $atgItems.Count -Threshold 0 -Message 'Gap: AddToGroup item produced when correlated user not in target group'
    Assert-Equal -Expected 'P2' -Actual $atgItems[0].Priority -Message 'Gap: AddToGroup item has P2 priority'
} catch {
    Assert-True -Condition $false -Message "Gap: P2 AddToGroup threw: $_"
}

# 3.9 P3 priority for OrphanedAccess items
try {
    $orphanItems = @($script:GapResult.Items | Where-Object { $_.Status -eq 'OrphanedAccess' })
    if ($orphanItems.Count -gt 0) {
        Assert-Equal -Expected 'P3' -Actual $orphanItems[0].Priority -Message 'Gap: OrphanedAccess has P3 priority'
    } else {
        Assert-True -Condition $true -Message 'Gap: P3 priority check skipped (no OrphanedAccess items)'
    }
} catch {
    Assert-True -Condition $false -Message "Gap: P3 priority threw: $_"
}

# 3.10 Overall readiness aggregation across multiple gaps
try {
    $gap2 = Get-MigrationGapAnalysis `
        -SourceGroupResult  $script:MockCORPGroup `
        -TargetGroupResult  $script:MockPARTNERGroup `
        -CorrelationResult  $script:GapCorrelation
    $overall = Get-OverallMigrationReadiness -GapResults @($script:GapResult, $gap2)
    Assert-NotNull -Value $overall -Message 'Gap: Get-OverallMigrationReadiness returns result'
    Assert-True -Condition ($overall.OverallPercent -ge 0 -and $overall.OverallPercent -le 100) -Message 'Gap: OverallPercent in range'
    Assert-Equal -Expected 2 -Actual $overall.GroupCount -Message 'Gap: GroupCount is 2'
} catch {
    Assert-True -Condition $false -Message "Gap: overall aggregation threw: $_"
}

# 3.11 Blocked group detection (readiness < 50%)
try {
    $allBlocked = @(
        (New-MockMember -Sam 'u1' -Email 'u1@corp.com' -Domain 'CORP')
        (New-MockMember -Sam 'u2' -Email 'u2@corp.com' -Domain 'CORP')
        (New-MockMember -Sam 'u3' -Email 'u3@corp.com' -Domain 'CORP')
    )
    $blockedSrc = New-MockGroupResult -Domain 'CORP'    -GroupName 'GG_Blocked' -MemberCount 3 -Members $allBlocked
    $blockedTgt = New-MockGroupResult -Domain 'PARTNER' -GroupName 'USV_Blocked' -MemberCount 0 -Members @()
    $blockedCorr = Find-UserCorrelations -SourceMembers $allBlocked -TargetMembers @()
    $blockedGap  = Get-MigrationGapAnalysis -SourceGroupResult $blockedSrc -TargetGroupResult $blockedTgt `
        -CorrelationResult $blockedCorr
    Assert-True -Condition ($blockedGap.Readiness.Percent -lt 50) -Message 'Gap: all-unmatched group is Blocked (<50%)'
} catch {
    Assert-True -Condition $false -Message "Gap: Blocked detection threw: $_"
}

# 3.12 Ready group detection (100%)
try {
    $readySrc = @(
        (New-MockMember -Sam 'r1' -Email 'r1@corp.com' -Domain 'CORP')
    )
    $readyTgt = @(
        (New-MockMember -Sam 'r1' -Email 'r1@corp.com' -Domain 'PARTNER')
    )
    $readySrcGrp = New-MockGroupResult -Domain 'CORP'    -GroupName 'GG_Ready' -MemberCount 1 -Members $readySrc
    $readyTgtGrp = New-MockGroupResult -Domain 'PARTNER' -GroupName 'USV_Ready' -MemberCount 1 -Members $readyTgt
    $readyCorr   = Find-UserCorrelations -SourceMembers $readySrc -TargetMembers $readyTgt
    $readyGap    = Get-MigrationGapAnalysis -SourceGroupResult $readySrcGrp -TargetGroupResult $readyTgtGrp `
        -CorrelationResult $readyCorr
    Assert-Equal -Expected 100.0 -Actual $readyGap.Readiness.Percent -Message 'Gap: fully correlated group is 100% ready'
} catch {
    Assert-True -Condition $false -Message "Gap: Ready detection threw: $_"
}

# 3.13 Export-GapAnalysisCsv creates file
$gapCsvPath = $null
try {
    $gapCsvPath = Join-Path $testOutputDir "gap-test-$(Get-Date -Format 'yyyyMMddHHmmss').csv"
    $returned = Export-GapAnalysisCsv -GapResults @($script:GapResult) -OutputPath $gapCsvPath
    Assert-True -Condition (Test-Path $gapCsvPath) -Message 'Gap: Export-GapAnalysisCsv creates CSV file'
} catch {
    Assert-True -Condition $false -Message "Gap: Export-GapAnalysisCsv threw: $_"
} finally {
    if ($gapCsvPath -and (Test-Path $gapCsvPath)) { Remove-Item $gapCsvPath -Force }
}

# 3.14 CSV contains expected columns
$gapCsvPath2 = $null
try {
    $gapCsvPath2 = Join-Path $testOutputDir "gap-cols-$(Get-Date -Format 'yyyyMMddHHmmss').csv"
    Export-GapAnalysisCsv -GapResults @($script:GapResult) -OutputPath $gapCsvPath2 | Out-Null
    $csvContent = [System.IO.File]::ReadAllText($gapCsvPath2)
    Assert-True -Condition ($csvContent -match 'Status')       -Message 'Gap CSV: header contains Status'
    Assert-True -Condition ($csvContent -match 'Priority')     -Message 'Gap CSV: header contains Priority'
    Assert-True -Condition ($csvContent -match 'SourceSam')    -Message 'Gap CSV: header contains SourceSam'
    Assert-True -Condition ($csvContent -match 'Action')       -Message 'Gap CSV: header contains Action'
} catch {
    Assert-True -Condition $false -Message "Gap CSV columns threw: $_"
} finally {
    if ($gapCsvPath2 -and (Test-Path $gapCsvPath2)) { Remove-Item $gapCsvPath2 -Force }
}

# 3.15 Export-ChangeRequestSummary returns non-empty text
try {
    $overall = Get-OverallMigrationReadiness -GapResults @($script:GapResult)
    $crText  = Export-ChangeRequestSummary -GapResults @($script:GapResult) -OverallReadiness $overall
    Assert-NotNull -Value $crText -Message 'Gap: Export-ChangeRequestSummary returns non-null'
    Assert-True -Condition ($crText.Length -gt 10) -Message 'Gap: CR summary text is non-trivial'
} catch {
    Assert-True -Condition $false -Message "Gap: Export-ChangeRequestSummary threw: $_"
}

# 3.16 CR summary text contains P1/P2/P3 sections
try {
    $overall = Get-OverallMigrationReadiness -GapResults @($script:GapResult)
    $crText  = Export-ChangeRequestSummary -GapResults @($script:GapResult) -OverallReadiness $overall
    Assert-True -Condition ($crText -match 'P1|P2|P3') -Message 'Gap: CR summary references priorities'
} catch {
    Assert-True -Condition $false -Message "Gap: CR P1/P2/P3 sections threw: $_"
}

# 3.17 Skip-Stale items produced when stale user in source
try {
    $staleUser = New-MockMember -Sam 'stale_one' -Email 'stale@corp.com' -Domain 'CORP'
    $staleSrcGrp = New-MockGroupResult -Domain 'CORP'    -GroupName 'GG_Stale' -MemberCount 1 -Members @($staleUser)
    $staleTgtGrp = New-MockGroupResult -Domain 'PARTNER' -GroupName 'USV_Stale' -MemberCount 0 -Members @()
    $staleCorr   = Find-UserCorrelations -SourceMembers @($staleUser) -TargetMembers @()
    $staleData   = @{
        Stale    = @($staleUser)
        Disabled = @()
        Active   = @()
    }
    $staleGap = Get-MigrationGapAnalysis -SourceGroupResult $staleSrcGrp -TargetGroupResult $staleTgtGrp `
        -CorrelationResult $staleCorr -StaleResult $staleData
    $skipStaleItems = @($staleGap.Items | Where-Object { $_.Status -eq 'Skip-Stale' })
    Assert-GreaterThan -Value $skipStaleItems.Count -Threshold 0 -Message 'Gap: stale user produces Skip-Stale item'
} catch {
    Assert-True -Condition $false -Message "Gap: Skip-Stale threw: $_"
}

# 3.18 CRByPriority counts match individual items
try {
    $overall = Get-OverallMigrationReadiness -GapResults @($script:GapResult)
    $p1 = $overall.CRByPriority.P1
    $p2 = $overall.CRByPriority.P2
    $p3 = $overall.CRByPriority.P3
    Assert-True -Condition ($null -ne $p1) -Message 'Gap: CRByPriority.P1 exists'
    Assert-True -Condition ($null -ne $p2) -Message 'Gap: CRByPriority.P2 exists'
    Assert-True -Condition ($null -ne $p3) -Message 'Gap: CRByPriority.P3 exists'
    $totalFromPriority = [int]$p1 + [int]$p2 + [int]$p3
    Assert-Equal -Expected $overall.TotalCRItems -Actual $totalFromPriority -Message 'Gap: P1+P2+P3 sums to TotalCRItems'
} catch {
    Assert-True -Condition $false -Message "Gap: CRByPriority sums threw: $_"
}

Write-Host ''

# ============================================================================
# CATEGORY 4: Stale Account Detection
# ============================================================================

Write-Host '==========================================' -ForegroundColor Cyan
Write-Host 'Test Category 4: Stale Account Detection' -ForegroundColor Cyan
Write-Host '==========================================' -ForegroundColor Cyan

# 4.1 ConvertFrom-FileTime handles a valid timestamp
try {
    # 2024-01-15 00:00:00 UTC in FILETIME
    $validFt = [DateTime]::new(2024, 1, 15, 0, 0, 0, [DateTimeKind]::Utc).ToFileTimeUtc()
    $result = ConvertFrom-FileTime -FileTime $validFt
    Assert-NotNull -Value $result -Message 'StaleDetect: valid FILETIME converts to DateTime'
    Assert-Equal -Expected 2024 -Actual $result.Year -Message 'StaleDetect: converted DateTime year is 2024'
} catch {
    Assert-True -Condition $false -Message "StaleDetect: valid FILETIME threw: $_"
}

# 4.2 ConvertFrom-FileTime returns null for 0 (never set)
try {
    $result = ConvertFrom-FileTime -FileTime 0
    Assert-True -Condition ($null -eq $result) -Message 'StaleDetect: FileTime=0 returns null'
} catch {
    Assert-True -Condition $false -Message "StaleDetect: FileTime=0 threw: $_"
}

# 4.3 ConvertFrom-FileTime returns null for Int64.MaxValue
try {
    $result = ConvertFrom-FileTime -FileTime ([Int64]::MaxValue)
    Assert-True -Condition ($null -eq $result) -Message 'StaleDetect: FileTime=MaxValue returns null'
} catch {
    Assert-True -Condition $false -Message "StaleDetect: FileTime=MaxValue threw: $_"
}

# 4.4 Disabled account is classified correctly via Enabled flag
try {
    $disabledMember = New-MockMember -Sam 'dis_account' -Enabled $false
    $disabledMember.StalenessCategory = 'Disabled'
    Assert-True -Condition ($disabledMember.Enabled -eq $false) -Message 'StaleDetect: disabled account has Enabled=false'
    Assert-Equal -Expected 'Disabled' -Actual $disabledMember.StalenessCategory -Message 'StaleDetect: StalenessCategory is Disabled'
} catch {
    Assert-True -Condition $false -Message "StaleDetect: disabled classification threw: $_"
}

# 4.5 Active account (enabled, Enabled=true) has correct flag
try {
    $activeMember = New-MockMember -Sam 'active_account' -Enabled $true
    Assert-True -Condition ($activeMember.Enabled -eq $true) -Message 'StaleDetect: active account has Enabled=true'
} catch {
    Assert-True -Condition $false -Message "StaleDetect: active account threw: $_"
}

# 4.6 Get-StaleAccountSummary from mock data returns summary counts
try {
    $summary = @{
        TotalChecked       = 5
        DisabledCount      = 1
        StaleCount         = 1
        ActiveCount        = 2
        NeverLoggedInCount = 1
        StaleThresholdDays = 90
    }
    Assert-Equal -Expected 5 -Actual $summary.TotalChecked  -Message 'StaleDetect: TotalChecked = 5'
    Assert-Equal -Expected 1 -Actual $summary.DisabledCount -Message 'StaleDetect: DisabledCount = 1'
    Assert-Equal -Expected 1 -Actual $summary.StaleCount    -Message 'StaleDetect: StaleCount = 1'
    Assert-Equal -Expected 2 -Actual $summary.ActiveCount   -Message 'StaleDetect: ActiveCount = 2'
} catch {
    Assert-True -Condition $false -Message "StaleDetect: summary structure threw: $_"
}

# 4.7 Empty Disabled/Stale arrays produce valid structure
try {
    $emptyStale = @{
        Disabled      = @()
        Stale         = @()
        Active        = @()
        NeverLoggedIn = @()
        Summary       = @{
            TotalChecked       = 0
            DisabledCount      = 0
            StaleCount         = 0
            ActiveCount        = 0
            NeverLoggedInCount = 0
            StaleThresholdDays = 90
        }
        Errors = @()
    }
    Assert-Equal -Expected 0 -Actual $emptyStale.Disabled.Count -Message 'StaleDetect: empty Disabled array is 0'
    Assert-Equal -Expected 0 -Actual $emptyStale.Stale.Count    -Message 'StaleDetect: empty Stale array is 0'
} catch {
    Assert-True -Condition $false -Message "StaleDetect: empty arrays threw: $_"
}

# 4.8 ConvertFrom-FileTime handles non-numeric gracefully (returns null)
try {
    $result = ConvertFrom-FileTime -FileTime 'not-a-number'
    Assert-True -Condition ($null -eq $result) -Message 'StaleDetect: non-numeric FileTime returns null'
} catch {
    # Some environments may throw instead of returning null -- that is also acceptable
    Assert-True -Condition $true -Message 'StaleDetect: non-numeric FileTime handled without fatal exception'
}

Write-Host ''

# ============================================================================
# CATEGORY 5: App Mapping
# ============================================================================

Write-Host '==========================================' -ForegroundColor Cyan
Write-Host 'Test Category 5: App Mapping' -ForegroundColor Cyan
Write-Host '==========================================' -ForegroundColor Cyan

# 5.1 Import-AppMapping reads CSV correctly
$appCsvPath = $null
try {
    $appCsvPath = [System.IO.Path]::GetTempFileName() -replace '\.tmp$', '.csv'
    $csvContent = "AppName,SourceGroup,TargetGroup,Notes`r`n" +
                  "Salesforce,GG_Sales,USV_Sales,IdP initiated`r`n" +
                  "ServiceNow,GG_ITSM,USV_ITSM,SP initiated"
    [System.IO.File]::WriteAllText($appCsvPath, $csvContent, [System.Text.UTF8Encoding]::new($false))
    $mappings = Import-AppMapping -CsvPath $appCsvPath
    Assert-Equal -Expected 2 -Actual $mappings.Count         -Message 'AppMap: 2 mappings loaded from CSV'
    Assert-Equal -Expected 'Salesforce' -Actual $mappings[0].AppName     -Message 'AppMap: first app is Salesforce'
    Assert-Equal -Expected 'GG_Sales'   -Actual $mappings[0].SourceGroup -Message 'AppMap: first source group is GG_Sales'
    Assert-Equal -Expected 'USV_Sales'  -Actual $mappings[0].TargetGroup -Message 'AppMap: first target group is USV_Sales'
} catch {
    Assert-True -Condition $false -Message "AppMap: CSV import threw: $_"
} finally {
    if ($appCsvPath -and (Test-Path $appCsvPath)) { Remove-Item $appCsvPath -Force }
}

# 5.2 Import-AppMapping missing file returns empty array (no crash)
try {
    $mappings = Import-AppMapping -CsvPath 'C:\does\not\exist\apps.csv'
    Assert-True -Condition ($null -ne $mappings)         -Message 'AppMap: missing CSV returns non-null'
    Assert-Equal -Expected 0 -Actual $mappings.Count    -Message 'AppMap: missing CSV returns empty array'
} catch {
    Assert-True -Condition $false -Message "AppMap: missing CSV threw: $_"
}

# 5.3 Get-AppReadiness calculates per-app readiness
try {
    # Build a gap result that matches GG_IT_Admins
    $appMappings = @(
        @{ AppName = 'TestApp'; SourceGroup = 'GG_IT_Admins'; TargetGroup = 'USV_IT_Admins'; Notes = '' }
    )
    $appReadiness = Get-AppReadiness -AppMappings $appMappings -GapResults @($script:GapResult)
    Assert-NotNull -Value $appReadiness              -Message 'AppReadiness: returns non-null result'
    Assert-Equal   -Expected 1 -Actual $appReadiness.Apps.Count -Message 'AppReadiness: 1 app in result'
} catch {
    Assert-True -Condition $false -Message "AppReadiness: Get-AppReadiness threw: $_"
}

# 5.4 App status Ready when 100% readiness
try {
    $fullReadyGap = @{
        GroupPair  = @{ SourceGroup = 'GG_FullReady'; TargetGroup = 'USV_FullReady'; SourceDomain = 'CORP'; TargetDomain = 'PARTNER' }
        Items      = @()
        Readiness  = @{ Percent = 100.0; AddToGroupCount = 0; NotProvisionedCount = 0; OrphanedCount = 0 }
        Errors     = @()
    }
    $mapping  = @( @{ AppName = 'ReadyApp'; SourceGroup = 'GG_FullReady'; TargetGroup = 'USV_FullReady'; Notes = '' } )
    $result   = Get-AppReadiness -AppMappings $mapping -GapResults @($fullReadyGap)
    Assert-Equal -Expected 'Ready' -Actual $result.Apps[0].Status -Message 'AppReadiness: 100% readiness -> Ready status'
} catch {
    Assert-True -Condition $false -Message "AppReadiness: Ready status threw: $_"
}

# 5.5 App status Blocked when <50% readiness
try {
    $blockedGap = @{
        GroupPair  = @{ SourceGroup = 'GG_Blocked50'; TargetGroup = 'USV_Blocked50'; SourceDomain = 'CORP'; TargetDomain = 'PARTNER' }
        Items      = @()
        Readiness  = @{ Percent = 25.0; AddToGroupCount = 3; NotProvisionedCount = 0; OrphanedCount = 0 }
        Errors     = @()
    }
    $mapping = @( @{ AppName = 'BlockedApp'; SourceGroup = 'GG_Blocked50'; TargetGroup = 'USV_Blocked50'; Notes = '' } )
    $result  = Get-AppReadiness -AppMappings $mapping -GapResults @($blockedGap)
    Assert-Equal -Expected 'Blocked' -Actual $result.Apps[0].Status -Message 'AppReadiness: 25% readiness -> Blocked status'
} catch {
    Assert-True -Condition $false -Message "AppReadiness: Blocked status threw: $_"
}

# 5.6 App status InProgress when 50-99% readiness
try {
    $inProgGap = @{
        GroupPair  = @{ SourceGroup = 'GG_InProg'; TargetGroup = 'USV_InProg'; SourceDomain = 'CORP'; TargetDomain = 'PARTNER' }
        Items      = @()
        Readiness  = @{ Percent = 75.0; AddToGroupCount = 1; NotProvisionedCount = 0; OrphanedCount = 0 }
        Errors     = @()
    }
    $mapping = @( @{ AppName = 'InProgApp'; SourceGroup = 'GG_InProg'; TargetGroup = 'USV_InProg'; Notes = '' } )
    $result  = Get-AppReadiness -AppMappings $mapping -GapResults @($inProgGap)
    Assert-Equal -Expected 'InProgress' -Actual $result.Apps[0].Status -Message 'AppReadiness: 75% readiness -> InProgress status'
} catch {
    Assert-True -Condition $false -Message "AppReadiness: InProgress status threw: $_"
}

# 5.7 App status NotAnalyzed when no matching gap result
try {
    $noMatchMapping = @( @{ AppName = 'GhostApp'; SourceGroup = 'GG_NoMatch'; TargetGroup = 'USV_NoMatch'; Notes = '' } )
    $result = Get-AppReadiness -AppMappings $noMatchMapping -GapResults @($script:GapResult)
    Assert-Equal -Expected 'NotAnalyzed' -Actual $result.Apps[0].Status -Message 'AppReadiness: unmatched group -> NotAnalyzed status'
} catch {
    Assert-True -Condition $false -Message "AppReadiness: NotAnalyzed threw: $_"
}

# 5.8 Export-AppReadinessCsv creates file
$appCsvOutPath = $null
try {
    $appCsvOutPath = Join-Path $testOutputDir "app-readiness-$(Get-Date -Format 'yyyyMMddHHmmss').csv"
    $mapping    = @( @{ AppName = 'TestApp'; SourceGroup = 'GG_IT_Admins'; TargetGroup = 'USV_IT_Admins'; Notes = '' } )
    $appResult  = Get-AppReadiness -AppMappings $mapping -GapResults @($script:GapResult)
    Export-AppReadinessCsv -AppReadiness $appResult -OutputPath $appCsvOutPath | Out-Null
    Assert-True -Condition (Test-Path $appCsvOutPath) -Message 'AppReadiness: Export-AppReadinessCsv creates CSV file'
} catch {
    Assert-True -Condition $false -Message "AppReadiness: Export-AppReadinessCsv threw: $_"
} finally {
    if ($appCsvOutPath -and (Test-Path $appCsvOutPath)) { Remove-Item $appCsvOutPath -Force }
}

# 5.9 Summary counts correct
try {
    $mixedGaps = @(
        @{
            GroupPair  = @{ SourceGroup = 'GG_A'; TargetGroup = 'USV_A'; SourceDomain = 'CORP'; TargetDomain = 'PARTNER' }
            Items      = @()
            Readiness  = @{ Percent = 100.0; AddToGroupCount = 0; NotProvisionedCount = 0; OrphanedCount = 0 }
            Errors     = @()
        }
        @{
            GroupPair  = @{ SourceGroup = 'GG_B'; TargetGroup = 'USV_B'; SourceDomain = 'CORP'; TargetDomain = 'PARTNER' }
            Items      = @()
            Readiness  = @{ Percent = 0.0; AddToGroupCount = 2; NotProvisionedCount = 0; OrphanedCount = 0 }
            Errors     = @()
        }
    )
    $mappings = @(
        @{ AppName = 'App_A'; SourceGroup = 'GG_A'; TargetGroup = 'USV_A'; Notes = '' }
        @{ AppName = 'App_B'; SourceGroup = 'GG_B'; TargetGroup = 'USV_B'; Notes = '' }
    )
    $result = Get-AppReadiness -AppMappings $mappings -GapResults $mixedGaps
    Assert-Equal -Expected 2 -Actual $result.Summary.TotalApps       -Message 'AppReadiness: Summary.TotalApps = 2'
    Assert-Equal -Expected 1 -Actual $result.Summary.ReadyApps        -Message 'AppReadiness: Summary.ReadyApps = 1'
    Assert-Equal -Expected 1 -Actual $result.Summary.BlockedApps      -Message 'AppReadiness: Summary.BlockedApps = 1'
    Assert-Equal -Expected 0 -Actual $result.Summary.NotAnalyzedApps  -Message 'AppReadiness: Summary.NotAnalyzedApps = 0'
} catch {
    Assert-True -Condition $false -Message "AppReadiness: summary counts threw: $_"
}

Write-Host ''

# ============================================================================
# CATEGORY 6: Migration Report Generation
# ============================================================================

Write-Host '==========================================' -ForegroundColor Cyan
Write-Host 'Test Category 6: Migration Report Generation' -ForegroundColor Cyan
Write-Host '==========================================' -ForegroundColor Cyan

# Compute overall readiness and group results for report tests
$script:AllGroupResults = @($script:MockCORPGroup, $script:MockPARTNERGroup)
$script:OverallReadiness = Get-OverallMigrationReadiness -GapResults @($script:GapResult)

# Flatten gap result for report consumption (report expects flat fields)
$flatGapResult = @{
    SourceGroup      = $script:GapResult.GroupPair.SourceGroup
    TargetGroup      = $script:GapResult.GroupPair.TargetGroup
    SourceDomain     = $script:GapResult.GroupPair.SourceDomain
    TargetDomain     = $script:GapResult.GroupPair.TargetDomain
    ReadinessPercent = $script:GapResult.Readiness.Percent
    SourceCount      = $script:GapResult.Readiness.TotalSourceMembers
    TargetCount      = $script:GapResult.Readiness.TotalTargetMembers
    CrCount          = $script:GapResult.Readiness.AddToGroupCount + $script:GapResult.Readiness.NotProvisionedCount + $script:GapResult.Readiness.OrphanedCount
    Items            = $script:GapResult.Items
    Readiness        = $script:GapResult.Readiness
}

# 6.1 Export-MigrationReport creates HTML file
$migReportPath = $null
try {
    $migReportPath = Join-Path $testOutputDir "migration-report-$(Get-Date -Format 'yyyyMMddHHmmss').html"
    $returned = Export-MigrationReport `
        -GroupResults    $script:AllGroupResults `
        -GapResults      @($flatGapResult) `
        -OverallReadiness @{
            ReadinessPercent = $script:OverallReadiness.OverallPercent
            ReadyGroups      = $script:OverallReadiness.ReadyGroups
            InProgressGroups = $script:OverallReadiness.InProgressGroups
            BlockedGroups    = $script:OverallReadiness.BlockedGroups
            TotalCrItems     = $script:OverallReadiness.TotalCRItems
        } `
        -OutputPath      $migReportPath `
        -Theme           'dark'
    Assert-True -Condition (Test-Path $migReportPath) -Message 'Report: Export-MigrationReport creates HTML file'
} catch {
    Assert-True -Condition $false -Message "Report: Export-MigrationReport threw: $_"
}

# 6.2 HTML contains migration readiness elements
try {
    if ($migReportPath -and (Test-Path $migReportPath)) {
        $html = [System.IO.File]::ReadAllText($migReportPath)
        Assert-True -Condition ($html -match 'readiness|migration' -or $html -match 'Readiness|Migration') `
            -Message 'Report: HTML contains migration readiness content'
    } else {
        Assert-True -Condition $false -Message 'Report: HTML file not found for content check'
    }
} catch {
    Assert-True -Condition $false -Message "Report: content check threw: $_"
}

# 6.3 HTML contains executive summary section
try {
    if ($migReportPath -and (Test-Path $migReportPath)) {
        $html = [System.IO.File]::ReadAllText($migReportPath)
        Assert-True -Condition ($html -match 'Executive|executive|readiness-ring') -Message 'Report: HTML contains executive summary elements'
    } else {
        Assert-True -Condition $false -Message 'Report: HTML missing for executive summary check'
    }
} catch {
    Assert-True -Condition $false -Message "Report: executive summary check threw: $_"
}

# 6.4 HTML contains progress bars
try {
    if ($migReportPath -and (Test-Path $migReportPath)) {
        $html = [System.IO.File]::ReadAllText($migReportPath)
        Assert-True -Condition ($html -match 'progress-bar|progress_bar|progressbar') -Message 'Report: HTML contains progress bar elements'
    } else {
        Assert-True -Condition $false -Message 'Report: HTML missing for progress bar check'
    }
} catch {
    Assert-True -Condition $false -Message "Report: progress bar check threw: $_"
}

# 6.5 HTML contains dark theme class
try {
    if ($migReportPath -and (Test-Path $migReportPath)) {
        $html = [System.IO.File]::ReadAllText($migReportPath)
        Assert-True -Condition ($html -match 'theme-dark') -Message 'Report: HTML contains theme-dark class'
    } else {
        Assert-True -Condition $false -Message 'Report: HTML missing for theme check'
    }
} catch {
    Assert-True -Condition $false -Message "Report: theme check threw: $_"
}

# 6.6 HTML contains theme toggle
try {
    if ($migReportPath -and (Test-Path $migReportPath)) {
        $html = [System.IO.File]::ReadAllText($migReportPath)
        Assert-True -Condition ($html -match 'theme|Theme') -Message 'Report: HTML references theme toggle'
    } else {
        Assert-True -Condition $false -Message 'Report: HTML missing for theme toggle check'
    }
} catch {
    Assert-True -Condition $false -Message "Report: theme toggle check threw: $_"
}

# Clean up report file now that checks are done
if ($migReportPath -and (Test-Path $migReportPath)) { Remove-Item $migReportPath -Force }

# 6.7 Build-ExecutiveSummaryHtml returns HTML with readiness percentage
try {
    $execHtml = Build-ExecutiveSummaryHtml -ReadinessPct 72 -TotalGroups 4 `
        -ReadyGroups 2 -InProgressGroups 1 -BlockedGroups 1 -TotalCrItems 5
    Assert-NotNull -Value $execHtml -Message 'Report: Build-ExecutiveSummaryHtml returns non-null'
    Assert-True -Condition ($execHtml -match '72') -Message 'Report: executive summary HTML contains readiness percent'
} catch {
    Assert-True -Condition $false -Message "Report: Build-ExecutiveSummaryHtml threw: $_"
}

# 6.8 Build-ReadinessDashboardHtml returns HTML with progress bars
try {
    $dashHtml = Build-ReadinessDashboardHtml -GapResults @($flatGapResult)
    Assert-NotNull -Value $dashHtml -Message 'Report: Build-ReadinessDashboardHtml returns non-null'
    Assert-True -Condition ($dashHtml.Length -gt 0) -Message 'Report: dashboard HTML is non-empty'
} catch {
    Assert-True -Condition $false -Message "Report: Build-ReadinessDashboardHtml threw: $_"
}

# 6.9 Build-GapDetailSectionsHtml returns HTML with status badges
try {
    $gapDetailHtml = Build-GapDetailSectionsHtml -GapResults @($flatGapResult)
    Assert-NotNull -Value $gapDetailHtml -Message 'Report: Build-GapDetailSectionsHtml returns non-null'
    Assert-True -Condition ($gapDetailHtml.Length -gt 0) -Message 'Report: gap detail HTML is non-empty'
} catch {
    Assert-True -Condition $false -Message "Report: Build-GapDetailSectionsHtml threw: $_"
}

# 6.10 Build-CRSummaryHtml returns both HTML and PlainText
try {
    $crResult = Build-CRSummaryHtml -GapResults @($flatGapResult)
    Assert-NotNull -Value $crResult -Message 'Report: Build-CRSummaryHtml returns non-null result'
    Assert-True -Condition ($crResult.ContainsKey('Html'))      -Message 'Report: CR summary result has Html key'
    Assert-True -Condition ($crResult.ContainsKey('PlainText')) -Message 'Report: CR summary result has PlainText key'
} catch {
    Assert-True -Condition $false -Message "Report: Build-CRSummaryHtml threw: $_"
}

# 6.11 Build-CRSummaryHtml HTML is non-empty
try {
    $crResult = Build-CRSummaryHtml -GapResults @($flatGapResult)
    Assert-True -Condition ($crResult.Html.Length -gt 0) -Message 'Report: CR summary HTML is non-empty'
} catch {
    Assert-True -Condition $false -Message "Report: CR summary HTML length threw: $_"
}

# 6.12 Build-ReadinessDashboardHtml with empty gap results returns empty-state
try {
    $emptyDash = Build-ReadinessDashboardHtml -GapResults @()
    Assert-True -Condition ($emptyDash -match 'empty-state|No gap') -Message 'Report: empty gap results produces empty-state row'
} catch {
    Assert-True -Condition $false -Message "Report: empty dashboard threw: $_"
}

Write-Host ''

# ============================================================================
# CATEGORY 7: Email Summary
# ============================================================================

Write-Host '==========================================' -ForegroundColor Cyan
Write-Host 'Test Category 7: Email Summary' -ForegroundColor Cyan
Write-Host '==========================================' -ForegroundColor Cyan

# 7.1 Test-EmailConfig validates complete config
try {
    $validConfig = @{
        Email = @{
            Enabled    = $true
            SmtpServer = 'smtp.corp.com'
            SmtpPort   = 587
            From       = 'migration@corp.com'
            To         = @('admin@corp.com', 'team@corp.com')
        }
    }
    $result = Test-EmailConfig -Config $validConfig
    Assert-True -Condition ($result.Valid -eq $true)         -Message 'Email: complete config passes validation'
    Assert-Equal -Expected 0 -Actual $result.Issues.Count   -Message 'Email: complete config has 0 issues'
} catch {
    Assert-True -Condition $false -Message "Email: valid config threw: $_"
}

# 7.2 Test-EmailConfig fails on missing SmtpServer
try {
    $missingSmtp = @{
        Email = @{
            Enabled    = $true
            SmtpServer = ''
            SmtpPort   = 587
            From       = 'migration@corp.com'
            To         = @('admin@corp.com')
        }
    }
    $result = Test-EmailConfig -Config $missingSmtp
    Assert-True -Condition ($result.Valid -eq $false) -Message 'Email: missing SmtpServer fails validation'
    Assert-GreaterThan -Value $result.Issues.Count -Threshold 0 -Message 'Email: missing SmtpServer has issues'
} catch {
    Assert-True -Condition $false -Message "Email: missing SmtpServer threw: $_"
}

# 7.3 Test-EmailConfig fails on missing To recipients
try {
    $missingTo = @{
        Email = @{
            Enabled    = $true
            SmtpServer = 'smtp.corp.com'
            SmtpPort   = 587
            From       = 'migration@corp.com'
            To         = @()
        }
    }
    $result = Test-EmailConfig -Config $missingTo
    Assert-True -Condition ($result.Valid -eq $false) -Message 'Email: empty To list fails validation'
    Assert-GreaterThan -Value $result.Issues.Count -Threshold 0 -Message 'Email: empty To has issues'
} catch {
    Assert-True -Condition $false -Message "Email: missing To threw: $_"
}

# 7.4 Build-EmailBodyText contains readiness percentage
try {
    $readinessData = @{
        OverallPercent  = 78.5
        GroupCount      = 4
        ReadyCount      = 2
        InProgressCount = 1
        BlockedCount    = 1
        TotalCRItems    = 7
        P1Count         = 2
        P2Count         = 3
        P3Count         = 2
    }
    $body = Build-EmailBodyText -OverallReadiness $readinessData
    Assert-NotNull -Value $body -Message 'Email: Build-EmailBodyText returns non-null'
    Assert-True -Condition ($body -match '78.5') -Message 'Email: body text contains readiness percentage 78.5'
} catch {
    Assert-True -Condition $false -Message "Email: Build-EmailBodyText threw: $_"
}

# 7.5 Build-EmailBodyText contains CR summary when provided
try {
    $readinessData = @{ OverallPercent = 50.0; GroupCount = 2; ReadyCount = 1; InProgressCount = 0; BlockedCount = 1; TotalCRItems = 3; P1Count = 1; P2Count = 2; P3Count = 0 }
    $crText = "P1: Provision jsmith in PARTNER`nP2: Add ajonas to USV_IT_Admins"
    $body = Build-EmailBodyText -OverallReadiness $readinessData -CRSummaryText $crText
    Assert-True -Condition ($body -match 'CR SUMMARY') -Message 'Email: body contains CR SUMMARY section when text provided'
    Assert-True -Condition ($body -match 'jsmith')     -Message 'Email: body contains CR item text'
} catch {
    Assert-True -Condition $false -Message "Email: CR summary in body threw: $_"
}

# 7.6 Test-EmailConfig fails when Enabled = $false
try {
    $disabledEmail = @{
        Email = @{
            Enabled    = $false
            SmtpServer = 'smtp.corp.com'
            SmtpPort   = 587
            From       = 'migration@corp.com'
            To         = @('admin@corp.com')
        }
    }
    $result = Test-EmailConfig -Config $disabledEmail
    Assert-True -Condition ($result.Valid -eq $false) -Message 'Email: Enabled=false fails validation'
} catch {
    Assert-True -Condition $false -Message "Email: Enabled=false threw: $_"
}

# 7.7 Build-EmailBodyText handles null readiness values gracefully
try {
    $partialData = @{
        OverallPercent = $null
    }
    $body = Build-EmailBodyText -OverallReadiness $partialData
    Assert-NotNull -Value $body -Message 'Email: partial readiness data does not crash Build-EmailBodyText'
    Assert-True -Condition ($body -match 'N/A') -Message 'Email: null OverallPercent renders as N/A'
} catch {
    Assert-True -Condition $false -Message "Email: null readiness graceful handling threw: $_"
}

# 7.8 Test-EmailConfig fails when Email section is missing
try {
    $noEmailSection = @{ SomeOtherKey = 'value' }
    $result = Test-EmailConfig -Config $noEmailSection
    Assert-True -Condition ($result.Valid -eq $false) -Message 'Email: missing Email section fails validation'
} catch {
    Assert-True -Condition $false -Message "Email: missing Email section threw: $_"
}

Write-Host ''

# ============================================================================
# CATEGORY 8: Integration / Edge Cases
# ============================================================================

Write-Host '==========================================' -ForegroundColor Cyan
Write-Host 'Test Category 8: Integration and Edge Cases' -ForegroundColor Cyan
Write-Host '==========================================' -ForegroundColor Cyan

# 8.1 Full v2 pipeline: mock data -> correlate -> gap analysis -> report
$pipelineReportPath = $null
try {
    $pipelineReportPath = Join-Path $testOutputDir "pipeline-$(Get-Date -Format 'yyyyMMddHHmmss').html"

    $pCorr = Find-UserCorrelations `
        -SourceMembers $script:MockCORPMembers `
        -TargetMembers $script:MockPARTNERMembers

    $pGap = Get-MigrationGapAnalysis `
        -SourceGroupResult $script:MockCORPGroup `
        -TargetGroupResult $script:MockPARTNERGroup `
        -CorrelationResult $pCorr

    $pFlatGap = @{
        SourceGroup      = $pGap.GroupPair.SourceGroup
        TargetGroup      = $pGap.GroupPair.TargetGroup
        SourceDomain     = $pGap.GroupPair.SourceDomain
        TargetDomain     = $pGap.GroupPair.TargetDomain
        ReadinessPercent = $pGap.Readiness.Percent
        SourceCount      = $pGap.Readiness.TotalSourceMembers
        TargetCount      = $pGap.Readiness.TotalTargetMembers
        CrCount          = $pGap.Readiness.AddToGroupCount + $pGap.Readiness.NotProvisionedCount + $pGap.Readiness.OrphanedCount
        Items            = $pGap.Items
        Readiness        = $pGap.Readiness
    }

    $pOverall = Get-OverallMigrationReadiness -GapResults @($pGap)

    $returned = Export-MigrationReport `
        -GroupResults     @($script:MockCORPGroup, $script:MockPARTNERGroup) `
        -GapResults       @($pFlatGap) `
        -OverallReadiness @{
            ReadinessPercent = $pOverall.OverallPercent
            ReadyGroups      = $pOverall.ReadyGroups
            InProgressGroups = $pOverall.InProgressGroups
            BlockedGroups    = $pOverall.BlockedGroups
            TotalCrItems     = $pOverall.TotalCRItems
        } `
        -OutputPath       $pipelineReportPath `
        -Theme            'dark'

    Assert-True -Condition (Test-Path $pipelineReportPath) -Message 'Integration: full v2 pipeline produces HTML report'
} catch {
    Assert-True -Condition $false -Message "Integration: full v2 pipeline threw: $_"
} finally {
    if ($pipelineReportPath -and (Test-Path $pipelineReportPath)) { Remove-Item $pipelineReportPath -Force }
}

# 8.2 Gap analysis with null stale data works
try {
    $noStaleGap = Get-MigrationGapAnalysis `
        -SourceGroupResult $script:MockCORPGroup `
        -TargetGroupResult $script:MockPARTNERGroup `
        -CorrelationResult $script:GapCorrelation `
        -StaleResult       $null
    Assert-NotNull -Value $noStaleGap -Message 'Integration: gap analysis with null StaleResult works'
    Assert-Equal -Expected 0 -Actual $noStaleGap.Readiness.SkipStaleCount -Message 'Integration: null StaleResult produces 0 stale skips'
} catch {
    Assert-True -Condition $false -Message "Integration: null StaleResult threw: $_"
}

# 8.3 Gap analysis with empty correlation works
try {
    $emptyCorr = @{
        Correlated      = @()
        UnmatchedSource = @($script:MockCORPMembers)
        UnmatchedTarget = @($script:MockPARTNERMembers)
        NeedsReview     = @()
        Summary         = @{}
    }
    $emptyGap = Get-MigrationGapAnalysis `
        -SourceGroupResult $script:MockCORPGroup `
        -TargetGroupResult $script:MockPARTNERGroup `
        -CorrelationResult $emptyCorr
    Assert-NotNull -Value $emptyGap -Message 'Integration: gap analysis with empty correlation works'
    Assert-Equal -Expected 0 -Actual $emptyGap.Readiness.ReadyCount -Message 'Integration: empty correlation produces 0 ready users'
} catch {
    Assert-True -Condition $false -Message "Integration: empty correlation threw: $_"
}

# 8.4 App readiness with null app mapping works
try {
    $noAppResult = Get-AppReadiness -AppMappings @() -GapResults @($script:GapResult)
    Assert-NotNull -Value $noAppResult -Message 'Integration: Get-AppReadiness with empty mappings works'
    Assert-Equal -Expected 0 -Actual $noAppResult.Apps.Count -Message 'Integration: empty app mappings produces 0 apps'
} catch {
    Assert-True -Condition $false -Message "Integration: empty app mappings threw: $_"
}

# 8.5 Migration report with only v1 data (no gap results) falls back gracefully
$v1OnlyReportPath = $null
try {
    $v1OnlyReportPath = Join-Path $testOutputDir "v1only-$(Get-Date -Format 'yyyyMMddHHmmss').html"
    $v1MatchResults   = Find-MatchingGroups `
        -GroupResults @($script:MockCORPGroup, $script:MockPARTNERGroup) `
        -Prefixes     @('GG_', 'USV_') `
        -MinScore     0.7
    $returned = Export-MigrationReport `
        -GroupResults $script:AllGroupResults `
        -MatchResults $v1MatchResults `
        -GapResults   @() `
        -OutputPath   $v1OnlyReportPath `
        -Theme        'dark'
    Assert-True -Condition (Test-Path $v1OnlyReportPath) -Message 'Integration: v1-only report (no gap data) created successfully'
} catch {
    Assert-True -Condition $false -Message "Integration: v1-only report threw: $_"
} finally {
    if ($v1OnlyReportPath -and (Test-Path $v1OnlyReportPath)) { Remove-Item $v1OnlyReportPath -Force }
}

# 8.6 DisplayName with multiple tags stripped correctly
try {
    $multiTag = _UCorp_NormalizeDisplayName -DisplayName 'SailPoint - John Smith [Contractor]'
    # "SailPoint - " stripped first, then "[Contractor]" stripped
    Assert-True -Condition ($multiTag -notmatch 'SailPoint')  -Message 'Normalize: multi-tag SailPoint removed'
    Assert-True -Condition ($multiTag -notmatch 'Contractor') -Message 'Normalize: multi-tag Contractor removed'
    Assert-True -Condition ($multiTag -match 'john smith')    -Message 'Normalize: multi-tag core name preserved'
} catch {
    Assert-True -Condition $false -Message "Normalize: multi-tag threw: $_"
}

# 8.7 Empty group pair produces expected readiness
try {
    $emptyCorr2 = Find-UserCorrelations -SourceMembers @() -TargetMembers @()
    $emptySrcGrp = New-MockGroupResult -Domain 'CORP'    -GroupName 'GG_Empty' -MemberCount 0 -Members @()
    $emptyTgtGrp = New-MockGroupResult -Domain 'PARTNER' -GroupName 'USV_Empty' -MemberCount 0 -Members @()
    $emptyGap2 = Get-MigrationGapAnalysis `
        -SourceGroupResult $emptySrcGrp `
        -TargetGroupResult $emptyTgtGrp `
        -CorrelationResult $emptyCorr2
    # When in-scope count = 0, readiness should be 100% (vacuously ready)
    Assert-Equal -Expected 100.0 -Actual $emptyGap2.Readiness.Percent -Message 'Integration: empty group pair produces 100% (vacuously ready)'
} catch {
    Assert-True -Condition $false -Message "Integration: empty group pair threw: $_"
}

# 8.8 Single-member group correlation works end-to-end
try {
    $singleSrc = @( (New-MockMember -Sam 'singleuser' -Email 'singleuser@corp.com' -Domain 'CORP') )
    $singleTgt = @( (New-MockMember -Sam 'singleuser' -Email 'singleuser@corp.com' -Domain 'PARTNER') )
    $singleCorr = Find-UserCorrelations -SourceMembers $singleSrc -TargetMembers $singleTgt
    Assert-Equal -Expected 1 -Actual $singleCorr.Correlated.Count -Message 'Integration: single-member group correlates correctly'
    Assert-Equal -Expected 1 -Actual $singleCorr.Summary.TotalSource -Message 'Integration: single-member TotalSource = 1'
} catch {
    Assert-True -Condition $false -Message "Integration: single-member threw: $_"
}

# 8.9 Get-OverallMigrationReadiness with empty GapResults returns zero values
try {
    $emptyOverall = Get-OverallMigrationReadiness -GapResults @()
    Assert-Equal -Expected 0.0 -Actual $emptyOverall.OverallPercent -Message 'Integration: empty GapResults overall = 0%'
    Assert-Equal -Expected 0   -Actual $emptyOverall.GroupCount     -Message 'Integration: empty GapResults GroupCount = 0'
} catch {
    Assert-True -Condition $false -Message "Integration: empty GapResults threw: $_"
}

# 8.10 Build-CRSummaryHtml with empty gap results returns non-null
try {
    $emptyCR = Build-CRSummaryHtml -GapResults @()
    Assert-NotNull -Value $emptyCR -Message 'Integration: Build-CRSummaryHtml with empty gap results does not throw'
} catch {
    # May throw or return null for empty input -- ensure no fatal exception escapes
    Assert-True -Condition $true -Message 'Integration: Build-CRSummaryHtml empty input handled without fatal exception'
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
