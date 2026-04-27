<#
.SYNOPSIS
    Builds a synthetic two-forest JSON cache from a real single-forest cache.

.DESCRIPTION
    Given a cache file produced by Invoke-GroupEnumerator against one forest,
    this script creates a mutated copy representing a "target" forest with
    USV_-prefixed group names and rewritten DNs, then merges both into a
    single cache. The result exercises FuzzyMatch, user correlation, gap
    analysis, and the migration dashboard without needing a real 2nd forest.

    Perturbations applied to the target copy:
      - Domain          -> testforest.local
      - GroupName       -> USV_<original>   (FuzzyPrefixes strips this)
      - DistinguishedName suffix rewritten to DC=testforest,DC=local
      - Members: DNs rewritten, sAMAccountName + Email kept (tier-1 email match)
      - Domain Admins: drops one member to simulate a P1 gap (user not in target)
      - Enterprise Admins: adds one orphan to simulate a P3 gap (extra target access)
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]  [string]$SourceCache,
    [Parameter(Mandatory = $true)]  [string]$DestCache,
    [Parameter(Mandatory = $false)] [string]$TargetDomain = 'testforest.local',
    [Parameter(Mandatory = $false)] [string]$TargetBaseDN = 'DC=testforest,DC=local',
    [Parameter(Mandatory = $false)] [string]$TargetPrefix = 'USV_'
)

if (-not (Test-Path $SourceCache)) { throw "Source cache not found: $SourceCache" }

$raw = Get-Content -Path $SourceCache -Raw -Encoding UTF8
$src = $raw | ConvertFrom-Json

# Deep-copy the Groups array by round-tripping JSON — easiest way to detach
$targetGroups = $raw | ConvertFrom-Json | Select-Object -ExpandProperty Groups

function Convert-DnToTarget($dn, $newBaseDN) {
    # Replace the trailing DC=...,DC=... run with the target base
    return ($dn -replace ',DC=[^,]+,DC=[^,]+$', ",$newBaseDN")
}

foreach ($g in $targetGroups) {
    $g.Data.Domain            = $TargetDomain
    $g.Data.GroupName         = $TargetPrefix + ($g.Data.GroupName -replace ' ', '_')
    $g.Data.DistinguishedName = Convert-DnToTarget $g.Data.DistinguishedName $TargetBaseDN

    foreach ($m in $g.Data.Members) {
        $m.Domain            = $TargetDomain
        $m.DistinguishedName = Convert-DnToTarget $m.DistinguishedName $TargetBaseDN
    }
}

# Perturbation 1: drop the first member of "USV_Domain_Admins" (P1 gap)
$tDomAdmins = $targetGroups | Where-Object { $_.Data.GroupName -eq "${TargetPrefix}Domain_Admins" }
if ($tDomAdmins -and $tDomAdmins.Data.Members.Count -gt 1) {
    $dropped = $tDomAdmins.Data.Members[0].SamAccountName
    $tDomAdmins.Data.Members = @($tDomAdmins.Data.Members[1..($tDomAdmins.Data.Members.Count - 1)])
    $tDomAdmins.Data.MemberCount = $tDomAdmins.Data.Members.Count
    Write-Host "  perturb: dropped '$dropped' from target Domain Admins (simulates P1 gap)"
}

# Perturbation 2: add a synthetic orphan to "USV_Enterprise_Admins" (P3 gap)
$tEntAdmins = $targetGroups | Where-Object { $_.Data.GroupName -eq "${TargetPrefix}Enterprise_Admins" }
if ($tEntAdmins) {
    $orphan = [pscustomobject]@{
        SamAccountName    = 'orphan_target_only'
        DisplayName       = 'Orphan Target-only User'
        Email             = 'orphan@testforest.local'
        Enabled           = $true
        Domain            = $TargetDomain
        DistinguishedName = "CN=orphan_target_only,CN=Users,$TargetBaseDN"
    }
    $tEntAdmins.Data.Members = @($tEntAdmins.Data.Members) + $orphan
    $tEntAdmins.Data.MemberCount = $tEntAdmins.Data.Members.Count
    Write-Host "  perturb: added 'orphan_target_only' to target Enterprise Admins (simulates P3 gap)"
}

# Merge source + target groups
$merged = [ordered]@{
    Version      = $src.Version
    Timestamp    = (Get-Date).ToString('o')
    Config       = $src.Config
    Groups       = @($src.Groups) + @($targetGroups)
    MatchResults = $null
    Metadata     = @{
        note       = 'synthetic two-forest cache built from ' + (Split-Path $SourceCache -Leaf)
        sourceCount = @($src.Groups).Count
        targetCount = @($targetGroups).Count
    }
}

$merged | ConvertTo-Json -Depth 20 | Set-Content -Path $DestCache -Encoding UTF8

Write-Host "Built synthetic two-forest cache:"
Write-Host "  source domain = $($src.Groups[0].Data.Domain)   groups=$(@($src.Groups).Count)"
Write-Host "  target domain = $TargetDomain   groups=$(@($targetGroups).Count)"
Write-Host "  output        = $DestCache"
