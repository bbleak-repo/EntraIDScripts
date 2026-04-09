# Architecture Plan - Group Enumerator Tool

## Overview
Cross-domain group membership enumeration with fuzzy matching and HTML reporting.

## File Structure
```
EntraID/
  Invoke-GroupEnumerator.ps1          # Main orchestrator
  Config/group-enum-config.json       # Tool configuration
  Modules/
    GroupEnumerator.ps1               # LDAP enumeration (reuses Helpers.ps1 patterns)
    FuzzyMatcher.ps1                  # Cross-domain group name matching
    GroupReportGenerator.ps1          # HTML report generation
  Templates/
    group-report-template.html        # HTML template with dark/light CSS
  Tests/
    Test-GroupEnumerator.ps1          # Full test suite
```

## CSV Input Format
Single CSV file with headers:
```csv
Domain,GroupName
CORP,GG_IT_Admins
PARTNER,USV_IT_Admins
CORP,GG_Finance_Users
PARTNER,Finance_Users
```
Also supports: `DOMAIN\GroupName` format (auto-parsed), or just `GroupName` with -Domain param.

## Configuration (group-enum-config.json)
```json
{
    "LdapPageSize": 1000,
    "LdapTimeout": 120,
    "MaxMemberCount": 5000,
    "SkipLargeGroups": true,
    "LargeGroupThreshold": 5000,
    "SkipGroups": ["Domain Users", "Domain Computers", "Authenticated Users"],
    "FuzzyPrefixes": ["GG_", "USV_", "SG_", "DL_", "GL_"],
    "FuzzyMinScore": 0.7,
    "OutputDirectory": "Output",
    "DefaultTheme": "dark",
    "CachePath": "Cache",
    "CacheEnabled": true
}
```

## Module Contracts

### GroupEnumerator.ps1
```powershell
function Get-GroupMembers {
    param(
        [string]$Domain,
        [string]$GroupName,
        [PSCredential]$Credential,
        [hashtable]$Config
    )
    # Returns:
    @{
        Data = @{
            GroupName = "GG_IT_Admins"
            Domain = "CORP"
            DistinguishedName = "CN=..."
            MemberCount = 42
            Members = @(
                @{
                    SamAccountName = "jsmith"
                    DisplayName = "John Smith"
                    Email = "jsmith@corp.com"
                    Enabled = $true
                    Domain = "CORP"
                    DistinguishedName = "CN=..."
                }
            )
            Skipped = $false
            SkipReason = $null
        }
        Errors = @()
    }
}

function Import-GroupList {
    param([string]$CsvPath, [string]$DefaultDomain)
    # Parses CSV, returns @( @{ Domain="X"; GroupName="Y" }, ... )
}
```

### FuzzyMatcher.ps1
```powershell
function Find-MatchingGroups {
    param(
        [array]$GroupResults,     # All enumerated group results
        [string[]]$Prefixes,     # Prefixes to strip for comparison
        [double]$MinScore         # Minimum similarity score (0.0-1.0)
    )
    # Returns:
    @{
        Matched = @(
            @{
                NormalizedName = "IT_Admins"
                Groups = @(
                    @{ Domain = "CORP"; GroupName = "GG_IT_Admins"; MemberCount = 42 },
                    @{ Domain = "PARTNER"; GroupName = "USV_IT_Admins"; MemberCount = 38 }
                )
                Score = 1.0
            }
        )
        Unmatched = @(
            @{ Domain = "CORP"; GroupName = "GG_Finance_Only"; MemberCount = 15 }
        )
    }
}

function Get-NormalizedName {
    param([string]$GroupName, [string[]]$Prefixes)
    # Strips known prefixes, normalizes for comparison
}

function Get-SimilarityScore {
    param([string]$Name1, [string]$Name2)
    # Levenshtein-based similarity (0.0-1.0)
}
```

### GroupReportGenerator.ps1
```powershell
function Export-GroupReport {
    param(
        [array]$GroupResults,      # All group enumeration results
        [hashtable]$MatchResults,  # From FuzzyMatcher (or null)
        [string]$OutputPath,
        [string]$Theme,            # "dark" or "light" (default in report is toggleable)
        [hashtable]$Config
    )
    # Generates HTML with:
    # 1. Summary section: table of Domain\Group | MemberCount (side-by-side for matches)
    # 2. Detail section: per-group member tables
    # 3. Dark/light toggle via JS
}

function Export-GroupDataJson {
    param(
        [array]$GroupResults,
        [hashtable]$MatchResults,
        [string]$OutputPath
    )
    # Saves JSON cache file (no encryption)
}

function Import-GroupDataJson {
    param([string]$JsonPath)
    # Loads cached data for report regeneration
}
```

## HTML Report Structure
1. **Header**: Tool name, timestamp, domain summary
2. **Theme toggle**: JS button to swap dark/light CSS variables
3. **Summary table**:
   - Matched groups: Domain1\Group | Count | Domain2\Group | Count | Delta
   - Unmatched groups: Domain\Group | Count
4. **Detail sections**: Collapsible per-group with full member tables
   - Columns: SamAccountName | DisplayName | Email | Enabled
   - For matched groups: side-by-side tables with diff highlighting
5. **Footer**: Generation info

## JSON Cache Structure
```json
{
    "Metadata": {
        "GeneratedTimestamp": "2026-04-08 14:30:00",
        "ToolVersion": "1.0.0",
        "CsvSource": "groups.csv",
        "Domains": ["CORP", "PARTNER"],
        "FuzzyMatchEnabled": true
    },
    "Groups": [ ... ],
    "MatchResults": { ... }
}
```

## Main Script Parameters
```powershell
param(
    [Parameter(Mandatory=$true)]
    [string]$CsvPath,

    [PSCredential]$Credential,

    [switch]$FuzzyMatch,

    [string]$ConfigPath = ".\Config\group-enum-config.json",

    [string]$OutputPath,

    [switch]$FromCache,
    [string]$CachePath,

    [ValidateSet("dark","light")]
    [string]$Theme = "dark"
)
```
