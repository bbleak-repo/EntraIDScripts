# V2 Architecture Plan - Migration Readiness Group Enumerator

## Context
Okta migration from CORP (EntraID) to PARTNER (Okta tenant). Users have distinct
contractor accounts in each domain (e.g. jsmith in CORP, jsmith02 in PARTNER).
AD groups control Okta app access for IdP and SP-initiated SSO flows.
Goal: build data for Change Requests, not execute changes.

## New Modules

### 1. Modules/NestedGroupResolver.ps1
Recursively resolve group membership to flat user lists.
- `Resolve-NestedGroupMembers` - takes a group result, returns flattened user array
- Track recursion depth (configurable limit, default 10)
- Log nested groups found at each level
- De-duplicate users who appear through multiple nesting paths
- Return: @{ FlatMembers = @(...); NestedGroups = @(...); MaxDepthReached = $false }

### 2. Modules/UserCorrelation.ps1
Cross-domain user identity matching with confidence scoring.

**Correlation tiers (in priority order):**
| Tier | Match Type | Confidence | Action |
|------|-----------|------------|--------|
| 1 | Email exact match | High | Auto-correlate |
| 2 | SAM exact match | Medium | Auto-correlate, flag for review |
| 3 | DisplayName exact match | Medium | Flag for review |
| 4 | SAM fuzzy match (jsmith ~ jsmith02) | Low | Flag for human review |
| 5 | No match found | None | Report as "user not in target domain" |

Functions:
- `Find-UserCorrelations` - correlate users across two domain member lists
- `Get-UserMatchScore` - score a potential match pair
- `Get-FuzzySamVariants` - generate likely SAM variants (append/strip digits, suffix patterns)
- Return: @{ Correlated = @(...); UnmatchedSource = @(...); UnmatchedTarget = @(...); NeedsReview = @(...) }

### 3. Modules/GapAnalysis.ps1
Migration gap analysis producing actionable data.

For each matched group pair (source=CORP, target=PARTNER):
- **In source, correlated, in target group** = "Ready" (no action)
- **In source, correlated, NOT in target group** = "Add to group" (CR item)
- **In source, NOT correlated** = "User not provisioned in target" (CR item)
- **In target, NOT correlated to source** = "Orphaned access - review" (CR item)

Functions:
- `Get-MigrationGapAnalysis` - full analysis for one group pair
- `Get-MigrationReadiness` - readiness score/percentage per group
- `Export-GapAnalysisCsv` - actionable CSV with columns:
  Action | Priority | SourceDomain\Group | TargetDomain\Group | SamAccountName |
  DisplayName | Email | CorrelationConfidence | Notes
- `Export-ChangeRequestSummary` - CR-ready summary document

### 4. Modules/StaleAccountDetector.ps1
Flag accounts to skip during migration.
- `Get-StaleAccounts` - check lastLogonTimestamp, userAccountControl
- Configurable stale threshold (default 90 days)
- Return: @{ Disabled = @(...); Stale = @(...); Active = @(...) }
- Stale accounts marked "skip" in gap analysis

### 5. Modules/AppMapping.ps1
Optional app-to-group mapping for application-level readiness.
- `Import-AppMapping` - load CSV: AppName,SourceGroup,TargetGroup
- `Get-AppReadiness` - per-app readiness based on underlying group readiness
- Return: @{ Apps = @( @{ Name; SourceGroup; TargetGroup; ReadinessPercent; GapCount } ) }

### 6. Modules/MigrationReportGenerator.ps1
Enhanced HTML report extending GroupReportGenerator.ps1.

Report sections:
1. **Executive Summary** - overall readiness %, group count, user count, CR count
2. **Migration Readiness Dashboard** - per-group progress bars (red/amber/green)
3. **Application Readiness** (if app mapping provided) - per-app status
4. **Gap Analysis Detail** - per-group with action items table
5. **User Correlation Report** - full mapping with confidence, flagged items
6. **Stale/Disabled Accounts** - do-not-migrate list
7. **Change Request Summary** - grouped by type (group adds, provisioning, reviews)
8. **Original Group Comparison** (from v1) - member diff tables

### 7. Modules/EmailSummary.ps1 (Optional)
- `Send-MigrationSummaryEmail` - SMTP delivery of summary HTML
- Uses .NET SmtpClient (same pattern as BreakGlass EmailDelivery.ps1)
- Config: SmtpServer, From, To[], Subject prefix
- Sends the full HTML report as body or attachment

## Modified Files
- `Invoke-GroupEnumerator.ps1` - add v2 switches and orchestration
- `Config/group-enum-config.json` - new config sections
- `Templates/migration-report-template.html` - new template
- `Tests/Test-GroupEnumerator.ps1` - extended tests

## Config Additions
```json
{
    "NestedGroupMaxDepth": 10,
    "StaleAccountDays": 90,
    "CorrelationStrategy": "email-first",
    "AppMappingCsvPath": null,
    "Email": {
        "Enabled": false,
        "SmtpServer": "",
        "From": "",
        "To": [],
        "SubjectPrefix": "[Migration Readiness]"
    }
}
```

## New Parameters for Invoke-GroupEnumerator.ps1
```powershell
[switch]$ResolveNested       # Flatten nested group memberships
[switch]$AnalyzeGaps         # Run migration gap analysis
[switch]$DetectStale          # Flag stale/disabled accounts
[string]$AppMappingCsv       # Optional app-to-group CSV
[switch]$SendEmail            # Send summary email
[int]$StaleDays = 90          # Stale account threshold
```

## Agent Assignment (TIER 3)
- Agent A: NestedGroupResolver.ps1 + StaleAccountDetector.ps1
- Agent B: UserCorrelation.ps1
- Agent C: GapAnalysis.ps1 + AppMapping.ps1
- Agent D: MigrationReportGenerator.ps1 + migration-report-template.html
- Agent E: EmailSummary.ps1
- Agent F (after A-E): Orchestrator updates + config
- Agent G (after A-E): Tests
