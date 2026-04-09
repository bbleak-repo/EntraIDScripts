# Cross-Domain Group Enumerator

A production-ready PowerShell tool for enumerating Active Directory group memberships across trusted forests, with cross-domain fuzzy matching, migration readiness analysis, and professional HTML reporting.

## Features

### V1 -- Group Enumeration & Comparison
- **CSV-driven input** -- `Domain,GroupName` or `DOMAIN\GroupName` backslash format (auto-detected)
- **LDAPS-first connectivity** -- Port 636 with TLS by default; Kerberos Sealing fallback (389) via `-AllowInsecure` when cross-forest CA trust is unavailable
- **Fuzzy group matching** -- Levenshtein-based name matching strips configurable prefixes (GG\_, USV\_, SG\_, DL\_, GL\_) to pair groups across domains
- **Dark/light HTML reports** -- Theme toggle persisted to localStorage, sortable columns, per-table search, copy-as-TSV for Excel
- **Side-by-side member diff** -- Color-coded highlighting showing members unique to each domain
- **JSON cache** -- Save/reload enumerated data with `-FromCache` for offline report regeneration
- **Structured logging** -- JSON Lines (.jsonl) with DEBUG/INFO/WARN/ERROR levels

### V2 -- Migration Readiness Analysis
- **Nested group resolution** -- Recursive flattening with cycle detection and configurable depth limit
- **5-tier user correlation** -- Matches users across domains where accounts differ:
  - Tier 1: Email exact match (High confidence)
  - Tier 2: SAM exact match (Medium, flagged for review)
  - Tier 3: DisplayName normalized match (Medium, strips identity system tags)
  - Tier 4: SAM fuzzy match (Low, requires human review)
  - Tier 5: No match (reported as unmatched)
- **Gap analysis** -- Per-group migration readiness scoring with Change Request generation:
  - P1: User not provisioned in target domain
  - P2: User exists but missing from target group
  - P3: Orphaned access in target (security review)
- **Stale account detection** -- Flags disabled and inactive accounts (configurable threshold)
- **Application mapping** -- Optional CSV mapping apps to groups for app-level readiness view
- **Migration dashboard** -- Progress bars, executive summary, CR summary with copy button
- **Email delivery** -- Optional SMTP summary (supports anonymous relay and authenticated TLS)

## Requirements

- PowerShell 5.1 or PowerShell 7+
- .NET DirectoryServices (included with Windows; available via .NET on other platforms)
- Network access to target domain controllers (port 636 or 389)
- No RSAT modules required
- No admin rights required (read-only LDAP queries)

## Quick Start

```powershell
# Basic group enumeration with fuzzy matching
.\Invoke-GroupEnumerator.ps1 -CsvPath .\groups.csv -FuzzyMatch

# Cross-forest with Kerberos Sealing fallback
.\Invoke-GroupEnumerator.ps1 -CsvPath .\groups.csv -FuzzyMatch -AllowInsecure

# Full migration readiness analysis
.\Invoke-GroupEnumerator.ps1 -CsvPath .\groups.csv -FuzzyMatch -AllowInsecure `
    -AnalyzeGaps -DetectStale -ResolveNested

# With application mapping
.\Invoke-GroupEnumerator.ps1 -CsvPath .\groups.csv -FuzzyMatch -AllowInsecure `
    -AnalyzeGaps -DetectStale -AppMappingCsv .\app-mapping.csv
```

See [QUICKSTART.md](docs/QUICKSTART.md) for detailed setup instructions.

## CSV Input Format

**Standard format:**
```csv
Domain,GroupName
CONTOSO,GG_IT_Admins
FABRIKAM,USV_IT_Admins
```

**Backslash format:**
```csv
Group
CONTOSO\GG_IT_Admins
FABRIKAM\USV_IT_Admins
```

**Application mapping (optional):**
```csv
AppName,SourceGroup,TargetGroup,Notes
CRM App,GG_Sales_Users,USV_Sales_Users,IdP initiated
Helpdesk,GG_ITSM_Team,USV_ITSM_Team,SP initiated
```

## Output Files

| File | Description |
|------|-------------|
| `Output/<csv>-<timestamp>.html` | HTML report (v1 or v2 migration dashboard) |
| `Cache/<csv>-<timestamp>.json` | JSON cache for offline regeneration |
| `Output/<csv>-<timestamp>-gaps.csv` | Gap analysis CSV (v2, when `-AnalyzeGaps`) |
| `Output/<csv>-<timestamp>-cr-summary.txt` | Change Request summary (v2) |
| `Logs/group-enum-<timestamp>.jsonl` | Structured log file |

## Configuration

Edit `Config/group-enum-config.json` to customize:

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
    "AllowInsecure": false,
    "LogLevel": "INFO",
    "StaleAccountDays": 90
}
```

## Architecture

```
Group-Enumerator/
  Invoke-GroupEnumerator.ps1       # Main orchestrator
  Config/
    group-enum-config.json         # All settings
  Modules/
    GroupEnumLogger.ps1            # JSON Lines structured logging
    GroupEnumerator.ps1            # LDAP enumeration + CSV import
    FuzzyMatcher.ps1               # Levenshtein fuzzy group matching
    GroupReportGenerator.ps1       # V1 HTML report generation
    NestedGroupResolver.ps1        # Recursive group flattening
    UserCorrelation.ps1            # 5-tier cross-domain user matching
    GapAnalysis.ps1                # Migration gap analysis + CR generation
    StaleAccountDetector.ps1       # Disabled/stale account detection
    AppMapping.ps1                 # App-to-group readiness mapping
    MigrationReportGenerator.ps1   # V2 migration dashboard HTML
    EmailSummary.ps1               # Optional SMTP delivery
  Templates/
    group-report-template.html     # V1 HTML template
    migration-report-template.html # V2 migration dashboard template
  Tests/
    Test-GroupEnumerator.ps1       # 141 tests (v1 features)
    Test-MigrationReadiness.ps1    # 150 tests (v2 features)
  docs/
    QUICKSTART.md
    DEV-GUIDE.md
```

## Testing

```powershell
# Run v1 tests (141 tests, no AD required)
pwsh -File Tests/Test-GroupEnumerator.ps1

# Run v2 migration tests (150 tests, no AD required)
pwsh -File Tests/Test-MigrationReadiness.ps1
```

All tests use mock data and run on any platform (Windows, macOS, Linux).

## LDAP Connection Strategy

| Tier | Port | Security | When Used |
|------|------|----------|-----------|
| 1 (default) | 636 | Full TLS (LDAPS) | Client trusts remote DC's CA |
| 2 (fallback) | 389 | Kerberos Sealing (SASL/GSSAPI) | `-AllowInsecure` + domain trust |
| 3 (last resort) | 389 | Kerberos auth only | `-AllowInsecure` + explicit credential |

The tool always tries LDAPS first. Fallback is logged with warnings and tracked in the report metadata.

## License

MIT
