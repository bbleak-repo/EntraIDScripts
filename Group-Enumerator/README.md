# Cross-Domain Group Enumerator

A production-ready PowerShell tool for enumerating Active Directory group memberships across trusted forests, with cross-domain fuzzy matching, migration readiness analysis, and professional HTML reporting.

## Features

### V1 -- Group Enumeration & Comparison
- **CSV-driven input** -- `Domain,GroupName` or `DOMAIN\GroupName` backslash format (auto-detected)
- **Modern LDAP stack** -- Built on `System.DirectoryServices.Protocols.LdapConnection` (works against DCs enforcing LDAP Channel Binding / Signing, the modern hardened default)
- **Tiered connectivity** -- LDAPS-Verified (636) by default; with `-AllowInsecure` falls through LDAPS cert-bypass then LDAP 389 with Kerberos sign+seal; tier in use is surfaced in the report and logs
- **Per-domain connection pooling** -- One `LdapConnection` per domain, reused across every group, nested-resolve, and stale-check call in a single invocation
- **Fuzzy group matching** -- Levenshtein-based name matching strips configurable prefixes (GG\_, USV\_, SG\_, DL\_, GL\_) to pair groups across domains
- **Dark/light HTML reports** -- Theme toggle persisted to localStorage, sortable columns, per-table search, copy-as-TSV for Excel
- **Side-by-side member diff** -- Color-coded highlighting showing members unique to each domain
- **JSON cache** -- Save/reload enumerated data with `-FromCache` for offline report regeneration
- **Structured logging** -- JSON Lines (.jsonl) with DEBUG/INFO/WARN/ERROR levels, per-tier LdapConnect events

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
- **Cross-forest member resolution** -- When multiple domains are pooled, member DNs that live in another pooled domain are routed to the correct connection, and ForeignSecurityPrincipal entries are resolved by SID against the foreign pool (two-way trust scenarios)
- **Application mapping** -- Optional CSV mapping apps to groups for app-level readiness view
- **Migration dashboard** -- Progress bars, executive summary, CR summary with copy button
- **Email delivery** -- Optional SMTP summary (supports anonymous relay and authenticated TLS)

## Requirements

- PowerShell 5.1 or PowerShell 7+
- `System.DirectoryServices.Protocols` (ships with .NET on Windows; available via .NET on other platforms)
- Network access to target domain controllers on port 636 (LDAPS) or 389 (LDAP) if using fallback tiers
- No RSAT modules required
- No admin rights required (read-only LDAP queries)
- Works against DCs enforcing LDAP Channel Binding and LDAP Signing (the hardened modern default)

## Quick Start

```powershell
# Show usage summary (also printed when invoked with no arguments)
.\Invoke-GroupEnumerator.ps1 -Help

# Simplest single-domain inventory (V1 report)
.\Invoke-GroupEnumerator.ps1 -CsvPath .\groups.csv

# Single-domain inventory with nested group flattening and stale flagging
.\Invoke-GroupEnumerator.ps1 -CsvPath .\groups.csv -ResolveNested -DetectStale

# Cross-domain fuzzy match (verified LDAPS only)
.\Invoke-GroupEnumerator.ps1 -CsvPath .\groups.csv -FuzzyMatch

# Full two-forest migration readiness with fallback tiers enabled
.\Invoke-GroupEnumerator.ps1 -CsvPath .\groups.csv -FuzzyMatch `
    -AnalyzeGaps -DetectStale -ResolveNested -AllowInsecure

# Offline re-render from a saved cache (no AD access)
.\Invoke-GroupEnumerator.ps1 -CsvPath .\groups.csv -FromCache `
    -CachePath .\Cache\groups-20260415-103821.json

# With application mapping
.\Invoke-GroupEnumerator.ps1 -CsvPath .\groups.csv -FuzzyMatch -AllowInsecure `
    -AnalyzeGaps -DetectStale -AppMappingCsv .\app-mapping.csv
```

See [QUICKSTART.md](docs/QUICKSTART.md) for detailed setup instructions, or run
`Get-Help .\Invoke-GroupEnumerator.ps1 -Detailed` for full parameter docs.

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
  Invoke-GroupEnumerator.ps1       # Main orchestrator (pool owner, flow control)
  Config/
    group-enum-config.json         # All settings
  Modules/
    ADLdap.ps1                     # Shared LDAP helper (LdapConnection, pool, tiers)
    GroupEnumLogger.ps1            # JSON Lines structured logging
    GroupEnumerator.ps1            # Group enumeration + cross-forest member resolution
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
    fixtures/
      test-groups.csv              # Example CSV for smoke testing
      test-groups-ip.csv           # Example CSV targeting a DC by IP
      Build-SyntheticTwoForest.ps1 # Builds a synthetic two-forest cache from a real one
  docs/
    QUICKSTART.md
    DEV-GUIDE.md
```

`ADLdap.ps1` is a self-contained, vendored helper with no dependencies on
anything else in this repo. It can be dropped into any sibling AD tool's
`Modules/` directory and dot-sourced; the file header marks it as the canonical
copy so future vendored copies can be diff-synced.

## Testing

```powershell
# Run v1 tests (141 tests, no AD required)
pwsh -File Tests/Test-GroupEnumerator.ps1

# Run v2 migration tests (150 tests, no AD required)
pwsh -File Tests/Test-MigrationReadiness.ps1
```

All tests use mock data and run on any platform (Windows, macOS, Linux).

## LDAP Connection Strategy

Connections are built on `System.DirectoryServices.Protocols.LdapConnection`
with `AuthType.Negotiate` (Kerberos preferred, NTLM fallback). Tiers are tried
in order of decreasing security and the tier in use is logged as a structured
`LdapConnect` event and surfaced in the report when any fallback is active.

| Tier | Port | Encryption | Cert verification | When used |
|------|------|------------|-------------------|-----------|
| 1 | 636 | TLS (LDAPS) | strict | **Default. Always attempted.** |
| 2 | 636 | TLS (LDAPS) | bypassed | `-AllowInsecure` when client cannot validate the DC cert |
| 3 | 389 | SASL sign + seal (Kerberos-wrapped) | n/a | `-AllowInsecure` when 636 is unreachable on the target DC |
| 4 | 389 | none | n/a | Not reachable via switches; reserved for explicit opt-in only |

On every successful bind the tool reads the domain's RootDSE for the
`defaultNamingContext` and caches the connection in the per-run pool, so
subsequent group/member/nested/stale queries for that domain reuse the same
authenticated session.

## License

MIT
