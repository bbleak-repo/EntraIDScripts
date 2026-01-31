# AD Architecture Discovery & Comparison Framework -- Status

**Last Updated:** 2026-01-30
**Status:** COMPLETE -- Ready for Windows Testing
**Branch:** main (uncommitted)

---

## What Was Built

A PowerShell framework that discovers and compares the architecture of two AD domains (e.g., prod vs dev). Uses only built-in .NET `System.DirectoryServices` classes -- no RSAT, no admin rights required. Generates HTML comparison reports, JSON exports, and CSV files.

---

## Current State

All code is written, syntax-validated, and tested against mock data on macOS. **107/107 tests pass.** The framework is ready to run against a real Active Directory domain from a Windows machine.

### What Works

- All 8 discovery modules execute and return structured data
- Mock provider has two realistic domains with deliberate differences
- Comparison engine detects 60 differences between mock-prod and mock-dev
- HTML report generates with dark-mode styling, collapsible sections, diff highlighting
- JSON report generates with full metadata (63KB for two-domain comparison)
- CSV export creates 7 category-specific files (OUs, Groups, DCs, Trusts, Sites, Subnets, DNS)
- SkipModules parameter correctly filters module execution
- Single-domain and comparison modes both work
- Graceful error handling -- modules fail independently without crashing the run

### What Has NOT Been Tested

- Real AD domain queries (requires Windows + network access to a DC)
- Cross-domain/cross-forest credential scenarios
- Large domain performance (10k+ OUs, 50k+ groups)
- DNS zone access restrictions (graceful degradation path)
- FSMO role detection against live DCs

---

## File Inventory

```
EntraID/
  AD-Discovery.ps1              # Main orchestrator (12KB)
  README.md                     # Full documentation (15KB)
  .gitignore                    # Excludes Output/, Tests/Output/, logs

  Config/
    discovery-config.json       # Settings: page size, timeouts, limits

  Modules/
    Helpers.ps1                 # LDAP utilities, platform detection (11KB)
    MockProvider.ps1            # Mock data: mock-prod.local + mock-dev.local (20KB)
    ForestDomain.ps1            # Forest/domain functional levels (5KB)
    Schema.ps1                  # Schema version, attributes, classes (6KB)
    OUStructure.ps1             # OU hierarchy with object counts (5KB)
    SitesSubnets.ps1            # Sites, subnets, site links (6KB)
    Trusts.ps1                  # Trust relationships (5KB)
    DomainControllers.ps1       # DCs, FSMO roles, GC status (11KB)
    Groups.ps1                  # Group inventory with safety limits (6KB)
    DNS.ps1                     # DNS zones, graceful degradation (6KB)
    ComparisonEngine.ps1        # Deep-diff comparison algorithm (15KB)
    ReportGenerator.ps1         # HTML/JSON/CSV report generation (31KB)

  Templates/
    report-template.html        # Dark-mode HTML template (11KB)

  Tests/
    Test-Discovery.ps1          # 107 tests, all passing (19KB)

  Output/                       # Generated reports (gitignored)
  Tests/Output/                 # Test artifacts (gitignored)
  docs/
    STATUS.md                   # This file
```

---

## How to Run

### Mock Mode (any platform with pwsh)

```powershell
# Two-domain comparison with all output formats
.\AD-Discovery.ps1 -UseMock -Server mock-prod.local -CompareServer mock-dev.local -Format HTML,JSON,CSV

# Single domain, JSON only
.\AD-Discovery.ps1 -UseMock -Server mock-prod.local -Format JSON

# Skip slow modules
.\AD-Discovery.ps1 -UseMock -Server mock-prod.local -SkipModules DNS,Groups
```

### Real AD (Windows only)

```powershell
# Single domain -- uses current credentials
.\AD-Discovery.ps1 -Server dc01.contoso.com

# Two-domain comparison with explicit credentials
$prodCred = Get-Credential
$devCred = Get-Credential
.\AD-Discovery.ps1 -Server dc01.prod.contoso.com -Credential $prodCred `
                   -CompareServer dc01.dev.contoso.com -CompareCredential $devCred `
                   -Format HTML,JSON,CSV
```

### Run Tests

```powershell
pwsh Tests/Test-Discovery.ps1
```

---

## Key Technical Details

| Item | Detail |
|------|--------|
| Target | PowerShell 5.1 on Windows 11 |
| AD Access | `[System.DirectoryServices]` / `[adsisearcher]` |
| LDAP Paging | PageSize=1000 on all queries |
| LDAP Filters | `objectCategory` (indexed) over `objectClass` |
| Resource Cleanup | `Dispose()` on SearchResultCollection in finally blocks |
| Group Safety | Max 5000 groups, member count estimation at 1500+ |
| Platform Detection | `$PSVersionTable.PSEdition -eq 'Desktop'` (not `$IsWindows`) |
| Module Return | All modules return `@{ Data = ...; Errors = @() }` |

---

## Known Issue Fixed During Build

**`$isWindows` variable conflict:** PowerShell 7 has a read-only automatic variable `$IsWindows`. The orchestrator uses `$isWindowsPlatform` instead to avoid the conflict. This does not affect PS 5.1 on Windows.

---

## Next Steps for Windows Testing

1. Copy project to Windows machine with domain access
2. Run `.\AD-Discovery.ps1 -Server <your-dc-fqdn>` to test single-domain discovery
3. Check Output/ for generated reports
4. If access denied on any module, verify with `-SkipModules` to isolate
5. For cross-domain comparison, prepare credentials for both domains
6. Review HTML report for completeness and accuracy against known domain structure

---

## Git Status

All files are currently untracked. No commits have been made yet. To commit:

```powershell
git add AD-Discovery.ps1 Modules/ Config/ Templates/ Tests/Test-Discovery.ps1 README.md .gitignore docs/
git commit -m "Initial implementation: AD Discovery & Comparison Framework"
```

Do not commit `Output/`, `Tests/Output/`, or `*.rtf` files.
