# AD Architecture Discovery & Comparison Framework -- Status

**Last Updated:** 2026-04-15
**Status:** COMPLETE -- Verified on Live AD (hardened DC with Channel Binding)
**Branch:** main (pushed to origin)

---

## What Was Built

A PowerShell framework that discovers and compares the architecture of two AD
domains. Uses `System.DirectoryServices.Protocols.LdapConnection` via the
shared `ADLdap.ps1` helper -- works against DCs enforcing LDAP Channel Binding
and LDAP Signing (the modern hardened default). No RSAT, no admin rights
required for discovery. Generates HTML comparison reports, JSON exports, and
CSV files.

Also includes the **Group-Enumerator** toolkit (`Group-Enumerator/`) for
cross-domain group membership enumeration, fuzzy matching, migration readiness
analysis, and gap/CR generation.

---

## Current State

All code is written, tested against mock data (107/107 tests pass), and
verified end-to-end against a live Active Directory domain
(`delusionalsecurity.review`) on Windows 11 with PowerShell 5.1 Desktop.

### What Works (verified live)

**AD-Discovery:**
- All 8 discovery modules execute and return structured data from a real DC
- ForestDomain: domain SID, functional levels (7 = Win2016+), naming contexts
- Schema: version 87, 1498 attributes, 269 classes, custom attribute listing
- OUStructure: OU hierarchy with depth + per-OU object counts
- SitesSubnets: sites, subnets, site links with cost/interval
- Trusts: trust enumeration (empty on single-forest lab — expected)
- DomainControllers: DC inventory, OS, FSMO roles, Global Catalog status
- Groups: 54 groups with type classification (Security/Distribution, scope)
- DNS: zone enumeration
- HTML report (57 KB, dark-mode, collapsible sections) generates cleanly
- JSON report (properly nested, all 8 modules, full data depth) generates cleanly
- Mock provider (107/107 tests) continues to pass on Windows
- Per-run LdapConnection pool: one connection per server, reused across all modules
- Tiered connectivity: LDAPS-Verified (636) by default; with `-AllowInsecure`,
  falls through LDAPS cert-bypass then LDAP 389 Kerberos sign+seal
- `-Help` switch and friendly usage on bare invocation

**Group-Enumerator:**
- 291/291 unit tests (141 V1 + 150 V2) pass
- Live V1: 4 groups enumerated, 16 members resolved, HTML + JSON + log
- Live V2: nested resolution (16 → 20 flat members), stale detection (15 flagged)
- Synthetic two-forest: fuzzy match (4/4 pairs), correlation (13), gap analysis
  (P1/P2/P3 CRs), migration dashboard (83% readiness), CR summary
- Connection pooling: one LdapConnection per domain, reused across all group/nested/stale calls
- Cross-forest member resolution: DN routing + ForeignSecurityPrincipal SID lookup
- `-Help`, `-AllowInsecure`, `-FromCache`, `-JsonOnly` all tested

### Known Limitations

- Two-domain comparison (`-CompareServer`) has only been tested via mock data,
  not yet against two live domains
- OUStructure currently reports OU counts and object counts per OU; does not
  enumerate individual users/computers/groups within each OU or GPO links
  (planned for `-Full` mode)
- Group-Enumerator does not enumerate group members when only one domain is
  supplied and `-FuzzyMatch` is omitted — V2 gap analysis requires matched pairs

### Test Data

The `Tests/fixtures/` directory contains scripts for populating a real AD with
test data:

- **`Seed-TestAD.ps1`** — creates `OU=_DiscoveryTestData` containing 24 OUs
  (depth 4), 36 users (active/disabled/service accounts), 25 groups
  (Global/DomainLocal/Universal, Security/Distribution, nested), 6 computers,
  3 contacts, and 60+ group membership links. Requires write permissions
  (Domain Admin or delegated). Idempotent.
- **`Remove-TestAD.ps1`** — single recursive delete of the entire
  `_DiscoveryTestData` tree via the LDAP Tree Delete control. Prompts for
  confirmation unless `-Force` is specified.

---

## File Inventory

```
EntraIDScripts/
  AD-Discovery.ps1              # Main orchestrator (pool owner, -Help, -AllowInsecure)
  README.md                     # Full documentation
  .gitignore                    # Excludes Output/, Cache/, Logs/, *.log, *.jsonl

  Config/
    discovery-config.json       # Settings: page size, timeouts, output formats

  Modules/
    ADLdap.ps1                  # Shared LDAP helper (LdapConnection, pool, tiers) [vendored]
    Helpers.ps1                 # Shim layer over ADLdap + platform detection + utilities
    MockProvider.ps1            # Mock data: mock-prod.local + mock-dev.local
    ForestDomain.ps1            # Forest/domain functional levels, domain SID
    Schema.ps1                  # Schema version, attributes, classes
    OUStructure.ps1             # OU hierarchy with object counts
    SitesSubnets.ps1            # Sites, subnets, site links
    Trusts.ps1                  # Trust relationships
    DomainControllers.ps1       # DCs, FSMO roles, GC status
    Groups.ps1                  # Group inventory with type classification
    DNS.ps1                     # DNS zones
    ComparisonEngine.ps1        # Deep-diff comparison algorithm
    ReportGenerator.ps1         # HTML/JSON/CSV report generation

  Templates/
    report-template.html        # Dark-mode HTML template

  Tests/
    Test-Discovery.ps1          # 107 tests, all passing
    fixtures/
      Seed-TestAD.ps1           # Populates AD with realistic test data
      Remove-TestAD.ps1         # Tears down test data (recursive OU delete)

  Group-Enumerator/
    Invoke-GroupEnumerator.ps1  # Cross-domain group enumeration orchestrator
    Modules/                    # 12 modules including ADLdap.ps1 (canonical)
    Tests/                      # 291 tests (141 V1 + 150 V2)
    docs/                       # QUICKSTART.md, DEV-GUIDE.md

  docs/
    STATUS.md                   # This file
```

---

## How to Run

### Show usage (any platform)

```powershell
.\AD-Discovery.ps1 -Help
.\AD-Discovery.ps1              # also shows usage when no args given
```

### Mock Mode (any platform)

```powershell
.\AD-Discovery.ps1 -UseMock -Server mock-prod.local -CompareServer mock-dev.local
```

### Real AD (Windows)

```powershell
# Simplest — integrated auth, verified LDAPS
.\AD-Discovery.ps1 -Server dc01.contoso.com

# With fallback tiers (lab / cross-forest / rotated certs)
.\AD-Discovery.ps1 -Server dc01.contoso.com -AllowInsecure

# Two-domain comparison
.\AD-Discovery.ps1 -Server dc01.prod.contoso.com -CompareServer dc01.dev.contoso.com -AllowInsecure
```

### Seed Test Data (requires Domain Admin or delegated write)

```powershell
$adminCred = Get-Credential DOMAIN\Admin
.\Tests\fixtures\Seed-TestAD.ps1 -Server dc01.contoso.com -Credential $adminCred -AllowInsecure

# Run discovery against populated domain
.\AD-Discovery.ps1 -Server dc01.contoso.com -AllowInsecure

# Teardown
.\Tests\fixtures\Remove-TestAD.ps1 -Server dc01.contoso.com -Credential $adminCred -AllowInsecure
```

### Run Tests

```powershell
# AD-Discovery mock tests (107 tests)
pwsh Tests/Test-Discovery.ps1

# Group-Enumerator unit tests (291 tests)
pwsh Group-Enumerator/Tests/Test-GroupEnumerator.ps1
pwsh Group-Enumerator/Tests/Test-MigrationReadiness.ps1
```

---

## Key Technical Details

| Item | Detail |
|------|--------|
| LDAP Stack | `System.DirectoryServices.Protocols.LdapConnection` via `ADLdap.ps1` |
| Auth | `AuthType.Negotiate` (Kerberos preferred, NTLM fallback) |
| Connection Tiers | LDAPS-Verified → LDAPS-Unverified → LDAP-SignSeal (gated by `-AllowInsecure`) |
| Connection Reuse | Per-run pool: one `LdapConnection` per server, shared across all modules |
| Channel Binding | Fully supported (legacy ADSI `DirectoryEntry` is not used anywhere) |
| LDAP Paging | `PageResultRequestControl` with configurable page size (default 1000) |
| LDAP Filters | `objectCategory` (indexed) over `objectClass` |
| Binary Attrs | `objectSid`, `objectGUID`, etc. returned as `byte[]` via `-BinaryAttributes` |
| DateTime Attrs | `whenCreated`, `whenChanged` auto-converted from Generalized Time to `[datetime]` |
| Group Safety | Max 5000 groups, member count estimation, configurable threshold |
| Platform Detection | `$PSVersionTable.PSEdition -eq 'Desktop'` (not `$IsWindows`) |
| Module Return | All modules return `@{ Data = ...; Errors = @() }` |
| Target | PowerShell 5.1 (Desktop) on Windows 11; PS 7+ for mock mode on macOS/Linux |

---

## Bugs Fixed During Live Testing (2026-04-15)

### AD-Discovery
1. `Join-Path` three-argument call — PS 7+ syntax, incompatible with PS 5.1. Chained calls for compat.
2. Shim missing `SearchScope` property — Schema/OUStructure/DomainControllers modules override default Subtree scope. Added writable field to the shim PSCustomObject.
3. OUStructure pipeline-unwrap bug — `Sort-Object` on a single-element array produces a bare hashtable; `.Count` then returns the number of hashtable keys (9) not the number of OUs (1). Wrapped in `@()`.
4. ADLdap `Invoke-AdLdapSearch` empty-BaseDN handling — `if ($BaseDN)` treated empty string (the canonical RootDSE address) as falsy, falling through to the domain root. Replaced with `PSBoundParameters.ContainsKey('BaseDN')`.
5. ADLdap entry-skip on empty DN — entries with an empty `DistinguishedName` (legitimately, the RootDSE) were dropped. Removed the skip; referrals land in `$resp.References`, not `$resp.Entries`.

### Group-Enumerator
1. Parser: `$corrKey:` drive-reference bug (4 sites)
2. `Measure-Object -Property { scriptblock }` (5 sites across 3 files)
3. `Select-Object -ExpandProperty` on hashtables (FuzzyMatcher)
4. FuzzyMatcher missing `SourceDomain`/`SourceGroup`/`TargetDomain`/`TargetGroup` directional fields
5. `MigrationReportGenerator` reading `ReadinessPercent` instead of `OverallPercent` from gap analysis
6. Orchestrator treating tier-downgrade warnings as fatal errors for nested/stale

---

## Version History

- **1.1.0** (2026-04-15): LdapConnection migration + live verification
- **1.0.0** (2026-01-30): Initial implementation (mock-only)
