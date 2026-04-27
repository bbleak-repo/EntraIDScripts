# Development Guide

## Project Structure

```
Group-Enumerator/
  Invoke-GroupEnumerator.ps1       # Main orchestrator (pool owner, flow control, -Help)
  Config/
    group-enum-config.json         # Runtime configuration (all settings with defaults)
  Modules/
    ADLdap.ps1                     # LdapConnection helpers, pool, tiers, binary attrs (CANONICAL)
    GroupEnumLogger.ps1            # JSON Lines structured logging
    GroupEnumerator.ps1            # Group enumeration + cross-forest member resolution
    FuzzyMatcher.ps1               # Levenshtein fuzzy group name matching
    GroupReportGenerator.ps1       # V1 HTML report (group comparison)
    NestedGroupResolver.ps1        # Recursive group member flattening
    UserCorrelation.ps1            # 5-tier cross-domain user identity matching
    GapAnalysis.ps1                # Migration gap analysis + CR generation
    StaleAccountDetector.ps1       # Disabled/stale account flagging
    AppMapping.ps1                 # Optional app-to-group readiness
    MigrationReportGenerator.ps1   # V2 migration dashboard HTML
    EmailSummary.ps1               # Optional SMTP email delivery
  Templates/
    group-report-template.html     # V1 dark/light HTML template
    migration-report-template.html # V2 migration dashboard template
    groups-example-standard.csv    # Sample input CSV (Domain,GroupName format)
    groups-example-backslash.csv   # Sample input CSV (Group / DOMAIN\GroupName format)
  Tests/
    Test-GroupEnumerator.ps1       # 141 v1 tests
    Test-MigrationReadiness.ps1    # 150 v2 tests
    fixtures/
      test-groups.csv              # Example CSVs used for smoke runs
      test-groups-ip.csv
      Build-SyntheticTwoForest.ps1 # Fabricates a 2-forest cache from a 1-forest one
```

`ADLdap.ps1` is marked CANONICAL in its header comment. It is intentionally
self-contained (no dependencies on anything else in this repo) so it can be
copy-vendored into sibling AD tools. When fixing bugs, update the canonical
copy and diff-sync any vendored copies.

## Conventions

### Module Pattern
All modules are dot-sourced (not `.psm1`). They do NOT use `Export-ModuleMember`. Functions are available in the caller's scope after dot-sourcing.

### Return Pattern
```powershell
@{
    Data   = @{ ... }    # Result data
    Errors = @()         # Array of error message strings
}
```

### LDAP (ADLdap.ps1)
All LDAP work goes through the `ADLdap.ps1` helper. The legacy
`System.DirectoryServices.DirectoryEntry` / `DirectorySearcher` ADSI stack is
not used anywhere in this project -- it cannot bind to DCs that enforce LDAP
Channel Binding, which is the hardened modern default.

**Public API:**
```powershell
# Connection
$ctx  = New-AdLdapConnection -Server $domain [-Credential $c] [-AllowInsecure] [-TimeoutSeconds 120]
# Returns @{ Connection; BaseDN; Tier; Port; Secure; Server; Errors }

# Pooling (one LdapConnection per domain, owned by the caller)
$pool = New-AdLdapConnectionPool [-Credential $c] [-AllowInsecure] [-TimeoutSeconds 120]
$ctx  = Get-AdLdapPooledContext -Pool $pool -Domain $domain     # lazy open
Close-AdLdapConnectionPool $pool                                # dispose all

# Search (handles paging via PageResultRequestControl)
$hits = Invoke-AdLdapSearch -Context $ctx `
    -Filter '(&(objectCategory=group)(cn=Domain Admins))' `
    -Scope Subtree -Attributes @('distinguishedName','member') `
    [-BinaryAttributes @('objectSid','objectGUID')] `
    [-PageSize 1000] [-SizeLimit 0] [-TimeoutSeconds 120]
# Returns hashtable[], each @{ DistinguishedName; <attr> = <string|string[]|byte[]> }

# Cross-forest helpers
$foreign = Get-AdLdapContextForDN -Pool $pool -DistinguishedName $dn       # longest-suffix match
$sidStr  = ConvertTo-AdLdapSidString -SidBytes $bytes
$sidFlt  = ConvertTo-AdLdapSidFilter -SidBytes $bytes                       # for (objectSid=...)
$domSid  = Get-AdLdapDomainSid -Pool $pool -Context $ctx                   # cached on pool

# Single-shot disposal
Close-AdLdapConnection $ctx
```

**Conventions:**
- Always use `objectCategory` (indexed) in filters, never `objectClass`.
- Attribute reads from `Invoke-AdLdapSearch` come back as scalar string (1 value), string array (>1 values), or missing from the hashtable (0 values). Always guard multi-valued reads with `$h.ContainsKey('attr')` and `$h.attr -is [array]`.
- Binary attributes (`objectSid`, `objectGUID`, etc.) must be listed in `-BinaryAttributes` or they'll be mangled by a `[string]` cast. Listed attrs come back as `byte[]` (or `byte[][]` for multi-valued).
- For functions that accept `-ConnectionPool`, use `Get-AdLdapPooledContext` to acquire and do NOT close the context in `finally` -- the pool owner disposes. When no pool is supplied, open a one-shot context with `New-AdLdapConnection` and close it in `finally`. Gate with an `$ownCtx` boolean: `if ($ctx -and $ownCtx) { Close-AdLdapConnection $ctx }`.
- Connection tiers (tried in order): LDAPS-Verified, LDAPS-Unverified (requires `-AllowInsecure`), LDAP-SignSeal (requires `-AllowInsecure`), LDAP-Plain (explicit opt-in only). The tier that actually connected is on `$ctx.Tier` and should be propagated into any warning string in the function's `Errors` array.

### Logging
```powershell
Write-GroupEnumLog -Level 'INFO' -Operation 'EnumerateGroup' `
    -Message "Enumerated CORP\GG_IT_Admins" -Context @{
        domain      = 'CORP'
        groupName   = 'GG_IT_Admins'
        memberCount = 42
    }
```

Levels: `DEBUG`, `INFO`, `WARN`, `ERROR`. Context fields are merged flat into the JSON entry.

### PowerShell Gotchas
- `$(if (...))` for subexpressions (not `(if (...))`). Bare `if` inside hashtable literals or function call parens causes parse errors.
- Use unary comma `return , $collection` to prevent pipeline unrolling of single-element arrays and HashSets. Also wrap `Sort-Object` results in `@()` when the input may be a single element: `$arr = @($arr | Sort-Object ...)`. Without this, a single-element array becomes a bare hashtable after sorting, and `.Count` returns the number of *keys* instead of the number of *items*.
- `[array]$var` cast to preserve array type across assignment.
- `-contains` is case-insensitive for strings. Use HashSet for case-insensitive `.Contains()`.
- `Add-Content -Encoding UTF8` for log appends. `[System.IO.File]::WriteAllText($path, $content, [System.Text.UTF8Encoding]::new($false))` for reports (no BOM).

### HTML Templates
- All CSS/JS inline (self-contained single file)
- CSS custom properties for theming: `.theme-dark` / `.theme-light`
- Color palette: bg `#1a1a2e`, accent `#3498db`, matched `#52b788`, warning `#f59e0b`, error `#e63946`
- Font stack: `-apple-system, 'Segoe UI', system-ui, sans-serif`
- Template placeholders: `{{PLACEHOLDER_NAME}}` (double-braced)
- Resolve template path at module load time using `$PSScriptRoot` (not `$MyInvocation.MyCommand.Path`)

## Testing

### Framework
Custom assert functions matching the project's AD-Discovery test patterns:
- `Assert-True -Condition $bool -Message "text"`
- `Assert-Equal -Expected $x -Actual $y -Message "text"`
- `Assert-NotNull -Value $v -Message "text"`
- `Assert-GreaterThan -Value $v -Threshold $t -Message "text"`
- `Assert-Contains -Collection $c -Item $i -Message "text"`

### Running Tests
```powershell
# V1 tests (141 tests, ~0.2s)
pwsh -File Tests/Test-GroupEnumerator.ps1

# V2 tests (150 tests, ~0.3s)
pwsh -File Tests/Test-MigrationReadiness.ps1
```

All tests use mock data. No LDAP/AD dependency. Runs on Windows, macOS, Linux.

### Test Fixtures

`Tests/fixtures/` contains helpers for live testing:

| File | Purpose |
|------|---------|
| `test-groups.csv` | Example CSV for smoke runs against a real domain |
| `test-groups-ip.csv` | Example CSV targeting a DC by IP (tests cert-bypass fallback) |
| `Build-SyntheticTwoForest.ps1` | Derives a synthetic two-forest JSON cache from a real one-forest cache. Mutates domain names, group prefixes, drops/adds members to exercise fuzzy match, correlation, gap analysis, and migration dashboard without needing a real second forest. |

The parent repo also includes `Tests/fixtures/Seed-TestAD.ps1` and
`Remove-TestAD.ps1` — these populate a real AD with 24 OUs, 36 users, 25
groups, computers, and contacts under `OU=_DiscoveryTestData` so both
AD-Discovery and Group-Enumerator have rich wire data to exercise. Requires
Domain Admin or delegated write access. Idempotent; teardown is a single
recursive delete.

### Adding Tests
1. Add test in the appropriate category section
2. Wrap in `try/catch` with `$script:TestErrors` tracking
3. Clean up temp files in `finally` blocks
4. Use `New-MockMember` and `New-MockGroupResult` helpers for test data

## Adding a New Module

1. Create `Modules/NewModule.ps1` with comment-based help
2. Add to `$moduleFiles` array in `Invoke-GroupEnumerator.ps1`. `ADLdap.ps1` must be listed first so new modules can depend on it.
3. Add to module loading in both test files
4. Add corresponding tests in the appropriate test file
5. Update `Config/group-enum-config.json` if new config keys needed
6. Update `New-GroupEnumConfig` defaults in `GroupEnumerator.ps1`
7. If the module makes LDAP queries, follow the ADLdap conventions above: accept an optional `-ConnectionPool` parameter, use `Get-AdLdapPooledContext` when it's supplied, fall back to `New-AdLdapConnection` when it isn't, and gate disposal on `$ownCtx`.

## V1 vs V2 Flow

```
V1 (no v2 switches):
  CSV -> Open pool -> Enumerate (per group, pooled ctx) ->
    -> [FuzzyMatch (optional)] -> Cache -> HTML Report -> Close pool

V2 (-AnalyzeGaps):
  CSV -> Open pool -> Enumerate (per group, pooled ctx) ->
    -> FuzzyMatch ->
    -> ResolveNested (optional, pooled ctx) ->
    -> DetectStale (optional, pooled ctx) ->
    -> UserCorrelation (per matched pair) ->
    -> GapAnalysis (per matched pair) ->
    -> OverallReadiness ->
    -> AppMapping (optional) ->
    -> Cache -> Gap CSV -> CR Summary -> Migration HTML Report ->
    -> Email (optional) -> Close pool
```

V1 behavior is completely unchanged when no v2 switches are used. All v2 steps
are gated on explicit switches. The pool is owned by `Invoke-GroupEnumerator.ps1`
and disposed in a top-level `finally` so connections are always cleaned up even
on fatal errors. Cross-forest member resolution (direct foreign-DN routing and
ForeignSecurityPrincipal SID lookup) activates automatically whenever multiple
domains are in the pool -- it's not behind a switch.

## User Correlation Tiers

| Tier | Method | Confidence | Auto-correlate | Review |
|------|--------|------------|----------------|--------|
| 1 | Email exact match | High | Yes | No |
| 2 | SAM exact match | Medium | Yes | Yes |
| 3 | DisplayName normalized | Medium | Yes | Yes |
| 4 | SAM fuzzy (Levenshtein) | Low | Yes | Yes |
| 5 | No match | None | No | N/A |

DisplayName normalization strips identity system tags (parenthetical suffixes, common prefixes/suffixes like "EXT", "Contractor", etc.) before comparison.

## Gap Analysis Statuses

| Status | Priority | Meaning |
|--------|----------|---------|
| Ready | Info | User correlated and present in target group |
| AddToGroup | P2 | User correlated but not in target group |
| NotProvisioned | P1 | User has no account in target domain |
| OrphanedAccess | P3 | Target user with no source correlation |
| Skip-Stale | Info | Source account inactive, excluded |
| Skip-Disabled | Info | Source account disabled, excluded |
