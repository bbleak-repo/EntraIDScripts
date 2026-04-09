# Development Guide

## Project Structure

```
Group-Enumerator/
  Invoke-GroupEnumerator.ps1       # Main orchestrator (all parameters, flow control)
  Config/
    group-enum-config.json         # Runtime configuration (all settings with defaults)
  Modules/
    GroupEnumLogger.ps1            # JSON Lines structured logging
    GroupEnumerator.ps1            # LDAP enumeration, CSV import, config loading
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
  Tests/
    Test-GroupEnumerator.ps1       # 141 v1 tests
    Test-MigrationReadiness.ps1    # 150 v2 tests
```

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

### LDAP
- Always use `objectCategory` (indexed) in filters, never `objectClass`
- Always dispose `DirectoryEntry`, `DirectorySearcher`, and `SearchResultCollection` in `finally` blocks
- Use `New-LdapDirectoryEntry` helper for connection management (handles LDAPS/Kerberos fallback)
- LDAPS on port 636 with `SecureSocketsLayer` authentication type
- LDAP fallback on port 389 with `Secure -bor Sealing` for Kerberos encryption

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
- Use unary comma `return , $collection` to prevent pipeline unrolling of single-element arrays and HashSets.
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

### Adding Tests
1. Add test in the appropriate category section
2. Wrap in `try/catch` with `$script:TestErrors` tracking
3. Clean up temp files in `finally` blocks
4. Use `New-MockMember` and `New-MockGroupResult` helpers for test data

## Adding a New Module

1. Create `Modules/NewModule.ps1` with comment-based help
2. Add to `$moduleFiles` array in `Invoke-GroupEnumerator.ps1`
3. Add to module loading in both test files
4. Add corresponding tests in the appropriate test file
5. Update `Config/group-enum-config.json` if new config keys needed
6. Update `New-GroupEnumConfig` defaults in `GroupEnumerator.ps1`

## V1 vs V2 Flow

```
V1 (no v2 switches):
  CSV -> Enumerate -> FuzzyMatch -> Cache -> HTML Report

V2 (-AnalyzeGaps):
  CSV -> Enumerate -> FuzzyMatch ->
    -> ResolveNested (optional) ->
    -> DetectStale (optional) ->
    -> UserCorrelation (per matched pair) ->
    -> GapAnalysis (per matched pair) ->
    -> OverallReadiness ->
    -> AppMapping (optional) ->
    -> Cache -> Gap CSV -> CR Summary -> Migration HTML Report
    -> Email (optional)
```

V1 behavior is completely unchanged when no v2 switches are used. All v2 steps are gated on explicit switches.

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
