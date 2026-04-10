# Workflow Selection - Group Enumerator Tool

## Date: 2026-04-08
## Tier: TIER 2 (Standard)

### Complexity Assessment
- **Technical Complexity:** 5/10 (LDAP enumeration, fuzzy matching, HTML generation)
- **Files:** 7-8 (main script, 3 modules, config, template, tests)
- **Impact:** Minor (new tool, no changes to existing modules)

### Scope
Build a production-ready PowerShell group enumeration tool that:
1. Reads CSV input with domain\group names across trusted forests
2. Enumerates members via LDAP (reusing existing Helpers.ps1 patterns)
3. Fuzzy-matches groups across domains (optional -FuzzyMatch switch)
4. Caches data to JSON (no encryption, like CyberArk pattern)
5. Generates HTML report with dark/light toggle, summary + detail sections

### Agent Plan (3 agents)
- **Agent A:** Core modules (GroupEnumerator.ps1, FuzzyMatcher.ps1, config, CSV parser)
- **Agent B:** HTML report (GroupReportGenerator.ps1, template with dark/light toggle)
- **Agent C:** Main orchestrator (Invoke-GroupEnumerator.ps1) + Tests

### Dependencies
- Agents A & B: parallel (no dependencies)
- Agent C: depends on A & B (runs after)
