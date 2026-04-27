# EntraID Project -- Status

**Last Updated:** 2026-04-03
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

---
---

## Session: Microsoft Lighthouse MSP Security Deep Research (2026-03-30 to 2026-04-03)

**Status:** COMPLETE -- All deliverables produced
**Framework Used:** #NotebookLM DEEP TIER2 (Opus topic analysis + 7 Sonnet research agents + Sonnet technical writer)

### Context

Deep research into Microsoft Lighthouse functionality for MSPs, focused on cybersecurity. The user is evaluating how MSPs can securely manage client Azure tenants via Lighthouse/GDAP as part of SOW engagements. Key questions addressed:

- How does Lighthouse work (M365 vs Azure Lighthouse disambiguation)?
- How do customers secure and audit MSP access?
- GDAP permission model and least privilege tiering
- Can it support JIT after approvals similar to CyberArk?
- How does CyberArk integrate when it is the primary PAM product?
- How does Purview/Sentinel handle alerting for partner access?
- PRT mechanics from the MSP desktop perspective
- Conditional Access controls (US-only geo-fencing, phishing-resistant MFA, device compliance)
- SOPs, risks, limitations, breach case studies, compliance mapping

### Phase 0: Topic Analysis (Opus)

Decomposed the topic into 7 sub-topics with clear boundaries and cross-references. High interdependency level identified across all domains.

**Output:** `docs/deep-research/planning/PLAN_MS-Lighthouse-MSP-Security_2026-03-30.md`

### Phase 1: Parallel Research (7 Sonnet Agents)

All 7 agents completed successfully with sourced research files:

| # | Agent Topic | Output File | Key Findings |
|---|------------|-------------|--------------|
| 1 | Lighthouse Architecture & GDAP | `DEEP_Lighthouse-Architecture-GDAP_2026-03-30.md` | Two products named Lighthouse (M365 vs Azure); no standalone on-prem product; 3 GDAP service principals; XTAP service-provider flag |
| 2 | GDAP Permission Model | `DEEP_GDAP-Permission-Model_2026-03-30.md` | 3-tier role model; roles immutable after creation; Global Admin auto-extend prohibited; NOBELIUM drove DAP deprecation |
| 3 | Auditing, Sentinel, Purview | `DEEP_Auditing-Sentinel-Purview_2026-03-30.md` | UserType 9 = PartnerTechnician; Purview interactive search NOT supported via GDAP; MSP identity redacted in customer logs; 5 KQL queries |
| 4 | PAM, JIT, CyberArk | `DEEP_PAM-JIT-CyberArk_2026-03-30.md` | PIM for Groups = only GDAP JIT mechanism; CyberArk complementary (session recording, vaulting); no native PIM-CyberArk integration; Lighthouse JIT activates across all template tenants |
| 5 | Conditional Access Cross-Tenant | `DEEP_Conditional-Access-CrossTenant_2026-03-30.md` | US-only geo-fencing via Named Locations + service provider user type; VPN bypass risk; GDAP MFA always trusted; Entra P1 required in customer tenant |
| 6 | PRT & Device Trust | `DEEP_PRT-Device-Trust_2026-03-30.md` | PRT bound to TPM 2.0; GDAP MFA trust override is hardcoded; pass-the-PRT = all customer tenants at risk; WAM broker mechanics |
| 7 | SOPs, Risks, Limitations | `DEEP_SOPs-Risks-Limitations_2026-03-30.md` | 2,500 seat cap; breach case studies (SolarWinds, Kaseya $70M, ConnectWise CVSS 10.0, BerryDunn 1.1M); IR playbook; compliance mapping |

All source research files in: `docs/deep-research/source-research/DEEP_*_2026-03-30.md`

### Phase 2: Technical Writer (Sonnet)

Synthesized all 7 research files into unified podcast guide. Resolved contradictions (730 vs 720 day duration). Created SOP template.

**Outputs:**
- `docs/deep-research/podcasts/MS-Lighthouse-MSP-Security-Podcast-Guide.md` (10,417 words, ~50-55 min audio)
- `docs/deep-research/templates/GDAP-Lighthouse-Security-SOP-Template.md` (5,368 words, 9 SOPs)

### Phase 3: HTML Reference Files

4 HTML files with dark professional theme, embedded CSS, no external dependencies, print-friendly:

| File | Size | Audience | Content |
|------|------|----------|---------|
| `MS-Lighthouse-Executive-Summary.html` | 45K | C-suite / Board | Key stats, DAP vs GDAP, risk findings, 8 prioritized recommendations, compliance mapping |
| `MS-Lighthouse-Architecture-Permissions.html` | 28K | Security Architects | GDAP flow diagram, 4-tier permission model, role-by-workload collapsibles, SOW mapping, relationship parameters |
| `MS-Lighthouse-Security-Controls.html` | 30K | Security Engineers | CA policies, geo-fencing steps, PIM vs CyberArk comparison, KQL queries, PRT auth flow, session controls |
| `MS-Lighthouse-Risk-Compliance.html` | 26K | Risk/Compliance | Breach timeline cards, risk assessment matrix, IR playbook, SOC2/ISO27001/NIST mapping, cyber insurance |

All HTML files in: `docs/deep-research/`

### Critical Findings Summary

1. **Two Lighthouse products** -- M365 Lighthouse (MSP multi-tenant SaaS) vs Azure Lighthouse (ARM-layer). On-prem = Azure Lighthouse + Azure Arc.
2. **GDAP MFA trust override** -- Partner home-tenant MFA is ALWAYS trusted in customer tenants regardless of trust settings. Hardcoded behavior.
3. **PIM for Groups = only GDAP JIT option** -- No external tool (including CyberArk) can manage GDAP security group membership.
4. **CyberArk is complementary** -- Fills session recording, credential vaulting, rotation, and non-Microsoft gaps. No native PIM integration.
5. **Lighthouse JIT blast radius** -- Activates across ALL tenants in a GDAP template simultaneously, not per-customer.
6. **MSP identity redacted** -- Customer logs show "[Partner Name] Technician" not individual names. Forensic correlation requires MSP cooperation.
7. **Purview interactive audit search unsupported via GDAP** -- Must use PowerShell or Management Activity API.
8. **Lighthouse alerting limited** -- Only Defender for Business, Defender AV, Entra ID. Sentinel required for comprehensive monitoring.
9. **2,500 seat cap** per customer tenant in M365 Lighthouse.
10. **30-minute propagation delay** for GDAP security group removal (relevant for incident response).

### How to Resume This Work

**To generate the podcast audio:**
1. Upload `docs/deep-research/podcasts/MS-Lighthouse-MSP-Security-Podcast-Guide.md` to Google NotebookLM
2. Use the "Audio Overview" feature to generate the podcast

**To extend the research:**
- Source research files are in `docs/deep-research/source-research/DEEP_*_2026-03-30.md`
- Planning document with topic decomposition: `docs/deep-research/planning/PLAN_MS-Lighthouse-MSP-Security_2026-03-30.md`
- SOP template ready for MSP customization: `docs/deep-research/templates/GDAP-Lighthouse-Security-SOP-Template.md`

**To view the HTML reports:**
- Open any `.html` file in `docs/deep-research/` directly in a browser
- All are self-contained (embedded CSS, no external dependencies)

---
---

## Session: Microsoft Purview PAM / HLA Role Analysis (2026-04-03)

**Status:** COMPLETE -- All deliverables produced
**Focus:** Microsoft Purview role classification for PAM (CyberArk + Entra PIM)

### Context

Analyzed all ~90 Microsoft Purview roles (sourced from rbacmap.com) and classified them into a 4-tier HLA (High-Level Access) model for PAM protection using CyberArk and Entra ID PIM. Developed stakeholder pushback mitigation strategies. Produced three HTML deliverables for leadership, technical implementation, and change management.

### 1. Purview Role HLA Classification (4-Tier Model)

| Tier | Protection | Count | Examples |
|------|-----------|-------|---------|
| **Tier 1** | CyberArk Full PSM (session proxy + recording) | 12 | Global Admin, Security Admin, eDiscovery Admin, Compliance Data Admin, IRM, DLP Compliance Mgmt, DSPM Full Access |
| **Tier 2** | CyberArk Vault + Entra PIM (no PSM proxy) | ~15 | IRM Admins, Info Protection Admins, Sensitivity Label Admin, Audit Manager, Records Mgmt, Privacy Mgmt Admin |
| **Tier 3** | Entra PIM Only (JIT activation) | ~12 | eDiscovery Manager, IRM Investigators/Analysts, Info Protection Investigators, Content Explorer Content Viewer |
| **Tier 4** | MFA + Conditional Access (existing controls) | 50+ | All Viewer roles, all Reader roles, Communication Compliance Analysts |

**Key classification criteria:**
- Content Explorer access (view actual file contents) = automatic HLA
- Audit Manager = HLA (can shorten retention to cover tracks)
- DSPM Full Access = HLA (one-click policy creation across DLP + IRM + labels)
- eDiscovery Admin (Tier 1, org-wide) vs Manager (Tier 3, scoped to own cases)

### 2. Stakeholder Pushback Framework

Developed responses for common CyberArk/PSM usability concerns:
- **Key message:** "85% of users see zero workflow change" (only Tier 1 = 5-8 people use PSM)
- **Five framing strategies:** Risk-based tiering, Hybrid PAM (Vault+PIM), export automation via Graph API, risk quantification per role, regulatory compliance card
- **Usability mitigations:** CyberArk HTML5 Gateway, PAW for power users, tuned session timeouts (4-8hr), automated report pipelines

### 3. Small Team Variant (1-2 People Scenario)

Addressed the scenario where only 1-2 people need all HLA access with 2 shared service accounts:
- **Option A (Recommended):** Role-grouped accounts -- 4 accounts grouped by workflow domain:
  - `adm-purview-compliance@` (Compliance Admin, Compliance Data Admin, Retention, Records)
  - `adm-purview-security@` (Security Admin, DLP, Info Protection, Sensitivity Labels)
  - `adm-purview-investigations@` (eDiscovery Admin, IRM, Data Security Investigations)
  - `adm-purview-platform@` (Global Admin, Purview Admins, DSPM, Data Security Mgmt)
- **Option B:** 2 named accounts + PIM per-task role activation
- **Option C:** 2 god accounts + compensating controls (exclusive access, dual control, risk exception)
- **Key concern with god accounts:** Audit attribution loss, least privilege violation, blast radius

### 4. HTML Deliverables

All three use the project dark-theme design system (matching MS-Lighthouse docs):

| Document | Path | Lines | Audience |
|----------|------|-------|----------|
| **Leadership Proposal** | `docs/deep-research/Purview-PAM-Leadership-Proposal.html` | 1,194 | CISO, CCO, executive leadership |
| **Technical Implementation** | `docs/deep-research/Purview-PAM-Technical-Implementation.html` | 1,585 | IAM engineers, CyberArk admins |
| **Change Requests** | `docs/deep-research/Purview-PAM-Change-Requests.html` | 2,134 | Change management teams |

**Leadership Proposal includes:**
- Executive summary with stat cards
- Compromised role impact analysis table (7 roles with concrete attack scenarios)
- 4-tier model with color-coded panels
- Usability concern mitigation table
- Regulatory alignment (NIST, SOX, HIPAA, CMMC, ISO 27001, PCI DSS, CISA Zero Trust)
- 6-phase implementation timeline (21 weeks)
- Decision block: Option A (full), B (Tier 1-2 only), C (accept risk with signed exception)

**Technical Implementation includes:**
- Architecture flow diagrams for all 4 tiers
- Prerequisites (CyberArk PAS v13+, Entra ID P2, PSM HTML5 Gateway)
- Tier 1: Safe config, platform config, 12 account naming convention (adm-purview-*@), PSM session policies (8hr max, keystroke logging), connection component setup
- Tier 2: CyberArk vault config, PIM PowerShell/Graph API examples (Connect-MgGraph, eligible assignment creation), per-role PIM policy table, Conditional Access policies
- Tier 3: PIM eligible assignments, app-scoped CA policies, quarterly access reviews with PowerShell
- Tier 4: Baseline security, tier misclassification audit script
- Monitoring: CyberArk reporting, PIM reporting, Purview UAL queries (Search-UnifiedAuditLog), SIEM correlation rules (bypass detection)
- 4 operational runbooks: Emergency break glass, new role assignment, quarterly review, PSM troubleshooting
- Rollback plans for each tier

**Change Requests include:**
- **8 Entra PIM CRs** (CR-PIM-001 through CR-PIM-008):
  - 001: Compliance roles | 002: eDiscovery roles | 003: Info Protection & DLP | 004: Insider Risk Mgmt
  - 005: Data Governance & Data Map | 006: Audit Management | 007: Access Reviews | 008: Conditional Access
- **6 CyberArk CRs** (CR-CYA-001 through CR-CYA-006):
  - 001: Safe & platform config | 002: Tier 1 account onboarding | 003: Tier 2 credential vaulting
  - 004: PSM recording policies | 005: CyberArk-PIM integration monitoring | 006: Automated reporting
- Each CR has: scope, pre-implementation steps, implementation steps, testing criteria, rollback, dependencies, effort estimate, risk level
- 4-phase implementation sequence (16 weeks) with dependency chart
- Master summary table

### Open Items / Next Steps

1. **Small team variant in HTML docs** -- Update Leadership/CR docs to include role-grouped account model (Option A) as an alternative
2. **PlantUML diagrams** -- Create formal .puml architecture diagrams for the 4-tier model
3. **NotebookLM podcast** -- Could generate a podcast guide from the Purview PAM analysis for stakeholder education
4. **Git commit** -- All Purview PAM HTML files are uncommitted

### How to Resume This Work

**To view deliverables:**
- Open any `.html` file in `docs/deep-research/` directly in a browser
- All are self-contained (embedded CSS, no external dependencies)
- Files starting with `Purview-PAM-*` are from this session

**To extend:**
- Role data sourced from rbacmap.com (llms-full.txt endpoint)
- Small team variant discussion is in this STATUS.md only (not yet in HTML docs)
- CR numbering: PIM CRs use CR-PIM-0xx, CyberArk CRs use CR-CYA-0xx
- All CRs reference each other via dependency tags

### File Inventory Update

```
docs/deep-research/
  Purview-PAM-Leadership-Proposal.html       # NEW - 2026-04-03
  Purview-PAM-Technical-Implementation.html  # NEW - 2026-04-03
  Purview-PAM-Change-Requests.html           # NEW - 2026-04-03
  MS-Lighthouse-Executive-Summary.html       # Prior session (2026-03-30)
  MS-Lighthouse-Architecture-Permissions.html # Prior session
  MS-Lighthouse-Security-Controls.html       # Prior session
  MS-Lighthouse-Risk-Compliance.html         # Prior session
```
