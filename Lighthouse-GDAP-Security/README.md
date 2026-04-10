# Microsoft Lighthouse GDAP Security Toolkit

Security assessment, documentation, and audit tooling for MSPs managing customer tenants via Microsoft 365 Lighthouse and Granular Delegated Admin Privileges (GDAP).

## Contents

### Audit Script

| File | Description |
|------|-------------|
| `Audit-GDAP.ps1` | Read-only GDAP security audit script with HTML report generation |

**Customer Mode** (`-Mode Customer`) -- Run in the customer tenant with Global Reader:
- Scans cross-tenant access policy for service provider entries
- Detects GDAP service principals (confirms active GDAP)
- Flags Microsoft-Led Transition (MLT) migration evidence
- Reviews inbound trust settings (MFA, device compliance, hybrid join)
- Analyzes partner sign-in logs (locations, IPs, failed attempts)
- Scans audit logs for partner relationship lifecycle events

**Partner Mode** (`-Mode Partner`) -- Run in the MSP tenant:
- Lists all outbound GDAP relationships across customers
- Identifies MLT-created relationships (auto-migrated from DAP with overprivileged defaults)
- Flags Global Administrator and other high-privilege roles in standing GDAP access
- Identifies relationships approaching expiration
- Detects approved relationships with no security group assignments

```powershell
# Customer audit
.\Audit-GDAP.ps1 -Mode Customer

# Partner/MSP audit
.\Audit-GDAP.ps1 -Mode Partner

# Customer audit with 90 days of log history
.\Audit-GDAP.ps1 -Mode Customer -DaysBack 90
```

**Required Modules:**
- `Microsoft.Graph.Identity.SignIns` (Customer mode)
- `Microsoft.Graph.Applications` (Customer mode)
- `Microsoft.Graph.Reports` (Customer mode, log analysis)
- `Microsoft.Graph.Identity.Partner` (Partner mode)

### Reference Documentation (`docs/`)

| File | Audience | Description |
|------|----------|-------------|
| `MS-Lighthouse-Executive-Summary.html` | C-suite / Board | Key statistics, DAP vs GDAP comparison, risk findings, prioritized recommendations |
| `MS-Lighthouse-Architecture-Permissions.html` | Security Architects | GDAP architecture, 4-tier permission model, role-by-workload reference, SOW mapping |
| `MS-Lighthouse-Security-Controls.html` | Security Engineers | Conditional Access, PIM/JIT, auditing/Sentinel, PRT/device trust, KQL queries |
| `MS-Lighthouse-Risk-Compliance.html` | Risk/Compliance | Breach case studies, risk assessment matrix, incident response playbook, SOC2/ISO/NIST mapping |
| `MS-Lighthouse-Partner-Security-BestPractices.html` | MSP Engineers | SAML/OIDC integration security, Sentinel multi-tenant deployment, Purview, Defender |
| `MS-Lighthouse-CyberArk-Analysis.html` | Security Architects | CyberArk vs PIM analysis, hybrid PAM architecture, decision framework, cost analysis |
| `MS-Lighthouse-MSP-Security-Podcast-Guide.md` | All (audio) | 10,400-word narrative guide optimized for Google NotebookLM podcast generation |
| `GDAP-Lighthouse-Security-SOP-Template.md` | Operations | 9 standalone SOPs for GDAP lifecycle management |

All HTML files are self-contained (embedded CSS, dark theme, no external dependencies). Open directly in any browser.

## Key Security Findings

1. **PIM for Groups is the ONLY mechanism for GDAP JIT** -- no external tool (including CyberArk) can manage GDAP security group membership
2. **GDAP MFA trust from partner home tenant is always honored** -- hardcoded behavior customers cannot override
3. **Lighthouse JIT activates across all tenants in a template** -- not per-customer
4. **MSP identity is redacted** in customer logs ("[Partner Name] Technician")
5. **Purview interactive audit search is not supported via GDAP** -- use PowerShell or Management Activity API
6. **MLT-created relationships** may have overprivileged default roles (including Privileged Role Administrator)
7. **CyberArk and PIM are complementary** -- PIM handles GDAP JIT; CyberArk fills session recording, credential vaulting, and non-Microsoft gaps

## Requirements

- PowerShell 7+ (or Windows PowerShell 5.1)
- Microsoft.Graph PowerShell SDK modules (see Required Modules above)
- Appropriate Entra ID roles (Global Reader for customer mode)
- This toolkit performs **read-only operations only**

## Related

- [CISA Advisory AA22-131A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-131a) -- Protecting Against Cyber Threats to MSPs
- [Microsoft GDAP Documentation](https://learn.microsoft.com/en-us/partner-center/customers/gdap-introduction)
- [NIST SP 800-161r1](https://csrc.nist.gov/pubs/sp/800/161/r1/final) -- Cyber Supply Chain Risk Management
