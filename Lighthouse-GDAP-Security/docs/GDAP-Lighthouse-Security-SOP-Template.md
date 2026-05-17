# GDAP and Microsoft 365 Lighthouse Security SOP Template
## For MSP Security Architects and Engineers

**Version:** 1.0
**Date:** 2026-03-30
**Based on:** Microsoft Learn official documentation, CISA AA22-131A, DoD/NSA CSI Cloud Top 10 for MSPs
**Audience:** MSP security team, compliance officer, onboarding engineers

---

## About This Template

This template provides standalone, actionable SOPs for every major operational phase of Microsoft 365 Lighthouse and GDAP deployment. Copy and adapt each section into your internal runbook. Replace bracketed placeholders with your organization-specific values.

The SOPs in this document cover:

1. GDAP architecture design and role selection
2. Template creation and customer onboarding
3. Security group and PIM JIT configuration
4. Conditional Access policy deployment for partner access
5. Audit and monitoring configuration
6. Access review and relationship maintenance
7. Incident response for compromised MSP accounts
8. Customer and technician offboarding procedures

---

## SOP 1: GDAP Role Design and Access Matrix

**Purpose:** Define which Microsoft Entra built-in roles are required for each MSP job function before any portal configuration begins.

**Owner:** [MSP Security Architect or CISO]
**Frequency:** Once at initial deployment; reviewed at each SOW renewal cycle
**Prerequisites:** Current SOW or Managed Services Agreement for each customer tier

### Step 1.1: Map Job Functions to Tasks

For each MSP technician tier, enumerate the actual tasks performed in a typical week. Use Microsoft's least-privileged role-by-task reference at https://learn.microsoft.com/en-us/partner-center/customers/gdap-least-privileged-roles-by-task as your authoritative mapping.

Document the mapping in an Access Matrix spreadsheet with the following columns:

| MSP Job Title | Task Description | Minimum Required Role | Risk Tier | JIT Required? |
|---|---|---|---|---|
| [e.g., Tier-1 Help Desk] | Password reset for non-admin user | Password Administrator | Simple | No |
| [e.g., Tier-1 Help Desk] | Submit support tickets | Service Support Administrator | Simple | No |
| [e.g., Tier-2 Specialist] | Configure Intune device policies | Intune Administrator | Medium | No |
| [e.g., Tier-2 Specialist] | Configure security policies | Security Administrator | Medium | Recommended |
| [e.g., Escalation Engineer] | Reset admin MFA devices | Privileged Authentication Administrator | Complex | Yes |
| [e.g., Escalation Engineer] | Assign Entra directory roles | Privileged Role Administrator | Complex | Yes |
| [e.g., Emergency/Break Glass] | Full tenant administration | Global Administrator | Complex | Yes, with approval |

### Step 1.2: Define Tier Boundaries

**Tier 1 -- Help Desk / Service Desk (Low Risk, Always-On Eligible)**

Appropriate roles for standing or auto-approved JIT assignment:
- Service Support Administrator -- support ticket submission
- Helpdesk Administrator -- password resets for non-admins and limited admins
- Password Administrator -- non-admin password resets
- User Administrator -- user and group management, limited admin password resets
- License Administrator -- license assignment and troubleshooting
- Directory Reader -- basic directory read access
- Message Center Reader -- service communications
- Guest Inviter -- guest user invitations
- Global Reader -- read-only view across M365 services (read-only, low risk)
- Security Reader -- read-only security posture view

Do NOT include in Tier 1: Security Administrator, Conditional Access Administrator, Privileged Authentication Administrator, Privileged Role Administrator, Application Administrator.

**Tier 2 -- Technical Specialist (Medium Risk, JIT Recommended)**

Appropriate roles for workload-specific JIT with automated approval (justification and ticket number required, no human approver needed for standard activations):
- Exchange Administrator -- mailbox, transport rules, shared mailboxes
- Intune Administrator -- device enrollment, compliance policy configuration
- SharePoint Administrator -- site architecture and permissions
- Teams Administrator -- full Teams service management
- Compliance Administrator -- compliance portal management
- Cloud Device Administrator -- device management beyond Intune
- Authentication Administrator -- MFA/auth method management for non-admins
- Security Operator -- security policy execution (not configuration)

**Tier 3 -- Escalation / Privileged Access (High Risk, JIT with Human Approval Required)**

These roles must never be assigned as standing access:
- Security Administrator -- security policy configuration
- Privileged Authentication Administrator -- admin MFA resets
- Privileged Role Administrator -- directory role assignments
- Conditional Access Administrator -- CA policy modification
- Application Administrator -- app registration management
- Domain Name Administrator -- DNS and domain configuration
- Global Administrator -- only when no lower-privilege role exists

### Step 1.3: Define GDAP Relationship Structure

Determine how many GDAP relationships per customer are needed. Recommended minimum structure:

**Relationship 1: Standard Operations**
- Duration: 730 days with auto-extend enabled
- Roles: Tier 1 and selected Tier 2 roles (those in active SOW scope)
- Security groups: Tier1-[CustomerSegment] and Tier2-[CustomerSegment]

**Relationship 2: Security Operations** (if MSP delivers security monitoring)
- Duration: 180 days (aligned to initial contract term)
- Roles: Security Reader, Security Operator, Global Reader
- Security groups: SecOps-[CustomerSegment]

**Relationship 3: Break-Glass/Escalation** (if Global Administrator is sometimes needed)
- Duration: 90 days (forces periodic customer re-approval)
- Roles: Global Administrator, Privileged Role Administrator, Privileged Authentication Administrator
- Auto-extend: NOT enabled (forced periodic review)
- Security groups: [PIM-enabled groups with human approver required, zero standing members]

**Sign-off Gate:** The completed Access Matrix must be reviewed and approved by [CISO/Security Lead] before any portal configuration begins. This document is the audit evidence for role justification.

---

## SOP 2: Lighthouse Template Creation and Customer Onboarding

**Purpose:** Configure GDAP templates in Microsoft 365 Lighthouse and onboard customer tenants.

**Owner:** [MSP Lighthouse Administrator]
**Frequency:** Initial deployment; updated when SOW services change
**Prerequisites:** Access Matrix approved per SOP 1; Entra ID P2 licensing in partner tenant (required for JIT policies); Admin Agent role in Partner Center

### Step 2.1: Prerequisites Verification Checklist

Before beginning:

- [ ] Partner has Cloud Solution Provider relationship with customer in Partner Center
- [ ] Customer has qualifying M365 subscription (Enterprise, Business, Frontline, Education, or Exchange Online / Defender for Business)
- [ ] Customer has no more than 2,500 licensed users (Lighthouse hard limit; larger customers require separate management approach)
- [ ] Lighthouse Administrator holds Admin Agent role in Partner Center
- [ ] Entra ID P2 or M365 E5 licensing confirmed in partner tenant (for JIT policy creation)
- [ ] Access Matrix reviewed and approved
- [ ] SOW or MSA in place with explicit GDAP access language (see SOP 7 for contract requirements)

### Step 2.2: Create Security Groups in Partner Tenant

Before creating Lighthouse templates, create the security groups in the partner tenant's Entra ID.

Naming convention: [Tier]-[CustomerSegment or AllCustomers]-[WorkloadOrFunction]

Examples:
- Tier1-StandardSMB-Helpdesk
- Tier2-StandardSMB-Exchange
- Tier3-BreakGlass-GlobalAdmin (JIT-only, zero standing members)

For each Tier 3 group, enable PIM for Groups during or after group creation. Ensure the group is configured as "Eligible assignments only" with no standing active members.

### Step 2.3: Create GDAP Templates in Lighthouse

1. Navigate to https://lighthouse.microsoft.com
2. Select Home in left navigation, then select the "Set up GDAP" card
3. Navigate to Permissions, then Delegated Access, then select the GDAP Templates tab
4. Select "Create a template"
5. Provide a name reflecting the customer segment and service tier (example: "SMB Standard Operations" or "SMB Security Monitoring")
6. For each support role category (Service Desk Agent, Specialist, Escalation Engineer, etc.), select Edit and assign the Microsoft Entra roles identified in the Access Matrix
7. For each support role, assign the corresponding security group from Step 2.2
8. For Tier 3 groups: select "Create a just-in-time access policy for this security group" and configure:
   - User eligibility expiration: [90 days recommended]
   - JIT access duration: [1 hour for Global Admin roles; 4-8 hours for Tier 2 roles]
   - JIT approver group: [Designate a security group containing senior engineers or security leads]
9. Save the template
10. Repeat for each template type defined in SOP 1

### Step 2.4: Assign Templates to Customer Tenants and Send Approval Links

1. From the GDAP Templates page, select the three-dot menu next to the template and choose "Assign template"
2. Select the customer tenants to assign
3. Lighthouse generates a unique approval link for each customer that does not yet have an approved GDAP relationship
4. Send the approval link to the customer's Global Administrator with the following communication:

---

**[Template: GDAP Approval Request Email]**

Subject: Action Required -- Approve [MSP Name] Administrative Access for [Customer Organization]

Dear [Customer Admin Name],

As your managed services provider, we are updating your administrative access configuration to comply with Microsoft's current security standards. We are replacing the older Delegated Admin Privileges model with Granular Delegated Admin Privileges (GDAP), which provides you greater visibility and control over the specific access we hold.

Please click the link below to review and approve our access request. The approval page will show you:
- The name of the access relationship
- The duration of the relationship ([X] months/years)
- The specific administrative roles we are requesting and why we need them

Approval Link: [Insert Lighthouse-generated link]

The roles we are requesting correspond to the services described in our current Statement of Work dated [date]. If you have any questions about the specific roles or why they are needed, please contact [MSP Contact Name] at [contact information] before approving.

This approval requires a Global Administrator account in your Microsoft 365 tenant. The approval page will prompt you to sign in if you are not already signed in.

Thank you,
[MSP Name]

---

5. Document the approval request in your PSA system with:
   - Customer name
   - Roles requested
   - Relationship duration
   - Date link was sent
   - Customer contact who received the link

### Step 2.5: Verify Successful Onboarding

After customer approves:

- [ ] GDAP relationship appears as Active in Partner Center
- [ ] Security group assignments are visible in Partner Center for the relationship
- [ ] Customer appears in Lighthouse Tenants page (note: data population takes up to 48 hours)
- [ ] Verify no relationships have the yellow warning icon indicating missing security group assignments
- [ ] Create customer record in PSA system with relationship expiration date and next review date
- [ ] Schedule 30-day initial security baseline assessment in Lighthouse

---

## SOP 3: Conditional Access Policy Deployment for Partner Access

**Purpose:** Configure CA policies in customer tenants to enforce geographic restrictions, phishing-resistant MFA, and device compliance for MSP technicians.

**Owner:** [MSP Security Architect; implemented in customer tenant by Conditional Access Administrator via GDAP]
**Frequency:** During initial customer onboarding; reviewed quarterly

**Prerequisites:** Customer has Entra ID P1 licensing (required for per-organization cross-tenant access settings); Lighthouse GDAP with Conditional Access Administrator role or direct customer admin access

### Step 3.1: Configure Cross-Tenant Access Settings (Customer Tenant)

These settings control whether the customer tenant accepts MFA and device compliance claims from the MSP tenant.

1. In customer's Entra admin center, navigate to External Identities, then Cross-tenant access settings
2. Select the Organizational settings tab
3. Add the MSP's tenant ID as an organizational entry
4. In the Trust settings for that entry:
   - Enable "Trust multifactor authentication from Microsoft Entra tenants" (allows MSP's completed MFA to satisfy customer's MFA requirements)
   - Enable "Trust compliant devices" if the customer's CA policies will require device compliance (this delegates device compliance verification to the MSP's Intune)
5. Document the trust settings decision and justification in the customer's access configuration record

Note: For GDAP access specifically, MFA from the MSP's home tenant is always trusted regardless of this setting. The trust setting matters for B2B collaboration users but is partially overridden for GDAP by the service provider relationship.

### Step 3.2: Create Geographic Restriction Policy (US-Only Example)

For customers requiring US-only access from MSP technicians:

**Create the Named Location:**
1. Navigate to Entra ID, Conditional Access, Named locations
2. Create a Countries location named "Allowed Countries - United States Only"
3. Select United States
4. Leave "Include unknown countries/regions" unchecked
5. Save

**Create the CA Policy:**
1. Navigate to Conditional Access, Policies, New policy
2. Name: "Block Non-US Access - MSP Technicians"
3. Assignments, Users: Include "Guest or external users" with type "Service provider users" and scope to MSP tenant ID [MSP Tenant ID]
4. Target resources: All resources
5. Network condition: Include "Any network or location"; Exclude "Selected networks and locations" -- select the "Allowed Countries - United States Only" location
6. Access controls, Grant: Block access
7. Enable policy in Report-only mode first; verify impact using the "What if" tool; then set to On

Note: IP-based geolocation can be bypassed by cloud proxies. For higher assurance, combine with device compliance requirement or consider Global Secure Access with source IP restoration.

### Step 3.3: Create Phishing-Resistant MFA Policy

1. Navigate to Conditional Access, Policies, New policy
2. Name: "Require Phishing-Resistant MFA - MSP Technicians"
3. Assignments, Users: Include Service provider users, scoped to MSP tenant ID; Exclude break-glass/emergency access accounts
4. Target resources: All resources, or scope to sensitive applications (Entra admin center, Azure portal, M365 admin center)
5. Access controls, Grant: Require authentication strength, select "Phishing-resistant MFA strength"
6. Enable in Report-only mode; verify with affected MSP technicians; then set to On

Prerequisite: Confirm with MSP that their technicians have FIDO2 keys or Windows Hello for Business enrolled in the MSP tenant before activating this policy.

### Step 3.4: Configure Session Controls

1. In the existing MSP technician CA policy (or create a dedicated session policy):
2. Under Session:
   - Sign-in frequency: [4-8 hours recommended for admin portals]
   - Persistent browser session: Disable (do not allow users to remain signed in)
3. These controls create a session boundary aligned to GDAP JIT activation durations

---

## SOP 4: Audit and Monitoring Configuration

**Purpose:** Ensure MSP partner activity is captured, filterable, and alertable across all relevant logging systems.

**Owner:** [MSP Security Operations / MSSP Analyst]
**Frequency:** Configured at onboarding; alert thresholds reviewed quarterly

### Step 4.1: Sentinel Analytics Rules for Partner Activity

If the customer has Microsoft Sentinel deployed, create the following analytics rules or verify they are included in the deployed rule set:

**Rule 1: Service Provider Sign-In Monitor**
Alert on service provider sign-ins from unexpected countries or IP ranges. Base KQL:

```kusto
SigninLogs
| where CrossTenantAccessType == "serviceProvider"
| where ResultType == 0
| summarize SigninCount = count(), UniqueIPs = dcount(IPAddress),
            Countries = make_set(tostring(LocationDetails.countryOrRegion))
            by UserDisplayName, HomeTenantId, bin(TimeGenerated, 1d)
| where UniqueIPs > 3
```

Alert threshold: More than three distinct IP addresses in a single day from one partner identity.

**Rule 2: Privileged Role Assignment by Partner Technician**

Alert when a partner technician assigns privileged roles. Filter AuditLogs for Category == "RoleManagement" and OperationName containing "Add member to role" where the initiating account has cross-tenant access characteristics.

**Rule 3: Azure Lighthouse Delegation Changes**

Alert when registration definition or registration assignment objects are written or deleted in the Azure Activity Log (ResourceProviderValue == "MICROSOFT.MANAGEDSERVICES").

**Step 4.2: Create Automation Rule for Lighthouse False Positives**

If customer has Sentinel and Lighthouse is active:
1. In Sentinel, create an Automation Rule
2. Trigger: When incident is created
3. Condition: Alert provider contains "Microsoft 365 Lighthouse"
4. Action: Change incident status to Closed; add label "Lighthouse-Suppressed"

This prevents Lighthouse's normal Graph API data collection from generating false-positive incidents.

### Step 4.3: Configure Lighthouse Alert Rules

In the MSP's Lighthouse portal, enable and configure the following alert rules:

- [ ] Risky user: Alert when Entra ID Protection flags a user as At Risk in any managed tenant (critical for detecting compromised MSP admin accounts)
- [ ] Security incident: Alert on Defender incidents (configure to include Defender for Endpoint, Defender for Identity)
- [ ] Variance detection: Alert when deployment plan status moves to Incomplete, indicating security baseline drift
- [ ] Non-compliant device: Alert when devices fall outside Intune compliance policy

Configure email delivery of alerts to: [MSP SOC distribution list] and optionally webhook delivery to [PSA platform URL].

### Step 4.4: Purview Audit Log Access Method

Because the Purview portal's interactive audit search is not supported for GDAP access, document the approved methods for audit log review:

**Method 1 (Preferred): PowerShell with delegated token**
```powershell
# Run from partner tenant PowerShell session with delegated token for customer tenant
Search-UnifiedAuditLog -StartDate [date] -EndDate [date] -UserIds * -ResultSize 5000 |
    Where-Object { $_.UserType -eq 9 }  # Filter for PartnerTechnician (UserType 9)
```

**Method 2: Office 365 Management Activity API**
Ingest audit events through the API into your SIEM. This provides programmatic access without requiring interactive portal presence.

**Method 3: Customer-performed search**
For ad-hoc customer requests, the customer's own Compliance Administrator runs the search and exports results. Document the request and response in your ticketing system.

---

## SOP 5: Access Review and GDAP Relationship Maintenance

**Purpose:** Maintain least-privilege posture over time as personnel and services change.

**Owner:** [MSP Security Architect or designated Access Review Owner]
**Frequency:** Quarterly for security group membership; annually for role set review; at each relationship expiration (90 days prior notice)

### Step 5.1: Quarterly Security Group Membership Review

For each GDAP security group in the partner tenant:

1. Export current membership list from Entra ID
2. Cross-reference against current employee roster from HR system
3. Cross-reference against current job title and department assignments
4. For each member, verify:
   - Is this person still employed by the MSP?
   - Is their current job function consistent with this tier's access level?
   - Have they completed required security training for this tier?
5. Remove any members who do not pass all three checks
6. Document the review date, reviewer name, and any changes made

Target: No accounts in GDAP security groups that belong to former employees or to current employees whose job function no longer requires that tier's access level.

### Step 5.2: Annual Role Set Review

Review the approved role set in each GDAP relationship template against the current SOW:

1. Pull the current SOW or MSA for each customer segment
2. For each role in the GDAP template, verify there is a corresponding service in the SOW that requires that role
3. Identify any roles not needed for current SOW scope and document for removal
4. Note: Removing a role from an existing GDAP relationship is not possible. Document roles for removal and create a new relationship request with the corrected role set at the next natural renewal point

### Step 5.3: Relationship Expiration Management

GDAP relationships have hard expiration dates. Manage expirations proactively:

1. Export GDAP relationship expiration dates from Partner Center GDAP analytics or from PSA records
2. Flag all relationships expiring within 90 days
3. For relationships with auto-extend enabled: verify auto-extend is active and the relationship doesn't include Global Administrator (which cannot auto-extend)
4. For relationships without auto-extend or with Global Administrator: initiate renewal process:
   - Conduct access review per Step 5.1 before renewing
   - Create new relationship request with current role set (revised if needed per Step 5.2)
   - Send approval link to customer Global Administrator
   - Document the outreach and track response

4. If a customer's Global Administrator is unreachable and a relationship is expiring: escalate to account manager to re-establish customer contact before the expiration date

---

## SOP 6: Technician Onboarding and Access Provisioning

**Purpose:** Provision new MSP technicians with appropriate GDAP access following security controls.

**Owner:** [MSP Identity Administrator or Security Team]
**Frequency:** When new technicians are hired or change roles

### Step 6.1: Account Setup Requirements

New technician accounts must meet the following before GDAP group assignment:

- [ ] Account created in partner tenant Entra ID (not as a guest; must be a native member)
- [ ] MFA method registered in partner tenant (required for all partner tenant accounts by Microsoft partner security requirements)
- [ ] Windows device enrolled in MSP Intune with compliance policy applied and evaluated as Compliant
- [ ] Device is either Entra-joined (preferred) or hybrid-joined with PRT issuance confirmed
- [ ] Security awareness training for GDAP access procedures completed and documented
- [ ] HR onboarding record linked to Entra account for automated deprovisioning integration

### Step 6.2: Security Group Assignment

Assign the new technician to security groups corresponding to their job tier:

1. Determine the technician's tier assignment from the Access Matrix (SOP 1)
2. Add the account to the appropriate Tier 1 and/or Tier 2 security groups in Entra ID
3. For Tier 3 groups: add the account as an eligible member in PIM for Groups (not as an active member)
4. Document the assignment with justification linked to job title and SOW service scope
5. Verify in Partner Center that the security group appears correctly assigned to the relevant GDAP relationships

### Step 6.3: JIT Workflow Testing

Before the technician begins customer work, test the JIT workflow:

1. Navigate to myaccess.microsoft.com and confirm the technician can see their eligible group assignments
2. For Tier 3 groups, submit a test activation request and verify the approver receives the notification
3. Confirm the approver can approve and the technician receives confirmation
4. Verify the activation appears in Entra Identity Governance audit logs
5. After the test activation expires or is deactivated, confirm the technician no longer has active group membership

---

## SOP 7: Technician and Customer Offboarding

**Purpose:** Revoke delegated access when technicians leave or customer relationships end.

**Owner:** [MSP Identity Administrator + MSP Account Manager]
**Frequency:** On personnel termination or customer contract termination

### Step 7.1: Technician Departure -- Immediate Actions (Within 2 Hours of Last Day)

These actions must be completed on the technician's last day, not after:

Priority 1 (within 30 minutes of departure confirmation):
- [ ] Disable the technician's account in partner tenant Entra ID
- [ ] Revoke all active sign-in sessions: Revoke-MgUserSignInSession -UserId [UPN or Object ID]
- [ ] Remove account from ALL GDAP security groups in partner tenant
- [ ] Document exact timestamp of each group removal (30-minute propagation delay exists)

Priority 2 (within 2 hours):
- [ ] Reset account password (even on disabled account, to prevent reactivation abuse)
- [ ] Remove account from PIM eligible assignments in Entra Identity Governance
- [ ] Remove account from any Lighthouse RBAC roles
- [ ] Revoke any CyberArk safe memberships for this technician

Priority 3 (within 24 hours):
- [ ] Review audit logs for technician activity in the 7 days before departure for any anomalous activity
- [ ] Verify account appears as disabled in Entra ID with no active sessions
- [ ] Close or reassign any open tickets or PSA tasks assigned to the account
- [ ] Delete or archive the user account per your data retention policy

### Step 7.2: Customer Relationship Termination

When an MSP relationship with a customer ends by agreement, complete the following sequence:

1. **Terminate GDAP relationships in Partner Center**
   - Navigate to Partner Center, Customers, select the customer
   - For each GDAP relationship, select Terminate
   - Both parties receive email confirmation
   - Alternative: Delete the enterprise application in the customer's Entra ID under Enterprise Applications

2. **Remove customer from Lighthouse** (takes up to 48 hours to complete)
   - In Lighthouse Tenants page, select customer, three-dot menu, Remove tenant
   - No further management actions will be available after removal initiates

3. **Remove vendor applications** deployed in customer tenant during the management relationship

4. **Remove guest accounts** in the customer tenant originating from the partner tenant

5. **Remove notification contacts** added to the customer tenant's technical and security notification lists

6. **Remove monitoring artifacts**:
   - Alert rules configured in Lighthouse for this customer
   - Any Sentinel automation rules suppressing Lighthouse false positives for this workspace
   - Any custom analytics rules referencing the MSP's HomeTenantId

7. **Document completion** with timestamps for each step in the PSA system

---

## SOP 8: Incident Response for Compromised MSP Account

**Purpose:** Contain damage and investigate scope when a technician account compromise is suspected.

**Owner:** [MSP Incident Response Lead or CISO]
**Frequency:** Activated on confirmed or suspected account compromise

### Phase 1: Immediate Containment (0 to 30 Minutes)

STOP: Do not wait for complete evidence before starting containment. Speed matters more than certainty at this phase.

- [ ] Disable the compromised account in partner tenant Entra ID
- [ ] Revoke all active tokens: Revoke-MgUserSignInSession -UserId [UPN]
- [ ] Remove account from ALL GDAP security groups immediately
- [ ] Record exact timestamp of each removal action
- [ ] Reset account password via out-of-band channel (telephone or in person, not email)
- [ ] Alert MSP security operations / IR lead
- [ ] If external IR retainer exists: notify retainer provider

### Phase 2: Scope Investigation (30 Minutes to 4 Hours)

- [ ] Pull Unified Audit Log from partner tenant for compromised account: last 7-30 days
- [ ] Identify every customer tenant accessed during the suspected compromise window
- [ ] For each identified customer tenant, pull that tenant's audit log entries for the compromised account
- [ ] Specifically search for: user creation, role assignments, application registrations, CA policy modifications, conditional access exclusion additions, data exports, new guest invitations, service principal permission grants
- [ ] Document every finding with timestamps in the incident record
- [ ] Assess whether any attacker-controlled persistence mechanisms were installed in customer tenants

### Phase 3: Customer Notification

For each customer tenant where attacker activity is confirmed or cannot be ruled out:

- [ ] Notify customer within [X hours, aligned to your contractual SLA] of scope determination
- [ ] Provide: what access was obtained, when, what actions were taken (if known), containment steps completed, recommended customer remediation actions
- [ ] Advise customer to treat accounts created or modified during the window as potentially malicious
- [ ] Advise customer to review application registrations and consent grants added during the window
- [ ] Assess GDPR / state breach notification requirements based on data accessed

Regulatory notification thresholds:
- GDPR: 72 hours to supervisory authority if personal data was compromised
- US states: 30-72 hours (varies by state) after determining personal data was affected
- Document all notification decisions and timestamps

### Phase 4: Remediation

In partner tenant:
- [ ] Rotate all service account credentials
- [ ] Audit all security group memberships for unauthorized additions
- [ ] Review all application registrations for suspicious consent grants
- [ ] Identify and remediate the compromise vector before restoring operational access

In each affected customer tenant:
- [ ] Remove attacker-created accounts, application registrations, and CA modifications
- [ ] Reset credentials for accounts the attacker had access to modify
- [ ] Remediate Entra ID Identity Protection risk events for affected accounts

### Phase 5: Post-Incident Review (Within 14 Days)

- [ ] Document full incident timeline
- [ ] Identify root cause
- [ ] Evaluate whether existing detective controls should have identified the compromise earlier
- [ ] Produce remediation roadmap for identified security gaps
- [ ] Report to cyber insurance carrier
- [ ] Report to affected customers as appropriate for their compliance frameworks

---

## SOP 9: Compliance Framework Mapping Reference

**Purpose:** Quick-reference mapping for compliance assessments.

### SOC 2 Trust Services Criteria

| Criteria | Control | Implementation |
|---|---|---|
| CC6.1 Logical access security | Role-specific, time-limited delegated access | GDAP tiered role model with per-customer scoping |
| CC6.2 Authentication | MFA enforcement for all privileged access | Partner tenant MFA mandate, phishing-resistant MFA CA policies |
| CC6.3 Authorization | Formal access request and approval | PIM for Groups JIT with approval workflows |
| CC6.6 Logical access restrictions | Principle of least privilege enforced | Access Matrix + security group architecture |
| CC7.2 System monitoring | Monitoring of privileged access activity | Entra sign-in logs, Purview UserType 9 filtering, Lighthouse audit logs |
| CC9.2 Third-party risk | Partner access controls documented | GDAP relationship documentation, SOW alignment |

### ISO 27001:2022 Controls

| Control | Description | Implementation |
|---|---|---|
| A.5.16 Identity management | Managing identity lifecycles | Automated Entra provisioning + deprovisioning; security group ownership |
| A.5.18 Access rights | Granting, reviewing, revoking | GDAP three-tier model; quarterly access review SOP |
| A.8.2 Privileged access rights | Management of privileged access | PIM JIT; no standing Global Admin; access matrix |
| A.8.17 Clock synchronization | Ensuring timestamping consistency | Microsoft cloud logging infrastructure; UTC timestamps |
| A.8.15 Logging | Activity logging | Multi-layer logging architecture; Sentinel integration |
| A.8.34 Protection of information systems during audit testing | N/A for managed services context | -- |

### NIST 800-53 Rev 5

| Control Family | Controls | Implementation |
|---|---|---|
| Access Control (AC) | AC-2 (Account Mgmt), AC-3 (Access Enforcement), AC-6 (Least Privilege), AC-17 (Remote Access) | GDAP role scoping, JIT, security group architecture |
| Audit and Accountability (AU) | AU-2 through AU-12 | Entra audit logs, Purview UAL, Lighthouse logs, Sentinel |
| Identification and Authentication (IA) | IA-2 (MFA), IA-5 (Authenticator Management) | Phishing-resistant MFA CA policy, partner tenant MFA mandate |
| Configuration Management (CM) | CM-5 (Access Restrictions for Change), CM-7 (Least Functionality) | GDAP prevents changes outside approved role scope |
| Incident Response (IR) | IR-4 through IR-9 | Incident response SOP (SOP 8); customer notification procedures |

---

## Appendix A: Risk Rating Matrix for Common Misconfigurations

| Configuration | Risk Level | Mitigation |
|---|---|---|
| Standing Global Administrator in GDAP security group | Critical | Remove from standing; implement JIT with human approver (SOP 1) |
| Shared service account credentials for GDAP access | Critical | Individual per-technician accounts; no shared credentials |
| No MFA on partner tenant technician accounts | Critical | Enforce via partner tenant CA; Microsoft partner security requirements mandate this |
| Legacy DAP relationship coexisting with GDAP | High | Remove DAP after validating GDAP covers all workloads |
| No Conditional Access for partner sign-ins | High | Deploy location restriction + phishing-resistant MFA policies (SOP 3) |
| No security group membership access review | High | Implement quarterly review cycle (SOP 5) |
| Privileged Authentication Administrator as standing Tier-1 role | High | Move to Tier 3 with JIT and human approver |
| Administrative and productivity on the same account | Medium | Separate admin accounts from general productivity accounts |
| No formal technician offboarding procedure | High | Implement SOP 7 with 30-minute containment target |
| Purview interactive audit access not tested for GDAP | Medium | Document PowerShell workaround; test during onboarding |
| No Sentinel false positive suppression for Lighthouse | Low | Create automation rule at customer Sentinel onboarding |
| Auto-extend not configured for non-Global-Admin relationships | Medium | Enable auto-extend to prevent access outages at expiry |

---

## Appendix B: Cyber Insurance Documentation Requirements

Based on current underwriting trends for MSP applicants (Axcient, ConnectWise 2025 guidance):

Maintain the following as audit-ready evidence for cyber insurance renewals and incident notifications:

1. **Current Access Matrix** (SOP 1 output) -- documents role justification and least-privilege design
2. **GDAP relationship export** from Partner Center -- shows current relationship durations, roles, and customer associations
3. **PIM configuration screenshots** -- shows eligible-only assignments for Tier 3 groups with approver designations
4. **CA policy export** -- shows geographic restriction and phishing-resistant MFA policies applied to service provider users
5. **Quarterly access review records** -- shows security group membership reviews with dates and reviewer sign-off
6. **MFA registration report** -- shows 100% MFA coverage for all partner tenant accounts
7. **Incident response procedure** -- the completed SOP 8 with test exercise record
8. **Security awareness training records** -- for all staff with GDAP access

Underwriters increasingly require proof of controls, not self-attestation. These documents represent the evidence base for the controls described in this SOP.

---

## Appendix C: GDAP Role Quick Reference

**Simple (Tier 1 appropriate):**
Directory Readers, Global Reader, Helpdesk Administrator, License Administrator, Service Support Administrator, User Administrator, Message Center Reader

**Medium (Tier 2 appropriate, JIT recommended):**
Cloud Application Administrator, Exchange Administrator, Exchange Recipient Administrator, Intune Administrator, Power BI Administrator, Reports Reader, Security Administrator, Security Reader, Security Operator, SharePoint Administrator, Teams Administrator, Teams Communications Administrator, Compliance Administrator, Windows 365 Administrator

**Complex (Tier 3 only, JIT with human approval required):**
Application Administrator, Authentication Administrator, Billing Administrator, Cloud Device Administrator, Conditional Access Administrator, Domain Name Administrator, External Identity Provider Administrator, Global Administrator, Groups Administrator, Hybrid Identity Administrator, Privileged Authentication Administrator, Privileged Role Administrator

**Source:** Microsoft Learn - GDAP Role Guidance (Least Privileged Roles by Task)
https://learn.microsoft.com/en-us/partner-center/customers/gdap-least-privileged-roles-by-task
