# Microsoft Lighthouse MSP Security: A Comprehensive Guide
## Podcast Script and Narrative Guide for Google NotebookLM
**Prepared:** 2026-03-30
**Target runtime:** 45-60 minutes
**Audience:** MSP security architects and engineers evaluating secure Lighthouse/GDAP deployment

---

## The Opening Hook

Picture this: it's two in the morning on a Friday night. Your company is an established managed service provider with about eighty small and medium business customers. Your team manages their Microsoft 365 environments, their devices, their email, their user accounts. One of your senior technicians -- let's call him Marcus -- gets a Slack message from a number he doesn't recognize: "We have your access. Confirm within one hour or we publish the data." He screenshots it and goes back to sleep, thinking it's spam.

By six that morning, ransomware is running in four customer tenants simultaneously. The attackers didn't exploit a vulnerability in your infrastructure. They didn't write a single line of malware. They used Marcus's credentials -- credentials that had been purchased on the dark web from a phishing kit deployed three weeks earlier -- and logged straight into your Microsoft Partner Center. From there, because you were still running the old Delegated Admin Privileges model, they had Global Administrator access to every single one of your eighty customers. All eighty. With one username and one password.

This isn't a hypothetical. The Cybersecurity and Infrastructure Security Agency, along with cybersecurity authorities from the UK, Australia, Canada, and New Zealand, documented exactly this pattern in their landmark joint advisory AA22-131A in May 2022. Managed service providers have become the master keys of the modern enterprise. One compromise, multiplied across an entire portfolio.

Today, we're going to walk through the complete security architecture behind Microsoft Lighthouse and Granular Delegated Admin Privileges -- GDAP -- from the ground up. We'll cover how the permission model works, how your technician's device actually authenticates into customer environments at the cryptographic level, what Conditional Access can and can't do to protect those sessions, how just-in-time access and CyberArk fit into the picture, what the audit trail looks like, and what you actually do when something goes wrong.

By the end of this, you'll understand not just what to configure, but why each control exists and what it's protecting against. That "why" matters, because when an auditor asks you about your GDAP security posture, or when a customer's cyber insurer asks pointed questions about delegated access controls, you'll need to give answers that hold up.

Let's start by clearing up the most common point of confusion in this space.

---

## Part 1: Understanding the Landscape

### Two Products Named Lighthouse

Before we go anywhere else, we need to clear up a naming collision that trips up almost every MSP security conversation. Microsoft has two products called Lighthouse, and they do completely different things.

The first is Azure Lighthouse. This is a management delegation framework that lives inside the Azure Resource Manager layer. It's designed for service providers who need to manage Azure infrastructure -- virtual machines, storage accounts, Kubernetes clusters, networking -- across customer subscriptions without creating accounts in the customer's tenant. It uses two Azure resource objects called registration definitions and registration assignments that live inside the customer's subscription, and when a managing-tenant user makes an ARM API call, Azure Resource Manager checks those objects and authorizes the cross-tenant request. Azure Lighthouse is free, it supports ARM-scope operations only (meaning it cannot reach into data planes like Key Vault secrets), and it cannot delegate the Owner role or any role that contains data actions. If you want to extend that to on-premises servers, you combine Azure Lighthouse with Azure Arc, which projects physical and virtual machines into the Azure management plane through a connected agent.

The second product -- the one we're primarily focused on today -- is Microsoft 365 Lighthouse. This is a completely different product. It's a Software-as-a-Service portal available at lighthouse.microsoft.com, built specifically for Managed Service Providers enrolled in Microsoft's Cloud Solution Provider program. It doesn't manage Azure infrastructure at all. Instead, it aggregates identity, security, and device compliance data from multiple customer Microsoft 365 tenants through the Microsoft Graph API and presents that unified view across potentially hundreds of SMB customer environments. It's free for eligible CSP partners, and it requires that your customers have no more than two thousand five hundred licensed users to receive full management capabilities. Customers above that threshold appear in Lighthouse with limited functionality.

These two products can absolutely be used together by the same MSP -- Azure Lighthouse for infrastructure management, Microsoft 365 Lighthouse for identity and security posture. But they're architecturally separate mechanisms with separate access models, separate role systems, and separate audit trails. Mixing them up in a design conversation leads to serious confusion.

### The Cloud Solution Provider Program: The Prerequisite You Can't Skip

Microsoft 365 Lighthouse is exclusively available to partners enrolled in the Cloud Solution Provider program, or CSP. The program has two main tracks: Direct-Bill partners, who have a direct billing relationship with Microsoft and need to meet significant revenue thresholds to qualify, and Indirect Resellers, who work through distributor intermediaries. Both tracks can use Lighthouse. Critically, your customers don't need to be enrolled in CSP -- they just need to have accepted a delegated access relationship with you and have a qualifying Microsoft 365 subscription.

The CSP program is what creates the formal partner-customer relationship that Lighthouse relies on. Without that relationship, a customer's tenant won't appear in your Lighthouse portal, regardless of what GDAP configuration exists.

### The NOBELIUM Wake-Up Call: Why Everything Changed

To understand why GDAP exists and why it was a structural redesign rather than an incremental improvement, you need to understand what the old system was and why it failed so completely.

The old system was called Delegated Admin Privileges, or DAP. When a customer accepted a DAP relationship request from their CSP partner, two things happened automatically: the partner's Admin Agents security group got Global Administrator access in the customer's Entra ID tenant, and the Helpdesk Agents group got Helpdesk Administrator access. That was it. Two roles, both automatically assigned, lasting forever, with no expiration, no granularity by workload, and no way for the customer to restrict what the partner could do. The partner's entire Admin Agents population held Global Admin in every customer tenant simultaneously, from the day the relationship was created until the day someone manually ended it.

The Microsoft Security Intelligence Center documented in October 2021 that a threat actor it tracks as NOBELIUM -- subsequently attributed to Russia's Foreign Intelligence Service -- had targeted more than one hundred forty cloud service resellers and technology providers, compromising as many as fourteen of them. The attack vector was exactly what you'd expect: Global Administrator access through DAP. By compromising a single MSP employee in the Admin Agents group, NOBELIUM could pivot to every customer tenant that MSP managed. The service provider relationship was treated as a supply chain attack path.

Microsoft described this as "NOBELIUM targeting delegated administrative privileges to facilitate broader attacks," and it accelerated a transition that had been discussed internally but not yet mandated. GDAP was the structural response.

### Granular Delegated Admin Privileges: The Redesign

GDAP was built around three principles that DAP completely lacked: granularity, time-bounding, and per-customer scoping.

Granularity means that instead of automatically getting Global Administrator and Helpdesk Administrator, a partner requests specific Microsoft Entra built-in roles that correspond to the actual work they need to do. A partner managing Exchange might request Exchange Administrator and Security Reader. A partner providing full managed security services might request Security Administrator and Compliance Administrator. The specific roles are visible to and must be explicitly approved by a Global Administrator in the customer tenant. The customer sees what they're agreeing to.

Time-bounding means every GDAP relationship has an expiration date, anywhere from one day to two years. The default maximum is two years, and auto-extend can be enabled to add six-month increments automatically -- but only for relationships that don't include the Global Administrator role. That restriction is intentional. For Global Admin access, Microsoft is forcing periodic re-evaluation and renewed customer consent. Once a relationship expires, all partner access through that relationship ceases immediately.

Per-customer scoping means there is no equivalent of the old universal DAP link that gave access to every customer at once. Each GDAP relationship is specific to one customer tenant. A compromise of one GDAP relationship is contained to one customer rather than propagating across the portfolio.

The transition from DAP to GDAP was completed by the end of July 2024. If you still have customers with DAP relationships today, you are operating outside the current security model and carrying the full blast-radius risk of the pre-NOBELIUM era.

---

## Part 2: How GDAP Actually Works

### The Three-Stage Permission Flow

Understanding GDAP requires understanding that the customer's approval is necessary but not sufficient. Access flows through three distinct stages, and missing any one of them means your technicians have no access.

In the first stage, a partner admin creates a relationship request in Partner Center or through Lighthouse's GDAP setup wizard. They specify the relationship name, which will be visible to the customer, the duration in days, and the specific Microsoft Entra built-in roles being requested. The system generates a unique, single-use approval link for this specific relationship.

In the second stage, the partner sends that link to a Global Administrator at the customer organization. The customer opens the link, which takes them to an "Approve partner roles" page in their Microsoft 365 Admin Center. This page shows the relationship name, the duration, and the complete list of roles being requested. There's a mandatory pause built into the page -- the Next button is grayed out for fifteen to thirty seconds -- to ensure the customer actually reads what they're approving before they consent. Both parties receive email confirmation when approval happens.

Here's where many MSPs stop -- and then wonder why their technicians can't access the customer tenant. Approval is not the same as access. The third stage requires the MSP's admin to go into Partner Center, select the approved relationship for that customer, and explicitly assign security groups from the partner tenant to that relationship. Those security group assignments are what connect the approved role set to actual human beings. A relationship that's approved but has no security group assignments is like a door that's been unlocked but has no one on the other side of it. Lighthouse surfaces a warning indicator for relationships with no group assignments, but it's easily missed at scale.

### The Relationship Structure: What You Can and Can't Do

A few structural constraints shape everything else about how you design your GDAP architecture, and you need to internalize these before you touch a configuration.

First: you cannot change the roles in an existing GDAP relationship after it's created. If you realize six months in that you forgot to request Security Reader for a customer, you need to create a new relationship request with the additional role, send the customer another approval link, and have them approve it. This is customer-protective by design -- the customer's approval is meaningful precisely because the role set is immutable after consent. But it means your role design work must happen before you send your first approval link, not after.

Second: multiple relationships per customer are supported. You can have a standard operations relationship covering helpdesk and provisioning roles, a separate security monitoring relationship with only Security Reader and Security Operator, and a break-glass relationship covering Global Administrator with a ninety-day duration that requires renewed customer approval rather than auto-extending. Multiple relationships enable tiered access without having all roles visible in a single approval request.

Third: if a customer doesn't respond to an approval request within ninety days, it expires. You don't get a second chance to use the same link -- you'd create a new request. And once a relationship ends, whether by expiration or termination, you cannot reuse that relationship name for three hundred sixty-five days.

### The Security Group Architecture: Your Permission Bridge

In the partner tenant, you create Entra ID security groups that serve as the bridge between GDAP relationships and individual technicians. The roles approved in the GDAP relationship are assigned to these security groups in the partner tenant, not to individual users. A technician gains access to a customer tenant's delegated roles by being a member of the right security group.

This design has a powerful operational advantage. Adding a new technician to a group immediately grants them access across all customer tenants where that group has GDAP role assignments. Removing a departing employee from the group immediately revokes all their delegated access. You don't need to touch per-customer settings -- you manage access centrally in your own tenant.

The flip side is that the security group design deserves careful thought. A single monolithic group with all roles assigned represents minimal improvement over DAP. The real security gain comes from breaking roles out across multiple groups aligned to job functions. An MSP running three support tiers should have, at minimum, separate security groups for each tier, and probably separate groups for each tier plus separation between different workload domains -- exchange administration separate from device management separate from security operations.

### Lighthouse's Template System: Scaling to Hundreds of Customers

Manual GDAP configuration is practical for ten customers. It's not practical for a hundred. Microsoft 365 Lighthouse addresses this through a template system documented at its GDAP setup page.

A Lighthouse administrator creates a GDAP template that defines up to five named support role categories -- Account Manager, Service Desk Agent, Specialist, Escalation Engineer, and Administrator are the defaults, but you can customize them. For each role category, you map one or more Microsoft Entra built-in roles and assign one or more Entra security groups from your partner tenant.

Then you assign that template to customer tenants. Lighthouse generates individual relationship approval links for each customer that doesn't yet have a GDAP relationship with you. As customers approve their requests, Lighthouse automatically applies the security group assignments. Changes take up to an hour to appear in Lighthouse after customer approval.

One template can cover many customers. When an MSP moves from ten customers to fifty, the operational overhead doesn't multiply by five -- the template does the work. This is genuinely one of Lighthouse's most valuable capabilities and it's worth building your template architecture thoughtfully before you start sending approval links to customers.

---

## Part 3: The Desktop Experience -- What Actually Happens at the Keyboard

### The Primary Refresh Token: The Credential That Powers Everything

Let's slow down and look at the authentication machinery, because understanding this is what separates a security practitioner from someone who just follows configuration guides.

When your MSP technician -- let's call her Sarah -- sits down at her Windows workstation and signs in with her partner tenant credentials, something specific happens at the cryptographic level. Windows runs a component called CloudAP, the Microsoft Entra cloud authentication plugin. During that login, CloudAP communicates with Entra ID, presents evidence that Sarah is authenticating from a specific registered device by signing the request with a private key stored in the device's Trusted Platform Module chip, and Entra ID responds by issuing a Primary Refresh Token, or PRT.

The PRT is not a standard OAuth token that Sarah can see or copy. It's an opaque blob issued to device-resident broker software -- specifically the CloudAP and Web Account Manager plugins on Windows. Applications on the device never see the PRT directly. They interact with WAM, which uses the PRT on their behalf to obtain application-scoped access tokens. The PRT is valid for ninety days and renews continuously as long as Sarah actively uses the device.

What makes the PRT worth understanding deeply is what it carries inside. It contains a device ID linking it to the specific registered device object in Entra ID. It carries an MFA claim proving that multi-factor authentication was completed during the session that produced it. If Sarah's device is enrolled in and compliant with the MSP's Intune policies, the PRT carries a device compliance claim. All of these claims propagate into downstream application tokens obtained using that PRT.

The private key stored in the device's TPM chip is what protects all of this. Even a local administrator on that machine cannot extract the private key from a functioning TPM 2.0 chip. Every subsequent use of the PRT must include a proof-of-possession signature using a session key that can only be produced through a TPM operation. Having the PRT data alone is not enough to use it -- an attacker also needs to produce valid session key signatures, which requires control of that specific physical TPM.

### Getting Into Lighthouse Without Entering a Password

When Sarah opens Microsoft Edge and navigates to lighthouse.microsoft.com, she doesn't get a login prompt -- at least, she shouldn't if everything is configured correctly. Here's why.

As the browser navigates to a Microsoft Entra sign-in URL, Edge invokes a Windows platform API called IProofOfPossessionCookieInfoManager. This asks the CloudAP plugin to produce a signed PRT cookie. CloudAP engages the TPM to sign the cookie using the session key -- the same TPM-backed session key from PRT issuance. The signed cookie is injected into the request header. Entra ID validates the signature, confirms Sarah's device is still registered and not revoked, and issues a browser session cookie. Sarah arrives at Lighthouse without typing her credentials.

This works in Edge natively, in Chrome with the Windows Accounts extension, and in Firefox version ninety-one and later with a specific setting enabled. It does not work in private browsing modes -- InPrivate in Edge, Incognito in Chrome. Technicians using private browsing will be required to sign in interactively.

The browser session cookie that results from this flow is itself device-bound through the session key. Replaying that session cookie from a different device would fail validation. This is the PRT's device binding extending into browser-based Lighthouse access.

### The Cross-Tenant Authentication Chain

When Sarah selects a customer tenant inside Lighthouse, a cross-tenant authentication happens on her behalf. Her identity exists in the MSP's tenant. The resources she wants to reach belong to the customer's separate Entra ID tenant. What happens?

Entra ID recognizes this as a cross-tenant access attempt where the authenticating user is from the MSP's tenant but requesting access to the customer's resources. It evaluates the customer tenant's inbound cross-tenant access settings. If the customer has configured trust settings to accept MFA claims and device compliance claims from the MSP's tenant, those claims from Sarah's PRT are honored -- she doesn't get prompted for MFA again, and her device compliance status is accepted.

For GDAP specifically, there's a special rule that overrides the normal trust settings configuration. Microsoft has documented explicitly: when an external user signs in through GDAP, MFA is always required in the user's home tenant and always trusted in the resource tenant. Regardless of how the customer has configured their cross-tenant trust settings, as long as Sarah completed MFA in her partner tenant session -- which is proven by the MFA claim in her PRT -- the customer tenant will accept that as satisfying its MFA requirement. The only way a customer can prevent this is to remove the GDAP relationship entirely.

This is a deliberate design decision. CSP partner tenants are required by Microsoft to enforce MFA for all users. The implicit contract is that by accepting a GDAP relationship, the customer is trusting Microsoft's partner security requirements to ensure the partner's MFA is reliable.

### Entra-Joined vs. Hybrid-Joined: Which to Choose for MSP Workstations

If you're provisioning technician workstations from scratch, Microsoft's documentation consistently recommends Entra-joined as the preferred path. The reason comes back to the PRT. On an Entra-joined device, PRT issuance happens synchronously during Windows login -- Sarah cannot reach the Windows desktop until a valid PRT has been obtained from Entra ID. Every session begins with a freshly evaluated, device-bound PRT. Device management runs entirely through Intune with no Group Policy dependency on an on-premises domain controller.

On hybrid-joined devices, the user authenticates to on-premises Active Directory first and then PRT issuance from Entra ID happens asynchronously in the background. This means there's a window at login where Sarah has a valid Windows session but no current PRT. If Entra ID is unreachable at login time, Sarah may proceed to use the desktop without a current PRT, degrading single sign-on to cloud resources until the next successful PRT acquisition. For technicians who depend on uninterrupted access to cloud management tools, this asynchronous pattern is a practical concern.

The pass-the-PRT attack -- the modern equivalent of pass-the-hash -- is worth mentioning here. An attacker with code execution on Sarah's device can attempt to access the PRT and associated session artifacts. The TPM hardware binding is the primary defense: without the ability to produce TPM-backed session key signatures, extracted PRT data is unusable. But an attacker who can inject code into the CloudAP or WAM process space, or compromise the lsass.exe process, may be able to exercise the TPM's signing operations without extracting the underlying keys. This is why device hardening -- Credential Guard, Virtualization-Based Security, and Defender for Endpoint's attack surface reduction rules -- is the necessary complement to the cryptographic protections in the PRT architecture. An MSP technician's compromised workstation isn't just one compromised account. It's potential access to every customer tenant that technician manages.

---

## Part 4: Locking It Down -- Conditional Access for Partner Access

### The Dual Evaluation Model

When Sarah authenticates from the MSP tenant into a customer tenant, two tenants have opinions about the security of that access. Understanding who evaluates what is the prerequisite to designing any meaningful security control.

The Microsoft Entra Security Token Service evaluates the following in sequence. The user from the home tenant initiates sign-in to a resource in the resource tenant. During sign-in, the Entra STS evaluates the resource tenant's Conditional Access policies. It simultaneously checks whether the home tenant's outbound settings allow the user to leave, and whether the resource tenant's inbound settings allow them to enter. It checks whether the resource tenant has configured trust settings to accept MFA claims and device compliance claims from the MSP's tenant. If trust exists and the required claims are present, those claims satisfy the resource tenant's CA requirements. If they're absent, the corresponding challenges are issued in the home tenant.

The resource tenant -- the customer -- always has the authority to define what is required for access. The trust settings simply determine whether evidence gathered in the MSP's tenant can satisfy those requirements, or whether the customer tenant must independently verify them.

### Targeting CA Policies to MSP Technicians

Entra's Conditional Access user type system offers a more granular way to target MSP technicians than a generic "external users" bucket. For MSPs operating as CSP partners, the most precise targeting option is the Service Provider user external user type, identified by the isServiceProvider property in the partner-specific Graph configuration. Microsoft's documentation explicitly states that for policies intended to target service provider tenants, this is the type to use.

This targeting can be combined with tenant-specific scoping: a customer can craft a CA policy that applies specifically to users from their MSP's tenant ID, not to all external users. This specificity matters when you want the MSP to operate under stricter controls than other external collaborators without disrupting general B2B collaboration.

### Geo-Fencing: US-Only Access and Its Limits

Geographic restriction is one of the most frequently requested security controls in MSP scenarios. A healthcare organization with HIPAA obligations may need to ensure that MSP technicians can only access the environment from within the United States.

This is achievable through Entra's Named Locations feature combined with Conditional Access. A Named Location can be defined as a geographic country selection, and a CA policy can block access from any location that isn't in that named location. For strict MSP control, you create a location called "Allowed Countries - United States Only," create a CA policy targeting Service Provider users, configure the Network condition to include any location but exclude the US named location, and set the grant control to block. The logic reads: cover all locations, then carve out the US as an exception. Everything that isn't the US gets blocked.

Pause and think about the caveat here, because it's important. IP-based geolocation is only as reliable as the geolocation database. A technician routing traffic through a cloud proxy service located in the US will appear to be in the US regardless of their physical location. Microsoft's recommended mitigation is to use Global Secure Access with source IP restoration, which provides a verifiable chain of custody for the originating IP address. Alternatively, requiring device compliance attestation provides a location-independent security control that doesn't depend on IP geolocation at all.

For higher-assurance location verification, Microsoft Authenticator can collect GPS coordinates from a technician's mobile device, checked every hour. This method performs jailbreak detection and blocks location spoofing. It's significantly more invasive and is recommended only for very sensitive applications where that hourly prompt cadence is acceptable.

### Phishing-Resistant MFA: Requiring the Right Authentication Methods

Beyond simply requiring MFA, Entra's authentication strength feature lets customers specify exactly which authentication methods are acceptable. This matters for MSP scenarios because standard MFA methods -- SMS codes, push notifications -- are vulnerable to phishing and adversary-in-the-middle attacks. An attacker who sets up a reverse proxy between a technician and the Entra sign-in page can harvest tokens from a legitimate authentication flow even when standard MFA is present.

Microsoft provides three built-in authentication strength tiers. The Multifactor Authentication strength accepts any MFA-satisfying combination, including push notifications. Passwordless MFA strength accepts FIDO2 keys, Windows Hello for Business, and certificate-based authentication. Phishing-resistant MFA strength is the most restrictive, requiring methods with a cryptographic binding between the authentication and the specific sign-in surface. The acceptable methods are FIDO2 security keys, Windows Hello for Business or platform credentials, and Microsoft Entra certificate-based authentication at the multifactor level.

For MSP technicians -- who often have the highest privilege level of any identity touching a customer environment -- requiring phishing-resistant MFA is a reasonable security baseline for access to sensitive workloads.

When trust settings are configured between the MSP and customer tenant, and the technician completes FIDO2 or Windows Hello for Business authentication in the MSP tenant, those claims satisfy the phishing-resistant MFA requirement in the customer tenant. There's an important nuance here: the available phishing-resistant methods narrow somewhat when crossing tenant boundaries. Methods like Microsoft Authenticator phone sign-in and OATH hardware tokens, which the MSP tenant might accept as phishing-resistant, are not available for external users completing MFA in the resource tenant. Design your authentication method policy in the MSP tenant with cross-tenant enforcement in mind.

### Device Compliance: The Trust That Has No Verification

Device compliance requirements for MSP technicians are powerful, but there's a fundamental constraint you need to understand. A device can only be enrolled in one Intune tenant at a time. Sarah's laptop is enrolled in the MSP's Intune, not the customer's. If a customer creates a CA policy requiring device compliance without configuring device trust, Sarah's device will fail the requirement because the customer's Entra cannot evaluate compliance for a device it doesn't manage.

The solution is the "Trust compliant devices" setting within inbound cross-tenant access settings. When the customer enables this for the MSP's tenant, it accepts compliance claims from the MSP's Intune as proof that the device meets compliance requirements. This is what allows a CA policy requiring compliant devices to be satisfied by the MSP's device management.

Microsoft includes an explicit warning in its documentation: "Unless you're willing to trust claims regarding device compliance from an external user's home tenant, we don't recommend applying Conditional Access policies that require external users to use managed devices." This warning reflects the trust delegation inherent in the design. When a customer enables device trust for your MSP, they're accepting your attestation that your devices meet compliance standards -- without independently verifying your Intune policies. That's a relationship trust decision, not a technical verification.

### Session Controls: What Happens After Access Is Granted

CA policies govern not only whether access is granted but how long that access persists and under what conditions it must be renewed. For MSP technicians accessing sensitive customer environments, a few session control settings deserve explicit configuration.

Sign-in frequency limits how long a session can remain active before the technician must reauthenticate. The Entra default is ninety days, which is far too long for privileged access. A shorter frequency -- aligned to your GDAP JIT activation durations -- creates a consistent security envelope.

Persistent browser session control determines whether session cookies persist after the browser closes. Disabling persistence means Sarah must reauthenticate each time she opens a new browser session. This matters especially when technicians are working on shared workstations or jumping between customer environments on a single device.

Continuous Access Evaluation is automatically enabled and allows Entra to revoke access tokens in near real-time when certain events occur -- a user account being disabled, a password change, or a high-risk sign-in being detected. For MSP access scenarios, CAE means that if a technician's account is compromised and disabled in the MSP tenant, their access to customer resources can be terminated quickly without waiting for normal token expiration.

---

## Part 5: Watching the Watchers -- Auditing and Monitoring

### What Gets Logged and Where

When Sarah authenticates into a customer tenant and starts making changes, that activity passes through multiple overlapping logging systems, each capturing different pieces of the picture.

In the customer tenant's Entra ID sign-in logs, her login appears with CrossTenantAccessType set to "serviceProvider." This is a distinct category -- not the "b2bCollaboration" value you'd see for a guest user invitation, and not "none" for a standard single-tenant sign-in. The HomeTenantId shows the partner's Azure AD tenant identifier. The ResourceTenantId shows the customer's identifier. Here's a privacy detail that surprises many customers: Sarah's actual name doesn't appear directly in the customer's sign-in logs. Instead, the display name is rendered as something like "[MSP Name] Technician." The full object ID is still present for the MSP to correlate back to Sarah internally, but from the customer's view, a specific individual is partially obscured.

When Sarah makes administrative changes -- creates a user, modifies a group, assigns a role -- those changes appear in the customer tenant's Entra ID audit log. The InitiatedBy field contains the initiating identity's information. Because Sarah doesn't have a user object in the customer's directory, the display name may be masked, but the action and its target are fully recorded.

In the Microsoft Purview unified audit log, which captures thousands of event types across all Microsoft 365 services, partner technicians operating through GDAP are assigned UserType value nine, labeled "PartnerTechnician." This value was introduced specifically to address the identification gap for partner activity. Prior to this designation, partner actions could be difficult to distinguish from internal admin actions. UserType two is an internal administrator. UserType nine is you, the MSP technician operating through GDAP. This field is available in the AuditData JSON export column and accessible through the Office 365 Management Activity API, allowing SIEM tools to filter for partner activity programmatically.

### The Purview Audit Gap: A Known Limitation

Here's a limitation that trips up MSPs doing compliance work. As of early 2026, the interactive "Search audit log" tool in the Microsoft Purview portal is explicitly listed as unsupported for GDAP relationships. A partner technician who authenticates to a customer tenant through GDAP, even with Global Reader or Compliance Administrator roles, will encounter errors when trying to run ad-hoc audit log searches in the Purview portal. The error typically says "Failed to load data. Please try again later."

The architectural reason is that Purview compliance features require the accessing identity to exist within the customer tenant as a user object. GDAP access doesn't create a user object in the customer tenant -- that's one of its security advantages. But it creates this compliance workflow gap.

The workarounds are real but require planning. You can run Search-UnifiedAuditLog from PowerShell using a delegated token for the customer tenant -- this doesn't require portal presence and can work even without a full directory object. You can ingest audit events through the Office 365 Management Activity API into your SIEM. Or for particularly intensive compliance scenarios, you maintain a dedicated user account within the customer tenant with the Audit Logs Reader role.

### Lighthouse's Own Audit Logs

Microsoft 365 Lighthouse maintains its own audit log recording every action that generates a change through the portal. Auditing is enabled by default and cannot be disabled. The log takes up to an hour to reflect new actions.

Lighthouse surfaces four categories of logs through its interface. The Audit Logs tab records Lighthouse-specific actions: applying configuration policies, blocking user sign-ins, confirming user compromise, resetting passwords, triggering Intune device actions. Each record includes the action type, the affected customer tenant, the initiating user, and a timestamp. The Graph Logs tab records the underlying Microsoft Graph API requests made to customer tenants, including HTTP response codes. The Directory Logs tab surfaces the Entra ID audit log for each customer tenant, filtered inside Lighthouse. The Sign-In Logs tab shows sign-in events for customer tenants, filterable by risk state and risk level.

Only Lighthouse Administrators and Partner Center Admin Agents can view these logs. Readers and Operators cannot. This is a meaningful access control consideration -- your SOC analysts who need visibility into customer activity need the right Lighthouse RBAC role.

### Microsoft Sentinel: The Professional Tier

For MSPs building a managed security operations practice, the recommended Sentinel architecture involves deploying individual Sentinel workspaces within each customer tenant rather than centralizing all customer data in a single MSP workspace. Data ownership stays with each customer, data sovereignty requirements are met, costs are charged to each managed tenant rather than to the MSP, and one customer's data is never co-mingled with another's.

Access to all customer Sentinel workspaces is governed by Azure Lighthouse. The MSP onboards each customer's Azure subscription, which grants MSP users the appropriate Sentinel built-in roles -- Reader, Responder, or Contributor -- within each customer workspace. From the managing tenant, the MSP can create hunting queries, analytics rules, workbooks, and playbooks and apply them across customer environments.

One documented limitation: deploying data connectors into a customer Sentinel workspace from within the Lighthouse-managed context requires GDAP configured for that customer in addition to Azure Lighthouse. Azure Lighthouse alone isn't sufficient for connector deployment. You need both mechanisms.

Cross-workspace queries in Sentinel use the workspace() expression and the union operator to query multiple customer Log Analytics workspaces simultaneously. Microsoft recommends limiting these to five workspaces at a time for performance, with a hard limit of twenty workspaces per query. In October 2025, Microsoft announced multi-tenant content distribution through the Defender portal, enabling MSPs to centrally replicate analytics rules and automation rules across multiple customer tenants from one location.

A specific KQL query that every MSP Sentinel deployment should have active is filtering for service provider sign-ins: querying the SigninLogs table where CrossTenantAccessType equals "serviceProvider." This isolates all MSP technician sign-in events from all other sign-in traffic and forms the foundation for anomaly detection on partner access patterns.

### The Sentinel False Positive Problem

Here's a practical gotcha. Lighthouse sources its data from customer tenants through Microsoft Graph APIs. If a customer has Sentinel deployed and configured to alert on unusual Graph API activity, Lighthouse's normal data collection can generate incidents. Microsoft's recommended mitigation is creating an automation rule in Sentinel to classify Lighthouse-originated API calls as false positives. If you're managing Sentinel for customers, proactively configure this suppression rule during onboarding before customers see an alert flood and wonder if something is wrong.

### Defender for Cloud Apps: Behavioral Detection

Microsoft Defender for Cloud Apps adds a behavioral anomaly detection layer on top of sign-in and activity data. For MSP monitoring scenarios, the most relevant detections are impossible travel (a single account showing activity from two distant locations within a timeframe too short to travel between them), activity from unfamiliar locations (access from a country or region new to the organization's baseline), admin activity from risky IP addresses, and rogue admin takeover detection (repeated high-volume administrative changes within a configurable time window by an admin account, potentially indicating a compromised account making bulk destructive changes).

For MSP admin accounts managing multiple customer tenants, impossible travel detection is particularly valuable because a compromised credential might be used simultaneously by an attacker while the legitimate technician is also active.

---

## Part 6: Privileged Access Management -- JIT and What It Actually Controls

### The JIT Problem for MSPs

Standing privileged access is the condition where a technician permanently holds an administrative role that they only occasionally need. Marcus, from our opening scenario, was a senior MSP engineer. He held Global Administrator standing access to every customer because it made escalation easier and faster. The attackers didn't need to do anything sophisticated. They just logged in.

Just-in-time access is the answer. It converts standing access into eligible access. A technician doesn't hold a role until they need it, request it, provide a justification, complete a fresh MFA challenge, and -- for high-risk roles -- get approval from a human reviewer. After a configured duration, the access disappears automatically.

### Entra PIM for Groups: The Native Tool for GDAP JIT

The mechanism that enables JIT access for GDAP security groups is Entra Privileged Identity Management for Groups, commonly called PIM for Groups. PIM is a service within Microsoft Entra ID Governance that manages time-bound, approval-gated access to roles and group memberships.

The key concept PIM introduces is the distinction between active and eligible assignments. An active assignment means the user holds the permission continuously. An eligible assignment means the user has been pre-approved to request it but doesn't hold it. When they activate their eligibility, they provide a justification, complete MFA, and -- if required -- wait for an approver to say yes. The permission activates for the configured duration. When time runs out, it disappears automatically.

By applying PIM for Groups to your GDAP security groups, you convert all standing GDAP membership into eligible-only access. No technician holds active membership in any GDAP group. To work in any customer tenant, they must activate their group membership through PIM. This means that even if Sarah's credentials are stolen, the attacker cannot immediately access any customer tenant. They'd still need to complete an MFA challenge, and for high-privilege roles, obtain human approval. That activation attempt generates audit logs and, in a well-monitored environment, real-time alerts.

PIM for Groups requires Entra ID P2 licensing in the partner tenant. This licensing applies to the MSP's own tenant -- customer tenants do not need Entra ID P2 for the MSP's PIM JIT to function.

### The Three-Tier Architecture

The MSP practitioner community has converged on a three-tier structure for GDAP group configuration, scaling the JIT controls proportionally to the risk level of the roles involved.

Tier one groups cover low-impact roles: Global Reader, Password Administrator for non-administrator accounts, helpdesk functions. These groups use PIM activation but no approval requirement. A technician provides a justification or ticket number, completes MFA, and gets membership automatically. Activation duration is typically eight to ten hours, reflecting a full business day. This tier handles the vast majority of daily MSP operations.

Tier two groups cover roles with meaningful administrative capability: Exchange Administrator, Teams Administrator, Intune Administrator. These require PIM activation with explicit ticket justification and MFA re-authentication, but no separate human approval. Activation duration is one to two hours. The constraint forces technicians to scope their work tightly.

Tier three groups cover the highest-impact roles: Security Administrator, Global Administrator, Privileged Role Administrator. These require approval from a designated security officer or management approver in addition to MFA and justification. Activation duration is capped at one hour or less. For Global Administrator specifically, having this role available as a tier-three JIT eligible assignment rather than a standing assignment is the documented best practice. You still have it when you genuinely need it. But an attacker who steals credentials doesn't get it.

### Lighthouse's JIT Capability: What It Is and Isn't

Lighthouse includes a JIT configuration wizard as part of its GDAP setup flow. When creating a new security group within a GDAP template, you can select "Create a just-in-time access policy for this security group" and configure user eligibility expiration, JIT access duration, and the approver security group.

Here's the important nuance: Lighthouse's JIT policy creation wraps the Entra ID Entitlement Management access package infrastructure. It's a simplified wizard to configure that infrastructure without requiring you to navigate the full Entra ID Governance interface. The approval workflow itself runs in Entra ID at runtime. Lighthouse configures it at setup time.

There's an architectural constraint worth highlighting. When a technician activates JIT access through a Lighthouse-configured access package, the elevation applies to their access in every tenant attached to that GDAP template simultaneously -- not just the specific customer they're working on. An MSP that applies one template to all customers will find that a single JIT activation grants access across all of them. For high-privilege roles, this is a wider blast radius than you might intend. MSPs implementing strict per-customer JIT require either multiple GDAP templates or supplemental tooling that gates access at the per-tenant level.

### CyberArk: The Complementary Layer

CyberArk is the other major PAM player in this space, and for MSPs that already operate CyberArk as their primary enterprise PAM platform, understanding where it fits alongside GDAP/PIM is important.

Here's the fundamental thing to understand: CyberArk cannot grant or revoke GDAP security group membership. That's not a limitation of CyberArk's design -- it's a structural property of how GDAP access authorization works. GDAP relationships are enforced at the Microsoft identity plane, and JIT control of GDAP access must go through Entra PIM for Groups. There is no production-grade external tool that can substitute for PIM in this role.

What CyberArk excels at -- and where PIM does not -- is credential vaulting, automated credential rotation, and forensic-quality session recording. PIM records that a role was activated. It doesn't record what the user did with that role. CyberArk's Privileged Session Manager records every keystroke, every SQL query, every action during the session, in both text and video format. For customers in regulated industries where a compliance framework requires evidence of not just who had access but what they actually did, CyberArk's session recording fills a gap that PIM leaves open.

CyberArk also addresses service account management that PIM doesn't touch. The break-glass Global Administrator accounts that exist outside normal PIM scope for emergency use -- their credentials should live in CyberArk's vault. Access requires dual-control approval. The credential is rotated after each use. Retrieval events are recorded. This addresses the scenario where PIM itself is unavailable or the Microsoft identity plane is the subject of an incident.

In June 2025, CyberArk announced the CyberArk MSP Hub, a SaaS-based management console designed specifically for MSPs that aggregates visibility across all managed CyberArk customer environments into a unified dashboard. This is the CyberArk equivalent of what Lighthouse provides for Microsoft 365 management, and it reflects the convergence of both tooling ecosystems toward the same MSP operational pattern: single-pane-of-glass management across a portfolio of customer environments.

### The Hybrid Architecture in Practice

For an MSP with CyberArk already deployed, the practical hybrid architecture layers the two tools without requiring them to be integrated with each other, because there is currently no native integration between CyberArk's approval workflows and Entra PIM's approval workflow for GDAP group activation.

The Entra PIM layer handles all Microsoft-plane access. GDAP security groups are PIM-enabled with the three-tier architecture. All Microsoft 365 administration flows through GDAP group activation via PIM. Approvals for tier-three roles route through Entra approver groups. The audit trail lives in Entra Identity Governance.

The CyberArk layer handles everything else: Windows server administration, Linux server access, database credentials, network device credentials. All sessions to these systems route through CyberArk's Privileged Session Manager for recording. Credentials are stored in the vault and never visible to technicians. Rotation happens on schedule.

The two layers meet at the service account boundary. When a CyberArk automation or service account needs to authenticate to a Microsoft 365 API -- for automated compliance checks, for log ingestion, for anything machine-to-machine -- those credentials live in CyberArk's vault and are rotated by the Central Policy Manager. Human-interactive paths go through GDAP/PIM. Machine-interactive paths go through CyberArk.

The practical consequence is bifurcated approval workflows. PIM activations are approved through the Entra My Access portal. CyberArk session access is approved through CyberArk's dual-control or ServiceNow integration. The audit trails are separate. For organizations that want a single source of truth for all privilege approval decisions, the most practical integration path is using Logic Apps or Power Automate to replicate PIM approval events into a common SIEM or ticketing system alongside CyberArk events.

---

## Part 7: When Things Go Wrong -- Breaches, Incident Response, and the Real Cost

### Four Cases That Changed the Industry

The history of MSP security isn't theoretical. Several events over the past six years have defined what's possible when MSP access is weaponized, and each one informs the operational decisions you make today.

SolarWinds. December 2020. The attackers, later attributed to Russia's Foreign Intelligence Service, gained access to SolarWinds' development network in September 2019 -- more than a year before discovery. They spent months testing a code injection capability in the Orion performance monitoring platform. By March 2020, they were distributing legitimate software updates to Orion that contained their SUNBURST malware. More than eighteen thousand customers installed the trojanized update. Because Orion operated with broad privileged access to gather performance data, it held exactly the kind of trusted, hard-to-scrutinize position that MSP management tools occupy. Discovery came not from SolarWinds' own monitoring but from FireEye, which was investigating a theft of its own penetration testing tools. Dwell time: more than a year.

Kaseya. July 2, 2021. The REvil ransomware group exploited a zero-day in Kaseya's VSA Remote Monitoring and Management platform. The timing -- Friday afternoon before the Independence Day holiday weekend in the United States -- was not coincidental. They didn't attack individual MSPs. They compromised the Kaseya VSA instances themselves and used those compromised management platforms to push a malicious update to every managed endpoint. Between eight hundred and fifteen hundred downstream businesses were impacted. The Swedish supermarket chain Coop, which had no relationship with Kaseya, closed all eight hundred of its stores for nearly a week because its point-of-sale system management ran through an MSP using Kaseya VSA. REvil demanded seventy million dollars for a universal decryptor.

ConnectWise ScreenConnect. February 2024. A critical authentication bypass vulnerability -- rated ten-point-zero on the CVSS scale, the maximum severity -- was discovered in ConnectWise's Remote Support platform. Within days of disclosure, ransomware groups including Black Basta began active exploitation. The window between vulnerability disclosure and active exploitation was hours to days, not weeks. An MSP that ran a thirty-day patch cycle was exposed for thirty days after public disclosure.

Berry Dunn and Reliable Networks. 2023-2024. An unauthorized actor gained access to Reliable Networks' infrastructure and exfiltrated personally identifiable information for more than one-point-one million individuals. Berry Dunn, whose data was stored on Reliable's systems, subsequently filed legal action against the MSP, alleging failure to implement adequate security controls. The breach occurred in September 2023. Public notification didn't happen until April 2024. This case represents the downstream legal liability that flows from MSP security failures and the regulatory notification obligation questions that arise when breach discovery is delayed.

The pattern across all four cases: the MSP's tooling and its delegated access are not just operational infrastructure. They are high-value targets. An attacker who understands MSP economics understands that compromising the MSP yields a multiplied return.

### Incident Response When an MSP Account Is Compromised

When a technician account compromise is identified, standard enterprise incident response timelines don't apply. Every minute the attacker retains access is a minute during which they may be operating in multiple customer tenants simultaneously.

In the first thirty minutes, the priority is stopping access, not understanding how the compromise happened. Disable the compromised account in the partner tenant Entra ID immediately. Note that active sessions may persist after account disabling due to token caching -- token revocation is a separate action. Revoke all active tokens using the Revoke-MgUserSignInSession PowerShell command. Remove the compromised account from all GDAP security groups. Because of the thirty-minute propagation delay documented in Lighthouse's known issues, document the exact time of removal so incident timelines can account for the window during which the removal may not yet have taken effect. Reset the account's credentials and communicate the new password through an out-of-band channel -- telephone or in person, not email, since email may be compromised.

In the investigation phase, pull the Unified Audit Log for the compromised account from the partner tenant for the period from last known legitimate activity through containment. This log shows which customer tenants were accessed, what administrative actions were taken, and when. For each customer tenant that appears in that log, pull that tenant's own audit records for the compromised account. Look for user creation, role assignments, application registrations, Conditional Access policy modifications, and data export operations. These are the persistence mechanisms an attacker would plant.

The customer notification phase has regulatory dimensions. GDPR requires notification to supervisory authorities within seventy-two hours of becoming aware of a breach involving personal data. US state breach notification laws vary but many require notification within thirty to seventy-two hours of determining personal data was affected. Notify affected customers as soon as the scope of access in each tenant is understood, without waiting for the full investigation to complete.

### Offboarding: The Operational Control That Gets Forgotten

GDAP access revocation for departing technicians is as important as the initial setup, and it's where discipline frequently breaks down. The absence of a clean offboarding procedure creates legal and security exposure long after the business relationship ends.

When a technician leaves, the immediate priority is removing them from all GDAP security groups. This is the most impactful single action because it terminates their ability to access customer tenants through delegated access. Account disabling in Entra follows, combined with token revocation to terminate active sessions. The thirty-minute propagation delay for security group changes means there's a brief window after removal during which access may technically still be possible -- document the removal time in your incident record.

When a customer relationship ends, the offboarding sequence should terminate all GDAP relationships through Partner Center, remove the customer from the Lighthouse management view (a process that takes up to forty-eight hours), remove any vendor applications deployed in the customer tenant during the management relationship, and remove guest user accounts or notification contacts the MSP added.

---

## Part 8: Getting It Right -- SOPs, Compliance, and Best Practices

### The GDAP Setup Standard Operating Procedure

Sarah, the MSP security engineer evaluating this architecture for her organization, needs to translate everything we've covered into an operational process. Here's how a well-run MSP approaches GDAP setup end-to-end.

Before opening any portal, design the access matrix. Map MSP job titles to specific Microsoft Entra built-in roles, with justification for each role based on defined job tasks. Microsoft publishes a least-privileged role-by-task reference that covers every common administrative function. The output is a document that answers: what role do you actually need to reset a user's non-admin password? (Password Administrator.) What do you need to manage Intune device policies? (Intune Administrator.) What do you need to submit a support ticket? (Service Support Administrator.) This document becomes the baseline for future access reviews and audit evidence for compliance assessments.

Roles fall into three risk tiers per Microsoft's own classification. Simple roles appropriate for always-on tier-one assignment include Global Reader, Helpdesk Administrator, License Administrator, Service Support Administrator, and User Administrator. Medium roles appropriate for workload-specific tier-two assignment include Exchange Administrator, Intune Administrator, Security Administrator, Teams Administrator. Complex roles that should only exist behind JIT and approval workflows include Application Administrator, Conditional Access Administrator, Privileged Authentication Administrator, and Privileged Role Administrator.

Never include Global Administrator in a standing GDAP security group. If you genuinely need it for a specific task, create a dedicated group with PIM configured for JIT activation with a human approver, a maximum duration of one to four hours, and a separate GDAP relationship with a ninety-day duration that requires renewed customer consent rather than auto-extending.

Build your Lighthouse templates from the access matrix. Create the security groups. Apply PIM for Groups to each group aligned to its tier's controls. Assign templates to customer tenants and send approval links. Once customers approve, verify the security group assignments appear in Partner Center and set a calendar reminder for ninety days before each relationship's expiration.

### SOW Alignment: Roles Should Follow Contracts

Every GDAP role set should be traceable to a service in your Statement of Work. Identity and User Lifecycle Management service maps to User Administrator, License Administrator, Groups Administrator, Guest Inviter, and Authentication Administrator. Help Desk support maps to Helpdesk Administrator, Password Administrator, Service Support Administrator, and Directory Reader. Exchange management maps to Exchange Administrator and Exchange Recipient Administrator. Device management maps to Intune Administrator and Cloud Device Administrator. Security operations maps to Security Reader and Security Operator, with Security Administrator only available through an approval-gated JIT workflow. Compliance management maps to Compliance Administrator and Reports Reader.

If a role isn't in the SOW, it shouldn't be in the GDAP relationship. This principle eliminates scope creep, provides a documented justification for each role, and creates natural governance touchpoints: when the SOW renews, review whether the role set still matches.

For customers with stricter security requirements or regulatory obligations, shorter durations -- thirty to ninety days instead of two years -- for high-privilege roles create a governance rhythm. Each renewal is a customer conversation and an access review.

### Compliance Framework Mapping

The GDAP/Lighthouse/PIM architecture maps well to major compliance frameworks, and you'll likely need to articulate this mapping to auditors or when responding to customer questionnaires.

For SOC 2, the Security trust criterion CC6.1 (logical access security) is addressed by GDAP's per-customer, time-limited, role-specific access controls. CC6.2 (authentication) is addressed by mandatory MFA in the partner tenant and phishing-resistant authentication strength policies in customer CA. CC6.3 (authorization) is addressed by the three-tier security group model with PIM JIT. CC7.2 (monitoring) is addressed by Entra sign-in logs, Purview audit logs with UserType nine filtering, and Lighthouse audit logs.

For ISO 27001, control A.9.2 (user access management) maps to GDAP relationship lifecycle and GDAP security group membership reviews. Control A.9.4 (system and application access control) maps to Conditional Access policies and PIM JIT controls. Control A.12.4 (logging and monitoring) maps to the multi-layer audit trail described in Part Five.

For NIST 800-53, the privileged account management controls in AC-2 and AC-6 are directly addressed by the GDAP tiered role model, PIM for Groups, and the security group architecture. The audit and accountability controls in AU-2 through AU-12 are addressed by the combination of Entra audit logs, Purview unified audit log, and Lighthouse's own audit logging.

### Cyber Insurance: The New Underwriting Reality

Cyber insurance underwriters have become increasingly specific about MSP security requirements, and GDAP plus JIT access controls directly affect both coverage eligibility and premium rates.

The controls underwriters consistently ask about for MSP applicants: Is MFA enabled for all accounts with administrative access? (GDAP requires MFA in the partner tenant; this is documented.) Are privileged access controls in place limiting who can access customer environments and for how long? (JIT activation through PIM for Groups addresses this directly.) Is there an audit trail of administrative actions taken in customer environments? (Entra audit logs, Purview UserType nine filtering, and Lighthouse audit logs address this.) Is there a documented incident response plan for compromised MSP accounts? (The procedure outlined in Part Seven should be documented formally and tested annually.)

The trend in underwriting is toward requiring proof of these controls -- not self-attestation, but evidence from logging systems and configuration exports. MSPs who cannot demonstrate Conditional Access policy configurations, PIM activation logs, and GDAP relationship documentation face either denial of coverage or substantially elevated premiums.

---

## The Closing -- Security Mindset Takeaways

We've covered a lot of ground today. Let me bring it back to fundamentals.

The central security principle underlying everything we've discussed is that the MSP's partner tenant is the security boundary that protects all customer access. That's the target. That's what an attacker wants. Not any individual customer -- the MSP tenant, from which all customer environments can be reached through GDAP. Every security control we've discussed is ultimately about hardening that boundary, limiting what can be done with access to that boundary, and detecting when someone who shouldn't have access is trying to use it.

The second principle is least privilege through every layer. Not just at the GDAP relationship level -- though that matters enormously compared to DAP's Global Admin blanket. Also at the security group level, where you're choosing which roles go to which groups. At the PIM level, where standing access becomes eligible-only access. At the Conditional Access level, where device compliance and phishing-resistant MFA are the additional barriers even if credentials are compromised.

The third principle is auditability as a first-class design requirement. Every piece of this architecture generates logs: Entra sign-in logs with the serviceProvider CrossTenantAccessType, Purview audit entries with UserType nine, Lighthouse's four log categories, PIM activation records in Identity Governance, CyberArk session recordings. The architecture generates the evidence. Your job is to make sure that evidence is collected, retained, monitored with appropriate alerting, and accessible when you need it.

The fourth principle is supply chain awareness. You are in the supply chain of every organization you serve. SolarWinds, Kaseya, ConnectWise -- these weren't attacks on the MSPs themselves as the ultimate target. The MSPs were the path to the targets. That means your own security posture is the security posture of your customers. Hardening your GDAP architecture is not just about protecting the customers you serve. It's about not being the next case study.

And the fifth principle -- the one that's easy to forget when you're deep in role configuration -- is that security controls are only as effective as the people enforcing them. The best GDAP architecture in the world doesn't help if a departing technician's access isn't revoked, if the quarterly access review doesn't happen, if the JIT approval workflow goes to a distribution list that nobody monitors. The technical controls we've described today are necessary. The operational discipline to maintain them is what makes them sufficient.

Build the architecture. Document it against your SOW. Test it. Review it. Keep it current. That's the security mindset.

---

## Source Citations

The following sources were used across the seven research documents synthesized into this guide:

- Microsoft Learn - GDAP Introduction: https://learn.microsoft.com/en-us/partner-center/customers/gdap-introduction
- Microsoft Learn - GDAP FAQ: https://learn.microsoft.com/en-us/partner-center/customers/gdap-faq
- Microsoft Learn - Workloads Supported by GDAP: https://learn.microsoft.com/en-us/partner-center/customers/gdap-supported-workloads
- Microsoft Learn - Least Privileged Roles by Task: https://learn.microsoft.com/en-us/partner-center/customers/gdap-least-privileged-roles-by-task
- Microsoft Learn - GDAP Customer Approval: https://learn.microsoft.com/en-us/partner-center/customers/gdap-customer-approval
- Microsoft Learn - Microsoft-Led Transition from DAP to GDAP: https://learn.microsoft.com/en-us/partner-center/customers/gdap-microsoft-led-transition
- Microsoft Learn - Set Up GDAP in Microsoft 365 Lighthouse: https://learn.microsoft.com/en-us/microsoft-365/lighthouse/m365-lighthouse-setup-gdap
- Microsoft Learn - Overview of Permissions in Microsoft 365 Lighthouse: https://learn.microsoft.com/en-us/microsoft-365/lighthouse/m365-lighthouse-overview-of-permissions
- Microsoft Learn - Microsoft 365 Lighthouse Overview: https://learn.microsoft.com/en-us/microsoft-365/lighthouse/m365-lighthouse-overview
- Microsoft Learn - Microsoft 365 Lighthouse FAQ: https://learn.microsoft.com/en-us/microsoft-365/lighthouse/m365-lighthouse-faq
- Microsoft Learn - Microsoft 365 Lighthouse Known Issues: https://learn.microsoft.com/en-us/microsoft-365/lighthouse/m365-lighthouse-known-issues
- Microsoft Learn - Azure Lighthouse Overview: https://learn.microsoft.com/en-us/azure/lighthouse/overview
- Microsoft Learn - Azure Lighthouse Architecture: https://learn.microsoft.com/en-us/azure/lighthouse/concepts/architecture
- Microsoft Learn - Manage Hybrid Infrastructure with Azure Lighthouse and Azure Arc: https://learn.microsoft.com/en-us/azure/lighthouse/how-to/manage-hybrid-infrastructure-arc
- Microsoft Learn - Manage Sentinel Workspaces at Scale: https://learn.microsoft.com/en-us/azure/lighthouse/how-to/manage-sentinel-workspaces
- Microsoft Learn - Primary Refresh Token Concept: https://learn.microsoft.com/en-us/entra/identity/devices/concept-primary-refresh-token
- Microsoft Learn - Protecting Tokens in Microsoft Entra ID: https://learn.microsoft.com/en-us/entra/identity/devices/protecting-tokens-microsoft-entra-id
- Microsoft Learn - Token Theft Playbook: https://learn.microsoft.com/en-us/security/operations/token-theft-playbook
- Microsoft Learn - Token Protection in Conditional Access: https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-token-protection
- Microsoft Learn - PIM for Groups: https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/concept-pim-for-groups
- Microsoft Learn - PIM Configuration: https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-configure
- Microsoft Learn - PIM Approval Workflow: https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-approval-workflow
- Microsoft Learn - Authentication and Conditional Access for B2B Users: https://learn.microsoft.com/en-us/entra/external-id/authentication-conditional-access
- Microsoft Learn - Cross-Tenant Access Settings B2B Collaboration: https://learn.microsoft.com/en-us/entra/external-id/cross-tenant-access-settings-b2b-collaboration
- Microsoft Learn - Block Access by Location: https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-block-by-location
- Microsoft Learn - Authentication Strength Concept: https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-strengths
- Microsoft Learn - Authentication Strength for External Users: https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-guests-mfa-strength
- Microsoft Learn - Session Lifetime Policies: https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-session-lifetime
- Microsoft Learn - Audit Log Detailed Properties: https://learn.microsoft.com/en-us/purview/audit-log-detailed-properties
- Microsoft Learn - Audit Solutions Overview: https://learn.microsoft.com/en-us/purview/audit-solutions-overview
- Microsoft Learn - Review Audit Logs in Lighthouse: https://learn.microsoft.com/en-us/microsoft-365/lighthouse/m365-lighthouse-review-audit-logs
- Microsoft Learn - Monitor Service Provider Activity: https://learn.microsoft.com/en-us/azure/lighthouse/how-to/view-service-provider-activity
- Microsoft Learn - Manage Multiple Tenants in Sentinel as MSSP: https://learn.microsoft.com/en-us/azure/sentinel/multiple-tenants-service-providers
- Microsoft Learn - Lighthouse Alerts Overview: https://learn.microsoft.com/en-us/microsoft-365/lighthouse/m365-lighthouse-alerts-overview
- Microsoft Security Blog - NOBELIUM Targeting Delegated Administrative Privileges: https://www.microsoft.com/en-us/security/blog/2021/10/25/nobelium-targeting-delegated-administrative-privileges-to-facilitate-broader-attacks/
- Microsoft Learn - Partner Security Requirements Mandating MFA: https://learn.microsoft.com/en-us/partner-center/security/partner-security-requirements-mandating-mfa
- Microsoft Tech Community - How GDAP Allows Sentinel Customers to Delegate Access: https://techcommunity.microsoft.com/blog/microsoftsentinelblog/how-granular-delegated-admin-privileges-gdap-allows-sentinel-customers-to-delega/4503123
- CISA Advisory AA22-131A - Protecting Against Cyber Threats to MSPs: https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-131a
- DoD/NSA CSI - Cloud Top 10 for MSPs (March 2024): https://media.defense.gov/2024/Mar/07/2003407859/-1/-1/0/CSI-CloudTop10-Managed-Service-Providers.PDF
- CyberArk - MSP Hub Announcement (June 2025): https://www.cyberark.com/press/cyberark-for-msps-enhanced-console-and-new-program-enable-msps-to-build-differentiated-converged-identity-security-services/
- CyberArk - Privilege Cloud Session Management: https://www.cyberark.com/resources/privileged-access-management/cyberark-privilege-cloud-reduce-footprint-save-on-tco-and-boost-security-in-session-management
- CyberArk - Eliminating Standing Admin Privilege for Microsoft 365: https://www.cyberark.com/product-insights/eliminating-standing-admin-privilege-for-microsoft-365/
- CyberArk - Secure Infrastructure Access: https://docs.cyberark.com/ispss-access/latest/en/content/getstarted/acc-intro.htm
- Kaseya VSA Ransomware Attack: https://en.wikipedia.org/wiki/Kaseya_VSA_ransomware_attack
- CISA Kaseya Guidance: https://www.cisa.gov/news-events/news/kaseya-ransomware-attack-guidance-affected-msps-and-their-customers
- SolarWinds Attack - TechTarget: https://www.techtarget.com/whatis/feature/SolarWinds-hack-explained-Everything-you-need-to-know
- BerryDunn / Reliable Networks Breach: https://www.msspalert.com/news/it-consulting-firm-blames-msp-for-data-breach
- NIST SP 800-161r1 - Cyber Supply Chain Risk Management: https://csrc.nist.gov/pubs/sp/800/161/r1/final
- tminus365 - GDAP Role Guidance: https://tminus365.com/granular-delegated-admin-privileges/
- CloudBrothers - Trust CSP Cross-Tenant MFA GDAP: https://cloudbrothers.info/en/trust-csp-cross-tenant-mfa-gdap/
- blog.cloudcapsule.io - Secure GDAP Access with JIT Permissions: https://blog.cloudcapsule.io/blog/secure-your-gdap-access-with-just-in-time-permissions
- Practical365 - PIM Approval Workflows: https://practical365.com/leveling-up-privileged-identity-management-with-approvals/
- blog.ciaops.com - PIM for MSPs with Lighthouse and GDAP: https://blog.ciaops.com/2025/06/07/secure-access-for-smb-customers-pim-for-msps-with-microsoft-lighthouse-and-gdap/
- US Cloud - GDAP vs DAP: https://www.uscloud.com/blog/microsoft-security-and-compliance-gdap-vs-dap/
- Huntress - Understanding GDAP and Its Operational Impact: https://www.huntress.com/blog/understanding-gdap-and-its-operational-impact
- Practical365 - Identifying Potential Unwanted MSP Access: https://practical365.com/identifying-potential-unwanted-access-by-your-msp-csp-reseller/
- Channel Insider - MSP Data Breach Response Plan: https://www.channelinsider.com/security/data-breach-response-plan-for-msps/
- Axcient - MSP Cyber Insurance Requirements: https://axcient.com/blog/cyber-insurance-requirements-for-msps/
