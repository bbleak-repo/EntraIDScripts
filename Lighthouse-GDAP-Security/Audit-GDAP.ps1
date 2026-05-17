<#
.SYNOPSIS
    GDAP Security Audit Script -- Read-Only Assessment of Delegated Admin Configuration

.DESCRIPTION
    Audits Microsoft 365 GDAP (Granular Delegated Admin Privileges) configuration from either
    the customer tenant or the partner (MSP) tenant perspective. Generates an HTML report with
    findings, risk ratings, and remediation recommendations.

    Customer Mode (-Mode Customer):
      - Lists all service provider entries in cross-tenant access policy
      - Checks for GDAP service principals (confirms GDAP is active)
      - Checks for MLT (Microsoft-Led Transition) migration evidence
      - Reviews inbound trust settings (MFA, device compliance, hybrid join)
      - Scans sign-in logs for recent partner access patterns
      - Scans audit logs for partner relationship lifecycle events
      - Minimum role: Global Reader

    Partner Mode (-Mode Partner):
      - Lists all outbound GDAP relationships across customers
      - Identifies MLT-created relationships (auto-migrated from DAP)
      - Checks role assignments for overprivileged configurations
      - Identifies relationships approaching expiration
      - Checks for Global Admin in standing GDAP roles
      - Identifies relationships with no security group assignments
      - Minimum permission: DelegatedAdminRelationship.Read.All

.PARAMETER Mode
    Either 'Customer' or 'Partner'. Determines which audit perspective to use.

.PARAMETER OutputPath
    Directory for the HTML report. Defaults to .\Output

.PARAMETER DaysBack
    How many days of sign-in/audit log history to review. Default: 30

.PARAMETER SkipLogAnalysis
    Skip sign-in and audit log analysis (faster, but less detail)

.EXAMPLE
    # Audit from the customer side (run as Global Reader in the customer tenant)
    .\Audit-GDAP.ps1 -Mode Customer

.EXAMPLE
    # Audit from the MSP/partner side
    .\Audit-GDAP.ps1 -Mode Partner

.EXAMPLE
    # Customer audit with 90 days of log history
    .\Audit-GDAP.ps1 -Mode Customer -DaysBack 90

.NOTES
    Author: EntraID Project
    Version: 1.0.0
    Date: 2026-04-07

    Required Modules:
      - Microsoft.Graph.Identity.SignIns   (Customer mode)
      - Microsoft.Graph.Applications       (Customer mode)
      - Microsoft.Graph.Reports            (Customer mode, log analysis)
      - Microsoft.Graph.Identity.Partner   (Partner mode)
      - Microsoft.Graph.Identity.DirectoryManagement (Partner mode, role resolution)

    This script performs READ-ONLY operations. It does not modify any configuration.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Customer', 'Partner')]
    [string]$Mode,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = ".\Output",

    [Parameter(Mandatory = $false)]
    [int]$DaysBack = 30,

    [Parameter(Mandatory = $false)]
    [switch]$SkipLogAnalysis
)

$ErrorActionPreference = 'Continue'
$script:Findings = @()
$script:Stats = @{}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

function Add-Finding {
    param(
        [string]$Category,
        [string]$Title,
        [string]$Detail,
        [ValidateSet('Critical','High','Medium','Low','Info')]
        [string]$Severity,
        [string]$Recommendation
    )
    $script:Findings += [PSCustomObject]@{
        Category       = $Category
        Title          = $Title
        Detail         = $Detail
        Severity       = $Severity
        Recommendation = $Recommendation
    }
}

function Write-Status {
    param([string]$Message)
    Write-Host "  [*] $Message" -ForegroundColor Cyan
}

function Write-StatusOk {
    param([string]$Message)
    Write-Host "  [+] $Message" -ForegroundColor Green
}

function Write-StatusWarn {
    param([string]$Message)
    Write-Host "  [!] $Message" -ForegroundColor Yellow
}

function Write-StatusError {
    param([string]$Message)
    Write-Host "  [-] $Message" -ForegroundColor Red
}

# Well-known GDAP service principal App IDs
$GDAPServicePrincipals = @{
    '2832473f-ec63-45fb-976f-5d45a7d4bb91' = 'Partner customer delegated administration'
    'a3475900-ccec-4a69-98f5-a65cd5dc5306' = 'Partner customer delegated admin offline processor'
    'b39d63e7-7fa3-4b2b-94ea-ee256fdb8c2f' = 'Partner Center Delegated Admin Migrate'
}

# High-privilege role GUIDs that should not be standing access
$HighPrivilegeRoles = @{
    '62e90394-69f5-4237-9190-012177145e10' = 'Global Administrator'
    'e8611ab8-c189-46e8-94e1-60213ab1f814' = 'Privileged Role Administrator'
    '7be44c8a-adaf-4e2a-84d6-ab2649e08a13' = 'Privileged Authentication Administrator'
    '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3' = 'Application Administrator'
    'b0f54661-2d74-4c50-afa3-1ec803f12efe' = 'Billing Administrator'
    '892c5842-a9a6-463a-8041-72aa08ca3cf6' = 'Cloud Application Administrator'
    'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9' = 'Conditional Access Administrator'
    '17315797-102d-40b4-93e0-432062caca18' = 'Compliance Administrator'
    'e6d1a23a-da11-4be4-9570-befc86d067a7' = 'Compliance Data Administrator'
}

# Medium-privilege roles (workload-specific admins)
$MediumPrivilegeRoles = @{
    '29232cdf-9323-42fd-ade2-1d097af3e4de' = 'Exchange Administrator'
    '3a2c62db-5318-420d-8d74-23affee5d9d5' = 'Intune Administrator'
    'f28a1f50-f6e7-4571-818b-6a12f2af6b6c' = 'SharePoint Administrator'
    '69091246-20e8-4a56-aa4d-066075b2a7a8' = 'Teams Administrator'
    'f023fd81-a637-4b56-95fd-791ac0226033' = 'Security Administrator'
    '194ae4cb-b126-40b2-bd5b-6091b380977d' = 'Security Administrator'
}

# All well-known Entra role GUIDs for display name resolution
$WellKnownRoles = @{
    '62e90394-69f5-4237-9190-012177145e10' = 'Global Administrator'
    'e8611ab8-c189-46e8-94e1-60213ab1f814' = 'Privileged Role Administrator'
    '7be44c8a-adaf-4e2a-84d6-ab2649e08a13' = 'Privileged Authentication Administrator'
    '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3' = 'Application Administrator'
    'b0f54661-2d74-4c50-afa3-1ec803f12efe' = 'Billing Administrator'
    '892c5842-a9a6-463a-8041-72aa08ca3cf6' = 'Cloud Application Administrator'
    'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9' = 'Conditional Access Administrator'
    '17315797-102d-40b4-93e0-432062caca18' = 'Compliance Administrator'
    'e6d1a23a-da11-4be4-9570-befc86d067a7' = 'Compliance Data Administrator'
    '29232cdf-9323-42fd-ade2-1d097af3e4de' = 'Exchange Administrator'
    '3a2c62db-5318-420d-8d74-23affee5d9d5' = 'Intune Administrator'
    'f28a1f50-f6e7-4571-818b-6a12f2af6b6c' = 'SharePoint Administrator'
    '69091246-20e8-4a56-aa4d-066075b2a7a8' = 'Teams Administrator'
    'f023fd81-a637-4b56-95fd-791ac0226033' = 'Security Administrator'
    '729827e3-9c14-49f7-bb1b-9608f156bbb8' = 'Helpdesk Administrator'
    '88d8e3e3-8f55-4a1e-953a-9b9898b8876b' = 'Directory Readers'
    'f2ef992c-3afb-46b9-b7cf-a126ee74c451' = 'Global Reader'
    '4a5d8f65-41da-4de4-8968-e035b65339cf' = 'Reports Reader'
    'fe930be7-5e62-47db-91af-98c3a49a38b1' = 'User Administrator'
    '966707d0-3269-4727-9be2-8c3a10f19b9d' = 'Password Administrator'
    '75941009-915a-4869-abe7-691bff18279e' = 'License Administrator'
    'f70e1ce0-8398-499d-8811-6bdf0bd66dad' = 'Service Support Administrator'
    '9360feb5-f418-4baa-8175-e2a00bac4301' = 'Directory Writers'
    '7698a772-787b-4ac8-901f-60d6b08affd2' = 'Cloud Device Administrator'
    '11648597-926c-4cf3-9c36-bcebb0ba8dcc' = 'Power Platform Administrator'
    'a9ea8996-122f-4c74-9520-8edcd192826c' = 'Security Operator'
    '5f2222b1-57c3-48ba-8ad5-d4759f1fde6f' = 'Security Reader'
    '2b745bdf-0803-4d80-aa65-822c4493daac' = 'Groups Administrator'
    '95e79109-95c0-4d8e-aee3-d01accf2d47b' = 'Guest Inviter'
    '158c047a-c907-4556-b7ef-446551a6b5f7' = 'Authentication Administrator'
    'd37c8bed-0711-4417-ba38-b4abe66ce4c2' = 'Exchange Recipient Administrator'
}

function Resolve-RoleName {
    param([string]$RoleDefinitionId)
    if ($WellKnownRoles.ContainsKey($RoleDefinitionId)) {
        return $WellKnownRoles[$RoleDefinitionId]
    }
    return $RoleDefinitionId
}

function Get-RoleRiskLevel {
    param([string]$RoleDefinitionId)
    if ($HighPrivilegeRoles.ContainsKey($RoleDefinitionId)) { return 'High' }
    if ($MediumPrivilegeRoles.ContainsKey($RoleDefinitionId)) { return 'Medium' }
    return 'Low'
}

# ---------------------------------------------------------------------------
# Customer Mode
# ---------------------------------------------------------------------------

function Invoke-CustomerAudit {
    Write-Host "`n========================================" -ForegroundColor White
    Write-Host "GDAP Security Audit -- Customer Tenant" -ForegroundColor White
    Write-Host "========================================`n" -ForegroundColor White

    $requiredScopes = @(
        'Policy.Read.All',
        'Application.Read.All'
    )
    if (-not $SkipLogAnalysis) {
        $requiredScopes += 'AuditLog.Read.All'
    }

    Write-Status "Connecting to Microsoft Graph (scopes: $($requiredScopes -join ', '))"
    try {
        Connect-MgGraph -Scopes $requiredScopes -NoWelcome -ErrorAction Stop
        $context = Get-MgContext
        Write-StatusOk "Connected as $($context.Account) to tenant $($context.TenantId)"
        $script:Stats['TenantId'] = $context.TenantId
        $script:Stats['Account'] = $context.Account
    }
    catch {
        Write-StatusError "Failed to connect to Microsoft Graph: $_"
        Write-StatusError "Ensure you have the required modules installed:"
        Write-StatusError "  Install-Module Microsoft.Graph.Identity.SignIns"
        Write-StatusError "  Install-Module Microsoft.Graph.Applications"
        Write-StatusError "  Install-Module Microsoft.Graph.Reports"
        return
    }

    # --- Check 1: Cross-Tenant Access Policy Partners ---
    Write-Host "`n--- Check 1: Cross-Tenant Access Policy (Service Provider Entries) ---" -ForegroundColor White
    try {
        $partners = Get-MgPolicyCrossTenantAccessPolicyPartner -All -ErrorAction Stop
        $serviceProviders = $partners | Where-Object { $_.IsServiceProvider -eq $true }
        $script:Stats['TotalPartnerEntries'] = ($partners | Measure-Object).Count
        $script:Stats['ServiceProviderEntries'] = ($serviceProviders | Measure-Object).Count

        if (($serviceProviders | Measure-Object).Count -eq 0) {
            Write-StatusOk "No service provider (CSP/GDAP) partner entries found"
            Add-Finding -Category "Partner Access" -Title "No GDAP partners configured" `
                -Detail "No cross-tenant access policy entries with isServiceProvider=true were found." `
                -Severity "Info" -Recommendation "No action needed if this tenant is not managed by an MSP."
        }
        else {
            Write-StatusWarn "Found $($script:Stats['ServiceProviderEntries']) service provider partner(s)"
            foreach ($sp in $serviceProviders) {
                $trustDetail = ""
                $trustIssues = @()
                if ($sp.InboundTrust) {
                    $mfaTrust = $sp.InboundTrust.IsMfaAccepted
                    $deviceTrust = $sp.InboundTrust.IsCompliantDeviceAccepted
                    $hybridTrust = $sp.InboundTrust.IsHybridAzureADJoinedDeviceAccepted
                    $trustDetail = "MFA trusted: $mfaTrust | Compliant device trusted: $deviceTrust | Hybrid join trusted: $hybridTrust"

                    if (-not $deviceTrust) {
                        $trustIssues += "Device compliance not trusted -- CA cannot enforce partner device compliance"
                    }
                }
                else {
                    $trustDetail = "No inbound trust settings configured (defaults apply)"
                    $trustIssues += "No explicit inbound trust settings -- partner device claims not evaluated"
                }

                Write-Status "  Partner Tenant: $($sp.TenantId)"
                Write-Status "  Trust: $trustDetail"

                Add-Finding -Category "Partner Access" -Title "GDAP Partner: $($sp.TenantId)" `
                    -Detail "Service provider entry found. $trustDetail" `
                    -Severity "Info" -Recommendation "Verify this partner is expected and the trust settings align with your security requirements."

                if ($trustIssues.Count -gt 0) {
                    foreach ($issue in $trustIssues) {
                        Add-Finding -Category "Trust Settings" -Title "Trust gap for partner $($sp.TenantId)" `
                            -Detail $issue `
                            -Severity "Medium" -Recommendation "Enable 'Trust compliant devices' in cross-tenant access settings if you want to enforce device compliance for this partner's technicians."
                    }
                }
            }
        }
    }
    catch {
        Write-StatusError "Failed to query cross-tenant access policy: $_"
        Add-Finding -Category "Error" -Title "Cannot read cross-tenant access policy" `
            -Detail "Error: $_. Ensure the account has Policy.Read.All permission (Global Reader role)." `
            -Severity "High" -Recommendation "Verify the account has Global Reader or Security Reader role."
    }

    # --- Check 2: GDAP Service Principals ---
    Write-Host "`n--- Check 2: GDAP Service Principals ---" -ForegroundColor White
    $foundSPs = @()
    $mltEvidence = $false
    foreach ($appId in $GDAPServicePrincipals.Keys) {
        try {
            $sp = Get-MgServicePrincipal -Filter "appId eq '$appId'" -ErrorAction Stop
            if ($sp) {
                $name = $GDAPServicePrincipals[$appId]
                $foundSPs += $name
                Write-StatusWarn "Found: $name (AppId: $appId)"

                if ($appId -eq 'b39d63e7-7fa3-4b2b-94ea-ee256fdb8c2f') {
                    $mltEvidence = $true
                    Add-Finding -Category "DAP Migration" `
                        -Title "Microsoft-Led Transition (MLT) evidence detected" `
                        -Detail "The 'Partner Center Delegated Admin Migrate' service principal is present. This tenant was migrated from DAP to GDAP via Microsoft's automated transition. MLT relationships may have overprivileged default roles (including Privileged Role Administrator and Privileged Authentication Administrator)." `
                        -Severity "High" `
                        -Recommendation "Review all GDAP relationships for MLT-created entries (names starting with 'MLT_'). Replace them with properly scoped GDAP templates aligned to the MSP's SOW. The MLT default role set includes high-privilege roles that should be behind JIT."
                }
            }
        }
        catch {
            # SP not found -- this is fine
        }
    }
    $script:Stats['GDAPServicePrincipals'] = $foundSPs.Count
    $script:Stats['MLTDetected'] = $mltEvidence

    if ($foundSPs.Count -eq 0) {
        Write-StatusOk "No GDAP service principals found -- no GDAP relationships have been established"
        Add-Finding -Category "GDAP Status" -Title "No GDAP service principals present" `
            -Detail "None of the 3 Microsoft-managed GDAP service principals exist in this tenant." `
            -Severity "Info" -Recommendation "No action needed if this tenant is not managed by an MSP."
    }
    elseif ($foundSPs.Count -ge 2 -and -not $mltEvidence) {
        Write-StatusOk "GDAP service principals present (no MLT evidence) -- clean GDAP setup"
        Add-Finding -Category "GDAP Status" -Title "GDAP is active (clean setup)" `
            -Detail "Found $($foundSPs.Count) GDAP service principals. No MLT migration evidence." `
            -Severity "Info" -Recommendation "Review partner relationships in M365 Admin Center > Settings > Partner relationships to verify role assignments."
    }

    # --- Check 3: Sign-In Log Analysis ---
    if (-not $SkipLogAnalysis) {
        Write-Host "`n--- Check 3: Partner Sign-In Activity (last $DaysBack days) ---" -ForegroundColor White
        try {
            $startDate = (Get-Date).AddDays(-$DaysBack).ToString("yyyy-MM-ddTHH:mm:ssZ")
            $signIns = Get-MgAuditLogSignIn -Filter "createdDateTime ge $startDate and crossTenantAccessType eq 'serviceProvider'" -Top 500 -ErrorAction Stop
            $signInCount = ($signIns | Measure-Object).Count
            $script:Stats['PartnerSignIns'] = $signInCount

            if ($signInCount -eq 0) {
                Write-StatusOk "No partner sign-ins in the last $DaysBack days"
                Add-Finding -Category "Access Activity" -Title "No recent partner access" `
                    -Detail "No sign-ins with CrossTenantAccessType='serviceProvider' found in the last $DaysBack days." `
                    -Severity "Info" -Recommendation "If the MSP should be actively managing this tenant, verify they have correct GDAP access."
            }
            else {
                Write-StatusWarn "Found $signInCount partner sign-in(s) in the last $DaysBack days"

                # Analyze locations
                $locations = $signIns | Group-Object -Property Location | Sort-Object Count -Descending
                $ips = $signIns | Group-Object -Property IpAddress | Sort-Object Count -Descending
                $failedSignIns = $signIns | Where-Object { $_.Status.ErrorCode -ne 0 }
                $failedCount = ($failedSignIns | Measure-Object).Count

                $locationSummary = ($locations | ForEach-Object { "$($_.Name): $($_.Count)" }) -join "; "
                $ipSummary = ($ips | Select-Object -First 5 | ForEach-Object { "$($_.Name): $($_.Count)" }) -join "; "

                Add-Finding -Category "Access Activity" `
                    -Title "$signInCount partner sign-ins detected" `
                    -Detail "Locations: $locationSummary. Top IPs: $ipSummary. Failed attempts: $failedCount." `
                    -Severity "Info" `
                    -Recommendation "Verify these locations and IPs match your MSP's expected access profile. Investigate any unexpected locations."

                if ($failedCount -gt 10) {
                    Add-Finding -Category "Access Activity" `
                        -Title "Elevated failed partner sign-ins: $failedCount" `
                        -Detail "More than 10 failed partner sign-in attempts in the last $DaysBack days." `
                        -Severity "Medium" `
                        -Recommendation "Investigate failed sign-in patterns. Could indicate credential attacks targeting the MSP's accounts."
                }

                # Check for non-US locations if any exist
                $nonUS = $locations | Where-Object { $_.Name -and $_.Name -notmatch 'US|United States' }
                if (($nonUS | Measure-Object).Count -gt 0) {
                    $nonUSList = ($nonUS | ForEach-Object { "$($_.Name): $($_.Count)" }) -join "; "
                    Add-Finding -Category "Access Activity" `
                        -Title "Partner access from non-US locations detected" `
                        -Detail "Sign-ins from: $nonUSList" `
                        -Severity "Medium" `
                        -Recommendation "If your security policy requires US-only access, configure a Conditional Access policy with Named Location geo-fencing targeting the 'Service provider' user type."
                }
            }
        }
        catch {
            Write-StatusError "Failed to query sign-in logs: $_"
            Add-Finding -Category "Error" -Title "Cannot read sign-in logs" `
                -Detail "Error: $_. Requires AuditLog.Read.All permission." `
                -Severity "Low" -Recommendation "Grant AuditLog.Read.All or run with -SkipLogAnalysis."
        }

        # --- Check 4: Audit Log -- Partner Relationship Events ---
        Write-Host "`n--- Check 4: Partner Relationship Lifecycle Events ---" -ForegroundColor White
        try {
            $auditStart = (Get-Date).AddDays(-$DaysBack).ToString("yyyy-MM-ddTHH:mm:ssZ")
            $addEvents = Get-MgAuditLogDirectoryAudit -Filter "activityDisplayName eq 'Add partner to company' and activityDateTime ge $auditStart" -All -ErrorAction Stop
            $removeEvents = Get-MgAuditLogDirectoryAudit -Filter "activityDisplayName eq 'Remove partner from company' and activityDateTime ge $auditStart" -All -ErrorAction Stop

            $addCount = ($addEvents | Measure-Object).Count
            $removeCount = ($removeEvents | Measure-Object).Count
            $script:Stats['PartnerAdded'] = $addCount
            $script:Stats['PartnerRemoved'] = $removeCount

            if ($addCount -gt 0) {
                Write-StatusWarn "Found $addCount 'Add partner' event(s) in the last $DaysBack days"
                Add-Finding -Category "Relationship Lifecycle" `
                    -Title "$addCount new partner relationship(s) established" `
                    -Detail "New GDAP relationships were created in the last $DaysBack days." `
                    -Severity "Info" `
                    -Recommendation "Verify each new relationship was approved by an authorized Global Administrator."
            }
            if ($removeCount -gt 0) {
                Write-StatusWarn "Found $removeCount 'Remove partner' event(s) in the last $DaysBack days"
                Add-Finding -Category "Relationship Lifecycle" `
                    -Title "$removeCount partner relationship(s) terminated" `
                    -Detail "GDAP relationships were terminated in the last $DaysBack days." `
                    -Severity "Info" `
                    -Recommendation "Verify terminations were intentional and properly documented."
            }
            if ($addCount -eq 0 -and $removeCount -eq 0) {
                Write-StatusOk "No partner relationship changes in the last $DaysBack days"
            }
        }
        catch {
            Write-StatusError "Failed to query audit logs: $_"
        }
    }
    else {
        Write-Status "Skipping log analysis (-SkipLogAnalysis specified)"
    }

    # --- Check 5: Conditional Access Baseline ---
    Write-Host "`n--- Check 5: Conditional Access Partner Targeting ---" -ForegroundColor White
    Write-Status "Note: Checking CA policy details requires Policy.Read.All or Conditional Access Administrator."
    Write-Status "Recommendation: Verify these CA policies exist in the Entra admin center:"
    Add-Finding -Category "Conditional Access" `
        -Title "Manual verification required: Partner-scoped CA policies" `
        -Detail "The following CA policies should exist targeting the 'Service provider' user type for each MSP partner: (1) Require phishing-resistant MFA, (2) Block non-US locations (if geo-fencing required), (3) Require compliant device, (4) Sign-in frequency 4 hours, (5) Non-persistent browser session." `
        -Severity "Medium" `
        -Recommendation "Review CA policies in Entra admin center > Protection > Conditional Access. Verify 'Service provider' user type is targeted for partner-specific controls."
}

# ---------------------------------------------------------------------------
# Partner Mode
# ---------------------------------------------------------------------------

function Invoke-PartnerAudit {
    Write-Host "`n========================================" -ForegroundColor White
    Write-Host "GDAP Security Audit -- Partner (MSP) Tenant" -ForegroundColor White
    Write-Host "========================================`n" -ForegroundColor White

    $requiredScopes = @('DelegatedAdminRelationship.Read.All')

    Write-Status "Connecting to Microsoft Graph (scopes: $($requiredScopes -join ', '))"
    try {
        Connect-MgGraph -Scopes $requiredScopes -NoWelcome -ErrorAction Stop
        $context = Get-MgContext
        Write-StatusOk "Connected as $($context.Account) to tenant $($context.TenantId)"
        $script:Stats['TenantId'] = $context.TenantId
        $script:Stats['Account'] = $context.Account
    }
    catch {
        Write-StatusError "Failed to connect to Microsoft Graph: $_"
        Write-StatusError "Ensure you have Microsoft.Graph.Identity.Partner installed:"
        Write-StatusError "  Install-Module Microsoft.Graph.Identity.Partner"
        return
    }

    # --- Check 1: List All GDAP Relationships ---
    Write-Host "`n--- Check 1: GDAP Relationships ---" -ForegroundColor White
    try {
        $relationships = Get-MgTenantRelationshipDelegatedAdminRelationship -All -ErrorAction Stop
        $activeRels = $relationships | Where-Object { $_.Status -eq 'active' }
        $expiredRels = $relationships | Where-Object { $_.Status -eq 'expired' }
        $pendingRels = $relationships | Where-Object { $_.Status -eq 'approvalPending' }

        $script:Stats['TotalRelationships'] = ($relationships | Measure-Object).Count
        $script:Stats['ActiveRelationships'] = ($activeRels | Measure-Object).Count
        $script:Stats['ExpiredRelationships'] = ($expiredRels | Measure-Object).Count
        $script:Stats['PendingRelationships'] = ($pendingRels | Measure-Object).Count

        Write-Status "Total: $($script:Stats['TotalRelationships']) | Active: $($script:Stats['ActiveRelationships']) | Expired: $($script:Stats['ExpiredRelationships']) | Pending: $($script:Stats['PendingRelationships'])"

        # --- Check 2: MLT Relationships ---
        Write-Host "`n--- Check 2: Microsoft-Led Transition (MLT) Relationships ---" -ForegroundColor White
        $mltRels = $activeRels | Where-Object { $_.DisplayName -match '^MLT_' }
        $mltCount = ($mltRels | Measure-Object).Count
        $script:Stats['MLTRelationships'] = $mltCount

        if ($mltCount -gt 0) {
            Write-StatusWarn "Found $mltCount MLT-created relationship(s) -- these were auto-migrated from DAP"
            foreach ($mlt in $mltRels) {
                $roleNames = ($mlt.AccessDetails.UnifiedRoles | ForEach-Object { Resolve-RoleName $_.RoleDefinitionId }) -join ", "
                Add-Finding -Category "MLT Migration" `
                    -Title "MLT relationship: $($mlt.DisplayName)" `
                    -Detail "Customer: $($mlt.Customer.DisplayName) ($($mlt.Customer.TenantId)). Roles: $roleNames. Expires: $($mlt.EndDateTime)" `
                    -Severity "High" `
                    -Recommendation "Replace this MLT-created relationship with a properly scoped GDAP template. MLT defaults include Privileged Role Administrator and Privileged Authentication Administrator as standing roles. Create a new GDAP relationship with SOW-aligned roles and enable PIM on all security groups."
            }
        }
        else {
            Write-StatusOk "No MLT-created relationships found"
        }

        # --- Check 3: Role Analysis ---
        Write-Host "`n--- Check 3: Role Privilege Analysis ---" -ForegroundColor White
        foreach ($rel in $activeRels) {
            $customerName = if ($rel.Customer.DisplayName) { $rel.Customer.DisplayName } else { $rel.Customer.TenantId }
            $roles = $rel.AccessDetails.UnifiedRoles
            $hasGlobalAdmin = $false
            $highPrivRoles = @()
            $allRoleNames = @()

            foreach ($role in $roles) {
                $roleId = $role.RoleDefinitionId
                $roleName = Resolve-RoleName $roleId
                $allRoleNames += $roleName

                if ($roleId -eq '62e90394-69f5-4237-9190-012177145e10') {
                    $hasGlobalAdmin = $true
                }
                if ($HighPrivilegeRoles.ContainsKey($roleId)) {
                    $highPrivRoles += $roleName
                }
            }

            if ($hasGlobalAdmin) {
                Write-StatusError "  $customerName -- GLOBAL ADMIN in standing GDAP!"
                Add-Finding -Category "Overprivilege" `
                    -Title "Global Administrator in GDAP: $customerName" `
                    -Detail "Relationship '$($rel.DisplayName)' includes Global Administrator as a standing GDAP role. Roles: $($allRoleNames -join ', ')" `
                    -Severity "Critical" `
                    -Recommendation "Remove Global Administrator from this GDAP relationship immediately. If GA is needed, create a separate GDAP relationship with 90-day duration (no auto-extend) and PIM approval-gated JIT. GA auto-extend is prohibited by Microsoft."
            }
            elseif ($highPrivRoles.Count -gt 0) {
                Write-StatusWarn "  $customerName -- $($highPrivRoles.Count) high-privilege role(s): $($highPrivRoles -join ', ')"
                Add-Finding -Category "Overprivilege" `
                    -Title "High-privilege roles in GDAP: $customerName" `
                    -Detail "Relationship '$($rel.DisplayName)' includes $($highPrivRoles.Count) high-privilege role(s): $($highPrivRoles -join ', '). All roles: $($allRoleNames -join ', ')" `
                    -Severity "High" `
                    -Recommendation "Ensure these roles are assigned to PIM-enabled security groups with approval workflows. High-privilege roles should never be standing access -- use Tier 3 PIM with human approver and <1 hour activation duration."
            }
            else {
                Write-StatusOk "  $customerName -- $($roles.Count) role(s), no high-privilege"
            }

            # Check expiration
            if ($rel.EndDateTime) {
                $daysUntilExpiry = ((Get-Date $rel.EndDateTime) - (Get-Date)).Days
                if ($daysUntilExpiry -le 30 -and $daysUntilExpiry -gt 0) {
                    Add-Finding -Category "Expiration" `
                        -Title "Relationship expiring soon: $customerName" `
                        -Detail "Relationship '$($rel.DisplayName)' expires in $daysUntilExpiry days ($($rel.EndDateTime)). Auto-extend: $($rel.AutoExtendDuration)" `
                        -Severity "Medium" `
                        -Recommendation "Review whether this relationship should be renewed. If auto-extend is PT0S (disabled), the relationship will expire and partner access will cease."
                }
                elseif ($daysUntilExpiry -le 0) {
                    # Already expired but in our active filter -- edge case
                }
            }

            # Check auto-extend on GA relationships
            if ($hasGlobalAdmin -and $rel.AutoExtendDuration -and $rel.AutoExtendDuration -ne 'PT0S') {
                Add-Finding -Category "Configuration" `
                    -Title "Auto-extend on Global Admin relationship: $customerName" `
                    -Detail "Relationship '$($rel.DisplayName)' has auto-extend enabled ($($rel.AutoExtendDuration)) AND includes Global Administrator. Microsoft prohibits auto-extend for GA -- this may be a data inconsistency." `
                    -Severity "Critical" `
                    -Recommendation "Verify this relationship's configuration in Partner Center. If auto-extend is genuinely enabled on a GA relationship, this is a security concern."
            }
        }

        # --- Check 4: Access Assignments (Security Groups) ---
        Write-Host "`n--- Check 4: Security Group Assignments ---" -ForegroundColor White
        foreach ($rel in $activeRels) {
            $customerName = if ($rel.Customer.DisplayName) { $rel.Customer.DisplayName } else { $rel.Customer.TenantId }
            try {
                $assignments = Get-MgTenantRelationshipDelegatedAdminRelationshipAccessAssignment -DelegatedAdminRelationshipId $rel.Id -All -ErrorAction Stop
                $activeAssignments = $assignments | Where-Object { $_.Status -eq 'active' }
                $assignmentCount = ($activeAssignments | Measure-Object).Count

                if ($assignmentCount -eq 0) {
                    Write-StatusWarn "  $customerName -- NO security group assignments (approved but unused)"
                    Add-Finding -Category "Configuration" `
                        -Title "No security group assignments: $customerName" `
                        -Detail "Relationship '$($rel.DisplayName)' is approved but has no active security group assignments. No partner users have actual access through this relationship." `
                        -Severity "Medium" `
                        -Recommendation "Either assign security groups to activate this relationship, or terminate it if no longer needed. Unused relationships are audit surface."
                }
                else {
                    Write-StatusOk "  $customerName -- $assignmentCount security group assignment(s)"
                }
            }
            catch {
                Write-Status "  $customerName -- Could not query access assignments: $_"
            }
        }

    }
    catch {
        Write-StatusError "Failed to query GDAP relationships: $_"
        Add-Finding -Category "Error" -Title "Cannot read GDAP relationships" `
            -Detail "Error: $_. Ensure the account has DelegatedAdminRelationship.Read.All permission." `
            -Severity "High" -Recommendation "Grant DelegatedAdminRelationship.Read.All via Graph API consent."
    }
}

# ---------------------------------------------------------------------------
# HTML Report Generation
# ---------------------------------------------------------------------------

function Generate-Report {
    param([string]$ReportPath)

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $criticalCount = ($script:Findings | Where-Object { $_.Severity -eq 'Critical' } | Measure-Object).Count
    $highCount = ($script:Findings | Where-Object { $_.Severity -eq 'High' } | Measure-Object).Count
    $mediumCount = ($script:Findings | Where-Object { $_.Severity -eq 'Medium' } | Measure-Object).Count
    $lowCount = ($script:Findings | Where-Object { $_.Severity -eq 'Low' } | Measure-Object).Count
    $infoCount = ($script:Findings | Where-Object { $_.Severity -eq 'Info' } | Measure-Object).Count

    $overallRisk = "LOW"
    $riskColor = "#3fb950"
    if ($criticalCount -gt 0) { $overallRisk = "CRITICAL"; $riskColor = "#da3633" }
    elseif ($highCount -gt 0) { $overallRisk = "HIGH"; $riskColor = "#f85149" }
    elseif ($mediumCount -gt 0) { $overallRisk = "MEDIUM"; $riskColor = "#d29922" }

    $statsHtml = ""
    foreach ($key in ($script:Stats.Keys | Sort-Object)) {
        $statsHtml += "<tr><td style='color:#e6edf3;font-weight:600;'>$key</td><td>$($script:Stats[$key])</td></tr>`n"
    }

    $findingsHtml = ""
    $severityOrder = @{ 'Critical' = 0; 'High' = 1; 'Medium' = 2; 'Low' = 3; 'Info' = 4 }
    $sortedFindings = $script:Findings | Sort-Object { $severityOrder[$_.Severity] }

    foreach ($f in $sortedFindings) {
        $sevColor = switch ($f.Severity) {
            'Critical' { '#da3633' }
            'High'     { '#f85149' }
            'Medium'   { '#d29922' }
            'Low'      { '#3fb950' }
            'Info'     { '#58a6ff' }
        }
        $findingsHtml += @"
<div style="background:#161b22;border:1px solid #30363d;border-left:4px solid $sevColor;border-radius:8px;padding:16px 20px;margin:12px 0;">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
    <strong style="color:#e6edf3;">$($f.Title)</strong>
    <span style="background:rgba(0,0,0,0.3);color:$sevColor;padding:2px 10px;border-radius:4px;font-size:0.75rem;font-weight:700;">$($f.Severity.ToUpper())</span>
  </div>
  <div style="color:#8b949e;font-size:0.9rem;margin-bottom:8px;"><strong>Category:</strong> $($f.Category)</div>
  <div style="color:#8b949e;font-size:0.9rem;margin-bottom:8px;">$($f.Detail)</div>
  <div style="color:#58a6ff;font-size:0.85rem;"><strong>Recommendation:</strong> $($f.Recommendation)</div>
</div>
"@
    }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>GDAP Security Audit Report -- $Mode Mode</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, 'Segoe UI', system-ui, sans-serif; background: #0d1117; color: #e6edf3; line-height: 1.6; }
  .container { max-width: 1100px; margin: 0 auto; padding: 0 24px 60px; }
  header { background: linear-gradient(135deg, #0d1b2a 0%, #1b263b 50%, #0d1117 100%); border-bottom: 3px solid $riskColor; padding: 40px 24px; text-align: center; }
  header h1 { font-size: 2rem; font-weight: 700; margin-bottom: 8px; }
  header .meta { color: #6e7681; font-size: 0.85rem; margin-top: 8px; }
  .risk-badge { display: inline-block; padding: 6px 20px; border-radius: 8px; font-size: 1.1rem; font-weight: 700; background: rgba(0,0,0,0.3); color: $riskColor; border: 2px solid $riskColor; margin-top: 12px; }
  .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; margin: 20px 0; }
  .stat-card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; text-align: center; }
  .stat-value { font-size: 1.5rem; font-weight: 700; }
  .stat-label { font-size: 0.8rem; color: #6e7681; }
  h2 { font-size: 1.3rem; font-weight: 600; margin: 32px 0 16px; padding-bottom: 8px; border-bottom: 2px solid #30363d; color: #58a6ff; }
  table { width: 100%; border-collapse: collapse; margin: 16px 0; font-size: 0.9rem; }
  th { background: #1c2129; text-align: left; padding: 8px 12px; border-bottom: 2px solid #30363d; font-weight: 600; color: #58a6ff; font-size: 0.8rem; text-transform: uppercase; }
  td { padding: 8px 12px; border-bottom: 1px solid #30363d; color: #8b949e; }
  footer { text-align: center; padding: 24px; color: #6e7681; font-size: 0.8rem; border-top: 1px solid #30363d; }
  @media print { body { background: #fff; color: #111; } header { background: #f0f0f0; } .stat-card { background: #f8f8f8; } th { background: #e8e8e8; color: #111; } td { color: #333; } }
</style>
</head>
<body>
<header>
  <h1>GDAP Security Audit Report</h1>
  <div style="color:#8b949e;">Mode: $Mode Tenant | Generated: $timestamp</div>
  <div class="meta">Tenant: $($script:Stats['TenantId']) | Account: $($script:Stats['Account'])</div>
  <div class="risk-badge">Overall Risk: $overallRisk</div>
</header>

<div class="container">

<h2>Finding Summary</h2>
<div class="stats-grid">
  <div class="stat-card"><div class="stat-value" style="color:#da3633;">$criticalCount</div><div class="stat-label">Critical</div></div>
  <div class="stat-card"><div class="stat-value" style="color:#f85149;">$highCount</div><div class="stat-label">High</div></div>
  <div class="stat-card"><div class="stat-value" style="color:#d29922;">$mediumCount</div><div class="stat-label">Medium</div></div>
  <div class="stat-card"><div class="stat-value" style="color:#3fb950;">$lowCount</div><div class="stat-label">Low</div></div>
  <div class="stat-card"><div class="stat-value" style="color:#58a6ff;">$infoCount</div><div class="stat-label">Info</div></div>
</div>

<h2>Audit Statistics</h2>
<table>
  <tr><th>Metric</th><th>Value</th></tr>
  $statsHtml
</table>

<h2>Detailed Findings</h2>
$findingsHtml

</div>

<footer>
  GDAP Security Audit Script v1.0.0 | Read-only assessment | Generated $timestamp
  <br>This report does not modify any configuration. Review all findings and recommendations with your security team.
</footer>
</body>
</html>
"@

    $html | Out-File -FilePath $ReportPath -Encoding UTF8
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

Write-Host "`n==========================================" -ForegroundColor White
Write-Host "  GDAP Security Audit Script v1.0.0" -ForegroundColor Cyan
Write-Host "  Mode: $Mode | Read-Only Assessment" -ForegroundColor Cyan
Write-Host "==========================================`n" -ForegroundColor White

# Ensure output directory
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

# Run the appropriate audit
if ($Mode -eq 'Customer') {
    Invoke-CustomerAudit
}
else {
    Invoke-PartnerAudit
}

# Generate report
$reportFile = Join-Path $OutputPath "GDAP-Audit-$Mode-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
Write-Host "`n--- Generating Report ---" -ForegroundColor White
Generate-Report -ReportPath $reportFile
Write-Host "`n  Report saved to: $reportFile" -ForegroundColor Green

# Summary
$critCount = ($script:Findings | Where-Object { $_.Severity -eq 'Critical' } | Measure-Object).Count
$highCount = ($script:Findings | Where-Object { $_.Severity -eq 'High' } | Measure-Object).Count
Write-Host "`n=========================================="
if ($critCount -gt 0) {
    Write-Host "  CRITICAL findings: $critCount" -ForegroundColor Red
}
if ($highCount -gt 0) {
    Write-Host "  HIGH findings: $highCount" -ForegroundColor Yellow
}
Write-Host "  Total findings: $($script:Findings.Count)" -ForegroundColor White
Write-Host "=========================================="

# Disconnect
try { Disconnect-MgGraph -ErrorAction SilentlyContinue } catch {}
