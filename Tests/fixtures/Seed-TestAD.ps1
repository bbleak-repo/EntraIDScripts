<#
.SYNOPSIS
    Populates AD with comprehensive test data for discovery and enumeration testing.

.DESCRIPTION
    Creates OU=_DiscoveryTestData containing a realistic corporate directory:
      - 20+ OUs (depth up to 4)
      - ~40 user accounts (active, disabled, never-logged-in, service accounts)
      - ~25 groups (Global/DomainLocal/Universal, Security/Distribution,
        nested memberships, cross-OU, one "large" group, one empty)
      - Computer objects for OU object-count testing
      - Contact objects for partial-entry/foreign-mail testing
      - Varied user attributes (title, department, manager, phone)

    Everything lives under OU=_DiscoveryTestData so teardown is one recursive
    delete via Remove-TestAD.ps1.

    Uses System.DirectoryServices.Protocols (LdapConnection) — no RSAT required.
    Requires write permissions (Domain Admin or delegated).

    Idempotent: checks existence before creating each object.

.PARAMETER Server
    DC hostname or domain FQDN.

.PARAMETER Credential
    Optional PSCredential. Defaults to current user.

.PARAMETER AllowInsecure
    Enable fallback tiers (cert bypass / 389 sign+seal).

.PARAMETER TestPassword
    Password for all test user accounts. Must meet domain complexity policy.

.EXAMPLE
    .\Seed-TestAD.ps1 -Server delusionalsecurity.review -AllowInsecure

.EXAMPLE
    $cred = Get-Credential DELUSIONAL\Admin
    .\Seed-TestAD.ps1 -Server delusionalsecurity.review -Credential $cred -AllowInsecure
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]  [string]$Server,
    [Parameter(Mandatory = $false)] [PSCredential]$Credential,
    [Parameter(Mandatory = $false)] [switch]$AllowInsecure,
    [Parameter(Mandatory = $false)] [string]$TestPassword = 'T3st!Pass#2026xQ'
)

$ErrorActionPreference = 'Stop'
$scriptRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

. (Join-Path $scriptRoot 'Modules\ADLdap.ps1')

Add-Type -AssemblyName System.DirectoryServices.Protocols

# =====================================================================
# Connect
# =====================================================================
$connParams = @{ Server = $Server; TimeoutSeconds = 120 }
if ($Credential)    { $connParams.Credential    = $Credential }
if ($AllowInsecure) { $connParams.AllowInsecure = $true }

$ctx = New-AdLdapConnection @connParams
$conn = $ctx.Connection
$baseDN = $ctx.BaseDN
$domain = $baseDN -replace 'DC=','' -replace ',','.'

Write-Host "Connected to $Server via $($ctx.Tier), baseDN=$baseDN" -ForegroundColor Green

$root = "OU=_DiscoveryTestData,$baseDN"

# =====================================================================
# Helpers
# =====================================================================
$script:Stats = @{ OUs = 0; Users = 0; Groups = 0; Computers = 0; Contacts = 0; Members = 0 }

function Test-Exists([string]$DN) {
    try {
        $r = New-Object System.DirectoryServices.Protocols.SearchRequest(
            $DN, '(objectClass=*)',
            [System.DirectoryServices.Protocols.SearchScope]::Base, @('dn'))
        return ($conn.SendRequest($r).Entries.Count -gt 0)
    } catch { return $false }
}

function Add-OU([string]$DN, [string]$Desc) {
    if (Test-Exists $DN) { Write-Host "  [skip] $DN" -ForegroundColor DarkGray; return }
    $a = @(
        (New-Object System.DirectoryServices.Protocols.DirectoryAttribute('objectClass', @('top','organizationalUnit')))
    )
    if ($Desc) { $a += (New-Object System.DirectoryServices.Protocols.DirectoryAttribute('description', $Desc)) }
    $null = $conn.SendRequest((New-Object System.DirectoryServices.Protocols.AddRequest($DN, $a)))
    Write-Host "  [new]  OU  $DN" -ForegroundColor Cyan
    $script:Stats.OUs++
}

function Add-User {
    param(
        [string]$DN, [string]$SAM, [string]$Display,
        [string]$Mail, [bool]$Enabled = $true,
        [string]$Title, [string]$Dept, [string]$Phone,
        [string]$ManagerDN
    )
    if (Test-Exists $DN) { Write-Host "  [skip] $SAM" -ForegroundColor DarkGray; return }
    $upn = "$SAM@$domain"
    $uac = if ($Enabled) { '512' } else { '514' }
    $attrs = [System.Collections.Generic.List[System.DirectoryServices.Protocols.DirectoryAttribute]]::new()
    $attrs.Add((New-Object System.DirectoryServices.Protocols.DirectoryAttribute('objectClass', @('top','person','organizationalPerson','user'))))
    $attrs.Add((New-Object System.DirectoryServices.Protocols.DirectoryAttribute('sAMAccountName', $SAM)))
    $attrs.Add((New-Object System.DirectoryServices.Protocols.DirectoryAttribute('userPrincipalName', $upn)))
    $attrs.Add((New-Object System.DirectoryServices.Protocols.DirectoryAttribute('displayName', $Display)))
    $attrs.Add((New-Object System.DirectoryServices.Protocols.DirectoryAttribute('userAccountControl', $uac)))
    if ($Mail)      { $attrs.Add((New-Object System.DirectoryServices.Protocols.DirectoryAttribute('mail', $Mail))) }
    if ($Title)     { $attrs.Add((New-Object System.DirectoryServices.Protocols.DirectoryAttribute('title', $Title))) }
    if ($Dept)      { $attrs.Add((New-Object System.DirectoryServices.Protocols.DirectoryAttribute('department', $Dept))) }
    if ($Phone)     { $attrs.Add((New-Object System.DirectoryServices.Protocols.DirectoryAttribute('telephoneNumber', $Phone))) }
    if ($ManagerDN) { $attrs.Add((New-Object System.DirectoryServices.Protocols.DirectoryAttribute('manager', $ManagerDN))) }

    $null = $conn.SendRequest((New-Object System.DirectoryServices.Protocols.AddRequest($DN, $attrs.ToArray())))

    # Set password
    $pwdBytes = [System.Text.Encoding]::Unicode.GetBytes('"' + $TestPassword + '"')
    $mod = New-Object System.DirectoryServices.Protocols.ModifyRequest($DN,
        [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace,
        'unicodePwd', $pwdBytes)
    try { $null = $conn.SendRequest($mod) }
    catch { Write-Host "    [warn] password set failed for $SAM" -ForegroundColor Yellow }

    Write-Host "  [new]  User $SAM (enabled=$Enabled)" -ForegroundColor Cyan
    $script:Stats.Users++
}

function Add-Group([string]$DN, [string]$SAM, [int]$Type, [string]$Desc) {
    if (Test-Exists $DN) { Write-Host "  [skip] $SAM" -ForegroundColor DarkGray; return }
    $a = @(
        (New-Object System.DirectoryServices.Protocols.DirectoryAttribute('objectClass', @('top','group')))
        (New-Object System.DirectoryServices.Protocols.DirectoryAttribute('sAMAccountName', $SAM))
        (New-Object System.DirectoryServices.Protocols.DirectoryAttribute('groupType', [string]$Type))
    )
    if ($Desc) { $a += (New-Object System.DirectoryServices.Protocols.DirectoryAttribute('description', $Desc)) }
    $null = $conn.SendRequest((New-Object System.DirectoryServices.Protocols.AddRequest($DN, $a)))
    Write-Host "  [new]  Group $SAM" -ForegroundColor Cyan
    $script:Stats.Groups++
}

function Add-Computer([string]$DN, [string]$SAM) {
    if (Test-Exists $DN) { Write-Host "  [skip] $SAM" -ForegroundColor DarkGray; return }
    $a = @(
        (New-Object System.DirectoryServices.Protocols.DirectoryAttribute('objectClass', @('top','person','organizationalPerson','user','computer')))
        (New-Object System.DirectoryServices.Protocols.DirectoryAttribute('sAMAccountName', "$SAM$"))
        (New-Object System.DirectoryServices.Protocols.DirectoryAttribute('userAccountControl', '4096'))
    )
    $null = $conn.SendRequest((New-Object System.DirectoryServices.Protocols.AddRequest($DN, $a)))
    Write-Host "  [new]  Computer $SAM" -ForegroundColor Cyan
    $script:Stats.Computers++
}

function Add-Contact([string]$DN, [string]$Display, [string]$Mail) {
    if (Test-Exists $DN) { Write-Host "  [skip] $Display" -ForegroundColor DarkGray; return }
    $a = @(
        (New-Object System.DirectoryServices.Protocols.DirectoryAttribute('objectClass', @('top','person','organizationalPerson','contact')))
        (New-Object System.DirectoryServices.Protocols.DirectoryAttribute('displayName', $Display))
        (New-Object System.DirectoryServices.Protocols.DirectoryAttribute('mail', $Mail))
    )
    $null = $conn.SendRequest((New-Object System.DirectoryServices.Protocols.AddRequest($DN, $a)))
    Write-Host "  [new]  Contact $Display" -ForegroundColor Cyan
    $script:Stats.Contacts++
}

function Add-Member([string]$GroupDN, [string]$MemberDN) {
    $mod = New-Object System.DirectoryServices.Protocols.ModifyRequest($GroupDN,
        [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Add,
        'member', $MemberDN)
    try {
        $null = $conn.SendRequest($mod)
        $script:Stats.Members++
    } catch {
        if ($_.Exception.Message -like '*already exists*' -or $_.Exception.Message -like '*ENTRY_EXISTS*' -or $_.Exception.Message -like '*00002083*') {
            # already a member — skip silently
        } else { throw }
    }
}

# Group type constants
$GS  = -2147483646   # Global Security
$DLS = -2147483644   # Domain Local Security
$US  = -2147483640   # Universal Security
$GD  = 2             # Global Distribution
$DLD = 4             # Domain Local Distribution
$UD  = 8             # Universal Distribution

try {
# =====================================================================
# OUs  (20 OUs, max depth 4)
# =====================================================================
Write-Host "`n=== Creating OUs ===" -ForegroundColor White
Add-OU $root                                        'Test data for AD Discovery toolkit'

# IT
Add-OU "OU=IT,$root"                                'Information Technology'
Add-OU "OU=Infrastructure,OU=IT,$root"              'IT Infrastructure'
Add-OU "OU=Servers,OU=Infrastructure,OU=IT,$root"   'Server team (depth 4)'
Add-OU "OU=Development,OU=IT,$root"                 'Software Development'
Add-OU "OU=Security,OU=IT,$root"                    'Information Security'
Add-OU "OU=Helpdesk,OU=IT,$root"                    'IT Helpdesk / Level 1 Support'

# HR
Add-OU "OU=HR,$root"                                'Human Resources'
Add-OU "OU=Recruitment,OU=HR,$root"                 'HR Recruitment'
Add-OU "OU=Benefits,OU=HR,$root"                    'HR Benefits Administration'

# Finance
Add-OU "OU=Finance,$root"                           'Finance Department'

# Engineering
Add-OU "OU=Engineering,$root"                       'Engineering Division'
Add-OU "OU=Mechanical,OU=Engineering,$root"         'Mechanical Engineering'
Add-OU "OU=Electrical,OU=Engineering,$root"         'Electrical Engineering'
Add-OU "OU=Software,OU=Engineering,$root"           'Software Engineering'

# Sales
Add-OU "OU=Sales,$root"                             'Sales Department'
Add-OU "OU=Regional,OU=Sales,$root"                 'Regional Sales Teams'
Add-OU "OU=West,OU=Regional,OU=Sales,$root"         'West Region (depth 4)'
Add-OU "OU=East,OU=Regional,OU=Sales,$root"         'East Region (depth 4)'

# Contractors
Add-OU "OU=Contractors,$root"                       'External Contractors'

# Service / Automation
Add-OU "OU=ServiceAccounts,$root"                   'Service and Automation Accounts'

# Shared resources
Add-OU "OU=SharedResources,$root"                   'Shared infrastructure'
Add-OU "OU=Printers,OU=SharedResources,$root"       'Printer queues'
Add-OU "OU=Kiosks,OU=SharedResources,$root"         'Kiosk workstations'

# Disabled accounts holding pen
Add-OU "OU=DisabledAccounts,$root"                  'Accounts pending deletion'

# =====================================================================
# Users  (~40 users)
# =====================================================================
Write-Host "`n=== Creating users ===" -ForegroundColor White

# IT - Infrastructure
$carolDN = "CN=Carol Sysadmin,OU=Infrastructure,OU=IT,$root"
$daveDN  = "CN=Dave Netadmin,OU=Infrastructure,OU=IT,$root"
Add-User -DN $carolDN  -SAM 'infra.carol' -Display 'Carol Sysadmin'     -Mail "carol@$domain" -Title 'Sr. Systems Administrator' -Dept 'IT' -Phone '555-0101'
Add-User -DN $daveDN   -SAM 'infra.dave'  -Display 'Dave Netadmin'      -Mail "dave@$domain"  -Title 'Network Administrator'     -Dept 'IT' -Phone '555-0102'
Add-User -DN "CN=Noah ServerEng,OU=Servers,OU=Infrastructure,OU=IT,$root" -SAM 'infra.noah' -Display 'Noah Server-Engineer' -Mail "noah@$domain" -Title 'Server Engineer' -Dept 'IT' -ManagerDN $carolDN

# IT - Development
$aliceDN = "CN=Alice Developer,OU=Development,OU=IT,$root"
Add-User -DN $aliceDN -SAM 'dev.alice' -Display 'Alice Developer' -Mail "alice@$domain" -Title 'Lead Developer'   -Dept 'IT'
Add-User -DN "CN=Bob Developer,OU=Development,OU=IT,$root"   -SAM 'dev.bob'   -Display 'Bob Developer'   -Mail "bob@$domain"   -Title 'Software Developer' -Dept 'IT' -ManagerDN $aliceDN
Add-User -DN "CN=Oscar DevOps,OU=Development,OU=IT,$root"    -SAM 'dev.oscar' -Display 'Oscar DevOps'    -Mail "oscar@$domain" -Title 'DevOps Engineer'     -Dept 'IT' -ManagerDN $aliceDN

# IT - Security
Add-User -DN "CN=Pam SecAnalyst,OU=Security,OU=IT,$root"  -SAM 'sec.pam'  -Display 'Pam Security-Analyst'  -Mail "pam@$domain"  -Title 'Security Analyst' -Dept 'IT Security'
Add-User -DN "CN=Quinn PenTest,OU=Security,OU=IT,$root"   -SAM 'sec.quinn' -Display 'Quinn Pen-Tester'     -Mail "quinn@$domain" -Title 'Penetration Tester' -Dept 'IT Security'

# IT - Helpdesk
Add-User -DN "CN=Ray Helpdesk,OU=Helpdesk,OU=IT,$root"    -SAM 'hd.ray'   -Display 'Ray Helpdesk'    -Mail "ray@$domain"  -Title 'Helpdesk Technician' -Dept 'IT Support'
Add-User -DN "CN=Sara Helpdesk,OU=Helpdesk,OU=IT,$root"   -SAM 'hd.sara'  -Display 'Sara Helpdesk'   -Mail "sara@$domain" -Title 'Helpdesk Technician' -Dept 'IT Support'

# HR
$eveDN = "CN=Eve HRDirector,OU=HR,$root"
Add-User -DN $eveDN -SAM 'hr.eve' -Display 'Eve HR-Director' -Mail "eve@$domain" -Title 'HR Director' -Dept 'Human Resources' -Phone '555-0201'
Add-User -DN "CN=Frank Recruiter,OU=Recruitment,OU=HR,$root" -SAM 'hr.frank'  -Display 'Frank Recruiter'  -Mail "frank@$domain"  -Title 'Recruiter'          -Dept 'Human Resources' -ManagerDN $eveDN
Add-User -DN "CN=Tina Benefits,OU=Benefits,OU=HR,$root"      -SAM 'hr.tina'   -Display 'Tina Benefits'    -Mail "tina@$domain"   -Title 'Benefits Specialist' -Dept 'Human Resources' -ManagerDN $eveDN

# Finance
Add-User -DN "CN=Grace Accountant,OU=Finance,$root"  -SAM 'fin.grace'  -Display 'Grace Accountant'  -Mail "grace@$domain"  -Title 'Senior Accountant' -Dept 'Finance' -Phone '555-0301'
Add-User -DN "CN=Hank Controller,OU=Finance,$root"   -SAM 'fin.hank'   -Display 'Hank Controller'   -Mail "hank@$domain"   -Title 'Financial Controller' -Dept 'Finance'
Add-User -DN "CN=Uma Auditor,OU=Finance,$root"       -SAM 'fin.uma'    -Display 'Uma Auditor'        -Mail "uma@$domain"    -Title 'Internal Auditor' -Dept 'Finance'

# Engineering
$irisDN = "CN=Iris MechLead,OU=Mechanical,OU=Engineering,$root"
Add-User -DN $irisDN -SAM 'eng.iris' -Display 'Iris Mech-Lead' -Mail "iris@$domain" -Title 'Mechanical Lead' -Dept 'Engineering'
Add-User -DN "CN=Jack ElecEng,OU=Electrical,OU=Engineering,$root"  -SAM 'eng.jack'  -Display 'Jack Electrical-Eng' -Mail "jack@$domain"  -Title 'Electrical Engineer' -Dept 'Engineering'
Add-User -DN "CN=Vera SoftEng,OU=Software,OU=Engineering,$root"   -SAM 'eng.vera'  -Display 'Vera Software-Eng'   -Mail "vera@$domain"  -Title 'Software Engineer'   -Dept 'Engineering'
Add-User -DN "CN=Walt MechEng,OU=Mechanical,OU=Engineering,$root" -SAM 'eng.walt'  -Display 'Walt Mechanical-Eng'  -Mail "walt@$domain"  -Title 'Mechanical Engineer' -Dept 'Engineering' -ManagerDN $irisDN
Add-User -DN "CN=Xena TestEng,OU=Software,OU=Engineering,$root"   -SAM 'eng.xena'  -Display 'Xena QA-Engineer'    -Mail "xena@$domain"  -Title 'QA Engineer'         -Dept 'Engineering'

# Sales
Add-User -DN "CN=Mike SalesDir,OU=Sales,$root"                    -SAM 'sales.mike' -Display 'Mike Sales-Director' -Mail "mike@$domain" -Title 'Sales Director' -Dept 'Sales' -Phone '555-0401'
Add-User -DN "CN=Yuri WestRep,OU=West,OU=Regional,OU=Sales,$root" -SAM 'sales.yuri' -Display 'Yuri West-Rep'       -Mail "yuri@$domain" -Title 'Account Executive' -Dept 'Sales - West'
Add-User -DN "CN=Zoe EastRep,OU=East,OU=Regional,OU=Sales,$root"  -SAM 'sales.zoe'  -Display 'Zoe East-Rep'        -Mail "zoe@$domain"  -Title 'Account Executive' -Dept 'Sales - East'
Add-User -DN "CN=Amy WestRep2,OU=West,OU=Regional,OU=Sales,$root" -SAM 'sales.amy'  -Display 'Amy West-Rep'        -Mail "amy@$domain"  -Title 'Account Executive' -Dept 'Sales - West'
Add-User -DN "CN=Ben EastRep2,OU=East,OU=Regional,OU=Sales,$root" -SAM 'sales.ben'  -Display 'Ben East-Rep'        -Mail "ben@$domain"  -Title 'Account Executive' -Dept 'Sales - East'

# Contractors (active + disabled + never-logged-in for stale testing)
Add-User -DN "CN=Karl Contractor,OU=Contractors,$root"         -SAM 'ext.karl'  -Display 'Karl Contractor (EXT)'  -Mail 'karl@external.test' -Title 'Contractor' -Dept 'External'
Add-User -DN "CN=Luna ExContractor,OU=Contractors,$root"       -SAM 'ext.luna'  -Display 'Luna Ex-Contractor (EXT)' -Enabled $false -Title 'Former Contractor' -Dept 'External'
Add-User -DN "CN=Max Temp,OU=Contractors,$root"                -SAM 'ext.max'   -Display 'Max Temp (EXT)'           -Mail 'max@external.test' -Title 'Temp Worker' -Dept 'External'

# Service accounts
Add-User -DN "CN=svc_backup,OU=ServiceAccounts,$root"          -SAM 'svc_backup'      -Display 'Backup Service'       -Title 'Service Account'
Add-User -DN "CN=svc_monitoring,OU=ServiceAccounts,$root"      -SAM 'svc_monitoring'   -Display 'Monitoring Service'   -Title 'Service Account'
Add-User -DN "CN=svc_deploy,OU=ServiceAccounts,$root"          -SAM 'svc_deploy'       -Display 'Deployment Pipeline'  -Title 'Service Account'
Add-User -DN "CN=svc_scanner,OU=ServiceAccounts,$root"         -SAM 'svc_scanner'      -Display 'Vulnerability Scanner' -Title 'Service Account'

# Disabled / holding pen
Add-User -DN "CN=Old Employee1,OU=DisabledAccounts,$root"      -SAM 'disabled.emp1' -Display 'Former Employee One'   -Enabled $false
Add-User -DN "CN=Old Employee2,OU=DisabledAccounts,$root"      -SAM 'disabled.emp2' -Display 'Former Employee Two'   -Enabled $false
Add-User -DN "CN=Old Employee3,OU=DisabledAccounts,$root"      -SAM 'disabled.emp3' -Display 'Former Employee Three' -Enabled $false

# =====================================================================
# Computer objects
# =====================================================================
Write-Host "`n=== Creating computers ===" -ForegroundColor White
Add-Computer "CN=PRINT-01,OU=Printers,OU=SharedResources,$root"  'PRINT-01'
Add-Computer "CN=PRINT-02,OU=Printers,OU=SharedResources,$root"  'PRINT-02'
Add-Computer "CN=KIOSK-LOBBY,OU=Kiosks,OU=SharedResources,$root" 'KIOSK-LOBBY'
Add-Computer "CN=KIOSK-CAFE,OU=Kiosks,OU=SharedResources,$root"  'KIOSK-CAFE'
Add-Computer "CN=SRV-BUILD01,OU=Servers,OU=Infrastructure,OU=IT,$root" 'SRV-BUILD01'
Add-Computer "CN=SRV-MONITOR,OU=Servers,OU=Infrastructure,OU=IT,$root" 'SRV-MONITOR'

# =====================================================================
# Contacts (foreign mail, exercises partial-entry path in Group-Enumerator)
# =====================================================================
Write-Host "`n=== Creating contacts ===" -ForegroundColor White
Add-Contact "CN=Vendor Support,OU=Contractors,$root"      'Vendor Support Team'     'support@vendor.example.com'
Add-Contact "CN=External Auditor,OU=Finance,$root"        'External Auditor Firm'   'audit@kpmg.example.com'
Add-Contact "CN=Partner Engineering,OU=Engineering,$root"  'Partner Eng Contact'     'eng@partner.example.com'

# =====================================================================
# Groups  (~25 groups, varied types)
# =====================================================================
Write-Host "`n=== Creating groups ===" -ForegroundColor White

# IT Security groups
Add-Group "CN=GG_IT_Admins,OU=IT,$root"             'GG_IT_Admins'             $GS  'IT Infrastructure administrators'
Add-Group "CN=GG_IT_Developers,OU=IT,$root"          'GG_IT_Developers'         $GS  'Software developers'
Add-Group "CN=GG_IT_Security,OU=IT,$root"            'GG_IT_Security'           $GS  'Information Security team'
Add-Group "CN=GG_IT_Helpdesk,OU=IT,$root"            'GG_IT_Helpdesk'           $GS  'Helpdesk technicians'
Add-Group "CN=DL_IT_ReadOnly,OU=IT,$root"            'DL_IT_ReadOnly'           $DLS 'Read-only access to IT resources (nested groups)'
Add-Group "CN=DL_IT_ServerAdmins,OU=IT,$root"        'DL_IT_ServerAdmins'       $DLS 'Local admin on member servers'

# HR
Add-Group "CN=GG_HR_Staff,OU=HR,$root"               'GG_HR_Staff'              $GS  'All HR staff'
Add-Group "CN=DL_HR_Confidential,OU=HR,$root"        'DL_HR_Confidential'       $DLS 'Access to confidential HR data'

# Finance
Add-Group "CN=GG_Finance_Analysts,OU=Finance,$root"  'GG_Finance_Analysts'      $GS  'Finance analysts and controllers'
Add-Group "CN=DL_Finance_Reports,OU=Finance,$root"   'DL_Finance_Reports'       $DLS 'Access to financial reporting (nested)'

# Engineering
Add-Group "CN=GG_Engineering_All,OU=Engineering,$root"       'GG_Engineering_All'       $GS  'All engineers'
Add-Group "CN=USV_Engineering_Access,OU=Engineering,$root"   'USV_Engineering_Access'   $US  'Cross-forest engineering resource access'

# Sales
Add-Group "CN=GG_Sales_Team,OU=Sales,$root"          'GG_Sales_Team'            $GS  'All sales staff'
Add-Group "CN=GG_Sales_West,OU=Sales,$root"          'GG_Sales_West'            $GS  'West region sales'
Add-Group "CN=GG_Sales_East,OU=Sales,$root"          'GG_Sales_East'            $GS  'East region sales'

# Distribution lists
Add-Group "CN=DL_AllStaff_Announce,OU=IT,$root"      'DL_AllStaff_Announce'     $GD  'Company-wide announcements (distribution)'
Add-Group "CN=DL_Engineering_Chat,OU=Engineering,$root" 'DL_Engineering_Chat'   $UD  'Engineering discussion list (universal distribution)'
Add-Group "CN=DL_Sales_Updates,OU=Sales,$root"       'DL_Sales_Updates'         $GD  'Sales pipeline updates'

# Cross-cutting groups at root test OU
Add-Group "CN=GG_AllEmployees,$root"                 'GG_AllEmployees'          $GS  'All active employees (nested dept groups)'
Add-Group "CN=DL_VPN_Access,$root"                   'DL_VPN_Access'            $DLS 'VPN access (nested: IT Admins + Engineering)'
Add-Group "CN=USV_CrossForest_Readers,$root"         'USV_CrossForest_Readers'  $US  'Cross-forest read access (placeholder, empty)'
Add-Group "CN=GG_ProjectAlpha,$root"                 'GG_ProjectAlpha'          $GS  'Cross-department project team'
Add-Group "CN=DL_PrinterAccess,$root"                'DL_PrinterAccess'         $DLS 'Printer access for all employees'

# Group with ONLY nested groups (no direct users) — tests nested-only resolution
Add-Group "CN=DL_AllITAccess,$root"                  'DL_AllITAccess'           $DLS 'All IT access via nested groups only'

# Empty group — edge case
Add-Group "CN=GG_FutureProject,$root"                'GG_FutureProject'         $GS  'Placeholder for upcoming project (intentionally empty)'

# =====================================================================
# Group Memberships  (50+ links)
# =====================================================================
Write-Host "`n=== Adding group memberships ===" -ForegroundColor White

# IT Admins
Add-Member "CN=GG_IT_Admins,OU=IT,$root"        "CN=Carol Sysadmin,OU=Infrastructure,OU=IT,$root"
Add-Member "CN=GG_IT_Admins,OU=IT,$root"        "CN=Dave Netadmin,OU=Infrastructure,OU=IT,$root"
Add-Member "CN=GG_IT_Admins,OU=IT,$root"        "CN=Noah ServerEng,OU=Servers,OU=Infrastructure,OU=IT,$root"

# IT Developers
Add-Member "CN=GG_IT_Developers,OU=IT,$root"    "CN=Alice Developer,OU=Development,OU=IT,$root"
Add-Member "CN=GG_IT_Developers,OU=IT,$root"    "CN=Bob Developer,OU=Development,OU=IT,$root"
Add-Member "CN=GG_IT_Developers,OU=IT,$root"    "CN=Oscar DevOps,OU=Development,OU=IT,$root"

# IT Security
Add-Member "CN=GG_IT_Security,OU=IT,$root"      "CN=Pam SecAnalyst,OU=Security,OU=IT,$root"
Add-Member "CN=GG_IT_Security,OU=IT,$root"      "CN=Quinn PenTest,OU=Security,OU=IT,$root"

# IT Helpdesk
Add-Member "CN=GG_IT_Helpdesk,OU=IT,$root"      "CN=Ray Helpdesk,OU=Helpdesk,OU=IT,$root"
Add-Member "CN=GG_IT_Helpdesk,OU=IT,$root"      "CN=Sara Helpdesk,OU=Helpdesk,OU=IT,$root"

# DL_IT_ReadOnly = nested: all IT groups
Add-Member "CN=DL_IT_ReadOnly,OU=IT,$root"      "CN=GG_IT_Admins,OU=IT,$root"
Add-Member "CN=DL_IT_ReadOnly,OU=IT,$root"      "CN=GG_IT_Developers,OU=IT,$root"
Add-Member "CN=DL_IT_ReadOnly,OU=IT,$root"      "CN=GG_IT_Security,OU=IT,$root"
Add-Member "CN=DL_IT_ReadOnly,OU=IT,$root"      "CN=GG_IT_Helpdesk,OU=IT,$root"

# DL_IT_ServerAdmins = IT Admins nested
Add-Member "CN=DL_IT_ServerAdmins,OU=IT,$root"  "CN=GG_IT_Admins,OU=IT,$root"

# HR Staff
Add-Member "CN=GG_HR_Staff,OU=HR,$root"         "CN=Eve HRDirector,OU=HR,$root"
Add-Member "CN=GG_HR_Staff,OU=HR,$root"         "CN=Frank Recruiter,OU=Recruitment,OU=HR,$root"
Add-Member "CN=GG_HR_Staff,OU=HR,$root"         "CN=Tina Benefits,OU=Benefits,OU=HR,$root"
Add-Member "CN=DL_HR_Confidential,OU=HR,$root"  "CN=GG_HR_Staff,OU=HR,$root"

# Finance
Add-Member "CN=GG_Finance_Analysts,OU=Finance,$root" "CN=Grace Accountant,OU=Finance,$root"
Add-Member "CN=GG_Finance_Analysts,OU=Finance,$root" "CN=Hank Controller,OU=Finance,$root"
Add-Member "CN=GG_Finance_Analysts,OU=Finance,$root" "CN=Uma Auditor,OU=Finance,$root"
Add-Member "CN=DL_Finance_Reports,OU=Finance,$root"  "CN=GG_Finance_Analysts,OU=Finance,$root"
# Add the contact to the finance group (tests partial-entry path)
Add-Member "CN=GG_Finance_Analysts,OU=Finance,$root" "CN=External Auditor,OU=Finance,$root"

# Engineering
Add-Member "CN=GG_Engineering_All,OU=Engineering,$root" "CN=Iris MechLead,OU=Mechanical,OU=Engineering,$root"
Add-Member "CN=GG_Engineering_All,OU=Engineering,$root" "CN=Jack ElecEng,OU=Electrical,OU=Engineering,$root"
Add-Member "CN=GG_Engineering_All,OU=Engineering,$root" "CN=Vera SoftEng,OU=Software,OU=Engineering,$root"
Add-Member "CN=GG_Engineering_All,OU=Engineering,$root" "CN=Walt MechEng,OU=Mechanical,OU=Engineering,$root"
Add-Member "CN=GG_Engineering_All,OU=Engineering,$root" "CN=Xena TestEng,OU=Software,OU=Engineering,$root"
Add-Member "CN=USV_Engineering_Access,OU=Engineering,$root" "CN=GG_Engineering_All,OU=Engineering,$root"
# Add partner contact to engineering (cross-org collaboration)
Add-Member "CN=GG_Engineering_All,OU=Engineering,$root" "CN=Partner Engineering,OU=Engineering,$root"

# Sales
Add-Member "CN=GG_Sales_West,OU=Sales,$root"    "CN=Yuri WestRep,OU=West,OU=Regional,OU=Sales,$root"
Add-Member "CN=GG_Sales_West,OU=Sales,$root"    "CN=Amy WestRep2,OU=West,OU=Regional,OU=Sales,$root"
Add-Member "CN=GG_Sales_East,OU=Sales,$root"    "CN=Zoe EastRep,OU=East,OU=Regional,OU=Sales,$root"
Add-Member "CN=GG_Sales_East,OU=Sales,$root"    "CN=Ben EastRep2,OU=East,OU=Regional,OU=Sales,$root"
Add-Member "CN=GG_Sales_Team,OU=Sales,$root"    "CN=Mike SalesDir,OU=Sales,$root"
Add-Member "CN=GG_Sales_Team,OU=Sales,$root"    "CN=GG_Sales_West,OU=Sales,$root"
Add-Member "CN=GG_Sales_Team,OU=Sales,$root"    "CN=GG_Sales_East,OU=Sales,$root"

# AllEmployees = all dept groups nested + active contractors
Add-Member "CN=GG_AllEmployees,$root"  "CN=GG_IT_Admins,OU=IT,$root"
Add-Member "CN=GG_AllEmployees,$root"  "CN=GG_IT_Developers,OU=IT,$root"
Add-Member "CN=GG_AllEmployees,$root"  "CN=GG_IT_Security,OU=IT,$root"
Add-Member "CN=GG_AllEmployees,$root"  "CN=GG_IT_Helpdesk,OU=IT,$root"
Add-Member "CN=GG_AllEmployees,$root"  "CN=GG_HR_Staff,OU=HR,$root"
Add-Member "CN=GG_AllEmployees,$root"  "CN=GG_Finance_Analysts,OU=Finance,$root"
Add-Member "CN=GG_AllEmployees,$root"  "CN=GG_Engineering_All,OU=Engineering,$root"
Add-Member "CN=GG_AllEmployees,$root"  "CN=GG_Sales_Team,OU=Sales,$root"
Add-Member "CN=GG_AllEmployees,$root"  "CN=Karl Contractor,OU=Contractors,$root"
Add-Member "CN=GG_AllEmployees,$root"  "CN=Max Temp,OU=Contractors,$root"

# VPN Access = IT Admins + Engineering (nested groups)
Add-Member "CN=DL_VPN_Access,$root"    "CN=GG_IT_Admins,OU=IT,$root"
Add-Member "CN=DL_VPN_Access,$root"    "CN=GG_Engineering_All,OU=Engineering,$root"
Add-Member "CN=DL_VPN_Access,$root"    "CN=GG_IT_Security,OU=IT,$root"

# DL_AllITAccess = nested groups ONLY (no direct users)
Add-Member "CN=DL_AllITAccess,$root"   "CN=DL_IT_ReadOnly,OU=IT,$root"
Add-Member "CN=DL_AllITAccess,$root"   "CN=DL_IT_ServerAdmins,OU=IT,$root"

# PrinterAccess = AllEmployees nested
Add-Member "CN=DL_PrinterAccess,$root" "CN=GG_AllEmployees,$root"

# ProjectAlpha = cross-department
Add-Member "CN=GG_ProjectAlpha,$root"  "CN=Alice Developer,OU=Development,OU=IT,$root"
Add-Member "CN=GG_ProjectAlpha,$root"  "CN=Vera SoftEng,OU=Software,OU=Engineering,$root"
Add-Member "CN=GG_ProjectAlpha,$root"  "CN=Grace Accountant,OU=Finance,$root"
Add-Member "CN=GG_ProjectAlpha,$root"  "CN=Mike SalesDir,OU=Sales,$root"

# Distribution lists
Add-Member "CN=DL_AllStaff_Announce,OU=IT,$root"       "CN=GG_AllEmployees,$root"
Add-Member "CN=DL_Engineering_Chat,OU=Engineering,$root" "CN=GG_Engineering_All,OU=Engineering,$root"
Add-Member "CN=DL_Engineering_Chat,OU=Engineering,$root" "CN=GG_IT_Developers,OU=IT,$root"
Add-Member "CN=DL_Sales_Updates,OU=Sales,$root"        "CN=GG_Sales_Team,OU=Sales,$root"

# Vendor contact in a group (tests contact-in-group path)
Add-Member "CN=DL_IT_ReadOnly,OU=IT,$root"  "CN=Vendor Support,OU=Contractors,$root"

# =====================================================================
# Summary
# =====================================================================
Write-Host "`n$('=' * 50)" -ForegroundColor Green
Write-Host "Seed complete." -ForegroundColor Green
Write-Host "  Root OU    : $root" -ForegroundColor White
Write-Host "  OUs        : $($script:Stats.OUs)" -ForegroundColor White
Write-Host "  Users      : $($script:Stats.Users)" -ForegroundColor White
Write-Host "  Groups     : $($script:Stats.Groups)" -ForegroundColor White
Write-Host "  Computers  : $($script:Stats.Computers)" -ForegroundColor White
Write-Host "  Contacts   : $($script:Stats.Contacts)" -ForegroundColor White
Write-Host "  Memberships: $($script:Stats.Members)" -ForegroundColor White
Write-Host "`nTeardown:" -ForegroundColor Yellow
Write-Host "  .\Remove-TestAD.ps1 -Server $Server $(if ($AllowInsecure) {'-AllowInsecure'})" -ForegroundColor Yellow
Write-Host "$('=' * 50)" -ForegroundColor Green

} catch {
    Write-Host "`nERROR: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor DarkRed
    exit 1
} finally {
    Close-AdLdapConnection $ctx
}
