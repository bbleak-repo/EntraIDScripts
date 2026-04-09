# Quick Start Guide

## Prerequisites

- PowerShell 5.1 (Windows) or PowerShell 7+ (any platform)
- Network connectivity to target domain controllers on port 636 (LDAPS) or 389 (LDAP)
- A user account with read access to AD group membership (no admin needed)

## Step 1: Prepare Your CSV

Create a CSV file listing the groups to enumerate. Use either format:

**Option A -- Two columns:**
```csv
Domain,GroupName
CONTOSO,GG_IT_Admins
CONTOSO,GG_Finance_Users
FABRIKAM,USV_IT_Admins
FABRIKAM,USV_Finance_Users
```

**Option B -- Backslash format:**
```csv
Group
CONTOSO\GG_IT_Admins
CONTOSO\GG_Finance_Users
FABRIKAM\USV_IT_Admins
FABRIKAM\USV_Finance_Users
```

## Step 2: Basic Run (V1)

```powershell
# Simple enumeration with fuzzy cross-domain matching
.\Invoke-GroupEnumerator.ps1 -CsvPath .\groups.csv -FuzzyMatch
```

This will:
1. Enumerate all groups via LDAPS
2. Match groups across domains (GG_IT_Admins ~ USV_IT_Admins)
3. Generate an HTML report in `Output/`
4. Save a JSON cache in `Cache/`
5. Write a log file in `Logs/`

## Step 3: Cross-Forest Without CA Trust

If your workstation doesn't trust the remote forest's CA (common in cross-company scenarios):

```powershell
.\Invoke-GroupEnumerator.ps1 -CsvPath .\groups.csv -FuzzyMatch -AllowInsecure
```

This tries LDAPS first, then falls back to LDAP with Kerberos Sealing (encrypted session). The fallback is logged and noted in the report.

## Step 4: With Explicit Credentials

```powershell
$cred = Get-Credential -Message "Enter credentials for LDAP queries"
.\Invoke-GroupEnumerator.ps1 -CsvPath .\groups.csv -FuzzyMatch -AllowInsecure -Credential $cred
```

## Step 5: Migration Readiness Analysis (V2)

```powershell
.\Invoke-GroupEnumerator.ps1 -CsvPath .\groups.csv -FuzzyMatch -AllowInsecure `
    -AnalyzeGaps `          # Run gap analysis with user correlation
    -DetectStale `          # Flag disabled/stale accounts
    -ResolveNested `        # Flatten nested group memberships
    -StaleDays 90           # Accounts inactive > 90 days = stale
```

This produces:
- **Migration dashboard HTML** -- readiness percentages, progress bars, executive summary
- **Gap analysis CSV** -- actionable items for Change Requests (P1/P2/P3)
- **CR summary text** -- plain-text summary ready for ticket systems

## Step 6: Add Application Mapping (Optional)

Create an app mapping CSV:
```csv
AppName,SourceGroup,TargetGroup,Notes
CRM Application,GG_Sales_Users,USV_Sales_Users,IdP initiated
Helpdesk Portal,GG_ITSM_Team,USV_ITSM_Team,SP initiated
```

Then:
```powershell
.\Invoke-GroupEnumerator.ps1 -CsvPath .\groups.csv -FuzzyMatch -AllowInsecure `
    -AnalyzeGaps -DetectStale -AppMappingCsv .\app-mapping.csv
```

## Step 7: Regenerate Reports from Cache

```powershell
# Regenerate HTML from cached JSON (no LDAP needed)
.\Invoke-GroupEnumerator.ps1 -CsvPath .\groups.csv -FromCache `
    -CachePath .\Cache\groups-20260409-143000.json

# Change theme
.\Invoke-GroupEnumerator.ps1 -CsvPath .\groups.csv -FromCache `
    -CachePath .\Cache\groups-20260409-143000.json -Theme light
```

## Step 8: Email the Report (Optional)

Configure email in `Config/group-enum-config.json`:
```json
{
    "Email": {
        "Enabled": true,
        "SmtpServer": "smtp.company.com",
        "SmtpPort": 25,
        "From": "migration-tool@company.com",
        "To": ["team@company.com"],
        "SubjectPrefix": "[Migration Readiness]",
        "AttachReport": true
    }
}
```

Then add `-SendEmail`:
```powershell
.\Invoke-GroupEnumerator.ps1 -CsvPath .\groups.csv -FuzzyMatch -AllowInsecure `
    -AnalyzeGaps -DetectStale -SendEmail
```

## Configuration

All settings are in `Config/group-enum-config.json`. Key options:

| Setting | Default | Description |
|---------|---------|-------------|
| `FuzzyPrefixes` | GG_, USV_, SG_, DL_, GL_ | Prefixes stripped before fuzzy matching |
| `FuzzyMinScore` | 0.7 | Minimum Levenshtein similarity (0.0-1.0) |
| `SkipGroups` | Domain Users, etc. | Groups to skip automatically |
| `LargeGroupThreshold` | 5000 | Skip groups with more members than this |
| `AllowInsecure` | false | Enable LDAP 389 fallback (overridden by -AllowInsecure switch) |
| `LogLevel` | INFO | DEBUG for verbose, WARN for errors only |
| `StaleAccountDays` | 90 | Days since last logon to consider stale |
| `NestedGroupMaxDepth` | 10 | Max recursion depth for nested groups |

## Troubleshooting

**LDAPS connection fails:**
- Ensure port 636 is open to the target DC
- If cross-forest CA trust is missing, use `-AllowInsecure`
- Check `Logs/*.jsonl` for detailed connection tier information

**Large groups causing timeouts:**
- Increase `LdapTimeout` in config (default 120 seconds)
- Add large groups to `SkipGroups` list
- Lower `LargeGroupThreshold` to skip them automatically

**Debug logging:**
- Set `"LogLevel": "DEBUG"` in config to see every LDAP connection attempt and member query
