# Quick Start Guide

## Prerequisites

- PowerShell 5.1 (Windows) or PowerShell 7+ (any platform)
- Network connectivity to target domain controllers on port 636 (LDAPS); 389 is only used by fallback tiers
- A user account with read access to AD group membership (no admin needed)
- Works against DCs enforcing LDAP Channel Binding and LDAP Signing -- no workaround required

## Getting help

Run the script with no arguments or with `-Help` to see a usage summary with examples:

```powershell
.\Invoke-GroupEnumerator.ps1
.\Invoke-GroupEnumerator.ps1 -Help
```

For full parameter documentation:

```powershell
Get-Help .\Invoke-GroupEnumerator.ps1 -Detailed
```

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

## Step 2: Basic Single-Domain Inventory (V1)

For a simple "show me who's in these groups" report against one domain, no switches are needed:

```powershell
.\Invoke-GroupEnumerator.ps1 -CsvPath .\groups.csv
```

This will:
1. Enumerate all groups via verified LDAPS (Tier 1) with integrated Kerberos auth
2. Generate a V1 HTML report in `Output/` (search, sort, copy-as-TSV)
3. Save a JSON cache in `Cache/`
4. Write a structured log in `Logs/`

Add `-ResolveNested -DetectStale` for a deeper inventory view that flattens nested memberships and flags inactive accounts:

```powershell
.\Invoke-GroupEnumerator.ps1 -CsvPath .\groups.csv -ResolveNested -DetectStale
```

## Step 3: Cross-Domain Matching (V1 + FuzzyMatch)

When your CSV includes groups from two or more domains, add `-FuzzyMatch` to pair them by normalized name (e.g. `GG_IT_Admins` ~ `USV_IT_Admins`):

```powershell
.\Invoke-GroupEnumerator.ps1 -CsvPath .\groups.csv -FuzzyMatch
```

## Step 4: Cross-Forest Without CA Trust (Fallback Tiers)

If your workstation can't validate the remote DC's TLS certificate (common in cross-forest or lab scenarios), enable the fallback tiers with `-AllowInsecure`:

```powershell
.\Invoke-GroupEnumerator.ps1 -CsvPath .\groups.csv -FuzzyMatch -AllowInsecure
```

Tier order is:
1. LDAPS 636 with strict cert verification (always tried first)
2. LDAPS 636 with cert verification bypassed -- channel still TLS-encrypted, you're just trusting the server identity on faith
3. LDAP 389 with SASL sign+seal -- Kerberos-wrapped session over unencrypted 389

Whichever tier actually connects is logged as a structured `LdapConnect` event and surfaced in the HTML report when it's anything other than Tier 1.

## Step 5: With Explicit Credentials

```powershell
$cred = Get-Credential -Message "Enter credentials for LDAP queries"
.\Invoke-GroupEnumerator.ps1 -CsvPath .\groups.csv -FuzzyMatch -AllowInsecure -Credential $cred
```

## Step 6: Migration Readiness Analysis (V2)

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

## Step 7: Add Application Mapping (Optional)

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

## Step 8: Regenerate Reports from Cache

```powershell
# Regenerate HTML from cached JSON (no LDAP needed)
.\Invoke-GroupEnumerator.ps1 -CsvPath .\groups.csv -FromCache `
    -CachePath .\Cache\groups-20260409-143000.json

# Change theme
.\Invoke-GroupEnumerator.ps1 -CsvPath .\groups.csv -FromCache `
    -CachePath .\Cache\groups-20260409-143000.json -Theme light
```

## Step 9: Email the Report (Optional)

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

**LDAPS (Tier 1) connection fails with cert errors:**
- Ensure port 636 is reachable to the target DC
- Use `-AllowInsecure` to enable Tier 2 (cert bypass) and Tier 3 (389 sign+seal)
- Check `Logs/*.jsonl` for `LdapConnect` events showing the actual tier used

**All tiers fail with "The user name or password is incorrect":**
- This is LDAP error 49; common causes are Channel Binding / Signing mismatches or a logon session that isn't actually authenticated to the target domain
- `LdapConnection` (the modern stack this tool uses) handles Channel Binding correctly, so this usually points at a credential issue
- Try `-Credential (Get-Credential)` to bind explicitly instead of relying on integrated auth

**Large groups causing timeouts:**
- Increase `LdapTimeout` in config (default 120 seconds)
- Add large groups to `SkipGroups` list
- Lower `LargeGroupThreshold` to skip them automatically

**Debug logging:**
- Set `"LogLevel": "DEBUG"` in config to see every LDAP connection attempt and member query
- Each `LdapConnect` log entry includes `tier`, `port`, `baseDN`, and `pooled` fields
