# Active Directory Discovery & Comparison Tool

Enterprise-grade Active Directory discovery and comparison toolkit designed for environments without RSAT or administrative privileges. Built with cross-platform support for testing and development.

## Features

- **Comprehensive Discovery**: Forest/domain info, schema, OU structure, sites/subnets, trusts, domain controllers, groups, and DNS zones
- **Two-Domain Comparison**: Deep delta analysis with detailed difference reporting (added, removed, changed, unchanged)
- **Multiple Output Formats**: Professional HTML reports (dark mode), structured JSON, and category-specific CSV exports
- **Modern LDAP Stack**: Built on `System.DirectoryServices.Protocols.LdapConnection` via the shared `ADLdap.ps1` helper. Works against DCs enforcing LDAP Channel Binding and LDAP Signing -- the hardened modern default.
- **Tiered Connectivity**: LDAPS-Verified (636) by default; with `-AllowInsecure` falls through LDAPS cert-bypass then LDAP 389 Kerberos sign+seal. Tier in use is logged.
- **Per-Run Connection Pool**: One `LdapConnection` per server, reused across every discovery module in a single invocation.
- **No RSAT Required**: Direct LDAP queries, no external dependencies
- **No Admin Rights**: Read-only operations suitable for standard user accounts
- **Cross-Platform Testing**: Mock data provider for macOS/Linux development and testing (`-UseMock`)
- **Modular Architecture**: Easy to extend with new discovery modules
- **Production Ready**: Comprehensive error handling, resource cleanup, and progress reporting

## Requirements

### Windows (Production)
- PowerShell 5.1 or later
- Windows 11 (tested) or Windows Server 2019+
- Network access to domain controllers on port 636 (LDAPS); 389 only if fallback tiers are enabled
- Standard domain user credentials (no admin rights required)
- Works against DCs with LDAP Channel Binding / Signing enforced

### macOS/Linux (Testing)
- PowerShell 7+ (Core)
- Mock mode only (`-UseMock` flag)
- No Active Directory connection required

## Quick Start

### Show usage summary

```powershell
# Bare invocation prints usage with grouped switches and examples, then exits
.\AD-Discovery.ps1
.\AD-Discovery.ps1 -Help

# Full parameter docs
Get-Help .\AD-Discovery.ps1 -Detailed
```

### Single Domain Discovery (Windows)

```powershell
# Simplest — integrated auth, verified LDAPS only
.\AD-Discovery.ps1 -Server dc01.contoso.com

# With fallback tiers (cross-forest, lab environments, or rotated certs)
.\AD-Discovery.ps1 -Server dc01.contoso.com -AllowInsecure

# With explicit credentials
$cred = Get-Credential
.\AD-Discovery.ps1 -Server dc01.contoso.com -Credential $cred -AllowInsecure

# Skip slow / unwanted modules
.\AD-Discovery.ps1 -Server dc01.contoso.com -SkipModules Schema,DNS

# Custom output location and format selection
.\AD-Discovery.ps1 -Server dc01.contoso.com -Format HTML,JSON -OutputPath "C:\Reports"
```

### Two-Domain Comparison (Windows)

```powershell
# Compare production and development domains
.\AD-Discovery.ps1 -Server dc01-prod.contoso.com -CompareServer dc01-dev.contoso.com -AllowInsecure

# With separate credentials for each domain
$prodCred = Get-Credential -Message "Production Domain"
$devCred  = Get-Credential -Message "Development Domain"
.\AD-Discovery.ps1 -Server dc01-prod.contoso.com -Credential $prodCred `
                   -CompareServer dc01-dev.contoso.com -CompareCredential $devCred `
                   -AllowInsecure
```

### Mock Mode Testing (macOS/Linux)

```powershell
# Test with mock data on macOS — no AD required
pwsh ./AD-Discovery.ps1 -UseMock -Server mock-prod.local -CompareServer mock-dev.local

# Mock domains available:
# - mock-prod.local: Windows Server 2022, 3 DCs, 15 OUs, complex structure
# - mock-dev.local:  Windows Server 2019, 2 DCs, 12 OUs, simplified structure
```

### Seed Test Data (Populate a Real AD for Testing)

If your AD domain is minimal (fresh install, few objects), use the seed script
to populate realistic test data. Requires Domain Admin or delegated write access.

```powershell
# Create OU=_DiscoveryTestData with 24 OUs, 36 users, 25 groups, 6 computers,
# 3 contacts, and 60+ membership links
$adminCred = Get-Credential DOMAIN\Admin
.\Tests\fixtures\Seed-TestAD.ps1 -Server dc01.contoso.com -Credential $adminCred -AllowInsecure

# Now run discovery against the populated domain
.\AD-Discovery.ps1 -Server dc01.contoso.com -AllowInsecure

# Teardown — single recursive delete of the entire _DiscoveryTestData OU
.\Tests\fixtures\Remove-TestAD.ps1 -Server dc01.contoso.com -Credential $adminCred -AllowInsecure
```

Both scripts are idempotent (seed skips existing objects, teardown is a no-op
if the OU doesn't exist) and use the same `ADLdap.ps1` LdapConnection stack.

## Detailed Usage

### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-Server` | String | Yes* | Primary domain controller FQDN or domain name |
| `-CompareServer` | String | No | Second domain for comparison |
| `-UseMock` | Switch | No | Use mock data provider (required on non-Windows) |
| `-AllowInsecure` | Switch | No | Enable fallback tiers when verified LDAPS fails (cert bypass, then 389 sign+seal) |
| `-Format` | String[] | No | Output formats: HTML, JSON, CSV (default from config) |
| `-SkipModules` | String[] | No | Modules to skip (e.g., DNS, Groups) |
| `-Credential` | PSCredential | No | Credentials for primary domain (default: current user via Kerberos) |
| `-CompareCredential` | PSCredential | No | Credentials for comparison domain |
| `-OutputPath` | String | No | Output directory (default: ./Output) |
| `-Help` | Switch | No | Show usage summary with examples and exit |

*Not required if `-UseMock` is specified. Running without `-Server` and without `-UseMock` prints the usage summary and exits with code 2.

### Discovery Modules

| Module | Description | Output |
|--------|-------------|--------|
| **ForestDomain** | Forest/domain functional levels, naming contexts, domain SID | Scalar properties |
| **Schema** | Schema version, Windows Server version, custom attributes | Version info + custom attribute collection |
| **OUStructure** | Complete OU hierarchy with depth, user/computer/group counts | OU collection with metrics |
| **SitesSubnets** | AD sites, subnets, site links, replication topology | Sites, subnets, site links collections |
| **Trusts** | Trust relationships, types, directions, status | Trust collection |
| **DomainControllers** | DC inventory, FSMO roles, OS versions, Global Catalog status | DC collection with roles |
| **Groups** | Security and distribution groups with membership counts | Group collection |
| **DNS** | DNS zones integrated with AD (forward and reverse) | Zone collection |

### Output Formats

#### HTML Report
- **Location**: `Output/discovery-YYYYMMDD-HHMMSS.html`
- **Features**:
  - Professional dark mode design
  - Collapsible sections for each module
  - Executive summary with key metrics
  - Diff highlighting for comparisons (green=added, red=removed, yellow=changed)
  - Print-friendly styles
  - Zebra-striped tables with hover effects
  - Responsive design for mobile/tablet

#### JSON Report
- **Location**: `Output/discovery-YYYYMMDD-HHMMSS.json`
- **Structure**:
  ```json
  {
    "Metadata": {
      "GeneratedTimestamp": "2026-01-30 14:30:00",
      "ToolVersion": "1.0.0",
      "ComparisonMode": true,
      "PrimaryDomain": "prod.local",
      "CompareDomain": "dev.local"
    },
    "PrimaryDomain": { ... },
    "CompareDomain": { ... },
    "ComparisonAnalysis": {
      "Summary": { ... },
      "ModuleComparisons": { ... }
    }
  }
  ```

#### CSV Exports
- **Location**: `Output/[domain]-[category].csv`
- **Files Generated**:
  - `OUs.csv`: OU structure with all properties
  - `Groups.csv`: Group inventory
  - `DomainControllers.csv`: DC details
  - `Trusts.csv`: Trust relationships
  - `Sites.csv`: Site information
  - `Subnets.csv`: Subnet assignments
  - `DNSZones.csv`: DNS zone inventory

## Module Architecture

### Standard Return Structure

All discovery modules follow this pattern:

```powershell
function Get-ModuleInfo {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Server,

        [Parameter(Mandatory = $false)]
        [PSCredential]$Credential,

        [Parameter(Mandatory = $false)]
        [hashtable]$Config = @{}
    )

    return @{
        Data = @{ ... }      # Hashtable with discovery results
        Errors = @(...)      # Array of error strings (empty if successful)
    }
}
```

### Mock Data Provider

For cross-platform testing and development:

```powershell
function Get-MockModuleInfo {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DomainName  # 'mock-prod.local' or 'mock-dev.local'
    )

    return @{
        Data = @{ ... }      # Realistic test data
        Errors = @()
    }
}
```

Mock domains have deliberate differences for comparison testing:
- **mock-prod.local**: Higher functional level (2016), more OUs (15), more DCs (3), more custom schema attributes (3)
- **mock-dev.local**: Lower functional level (2012R2), fewer OUs (12), fewer DCs (2), fewer custom schema attributes (2)

## Comparison Engine

The comparison engine performs deep recursive comparison across all modules:

### Comparison Categories

1. **Scalar Properties**: Direct value comparison (e.g., functional level, schema version)
2. **Collections**: Item-by-item matching with key field identification
   - **Added**: Items only in comparison domain
   - **Removed**: Items only in primary domain
   - **Changed**: Items in both with different properties
   - **Unchanged**: Items identical in both domains

### Key Field Mapping

Collections are matched using appropriate key fields:
- **OUs**: DistinguishedName
- **Groups**: Name
- **Domain Controllers**: Name
- **Sites**: Name
- **Trusts**: TargetName
- **DNS Zones**: Name

### Comparison Output

```powershell
@{
    Summary = @{
        TotalDifferences = 127
        AddedCount = 35
        RemovedCount = 42
        ChangedCount = 50
        UnchangedCount = 234
        ModulesCompared = 8
    }
    ModuleComparisons = @{
        ForestDomain = @{
            ScalarDifferences = @(...)
        }
        OUStructure = @{
            CollectionDifferences = @{
                Added = @(...)
                Removed = @(...)
                Changed = @(...)
                Unchanged = @(...)
            }
        }
        # ... other modules
    }
    Errors = @()
}
```

## Testing

Comprehensive test suite with **107 tests** covering all modules and comparison scenarios. Tests use the mock provider and run on any platform (Windows, macOS, Linux).

### Run Tests

```powershell
# Run all tests
pwsh ./Tests/Test-Discovery.ps1

# Verbose output
pwsh ./Tests/Test-Discovery.ps1 -Verbose
```

### Test Categories

1. **Platform Detection**: Verify Windows/Unix detection logic
2. **Mock Data Structure**: Validate all mock functions return correct format
3. **Mock Data Content**: Verify realistic data in mock objects
4. **Mock Domain Differences**: Confirm expected differences exist
5. **Comparison Engine**: Test deep comparison logic
6. **Report Generation**: Validate HTML, JSON, CSV output
7. **Error Handling**: Test graceful failure modes

### Expected Output

```
========================================
AD Discovery Toolkit - Test Suite
========================================

Loading modules...
  All modules loaded successfully

========================================
Test Category 1: Platform Detection
========================================
  [PASS] Test-IsWindowsPlatform returns a value
  [PASS] Unix platform correctly detected as non-Windows

...

========================================
Test Summary
========================================

Total Tests: 54
Passed: 54
Failed: 0
Duration: 2.3 seconds

All tests passed!
```

## Project Structure

```
EntraIDScripts/
├── AD-Discovery.ps1                 # Main entry point (pool owner, -Help, flow control)
├── README.md                        # This file
├── Config/
│   └── discovery-config.json        # Configuration settings
├── Modules/
│   ├── ADLdap.ps1                   # Shared LDAP helper (LdapConnection, pool, tiers) [CANONICAL in Group-Enumerator]
│   ├── Helpers.ps1                  # Shim layer over ADLdap + platform detection + utilities
│   ├── MockProvider.ps1             # Mock data for testing
│   ├── ForestDomain.ps1             # Forest/domain discovery
│   ├── Schema.ps1                   # Schema discovery
│   ├── OUStructure.ps1              # OU hierarchy discovery
│   ├── SitesSubnets.ps1             # Sites/subnets discovery
│   ├── Trusts.ps1                   # Trust discovery
│   ├── DomainControllers.ps1        # DC discovery
│   ├── Groups.ps1                   # Group discovery
│   ├── DNS.ps1                      # DNS discovery
│   ├── ComparisonEngine.ps1         # Domain comparison logic
│   └── ReportGenerator.ps1          # HTML/JSON/CSV report generation
├── Templates/
│   └── report-template.html         # Professional HTML report template
├── Tests/
│   ├── Test-Discovery.ps1           # Comprehensive test suite (107 tests, mock-driven)
│   ├── fixtures/
│   │   ├── Seed-TestAD.ps1          # Populates AD with realistic test data (24 OUs, 36 users, 25 groups)
│   │   └── Remove-TestAD.ps1        # Tears down test data (recursive OU delete)
│   └── Output/                      # Test output directory
└── Output/                          # Report output directory
```

`ADLdap.ps1` is vendored from the Group-Enumerator toolkit -- the canonical
copy lives at `Group-Enumerator/Modules/ADLdap.ps1` and its file header marks
it as such. The two copies should be kept byte-identical; diff-sync after
any fix.

## Troubleshooting

### Common Issues

#### Access Denied Errors

**Problem**: "Access denied" when querying AD

**Solutions**:
- Verify credentials are correct
- Ensure user account is not locked or expired
- Check network connectivity to domain controller
- Verify domain controller FQDN resolves correctly

#### "The LDAP server is unavailable" on Tier 1

**Problem**: TCP 636 is reachable and DNS resolves, but `New-AdLdapConnection`
fails at the bind step with "LDAP server is unavailable" on Tier 1
(LDAPS-Verified).

**Cause**: Almost always a TLS certificate trust failure -- the workstation
cannot validate the DC's current certificate. Common after cert rotation,
lab environments, cross-forest workstations without the remote CA trusted.

**Solutions**:
- Use `-AllowInsecure` to enable fallback tiers:
  ```powershell
  .\AD-Discovery.ps1 -Server dc01.contoso.com -AllowInsecure
  ```
  Tier 2 (LDAPS with cert bypass) will be tried next; the channel is still
  TLS-encrypted, you're just trusting the server identity on faith. Tier 3
  (LDAP 389 with Kerberos sign+seal) follows if Tier 2 also fails.
- Check the `LdapConnect` structured log events to see which tier actually
  connected. When any fallback tier is used, a warning is surfaced in the
  generated report.
- To restore Tier 1, import the DC's CA certificate into the workstation's
  Trusted Root Certification Authorities store.

#### Timeout Errors

**Problem**: Queries timeout on large domains

**Solutions**:
- Increase timeout in `Config/discovery-config.json`:
  ```json
  {
    "LdapTimeout": 300,
    "LdapPageSize": 500
  }
  ```
- Use `-SkipModules` to skip slow modules:
  ```powershell
  .\AD-Discovery.ps1 -Server dc01.contoso.com -SkipModules DNS,Groups
  ```

#### Platform Detection Issues

**Problem**: "Non-Windows platform detected without -UseMock flag"

**Solutions**:
- Add `-UseMock` flag on macOS/Linux:
  ```powershell
  pwsh ./AD-Discovery.ps1 -UseMock -Server mock-prod.local
  ```
- Use Windows for live AD queries

#### Empty Reports

**Problem**: Reports generated but contain no data

**Solutions**:
- Check errors in console output
- Verify network connectivity to DC
- Review JSON report for detailed error messages
- Test with mock data first to verify tool functionality

#### Test Failures

**Problem**: Test suite reports failures

**Solutions**:
- Check module loading in test output
- Verify PowerShell version (7+ required for macOS)
- Review specific test failure messages
- Check file permissions on output directory

### Performance Optimization

For large domains (10,000+ objects):
- Increase LDAP page size: `"LdapPageSize": 2000`
- Skip expensive modules during initial testing
- Run comparisons during off-peak hours
- Use domain-specific credentials with minimal group memberships

## Configuration

Edit `Config/discovery-config.json` to customize behavior:

```json
{
    "LdapPageSize": 1000,
    "LdapTimeout": 120,
    "DefaultOutputFormats": ["HTML", "JSON"],
    "OutputDirectory": "Output",
    "SkipModules": [],
    "IncludeGroupMembership": false,
    "MaxOUDepth": 10
}
```

## Extending the Tool

### Adding a New Discovery Module

1. Create new module file: `Modules/YourModule.ps1`
2. Implement discovery function following standard pattern
3. Implement mock function for testing
4. Add module to `AD-Discovery.ps1` module list
5. Update comparison engine key field mappings if needed
6. Add tests to `Tests/Test-Discovery.ps1`

Example:

```powershell
function Get-YourModuleInfo {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Server,

        [Parameter(Mandatory = $false)]
        [PSCredential]$Credential,

        [Parameter(Mandatory = $false)]
        [hashtable]$Config = @{}
    )

    $errors = @()
    $data = @{}

    try {
        # Your discovery logic here
        # Use helper functions from Helpers.ps1

        $data = @{
            YourProperty = $value
            YourCollection = @(...)
        }

    } catch {
        $errors += "Failed to retrieve data: $_"
    }

    return @{
        Data = $data
        Errors = $errors
    }
}
```

## License

[Your license here - placeholder for legal review]

## Support

For issues, questions, or contributions, contact:
- Internal: IT Discovery Team
- External: [Your contact method]

## Version History

- **1.1.0** (2026-04-15): LdapConnection migration
  - Replaced legacy `DirectoryEntry`/`DirectorySearcher` ADSI stack with
    `System.DirectoryServices.Protocols.LdapConnection` via the shared
    `ADLdap.ps1` helper. Works against DCs enforcing LDAP Channel Binding
    and LDAP Signing (the hardened modern default).
  - `Helpers.ps1` `Get-RootDSE` / `New-LdapSearcher` / `Invoke-LdapQuery`
    preserved as public API; internals rewritten as shims over ADLdap with
    automatic DateTime conversion for Generalized Time attributes and
    binary passthrough for SID/GUID/certificate attributes.
  - Per-run `LdapConnection` pool installed at the orchestrator level;
    reused across every discovery module.
  - `-AllowInsecure` switch: enables LDAPS cert-bypass and LDAP 389
    Kerberos sign+seal fallback tiers.
  - `-Help` switch and friendly usage output on bare invocation.
  - Bug fixes: `Join-Path` three-argument call incompatible with PS 5.1;
    shim `SearchScope` passthrough for consumers overriding the default.

- **1.0.0** (2026-01-30): Initial release
  - Core discovery modules (Forest, Schema, OUs)
  - Two-domain comparison engine
  - HTML/JSON/CSV report generation
  - Mock data provider for testing
  - Comprehensive test suite

---

**Note**: This tool performs read-only operations and does not modify Active Directory in any way. All queries use standard LDAP protocol with user-level permissions.
