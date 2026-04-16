<#
.SYNOPSIS
    Removes all test data created by Seed-TestAD.ps1.

.DESCRIPTION
    Deletes OU=_DiscoveryTestData and everything underneath it using the
    LDAP Tree Delete control (OID 1.2.840.113556.1.4.805), which performs
    a single recursive delete at the server side — no need to enumerate
    and delete children individually.

    Safe: only touches objects under OU=_DiscoveryTestData. Will not
    affect any other part of the directory.

.PARAMETER Server
    DC hostname or domain FQDN.

.PARAMETER Credential
    Optional PSCredential.

.PARAMETER AllowInsecure
    Enable fallback tiers.

.PARAMETER Force
    Skip the confirmation prompt.

.EXAMPLE
    .\Remove-TestAD.ps1 -Server delusionalsecurity.review -AllowInsecure
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]  [string]$Server,
    [Parameter(Mandatory = $false)] [PSCredential]$Credential,
    [Parameter(Mandatory = $false)] [switch]$AllowInsecure,
    [Parameter(Mandatory = $false)] [switch]$Force
)

$ErrorActionPreference = 'Stop'
$scriptRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

. (Join-Path $scriptRoot 'Modules\ADLdap.ps1')

Add-Type -AssemblyName System.DirectoryServices.Protocols

# --- Connect ---
$connParams = @{ Server = $Server; TimeoutSeconds = 120 }
if ($Credential)    { $connParams.Credential    = $Credential }
if ($AllowInsecure) { $connParams.AllowInsecure = $true }

$ctx = New-AdLdapConnection @connParams
$conn = $ctx.Connection
$baseDN = $ctx.BaseDN
$rootOU = "OU=_DiscoveryTestData,$baseDN"

Write-Host "Connected to $Server via $($ctx.Tier)" -ForegroundColor Green
Write-Host "Target: $rootOU" -ForegroundColor Yellow

# Check existence
try {
    $req = New-Object System.DirectoryServices.Protocols.SearchRequest(
        $rootOU, '(objectClass=*)',
        [System.DirectoryServices.Protocols.SearchScope]::Base, @('distinguishedName'))
    $resp = $conn.SendRequest($req)
    if ($resp.Entries.Count -eq 0) {
        Write-Host "`nOU does not exist: $rootOU" -ForegroundColor DarkYellow
        Write-Host "Nothing to remove." -ForegroundColor Gray
        Close-AdLdapConnection $ctx
        exit 0
    }
} catch {
    Write-Host "`nOU does not exist or is not accessible: $rootOU" -ForegroundColor DarkYellow
    Write-Host "Nothing to remove." -ForegroundColor Gray
    Close-AdLdapConnection $ctx
    exit 0
}

# Count children for the confirmation prompt
$childReq = New-Object System.DirectoryServices.Protocols.SearchRequest(
    $rootOU, '(objectClass=*)',
    [System.DirectoryServices.Protocols.SearchScope]::Subtree, @('distinguishedName'))
$childResp = $conn.SendRequest($childReq)
$childCount = $childResp.Entries.Count

Write-Host "`nThis will permanently delete $childCount object(s) under:" -ForegroundColor Red
Write-Host "  $rootOU" -ForegroundColor White

if (-not $Force) {
    $answer = Read-Host "Type 'YES' to confirm"
    if ($answer -ne 'YES') {
        Write-Host "Aborted." -ForegroundColor Yellow
        Close-AdLdapConnection $ctx
        exit 0
    }
}

try {
    # Tree Delete control (OID 1.2.840.113556.1.4.805)
    # Tells the DC to recursively delete the entry and all descendants in
    # one server-side operation. Much faster than bottom-up client delete.
    $treeDeleteOid = '1.2.840.113556.1.4.805'
    $delReq = New-Object System.DirectoryServices.Protocols.DeleteRequest($rootOU)
    $treeCtrl = New-Object System.DirectoryServices.Protocols.DirectoryControl($treeDeleteOid, $null, $true, $true)
    $null = $delReq.Controls.Add($treeCtrl)

    $null = $conn.SendRequest($delReq)

    Write-Host "`nDeleted $childCount object(s) under $rootOU" -ForegroundColor Green
    Write-Host "Teardown complete." -ForegroundColor Green

} catch {
    Write-Host "`nERROR during delete: $_" -ForegroundColor Red
    Write-Host "You may need to manually delete residual objects." -ForegroundColor Yellow
    exit 1
} finally {
    Close-AdLdapConnection $ctx
}
