<#
.SYNOPSIS
    Verifies CVE-2023-24932 mitigation status on local system
.DESCRIPTION
    Comprehensive verification of all mitigation components.
    Run locally to check current mitigation state.
.OUTPUTS
    Returns detailed status object with all verification results
.EXAMPLE
    .\Verify-MitigationStatus.ps1
    .\Verify-MitigationStatus.ps1 | Format-List
#>

[CmdletBinding()]
param()

$results = [ordered]@{
    ComputerName = $env:COMPUTERNAME
    Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    SecureBootEnabled = $false
    SecureBootError = $null
    PCA2023Enrolled = $false
    BootManagerUpdated = $false
    BootManagerSigner = $null
    DBXRevocationApplied = $false
    AvailableUpdates = $null
    AvailableUpdatesHex = $null
    MitigationPhase = "Unknown"
    OverallStatus = "Unknown"
}

Write-Host "=== CVE-2023-24932 Mitigation Status ===" -ForegroundColor Cyan
Write-Host ""

# 1. Check Secure Boot
Write-Host "Checking Secure Boot status..." -ForegroundColor Yellow
try {
    $results.SecureBootEnabled = Confirm-SecureBootUEFI
    Write-Host "  Secure Boot: $($results.SecureBootEnabled)" -ForegroundColor $(if ($results.SecureBootEnabled) { "Green" } else { "Red" })
}
catch {
    $results.SecureBootError = $_.Exception.Message
    Write-Host "  Secure Boot: Not available - $($_.Exception.Message)" -ForegroundColor Red
}

if (-not $results.SecureBootEnabled) {
    $results.OverallStatus = "Not Applicable - Secure Boot Disabled"
    $results.MitigationPhase = "N/A"
    Write-Host ""
    Write-Host "Secure Boot is not enabled. Mitigations are not applicable." -ForegroundColor Yellow
    return [PSCustomObject]$results
}

# 2. Check Mitigation 1: PCA2023 in DB
Write-Host "Checking Mitigation 1 (PCA2023 in DB)..." -ForegroundColor Yellow
try {
    $dbBytes = (Get-SecureBootUEFI db -ErrorAction Stop).bytes
    $dbString = [System.Text.Encoding]::ASCII.GetString($dbBytes)
    $results.PCA2023Enrolled = $dbString -match 'Windows UEFI CA 2023'
    Write-Host "  Windows UEFI CA 2023 enrolled: $($results.PCA2023Enrolled)" -ForegroundColor $(if ($results.PCA2023Enrolled) { "Green" } else { "Yellow" })
}
catch {
    Write-Host "  Error reading Secure Boot DB: $_" -ForegroundColor Red
}

# 3. Check Mitigation 2: Boot Manager Updated
Write-Host "Checking Mitigation 2 (Boot Manager)..." -ForegroundColor Yellow
try {
    $efiPath = "S:\EFI\Microsoft\Boot\bootmgfw.efi"
    $mounted = $false

    if (-not (Test-Path "S:\")) {
        $null = mountvol S: /s 2>$null
        $mounted = $true
    }

    if (Test-Path $efiPath) {
        $sig = Get-AuthenticodeSignature $efiPath -ErrorAction SilentlyContinue
        if ($sig) {
            $results.BootManagerSigner = $sig.SignerCertificate.Subject
            $results.BootManagerUpdated = $sig.SignerCertificate.Subject -match "Windows UEFI CA 2023"
        }
    }

    if ($mounted) {
        $null = mountvol S: /d 2>$null
    }

    Write-Host "  Boot Manager Updated: $($results.BootManagerUpdated)" -ForegroundColor $(if ($results.BootManagerUpdated) { "Green" } else { "Yellow" })
    if ($results.BootManagerSigner) {
        Write-Host "  Signer: $($results.BootManagerSigner)" -ForegroundColor Gray
    }
}
catch {
    Write-Host "  Error checking boot manager: $_" -ForegroundColor Red
}

# 4. Check Mitigation 3: DBX Revocation
Write-Host "Checking Mitigation 3 (DBX Revocation)..." -ForegroundColor Yellow
try {
    $dbxBytes = (Get-SecureBootUEFI dbx -ErrorAction Stop).bytes
    $dbxString = [System.Text.Encoding]::ASCII.GetString($dbxBytes)
    $results.DBXRevocationApplied = $dbxString -match 'Microsoft Windows Production PCA 2011'
    Write-Host "  PCA2011 in DBX (revoked): $($results.DBXRevocationApplied)" -ForegroundColor $(if ($results.DBXRevocationApplied) { "Green" } else { "Yellow" })
}
catch {
    Write-Host "  Error reading DBX: $_" -ForegroundColor Red
}

# 5. Check Registry Status
Write-Host "Checking Registry Status..." -ForegroundColor Yellow
try {
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Secureboot"
    $availableUpdates = (Get-ItemProperty -Path $regPath -Name AvailableUpdates -ErrorAction SilentlyContinue).AvailableUpdates
    $results.AvailableUpdates = $availableUpdates
    $results.AvailableUpdatesHex = if ($null -ne $availableUpdates) { "0x{0:X}" -f $availableUpdates } else { "N/A" }
    Write-Host "  AvailableUpdates: $($results.AvailableUpdates) ($($results.AvailableUpdatesHex))" -ForegroundColor Gray
}
catch {
    Write-Host "  Error reading registry: $_" -ForegroundColor Red
}

# Determine Phase and Overall Status
Write-Host ""
Write-Host "=== Summary ===" -ForegroundColor Cyan

if ($results.AvailableUpdates -eq 0 -or $null -eq $results.AvailableUpdates) {
    if ($results.PCA2023Enrolled -and $results.DBXRevocationApplied) {
        $results.MitigationPhase = "Complete (All 4 Mitigations)"
        $results.OverallStatus = "FULLY MITIGATED"
        Write-Host "Status: FULLY MITIGATED" -ForegroundColor Green
    }
    elseif ($results.PCA2023Enrolled) {
        $results.MitigationPhase = "M1M2 Complete"
        $results.OverallStatus = "Partial - M3M4 may be pending verification"
        Write-Host "Status: Mitigations 1 & 2 Complete" -ForegroundColor Yellow
    }
}
elseif ($results.PCA2023Enrolled) {
    $results.MitigationPhase = "M1M2 Complete - M3M4 Pending"
    $results.OverallStatus = "Mitigations 3 & 4 pending"
    Write-Host "Status: Mitigations 1 & 2 Complete - 3 & 4 Pending" -ForegroundColor Yellow
}
else {
    $results.MitigationPhase = "Not Started"
    $results.OverallStatus = "No mitigations applied"
    Write-Host "Status: NO MITIGATIONS APPLIED" -ForegroundColor Red
}

Write-Host ""
return [PSCustomObject]$results
