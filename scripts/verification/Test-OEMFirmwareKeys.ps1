<#
.SYNOPSIS
    Tests whether OEM firmware (Dell/HP/Lenovo) includes the Windows UEFI CA 2023 keys.
.DESCRIPTION
    Checks the UEFI Secure Boot DB and KEK databases for the presence of 2023
    certificates delivered via OEM BIOS updates. Reports whether the firmware-led
    mitigation path can be used or if the Windows-led path (M1-M4) is needed.
.EXAMPLE
    .\Test-OEMFirmwareKeys.ps1
.NOTES
    Must be run with administrator privileges on a UEFI Secure Boot system.
#>

[CmdletBinding()]
param()

Write-Host "=== OEM Firmware Key Check for CVE-2023-24932 ===" -ForegroundColor Cyan
Write-Host ""

# System info
$cs = Get-WmiObject Win32_ComputerSystem
$bios = Get-WmiObject Win32_BIOS
$manufacturer = $cs.Manufacturer
$model = $cs.Model
$biosVersion = $bios.SMBIOSBIOSVersion
$biosDate = $bios.ReleaseDate

Write-Host "Manufacturer : $manufacturer"
Write-Host "Model        : $model"
Write-Host "BIOS Version : $biosVersion"
Write-Host "BIOS Date    : $biosDate"
Write-Host ""

# Check Secure Boot
$secureBootEnabled = $false
try {
    $secureBootEnabled = Confirm-SecureBootUEFI -ErrorAction Stop
}
catch {
    Write-Host "[ERROR] Secure Boot not enabled or not supported." -ForegroundColor Red
    Write-Host "        This device does not require CVE-2023-24932 mitigations." -ForegroundColor Gray
    exit 0
}

Write-Host "Secure Boot  : Enabled" -ForegroundColor Green
Write-Host ""

# Check DB for Windows UEFI CA 2023
$dbHas2023 = $false
try {
    $dbBytes = (Get-SecureBootUEFI db -ErrorAction Stop).bytes
    $dbString = [System.Text.Encoding]::ASCII.GetString($dbBytes)
    $dbHas2023 = $dbString -match 'Windows UEFI CA 2023'
}
catch {
    Write-Host "[WARNING] Could not read Secure Boot DB: $_" -ForegroundColor Yellow
}

# Check KEK for 2023 key
$kekHas2023 = $false
try {
    $kekBytes = (Get-SecureBootUEFI KEK -ErrorAction Stop).bytes
    $kekString = [System.Text.Encoding]::ASCII.GetString($kekBytes)
    $kekHas2023 = $kekString -match '2023'
}
catch {
    Write-Host "[WARNING] Could not read Secure Boot KEK: $_" -ForegroundColor Yellow
}

# Check if boot manager is already signed with 2023 cert
$bootMgrUpdated = $false
try {
    $efiMounted = $false
    mountvol s: /s 2>$null
    if (Test-Path "S:\EFI\Microsoft\Boot\bootmgfw.efi") {
        $efiMounted = $true
        $sig = Get-AuthenticodeSignature "S:\EFI\Microsoft\Boot\bootmgfw.efi" -ErrorAction Stop
        $subject = $sig.SignerCertificate.Subject
        $bootMgrUpdated = $subject -match '2023'
    }
}
catch {
    # Silently handle - EFI partition may not be accessible
}

# Report results
Write-Host "=== Certificate Status ===" -ForegroundColor Cyan
Write-Host ""

if ($dbHas2023) {
    Write-Host "[PASS] Windows UEFI CA 2023 : PRESENT in DB" -ForegroundColor Green
}
else {
    Write-Host "[MISS] Windows UEFI CA 2023 : NOT in DB" -ForegroundColor Yellow
}

if ($kekHas2023) {
    Write-Host "[PASS] KEK 2023 key         : PRESENT in KEK" -ForegroundColor Green
}
else {
    Write-Host "[MISS] KEK 2023 key         : NOT in KEK" -ForegroundColor Yellow
}

if ($bootMgrUpdated) {
    Write-Host "[PASS] Boot Manager         : Signed with 2023 certificate" -ForegroundColor Green
}
else {
    Write-Host "[MISS] Boot Manager         : NOT yet signed with 2023 certificate" -ForegroundColor Yellow
}

Write-Host ""

# OEM-specific guidance
Write-Host "=== Recommendation ===" -ForegroundColor Cyan
Write-Host ""

$oemCategory = "Unknown"
if ($manufacturer -match "Dell") { $oemCategory = "Dell" }
elseif ($manufacturer -match "Lenovo") { $oemCategory = "Lenovo" }
elseif ($manufacturer -match "HP|Hewlett") { $oemCategory = "HP" }
elseif ($model -match "Virtual|VMware|HVM|Xen") { $oemCategory = "VM" }

if ($dbHas2023 -and $kekHas2023) {
    Write-Host "FIRMWARE-LED PATH: OEM firmware includes 2023 keys." -ForegroundColor Green
    Write-Host "  -> Skip Mitigation 1 (already in firmware)" -ForegroundColor Green
    Write-Host "  -> Apply M2 (0x100) to update boot manager" -ForegroundColor White
    Write-Host "  -> Then M3+M4 (0x280) after updating boot media" -ForegroundColor White
}
elseif ($dbHas2023) {
    Write-Host "PARTIAL FIRMWARE: DB has 2023 key, but KEK may need update." -ForegroundColor Yellow
    Write-Host "  -> Use Windows-Led path (0x140 then 0x280) for safety" -ForegroundColor White
}
else {
    Write-Host "WINDOWS-LED PATH: Firmware does not include 2023 keys." -ForegroundColor Yellow
    switch ($oemCategory) {
        "Dell" {
            Write-Host "  -> Dell device: Update BIOS to latest version first" -ForegroundColor White
            Write-Host "     Dell ships 2023 keys in late-2024+ BIOS updates" -ForegroundColor Gray
            Write-Host "     Run: dcu-cli.exe /applyUpdates -updateType=bios" -ForegroundColor Gray
        }
        "Lenovo" {
            Write-Host "  -> Lenovo device: Update BIOS to latest version first" -ForegroundColor White
            Write-Host "     Lenovo includes 2023 keys in current firmware" -ForegroundColor Gray
        }
        "HP" {
            Write-Host "  -> HP device: Check HP support for BIOS updates" -ForegroundColor White
            Write-Host "     HP may not yet ship 2023 keys; use Windows-Led M1-M4" -ForegroundColor Gray
            Write-Host "     Sure Start devices may need specific firmware updates" -ForegroundColor Gray
        }
        "VM" {
            Write-Host "  -> Virtual machine detected: Use Windows-Led path (M1-M4)" -ForegroundColor White
        }
        default {
            Write-Host "  -> Apply M1+M2 (0x140) then M3+M4 (0x280)" -ForegroundColor White
        }
    }
}

Write-Host ""

# Output structured result for fleet collection
$result = [PSCustomObject]@{
    ComputerName = $env:COMPUTERNAME
    Manufacturer = $manufacturer
    Model = $model
    BIOSVersion = $biosVersion
    OEMCategory = $oemCategory
    SecureBootEnabled = $secureBootEnabled
    DB_Has_2023 = $dbHas2023
    KEK_Has_2023 = $kekHas2023
    BootMgr_2023 = $bootMgrUpdated
    RecommendedPath = if ($dbHas2023 -and $kekHas2023) { "Firmware-Led" } else { "Windows-Led" }
}

$result
