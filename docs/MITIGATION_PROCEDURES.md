# CVE-2023-24932 Mitigation Procedures

Step-by-step procedures for applying CVE-2023-24932 mitigations on Windows systems.

## Choose Your Path

There are two approaches depending on your hardware:

| Path | When to Use | What It Covers |
|------|-------------|----------------|
| **[Firmware-Led](#firmware-led-path-oem-bios-updates)** | Dell/Lenovo with recent BIOS updates | OEM firmware delivers 2023 keys; you apply M2-M4 |
| **[Windows-Led](#windows-led-path-registry-mitigations)** | HP, older hardware, VMs, mixed fleets | Windows Update delivers all mitigations M1-M4 |

> **Not sure?** Run the check below. If the 2023 certificate is already in your firmware DB, use the firmware-led path. Otherwise, use the Windows-led path.

```powershell
# Quick check: are 2023 keys already in firmware?
$db = [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI db).bytes)
if ($db -match 'Windows UEFI CA 2023') {
    Write-Host "2023 certificate FOUND in DB - use Firmware-Led path (skip M1)" -ForegroundColor Green
} else {
    Write-Host "2023 certificate NOT found - use Windows-Led path (M1-M4)" -ForegroundColor Yellow
}
```

---

## Firmware-Led Path (OEM BIOS Updates)

Some OEMs (Dell, Lenovo) ship BIOS updates that include the Windows UEFI CA 2023 and KEK 2K CA 2023 certificates natively. When these keys are already in firmware, Mitigation 1 (DB enrollment) is handled at the BIOS level.

### OEM Status

| OEM | Firmware Status | Action |
|-----|----------------|--------|
| **Dell** | Shipping 2023 certs since late 2024; all sustaining platforms by end 2025 | Update BIOS to latest version |
| **Lenovo** | Proactively included across all systems | Update BIOS to latest version |
| **HP** | Many devices still on 2011-only keys (as of mid-2025) | Use Windows-Led path instead |

### Step 1: Update BIOS to Latest Version

Use your OEM's management tools to deploy the latest BIOS:

**Dell:**
```cmd
:: Dell Command Update (DCU)
dcu-cli.exe /applyUpdates -updateType=bios -reboot=enable

:: Or via SCCM/Intune with Dell BIOS packages
```

**Lenovo:**
```cmd
:: Lenovo System Update
"C:\Program Files (x86)\Lenovo\System Update\tvsu.exe" /CM

:: Or Lenovo Thin Installer for managed deployments
```

### Step 2: Verify Keys Are Present

After BIOS update and reboot:

```powershell
# Verify 2023 certificate in DB
[System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI db).bytes) -match 'Windows UEFI CA 2023'
# Must return True

# Verify 2023 KEK
[System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI KEK).bytes) -match '2023'
# Should return True on firmware that includes the new KEK
```

Or use the provided script:
```powershell
.\scripts\verification\Test-OEMFirmwareKeys.ps1
```

### Step 3: Apply Remaining Mitigations (M2-M4)

With M1 handled by firmware, proceed to deploy the new boot manager and revocations:

```cmd
:: Boot manager update (M2 only, since M1 is firmware-delivered)
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Secureboot /v AvailableUpdates /t REG_DWORD /d 0x100 /f
```

```powershell
Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update"
Restart-Computer
```

After verifying boot manager is updated and all boot media is refreshed:

```cmd
:: Revocation + SVN (M3 + M4, IRREVERSIBLE)
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Secureboot /v AvailableUpdates /t REG_DWORD /d 0x280 /f
```

```powershell
Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update"
Restart-Computer
```

> **Note:** You can also apply the full 0x140 value even when M1 is already present — Windows will detect the DB already contains PCA2023 and skip M1 automatically, only applying M2.

### Firmware-Led Considerations

- **EoSL devices:** Platforms reaching End of Service Life before January 2026 may not receive firmware with 2023 keys. Use the Windows-Led path for these.
- **BIOS reset:** On some Dell platforms, resetting BIOS defaults may remove the 2023 certificate if the device originally shipped without it. Re-apply the BIOS update or use M1 via Windows.
- **Mixed fleets:** If you have both Dell/Lenovo and HP devices, use firmware-led for Dell/Lenovo and Windows-led for HP. The verification scripts detect both paths.

---

## Windows-Led Path (Registry Mitigations)

The standard approach that works on all hardware. Uses Windows Update and registry values to deliver all four mitigations.

### Prerequisites Checklist

Before starting, complete these prerequisites:

- [ ] **Install Windows security updates** from July 8, 2025 or later
- [ ] **Verify Secure Boot is enabled**: `Confirm-SecureBootUEFI`
- [ ] **Create full system backup** including recovery media
- [ ] **Document current firmware version** and boot configuration
- [ ] **Backup BitLocker recovery keys** (CRITICAL):
  ```cmd
  manage-bde -protectors -get %systemdrive%
  ```
  Store the recovery key in a secure location (AD DS, Azure AD, or printed copy)
- [ ] **Check for known firmware issues** (see [Troubleshooting](TROUBLESHOOTING.md))
- [ ] **For Arm64 devices**: See [Arm64 Considerations](#arm64-device-considerations) below

---

## Phase 1: Mitigations 1 & 2 (Safe, Reversible)

### Combined Command (Recommended)

Apply both mitigations together to reduce reboots:

```cmd
:: Run as Administrator
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Secureboot /v AvailableUpdates /t REG_DWORD /d 0x140 /f
```

```powershell
Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update"
Restart-Computer
```

### Verification After Reboot

```powershell
# Check PCA2023 enrolled in DB
[System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI db).bytes) -match 'Windows UEFI CA 2023'
# Should return True

# Check boot manager signature
mountvol s: /s
Get-AuthenticodeSignature S:\EFI\Microsoft\Boot\bootmgfw.efi | Select-Object -ExpandProperty SignerCertificate | Select-Object Subject
# Should show Windows UEFI CA 2023
```

---

## Between Phase 1 and Phase 2

**CRITICAL: Complete these steps before Phase 2**

### Update Windows Recovery Environment (WinRE)

```powershell
# Check WinRE status
reagentc /info

# Disable WinRE
reagentc /disable

# Update WinRE image (from Windows installation media or DISM)
# Mount the WinRE partition and update boot files

# Re-enable WinRE
reagentc /enable
```

### Update All Boot Media

- [ ] Download latest Windows ISOs
- [ ] Recreate USB installation drives
- [ ] Update PXE/HTTP boot images
- [ ] Update VM templates
- [ ] Test boot from updated media on mitigated device

---

## Phase 2: Mitigations 3 & 4 (IRREVERSIBLE)

> ⚠️ **WARNING**: Phase 2 is IRREVERSIBLE. Once applied:
> - Old boot media will no longer work
> - Cannot be undone even with disk reformatting
> - Recovery media must be updated FIRST

### Pre-Phase 2 Verification

Confirm Phase 1 is complete:

```powershell
# Must return True before proceeding
[System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI db).bytes) -match 'Windows UEFI CA 2023'
```

### Apply Phase 2

```cmd
:: Run as Administrator - AFTER updating all recovery media
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Secureboot /v AvailableUpdates /t REG_DWORD /d 0x280 /f
```

```powershell
Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update"
Restart-Computer
```

### Verification After Phase 2

```powershell
# Check DBX contains revocation
[System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI dbx).bytes) -match 'Microsoft Windows Production PCA 2011'
# Should return True

# Check registry shows complete
$status = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Secureboot" -Name "AvailableUpdates").AvailableUpdates
# Should return 0 or null when all mitigations complete
```

---

## Registry Values Reference

### Individual Mitigations

| Value | Mitigation | Description |
|-------|------------|-------------|
| 0x40 | M1 only | Add PCA2023 to DB |
| 0x100 | M2 only | Update boot manager |
| 0x80 | M3 only | DBX revocation (IRREVERSIBLE) |
| 0x200 | M4 only | SVN update (IRREVERSIBLE) |

### Combined Values (Recommended)

| Value | Mitigations | Use Case |
|-------|-------------|----------|
| 0x140 | M1 + M2 | Phase 1 (safe) |
| 0x280 | M3 + M4 | Phase 2 (irreversible) |

> **Note (per Microsoft KB5025885):** The mitigations are **interlocked** so they cannot be deployed in the incorrect order. Windows will enforce the proper sequence regardless of the registry value set.

---

## Arm64 Device Considerations

### Non-Qualcomm Arm64 Devices

Microsoft blocks mitigations on non-Qualcomm Arm64 devices by default. To enable:

```cmd
:: Run as Administrator - ONLY for non-Qualcomm Arm64 devices
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Secureboot /v SkipDeviceCheck /t REG_DWORD /d 1 /f
```

**Warning**: Only use this on devices where you have confirmed compatibility with your hardware vendor.

### Arm64 Verification

```powershell
# Check if device is Arm64
$arch = (Get-WmiObject Win32_OperatingSystem).OSArchitecture
Write-Host "Architecture: $arch"

# Check processor
$proc = (Get-WmiObject Win32_Processor).Name
Write-Host "Processor: $proc"
```

---

## Quick Reference Card

### Apply Phase 1 (Safe)

```cmd
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Secureboot /v AvailableUpdates /t REG_DWORD /d 0x140 /f
```
```powershell
Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update"
Restart-Computer
```

### Verify Phase 1

```powershell
[System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI db).bytes) -match 'Windows UEFI CA 2023'
```

### Apply Phase 2 (IRREVERSIBLE)

```cmd
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Secureboot /v AvailableUpdates /t REG_DWORD /d 0x280 /f
```
```powershell
Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update"
Restart-Computer
```

### Check Overall Status

```powershell
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Secureboot" -Name "AvailableUpdates"
# 0 or null = All mitigations complete
```

---

## Automated Verification Script

Use the verification script from the scripts directory:

```powershell
.\scripts\verification\Verify-MitigationStatus.ps1
```

---

## Next Steps

- **[VM Guidance](VM_GUIDANCE.md)** - Special considerations for virtual machines
- **[Enterprise Deployment](ENTERPRISE_DEPLOYMENT.md)** - SCCM, Intune, GPO deployment
- **[Troubleshooting](TROUBLESHOOTING.md)** - Recovery procedures and known issues
