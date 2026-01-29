# CVE-2023-24932 Mitigation Procedures

Step-by-step procedures for applying CVE-2023-24932 mitigations on Windows systems.

## Prerequisites Checklist

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
