# CVE-2023-24932 and June 2026 Secure Boot Certificate Expiration Mitigation Guide

## Table of Contents
1. [Executive Summary](#executive-summary)
2. [Understanding the Threat Landscape](#understanding-the-threat-landscape)
3. [How CVE-2023-24932 and Certificate Expiration Are Connected](#how-cve-2023-24932-and-certificate-expiration-are-connected)
4. [Microsoft's Mitigation Timeline](#microsofts-mitigation-timeline)
5. [Windows Mitigation Procedures](#windows-mitigation-procedures)
6. [Linux Mitigation Procedures](#linux-mitigation-procedures)
7. [Enterprise Deployment Strategy](#enterprise-deployment-strategy)
8. [Verification and Validation](#verification-and-validation)
9. [Recovery Procedures](#recovery-procedures)
10. [Known Issues and Troubleshooting](#known-issues-and-troubleshooting)
11. [Resources and References](#resources-and-references)

---

## Executive Summary

The **June 2026 Secure Boot certificate expirations are the deadline**, while the **CVE-2023-24932 mitigations are the mechanism** Microsoft is using to transition Windows devices to a new Secure Boot trust model. The boot-manager revocations (PCA 2011 → UEFI CA 2023) proactively remove reliance on certificates that **will no longer be trusted once expiration and enforcement occur**.

### Critical Dates

| Certificate | Expiration Date | Impact |
|-------------|-----------------|--------|
| Microsoft Windows Production KEK CA 2011 | June 2026 | Cannot receive DBX updates |
| Microsoft Windows Production PCA 2011 | October 2026 | Boot failure for unsigned components |
| Microsoft Corporation UEFI CA 2011 | June 2026 | Third-party boot component failures |

### Key Takeaway

> **The Secure Boot certificate expirations in 2026 are inevitable. The CVE-2023-24932 mitigations are Microsoft's controlled transition plan to prevent widespread boot failures when those expirations occur. Organizations that delay preparation risk unbootable systems when enforcement begins.**

---

## Understanding the Threat Landscape

### What is CVE-2023-24932 (BlackLotus)?

CVE-2023-24932 is a publicly disclosed Secure Boot security feature bypass vulnerability that enables the **BlackLotus UEFI bootkit**. This sophisticated malware:

- Allows attackers with administrative or physical access to bypass Secure Boot
- Loads before the operating system, controlling the entire boot sequence
- Can disable security features including BitLocker, Windows Defender, and HVCI
- Persists across operating system reinstallation
- Targets the trust chain dependent on Windows Production PCA 2011

### The Expiring Certificates Problem

Microsoft's Secure Boot implementation relies on certificates issued in 2011:

- **Windows Production PCA 2011**: Signs Windows boot managers
- **KEK CA 2011**: Enables DBX (revocation list) updates
- **UEFI CA 2011**: Signs third-party boot components (including Linux shim)

These certificates **expire in 2026**. Once expired:
- Firmware will refuse to load boot components signed with expired certificates
- Devices using old boot managers **will not boot**
- No DBX security updates can be applied

---

## How CVE-2023-24932 and Certificate Expiration Are Connected

### The Critical Relationship

| Aspect | CVE-2023-24932 Mitigation | June 2026 Certificate Expiry |
|--------|---------------------------|------------------------------|
| Trigger | Active security exploit | Cryptographic expiration |
| What changes | Trust is **revoked** | Trust simply **expires** |
| Where enforced | UEFI firmware (DB/DBX/SVN) | Firmware signature validation |
| Rollback possible? | No | No |
| Impact if unprepared | Immediate boot failures | Mass boot failures |

### Why Microsoft Is Acting Now

Microsoft's response to CVE-2023-24932 involves a **trust reset**:

1. **Introduce new signing authority**: Windows UEFI CA 2023
2. **Issue new boot managers**: Signed with the 2023 certificate
3. **Revoke old boot managers**: Via DBX updates in firmware

If Microsoft waited until certificate expiration:
- The failure would be **sudden and global**
- There would be **no mitigation window**
- Recovery media worldwide would stop working simultaneously

The CVE work makes this break **controlled and testable**, instead of catastrophic.

---

## Microsoft's Mitigation Timeline

### Deployment Phases

| Phase | Date | Action |
|-------|------|--------|
| Initial Update | May 2023 | KB5025885 released with mitigations (disabled by default) |
| Second Deployment | July 2024 | Additional mitigation options added |
| Evaluation Period | Now - 2026 | Organizations test and deploy mitigations |
| Enforcement Phase | No earlier than January 2026 | Automatic revocation begins |
| Certificate Expiration | June-October 2026 | Old certificates expire |

### Important: Enforcement Phase Warning

Microsoft will provide **at least six months advance notice** before the Enforcement Phase begins. When enforcement starts:

- Windows Production PCA 2011 will be automatically added to DBX
- Updates will be **programmatically enforced**
- There will be **no option to disable** the revocations

---

## Windows Mitigation Procedures

### Prerequisites

1. **Install Windows security updates** from July 8, 2025 or later
2. **Verify Secure Boot is enabled**: `Confirm-SecureBootUEFI`
3. **Create full system backup** including recovery media
4. **Document current firmware version** and boot configuration

### The Four Required Mitigations

#### Mitigation 1: Install Updated Certificate (PCA2023) to DB

Adds the new Windows UEFI CA 2023 certificate to the Secure Boot signature database.

```cmd
:: Run as Administrator
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Secureboot /v AvailableUpdates /t REG_DWORD /d 0x40 /f
```

Then run the scheduled task and restart:
```powershell
Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update"
shutdown /r /t 0
```

**Verify** (after restart):
```powershell
[System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI db).bytes) -match 'Windows UEFI CA 2023'
# Should return True
```

#### Mitigation 2: Update Boot Manager

Deploys the new boot manager signed with PCA2023.

```cmd
:: Run as Administrator
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Secureboot /v AvailableUpdates /t REG_DWORD /d 0x100 /f
```

```powershell
Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update"
shutdown /r /t 0
```

**Verify**:
```powershell
# Mount EFI System Partition
mountvol s: /s

# Check boot manager signature
Get-AuthenticodeSignature S:\EFI\Microsoft\Boot\bootmgfw.efi | Select-Object -ExpandProperty SignerCertificate | Select-Object Subject
# Should show Windows UEFI CA 2023
```

#### Mitigation 3: Enable Revocation (DBX Update)

**CRITICAL WARNING**: This step is IRREVERSIBLE. Once applied:
- Old boot media will no longer work
- Cannot be undone even with disk reformatting
- Recovery media must be updated FIRST

```cmd
:: Run as Administrator - AFTER creating updated recovery media
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Secureboot /v AvailableUpdates /t REG_DWORD /d 0x80 /f
```

```powershell
Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update"
shutdown /r /t 0
```

#### Mitigation 4: Apply Secure Version Number (SVN) Update

Prevents rollback attacks by updating the firmware's SVN.

```cmd
:: Run as Administrator
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Secureboot /v AvailableUpdates /t REG_DWORD /d 0x200 /f
```

```powershell
Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update"
shutdown /r /t 0
```

### Combined Registry Values

For convenience, mitigations can be combined:

| Value | Mitigations Applied |
|-------|---------------------|
| 0x40 | Mitigation 1 only (DB update) |
| 0x100 | Mitigation 2 only (Boot manager) |
| 0x140 | Mitigations 1 + 2 |
| 0x80 | Mitigation 3 only (DBX revocation) |
| 0x200 | Mitigation 4 only (SVN) |
| 0x280 | Mitigations 3 + 4 |

**Recommended approach**: Apply 0x140 first, verify, then apply 0x280 separately.

### Update Windows Recovery Environment (WinRE)

WinRE must be updated **before** applying Mitigation 3:

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

---

## Linux Mitigation Procedures

### Understanding the Linux Boot Chain

Linux systems using Secure Boot typically follow this chain:
1. **UEFI Firmware** validates **shim** (signed by Microsoft UEFI CA)
2. **Shim** validates **GRUB2** (signed by distribution)
3. **GRUB2** validates **kernel** (signed by distribution)

### Certificate Verification

Check which certificates are enrolled:
```bash
# Install efitools if not present
sudo apt-get install efitools

# Check DB certificates
mokutil --db

# Look for these entries:
# - "Microsoft Corporation UEFI CA 2011" (legacy)
# - "Microsoft UEFI CA 2023" (new)
```

### For Systems with UEFI CA 2023 Only

Newer hardware (2024+) may only have the 2023 certificate. Verify:
```bash
mokutil --db | grep -E "(UEFI CA 2011|UEFI CA 2023)"
```

If only 2023 is present, you need:
- Updated shim signed with 2023 certificate
- Check your distribution for updated packages

### Update Shim and GRUB2

#### Ubuntu/Debian
```bash
sudo apt update
sudo apt install --only-upgrade shim-signed grub-efi-amd64-signed
sudo update-grub
```

#### RHEL/CentOS/Fedora
```bash
sudo dnf update shim-x64 grub2-efi-x64
sudo grub2-mkconfig -o /boot/efi/EFI/redhat/grub.cfg
```

#### openSUSE
```bash
sudo zypper update shim grub2-x86_64-efi
sudo grub2-mkconfig -o /boot/efi/EFI/opensuse/grub.cfg
```

### Apply DBX Updates Using fwupd

The recommended method for applying DBX updates on Linux:

```bash
# Install fwupd
sudo apt install fwupd  # Debian/Ubuntu
sudo dnf install fwupd  # Fedora/RHEL

# Check for available updates
fwupdmgr get-updates

# Apply firmware updates (including DBX)
fwupdmgr update

# Verify DBX contents
efi-readvar -v dbx
```

**Important**: fwupd checks that your current boot components are not in the DBX before applying updates, preventing boot failures.

### SBAT (Secure Boot Advanced Targeting)

Modern Linux distributions use SBAT for more flexible revocation:

```bash
# Check SBAT status
mokutil --sbat

# Verify shim SBAT level
objdump -j .sbat -s /boot/efi/EFI/ubuntu/shimx64.efi
```

### Machine Owner Key (MOK) Management

If using custom keys:
```bash
# Enroll a MOK
sudo mokutil --import my-key.der

# List enrolled MOKs
mokutil --list-enrolled

# Reboot and complete enrollment in MOK Manager
```

---

## Enterprise Deployment Strategy

### Recommended Deployment Phases

#### Phase 1: Assessment and Testing (Weeks 1-4)

1. **Inventory**
   - Document all hardware models in environment
   - Identify firmware versions and Secure Boot status
   - Catalog boot media (ISO images, USB drives, PXE servers)

2. **Lab Testing**
   - Test at least one device of each hardware type
   - Apply Mitigations 1 and 2 only
   - Document any issues

3. **Review Known Issues**
   - Check KB5025885 for firmware compatibility issues
   - Contact OEM vendors for identified problems

#### Phase 2: Initial Deployment - Mitigations 1 & 2 (Weeks 5-12)

1. **Pilot Group** (5% of devices)
   ```powershell
   # Combined Mitigations 1 + 2
   reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Secureboot /v AvailableUpdates /t REG_DWORD /d 0x140 /f
   Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update"
   ```

2. **Monitor and validate** pilot devices for 2 weeks

3. **Broader deployment** using:
   - SCCM/ConfigMgr Task Sequences
   - Intune configuration profiles
   - Group Policy with scheduled tasks

#### Phase 3: Boot Media Refresh (Weeks 8-16)

1. **Update installation media**
   - Download latest Windows ISOs
   - Recreate USB installation drives
   - Update PXE/HTTP boot images
   - Refresh WinRE partitions

2. **Test updated media**
   - Verify boot on mitigated devices
   - Test recovery scenarios

3. **Plan for regular updates**
   - Establish twice-yearly refresh cycle

#### Phase 4: Revocation Deployment - Mitigations 3 & 4 (After Phase 3 Complete)

**Do not proceed until**:
- All boot media updated
- WinRE updated on all devices
- Recovery procedures tested

1. **Deploy to pilot group**
   ```powershell
   # Combined Mitigations 3 + 4
   reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Secureboot /v AvailableUpdates /t REG_DWORD /d 0x280 /f
   Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update"
   ```

2. **Validate recovery procedures**
3. **Gradual rollout** (10% increments)

### Monitoring Progress

Track mitigation status via registry:
```powershell
# Check current status
$status = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Secureboot" -Name "AvailableUpdates" -ErrorAction SilentlyContinue
$status.AvailableUpdates

# Value meanings:
# 0x000 = All mitigations complete
# 0x040 = Mitigation 1 pending
# 0x100 = Mitigation 2 pending
# 0x080 = Mitigation 3 pending
# 0x200 = Mitigation 4 pending
```

### Configuration Manager (SCCM) Deployment

Scripts available at: [garytown/ConfigMgr/Baselines/CVE-2023-24932](https://github.com/garytown/ConfigMgr)

Sample compliance baseline:
```powershell
# Detection script for Mitigation 1
$db = [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI db).bytes)
if ($db -match 'Windows UEFI CA 2023') {
    return $true
} else {
    return $false
}
```

### Intune Deployment

Create a Win32 app or PowerShell script deployment:

```powershell
# CVE-2023-24932 Mitigation Script
param(
    [ValidateSet(1,2,3,4)]
    [int]$MitigationLevel = 2
)

$values = @{
    1 = 0x40   # DB update only
    2 = 0x140  # DB + Boot manager
    3 = 0x80   # DBX revocation
    4 = 0x280  # DBX + SVN
}

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Secureboot" /v AvailableUpdates /t REG_DWORD /d $values[$MitigationLevel] /f
Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update"
```

---

## Verification and Validation

### Windows Verification Commands

```powershell
# 1. Check Secure Boot status
Confirm-SecureBootUEFI

# 2. Verify PCA2023 in DB
[System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI db).bytes) -match 'Windows UEFI CA 2023'

# 3. Check boot manager certificate
mountvol s: /s
Get-AuthenticodeSignature S:\EFI\Microsoft\Boot\bootmgfw.efi

# 4. Verify DBX contains PCA2011 revocation (after Mitigation 3)
$dbx = Get-SecureBootUEFI dbx
# DBX is binary - use vendor tools for detailed inspection

# 5. Check registry status
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Secureboot" -Name "AvailableUpdates"
```

### Linux Verification Commands

```bash
# 1. Check Secure Boot status
bootctl status | grep "Secure Boot"

# 2. List all UEFI variables
efi-readvar

# 3. Check specific databases
efi-readvar -v db
efi-readvar -v dbx

# 4. Verify shim signature
sbverify --list /boot/efi/EFI/ubuntu/shimx64.efi

# 5. Check SBAT status
mokutil --sbat
```

### Compliance Reporting

Create a PowerShell script for fleet-wide reporting:

```powershell
$results = @{
    ComputerName = $env:COMPUTERNAME
    SecureBootEnabled = Confirm-SecureBootUEFI
    PCA2023Enrolled = ([System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI db).bytes) -match 'Windows UEFI CA 2023')
    MitigationStatus = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Secureboot" -Name "AvailableUpdates" -ErrorAction SilentlyContinue).AvailableUpdates
    FirmwareVersion = (Get-WmiObject -Class Win32_BIOS).SMBIOSBIOSVersion
}

$results | ConvertTo-Json
```

---

## Recovery Procedures

### Scenario 1: System Won't Boot After Mitigation

1. **Disable Secure Boot temporarily**
   - Enter UEFI/BIOS setup (F2, F10, F12, Del, or Esc during boot)
   - Navigate to Security → Secure Boot
   - Set Secure Boot to Disabled
   - Save and exit

2. **Boot to recovery environment**
   - Use updated recovery media
   - Or boot from Windows installation USB

3. **Investigate the issue**
   ```cmd
   :: From recovery command prompt
   bcdedit /enum all
   reagentc /info
   ```

### Scenario 2: Recovery Media No Longer Works

This occurs if Mitigation 3 was applied before updating recovery media.

**Solution**:
1. Create new recovery media from a mitigated system
2. Or temporarily disable Secure Boot to boot old media
3. Or use vendor recovery partition (if not revoked)

### Scenario 3: Dual-Boot Linux/Windows Broken

After Mitigation 3, old Linux boot components may be revoked.

**Solution**:
1. Update Linux shim and GRUB from latest distribution packages
2. Rebuild GRUB configuration
3. Verify signatures match enrolled certificates

```bash
# Boot with Secure Boot disabled, then:
sudo apt update
sudo apt install --reinstall shim-signed grub-efi-amd64-signed
sudo update-grub
sudo grub-install --target=x86_64-efi --efi-directory=/boot/efi
# Re-enable Secure Boot
```

### Creating Updated Recovery Media

```powershell
# 1. Mount WIM and add latest updates
dism /Mount-Wim /WimFile:C:\Recovery\WinRE.wim /Index:1 /MountDir:C:\Mount

# 2. Add updates
dism /Image:C:\Mount /Add-Package /PackagePath:C:\Updates\update.msu

# 3. Commit and unmount
dism /Unmount-Wim /MountDir:C:\Mount /Commit

# 4. Update WinRE partition
reagentc /disable
# Copy updated WinRE.wim to recovery partition
reagentc /enable
```

---

## Known Issues and Troubleshooting

### Known Firmware Compatibility Issues

| Issue | Affected Systems | Resolution |
|-------|------------------|------------|
| TPM 2.0 measurement failure | Windows Server 2012/2012 R2 | July 2024 update blocks mitigations; wait for firmware update |
| Boot failure after Mitigation 3 | Various OEM systems | Check KB5025885 for specific models |
| BitLocker recovery triggered | All TPM-based systems | Normal behavior; save recovery keys beforehand |

### Common Problems

#### Problem: "AvailableUpdates value doesn't change after reboot"

**Cause**: Scheduled task didn't run or encountered an error.

**Solution**:
```powershell
# Check task history
Get-ScheduledTask -TaskName "Secure-Boot-Update" | Get-ScheduledTaskInfo

# Run manually with logging
Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update"
Get-EventLog -LogName System -Source "Secure-Boot-Update" -Newest 10
```

#### Problem: "Secure Boot policy prevents boot after Mitigation 3"

**Cause**: Boot component revoked before replacement installed.

**Solution**:
1. Disable Secure Boot in firmware
2. Verify boot manager updated: `mountvol s: /s && dir S:\EFI\Microsoft\Boot\`
3. Re-apply Mitigation 2 if needed
4. Re-enable Secure Boot

#### Problem: "Linux won't boot after Windows DBX update"

**Cause**: Shim revoked in DBX.

**Solution**:
```bash
# Boot with Secure Boot disabled
# Check shim version
dpkg -l shim-signed  # Debian/Ubuntu
rpm -q shim-x64      # RHEL/Fedora

# Update shim
sudo apt install --reinstall shim-signed
# or
sudo dnf reinstall shim-x64

# Re-enable Secure Boot
```

### Diagnostic Commands

```powershell
# Windows - Check all Secure Boot variables
Get-SecureBootUEFI -Name PK
Get-SecureBootUEFI -Name KEK
Get-SecureBootUEFI -Name db
Get-SecureBootUEFI -Name dbx

# Check event log for Secure Boot events
Get-WinEvent -LogName "Microsoft-Windows-Kernel-Boot/Operational" |
    Where-Object {$_.Message -like "*Secure Boot*"} |
    Select-Object -First 20
```

```bash
# Linux - Comprehensive diagnostics
bootctl status
mokutil --sb-state
efi-readvar
journalctl -b | grep -i "secure\|shim\|grub"
```

---

## Resources and References

### Microsoft Official Documentation

- [Enterprise Deployment Guidance for CVE-2023-24932](https://support.microsoft.com/en-us/topic/enterprise-deployment-guidance-for-cve-2023-24932-88b8f034-20b7-4a45-80cb-c6049b0f9967)
- [How to manage Windows Boot Manager revocations for CVE-2023-24932](https://support.microsoft.com/en-us/topic/how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023-24932-41a975df-beb2-40c1-99a3-b3ff139f832d)
- [Revoking vulnerable Windows boot managers](https://techcommunity.microsoft.com/blog/windows-itpro-blog/revoking-vulnerable-windows-boot-managers/4121735)

### Linux Distribution Documentation

- [Ubuntu Secure Boot Documentation](https://documentation.ubuntu.com/security/security-features/platform-protections/secure-boot/)
- [Red Hat Secure Boot Article](https://access.redhat.com/articles/5991201)
- [Debian SecureBoot Wiki](https://wiki.debian.org/SecureBoot)
- [Arch Linux UEFI Secure Boot](https://wiki.archlinux.org/title/Unified_Extensible_Firmware_Interface/Secure_Boot)

### Community Resources

- [GARYTOWN ConfigMgr Scripts](https://garytown.com/powershell-script-kb5025885-how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023-24932)
- [AJ's Tech Chatter - BlackLotus Remediation](https://anthonyfontanez.com/index.php/2025/05/18/dealing-with-cve-2023-24932-aka-remediating-blacklotus/)

### Security Research

- [Eclypsium - Shim Vulnerabilities](https://eclypsium.com/blog/the-real-shim-shady-how-cve-2023-40547-impacts-most-linux-systems/)
- [UEFI Forum Specifications](https://uefi.org/specifications)

### Tools

- **fwupd**: Linux firmware update daemon - https://fwupd.org/
- **efitools**: Linux EFI tools - https://git.kernel.org/pub/scm/linux/kernel/git/jejb/efitools.git
- **sbsigntool**: Secure Boot signing tool

---

## Appendix A: Quick Reference Card

### Windows - Apply Mitigations 1 & 2 (Safe)

```cmd
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Secureboot /v AvailableUpdates /t REG_DWORD /d 0x140 /f
```
```powershell
Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update"
Restart-Computer
```

### Windows - Verify Mitigation Status

```powershell
# Check PCA2023 enrolled
[System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI db).bytes) -match 'Windows UEFI CA 2023'
```

### Linux - Update Secure Boot Components

```bash
# Debian/Ubuntu
sudo apt update && sudo apt install --only-upgrade shim-signed grub-efi-amd64-signed
# Apply DBX
fwupdmgr update
```

---

## Appendix B: Glossary

| Term | Definition |
|------|------------|
| **DB** | Signature Database - contains trusted signing certificates |
| **DBX** | Forbidden Signature Database - contains revoked certificates/hashes |
| **KEK** | Key Exchange Key - authorizes changes to DB/DBX |
| **PK** | Platform Key - root of trust for Secure Boot |
| **PCA** | Product Certificate Authority |
| **Shim** | First-stage bootloader for Linux Secure Boot |
| **SBAT** | Secure Boot Advanced Targeting - flexible revocation mechanism |
| **SVN** | Secure Version Number - prevents rollback attacks |
| **WinRE** | Windows Recovery Environment |

---

**Document Version:** 1.0
**Last Updated:** 2026-01-28
**Classification:** Internal Use
**Review Cycle:** Quarterly until June 2026

**Disclaimer:** This document is provided for informational purposes. Always test procedures in a non-production environment and consult official Microsoft and distribution documentation for the latest guidance.
