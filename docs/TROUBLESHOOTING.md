# Troubleshooting Guide for CVE-2023-24932

Recovery procedures, known issues, and diagnostic commands.

## Known Firmware Compatibility Issues

| Issue | Affected Systems | Resolution |
|-------|------------------|------------|
| TPM 2.0 measurement failure | Windows Server 2012/2012 R2 | Wait for firmware update from vendor |
| Boot failure after Mitigation 3 | Various OEM systems | Check KB5025885 for specific models |
| BitLocker recovery triggered | All TPM-based systems | Normal; save recovery keys beforehand |
| Hyper-V VM boot failure | Gen 2 VMs with old template | Update VM firmware settings |
| HP Sure Start | HP devices | May require BIOS update |
| VMware ESXi | VMs on ESXi | Ensure VM hardware version supports Secure Boot |
| Arm64 non-Qualcomm | Non-Qualcomm Arm64 | Use `SkipDeviceCheck` registry (see below) |

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

**Solutions:**
1. Create new recovery media from a mitigated system
2. Temporarily disable Secure Boot to boot old media
3. Use vendor recovery partition (if not revoked)

### Scenario 3: VM Won't Boot After Host Mitigation

**Hyper-V:**
```powershell
# Disable Secure Boot for the VM
Set-VMFirmware -VMName "VMName" -EnableSecureBoot Off

# Boot the VM and apply mitigations inside
Start-VM -VMName "VMName"

# After mitigations applied inside VM, re-enable Secure Boot
Set-VMFirmware -VMName "VMName" -EnableSecureBoot On
```

**VMware:**
1. Edit VM settings → VM Options → Boot Options
2. Temporarily disable Secure Boot
3. Apply mitigations inside VM
4. Re-enable Secure Boot

### Scenario 4: Cluster Node Won't Boot

```powershell
# From another node - remove failed node
Remove-ClusterNode -Name "FailedNode" -Force

# Recover the node using recovery media

# Re-add to cluster after successful boot
Add-ClusterNode -Name "RecoveredNode" -Cluster "ClusterName"
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

## Common Problems and Solutions

### Problem: AvailableUpdates value doesn't change after reboot

**Cause:** Scheduled task didn't run or encountered an error.

**Solution:**
```powershell
# Check task history
Get-ScheduledTask -TaskName "Secure-Boot-Update" | Get-ScheduledTaskInfo

# Run manually with logging
Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update"
Get-EventLog -LogName System -Source "Secure-Boot-Update" -Newest 10
```

### Problem: Secure Boot policy prevents boot after Mitigation 3

**Cause:** Boot component revoked before replacement installed.

**Solution:**
1. Disable Secure Boot in firmware
2. Verify boot manager updated:
   ```cmd
   mountvol s: /s
   dir S:\EFI\Microsoft\Boot\
   ```
3. Re-apply Mitigation 2 if needed
4. Re-enable Secure Boot

### Problem: VM fails to boot after host update

**Cause:** VM Secure Boot template mismatch.

**Solution (Hyper-V):**
```powershell
# Check current template
Get-VMFirmware -VMName "VMName" | Select-Object SecureBootTemplate

# Set correct template
Set-VMFirmware -VMName "VMName" -SecureBootTemplate "MicrosoftWindows"
```

### Problem: BitLocker recovery required after every boot

**Cause:** TPM PCR values changed by Secure Boot updates.

**Solution:**
```powershell
# Suspend BitLocker temporarily
Suspend-BitLocker -MountPoint "C:" -RebootCount 3

# Apply mitigations
# BitLocker will re-seal to new PCR values after mitigations complete
Resume-BitLocker -MountPoint "C:"
```

### Problem: Arm64 device - mitigations blocked

**Cause:** Microsoft blocks mitigations on non-Qualcomm Arm64 by default.

**Solution:**
```cmd
:: Only for confirmed compatible non-Qualcomm Arm64 devices
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Secureboot /v SkipDeviceCheck /t REG_DWORD /d 1 /f
```

---

## Diagnostic Commands

### Complete System Information

```powershell
Get-ComputerInfo | Select-Object *SecureBoot*, *UEFI*, *Firmware*
```

### Check All Secure Boot Variables

```powershell
Get-SecureBootUEFI -Name PK
Get-SecureBootUEFI -Name KEK
Get-SecureBootUEFI -Name db
Get-SecureBootUEFI -Name dbx
```

### Check Event Log for Secure Boot Events

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Kernel-Boot/Operational" |
    Where-Object {$_.Message -like "*Secure Boot*"} |
    Select-Object -First 20
```

### VM-Specific Diagnostics

```powershell
# Run inside VM
Get-WmiObject -Class Win32_ComputerSystem | Select-Object Model, Manufacturer
```

### Full Mitigation Status Check

Use the provided verification script:
```powershell
.\scripts\verification\Verify-MitigationStatus.ps1
```

---

## If Something Goes Wrong - Quick Reference

| Problem | Quick Fix |
|---------|-----------|
| BitLocker recovery prompt | Enter recovery key, suspend BitLocker, retry |
| System won't boot | Disable Secure Boot in BIOS, investigate |
| VM won't boot | Disable VM Secure Boot, apply mitigations inside |
| Old boot media fails | Use updated media or disable Secure Boot |
| Mitigations not applying | Check scheduled task ran, check event logs |

---

## Getting Help

### Microsoft Resources

- [Enterprise Deployment Guidance for CVE-2023-24932](https://support.microsoft.com/en-us/topic/enterprise-deployment-guidance-for-cve-2023-24932-88b8f034-20b7-4a45-80cb-c6049b0f9967)
- [How to manage Windows Boot Manager revocations](https://support.microsoft.com/en-us/topic/how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023-24932-41a975df-beb2-40c1-99a3-b3ff139f832d)

### Community Resources

- [GARYTOWN BlackLotus KB5025885 Scripts](https://github.com/gwblok/garytown/blob/master/BlackLotusKB5025885/readme.md)
- [GARYTOWN Blog - KB5025885 PowerShell Script](https://garytown.com/powershell-script-kb5025885-how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023-24932)
- [AJ's Tech Chatter - BlackLotus Remediation](https://anthonyfontanez.com/index.php/2025/05/18/dealing-with-cve-2023-24932-aka-remediating-blacklotus/)

---

## Next Steps

- **[Overview](OVERVIEW.md)** - Executive summary and timeline
- **[Mitigation Procedures](MITIGATION_PROCEDURES.md)** - Step-by-step commands
- **[VM Guidance](VM_GUIDANCE.md)** - Virtual machine considerations
- **[Enterprise Deployment](ENTERPRISE_DEPLOYMENT.md)** - SCCM, Intune, GPO
