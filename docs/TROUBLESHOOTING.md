# Troubleshooting Guide for CVE-2023-24932

Recovery procedures, known issues, and diagnostic commands.

## Known Firmware Compatibility Issues

| Issue | Affected Systems | Resolution |
|-------|------------------|------------|
| TPM 2.0 measurement block (unresolved) | Windows Server 2012/2012 R2 | No confirmed fix published; contact Microsoft Support |
| Boot failure after Mitigation 3 | Various OEM systems | Check KB5025885 for specific models |
| BitLocker recovery triggered | All TPM-based systems | Normal; save recovery keys beforehand |
| Hyper-V VM boot failure | Gen 2 VMs with old template | Update VM firmware settings |
| HP Sure Start blocks M1 | HP devices without BIOS F.26+ | Update to BIOS F.26 (Dec 2025); see [HP firmware issues](#hp-firmware-issues) |
| HP error 1795 on scheduled task | HP devices missing DB keys | BIOS does not include 2023 keys; update to F.26+ first |
| Dell BIOS reset removes 2023 keys | Dell devices after BIOS defaults reset | Re-apply BIOS update or use M1 via Windows |
| Dell 12G/13G PowerEdge — no BIOS update | 12th/13th Gen PowerEdge (EoSL) | No update coming; use Windows-Led M1-M4 or evaluate retirement |
| Dell NVIDIA Option ROM CA split | PowerEdge with NVIDIA PCIe cards | Add Option ROM UEFI CA explicitly to DB; see [NVIDIA Option ROM issue](#nvidia-option-rom-ca-issue-dell-poweredge) |
| **VMware VM boot failure after M3** | **VMware VMs with Secure Boot after DBX revocation** | **Known issue; Microsoft and VMware working on fix — see [VMware M3 issue](#vmware-vm-boot-failure-after-mitigation-3)** |
| ARM64 Qualcomm — mitigations blocked | Qualcomm-based ARM64 devices | Block still active; OEM firmware fix required — `SkipDeviceCheck` does NOT apply |
| ARM64 non-Qualcomm | Non-Qualcomm ARM64 | Use `SkipDeviceCheck` registry only after confirming compatibility |
| Windows 10 (no ESU) — no 2023 certs | Windows 10 without Extended Security Updates | No automated fix possible; enroll in ESU or upgrade OS |
| Post-Oct 2025 WinRE fails on un-updated systems | Systems without 2023 cert in DB trying to boot new media | Firmware must include 2023 cert before booting new WinRE under Secure Boot |

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

### Problem: HP device — error 1795 when running Secure Boot scheduled task

**Cause:** HP BIOS does not include the Windows UEFI CA 2023 certificate. The scheduled task fails because the firmware cannot accept the new boot manager signed with a certificate not yet in the DB.

**Solution:**
1. Check for BIOS updates from HP that include the 2023 keys
2. If no BIOS update available, apply Mitigation 1 first (0x40) to add the key via Windows, then proceed with M2-M4
3. Monitor HP support pages for Sure Start firmware compatibility updates

```powershell
# Verify whether HP BIOS has the key
$db = [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI db).bytes)
if ($db -match 'Windows UEFI CA 2023') {
    Write-Host "2023 key present - proceed with M2-M4"
} else {
    Write-Host "2023 key MISSING - apply M1 via Windows first (0x40)"
}
```

### HP Firmware Issues

HP devices with Sure Start may block the Secure Boot update process. Key details:

- HP has been slower than Dell/Lenovo in shipping firmware with 2023 certificates
- Sure Start devices have additional firmware validation that can interfere with DB updates
- Error 1795 in Event Viewer (`system firmware returned an error`) is the most common symptom
- HP has a specific exemption listed in Microsoft KB5025885

**Recommended approach for HP fleets:**
1. Use the Windows-Led path (M1-M4 via registry)
2. Apply M1 (0x40) first, verify the key is in DB, then proceed
3. Check HP support for BIOS updates per model

### Problem: Dell BIOS reset removes 2023 certificate

**Cause:** Resetting BIOS to factory defaults on some Dell platforms may remove the 2023 certificate if the device originally shipped before Dell added dual-certificate support.

**Solution:**
1. Re-apply the latest Dell BIOS update
2. Or apply Mitigation 1 via Windows (0x40) as a fallback
3. Avoid full BIOS resets on devices that have already been updated

### VMware VM Boot Failure After Mitigation 3

**Cause:** VMware VMs with x86 processors and Secure Boot enabled fail to boot after the DBX revocation (Mitigation 3 / `0x80`) is applied. This is a known issue; Microsoft is working with VMware on a fix.

**Current guidance:**
- Do **not** apply Mitigation 3 to VMware environments until a fix is confirmed
- Apply Mitigations 1 & 2 (Phase 1 / `0x140`) only
- Monitor [Microsoft KB5025885](https://support.microsoft.com/en-us/topic/how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023-24932-41a975df-beb2-40c1-99a3-b3ff139f832d) for resolution status

**Workaround if already applied:**
1. Edit VM settings → VM Options → Boot Options
2. Temporarily disable Secure Boot
3. Boot the VM and investigate

---

### Bitpixie (CVE-2023-21563) — WinRE Patching Is Mandatory

**Background:** CVE-2023-21563 ("Bitpixie"), demonstrated at 38C3 in December 2024 and actively exploited as of May 2025, allows BitLocker bypass by chaining a WinRE downgrade attack. An attacker chains an old, unpatched WinRE image to extract the BitLocker volume master key from memory.

**Why this matters for CVE-2023-24932 remediation:**
- An unpatched WinRE undermines the entire Secure Boot / BitLocker security posture
- Applying CVE-2023-24932 mitigations without patching WinRE leaves BitLocker vulnerable
- **WinRE patching is not optional** — it is a mandatory companion step

**Mitigation:** Ensure WinRE is updated as part of every CVE-2023-24932 remediation cycle. See the [Between Phase 1 and Phase 2](MITIGATION_PROCEDURES.md#between-phase-1-and-phase-2) section.

---

### NVIDIA Option ROM CA Issue (Dell PowerEdge)

**Cause:** Microsoft split UEFI CA 2011 into two 2023 CAs:
- `Windows UEFI CA 2023` (signs Microsoft boot components)
- `Microsoft Option ROM UEFI CA 2023` (signs third-party Option ROMs, including NVIDIA)

After the DB update is applied, NVIDIA PCIe cards on Dell PowerEdge servers may fail to initialize under Secure Boot because the Option ROM CA is not automatically included in the DB update.

**Symptoms:** NVIDIA GPU or NIC fails to initialize after Secure Boot DB update; system may fail to detect cards or present boot errors referencing UEFI driver signing.

**Solution:** Explicitly add the `Microsoft Option ROM UEFI CA 2023` certificate to the Secure Boot DB. See [Dell KB 000420051](https://www.dell.com/support/kbdoc/en-us/000420051) for model-specific guidance.

---

### Windows Server 2012 / 2012 R2 — TPM 2.0 Measurement Block

**Status: Unresolved as of March 2026.**

The block introduced by the July 2024 update — preventing Mitigations 2 and 3 on Windows Server 2012/2012 R2 with TPM 2.0 — has **no confirmed public resolution**. A hotfix released ~July 15, 2024 addressed a TPM *driver recognition* issue, but this is distinct from the *measurement compatibility* block on Mitigations 2 and 3.

Key facts:
- Windows Server 2012 reached end of extended support October 2023
- Windows Server 2012 R2 extended support ends October 2026 (ESU available)
- These OS versions do not receive 2023 Secure Boot certificates via CFR regardless
- Do **not** assume the TPM measurement block is resolved; contact Microsoft Support for current guidance on your specific build

---

### Problem: Arm64 device - mitigations blocked

**Qualcomm ARM64 (block still active):** The `SkipDeviceCheck` registry override does **not** apply to Qualcomm ARM64 devices. Microsoft is coordinating with Qualcomm for a firmware fix. Wait for an OEM firmware update before applying mitigations on Qualcomm-based ARM64 devices.

**Non-Qualcomm ARM64 only:**
```cmd
:: Only for NON-QUALCOMM ARM64 devices with confirmed OEM compatibility
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
| HP error 1795 | BIOS missing 2023 keys; apply M1 (0x40) via Windows first |
| Dell keys gone after BIOS reset | Re-apply latest BIOS update or use M1 via Windows |
| OEM firmware doesn't have 2023 keys | Use Windows-Led path (M1-M4) instead of firmware-led |

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
