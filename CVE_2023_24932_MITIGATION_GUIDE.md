# CVE-2023-24932 and June 2026 Secure Boot Certificate Expiration Mitigation Guide

## Table of Contents
1. [Executive Summary](#executive-summary)
2. [Understanding the Threat Landscape](#understanding-the-threat-landscape)
3. [How CVE-2023-24932 and Certificate Expiration Are Connected](#how-cve-2023-24932-and-certificate-expiration-are-connected)
4. [Microsoft's Mitigation Timeline](#microsofts-mitigation-timeline)
5. [Windows Mitigation Procedures](#windows-mitigation-procedures)
6. [Virtual Machine Considerations](#virtual-machine-considerations)
7. [Windows Server Mitigation](#windows-server-mitigation)
8. [Enterprise Deployment Strategy](#enterprise-deployment-strategy)
9. [Verification and Validation](#verification-and-validation)
10. [Recovery Procedures](#recovery-procedures)
11. [Known Issues and Troubleshooting](#known-issues-and-troubleshooting)
12. [Resources and References](#resources-and-references)

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
- **UEFI CA 2011**: Signs third-party boot components

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

## Virtual Machine Considerations

### Hyper-V Virtual Machines

#### Secure Boot in Hyper-V Generation 2 VMs

Hyper-V Generation 2 VMs support UEFI and Secure Boot. The mitigations apply differently based on the VM template:

| Template | Secure Boot Default | Certificate Authority |
|----------|---------------------|----------------------|
| Microsoft Windows | Enabled | Microsoft Windows Production CA 2011 |
| Microsoft UEFI Certificate Authority | Enabled | Microsoft UEFI CA (for third-party) |
| Open Source Shielded VM | Enabled | Custom CA |

#### Checking VM Secure Boot Status

```powershell
# On Hyper-V Host
Get-VMFirmware -VMName "VMName" | Select-Object SecureBoot, SecureBootTemplate

# List all VMs with Secure Boot status
Get-VM | ForEach-Object {
    $fw = Get-VMFirmware -VMName $_.Name
    [PSCustomObject]@{
        VMName = $_.Name
        SecureBoot = $fw.SecureBoot
        Template = $fw.SecureBootTemplate
    }
}
```

#### Applying Mitigations to Hyper-V VMs

1. **Update the Hyper-V host first** with latest Windows updates
2. **Update VM firmware** by applying Windows updates inside the VM
3. **Apply mitigations inside the VM** using the standard procedures

```powershell
# Inside the VM - Apply Mitigations 1 & 2
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Secureboot /v AvailableUpdates /t REG_DWORD /d 0x140 /f
Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update"
Restart-Computer
```

#### Hyper-V Host Considerations

- Host firmware updates affect all VMs
- Update Hyper-V host before updating guests
- Create VM checkpoints before applying mitigations
- Test on non-production VMs first

### VMware Virtual Machines

#### Secure Boot in VMware

VMware supports Secure Boot for VMs with EFI firmware:

| Version | Secure Boot Support |
|---------|---------------------|
| vSphere 6.5+ | Supported |
| Workstation 15+ | Supported |
| Fusion 11+ | Supported |

#### Checking Secure Boot Status in VMware

```powershell
# Inside the VM
Confirm-SecureBootUEFI

# Via PowerCLI on vSphere
Get-VM "VMName" | Get-AdvancedSetting -Name "firmware" | Select-Object Name, Value
```

#### VMware Considerations

- VM Hardware version 13+ required for Secure Boot
- Update VMware Tools after applying mitigations
- vSphere hosts do not require separate mitigation (hypervisor uses different boot chain)
- Guest OS mitigations are independent of host

### Azure Virtual Machines

#### Trusted Launch VMs

Azure Trusted Launch VMs support:
- Secure Boot
- vTPM (Virtual Trusted Platform Module)
- Boot integrity attestation

#### Checking Azure VM Secure Boot

```powershell
# Azure CLI
az vm show --resource-group MyResourceGroup --name MyVM --query "securityProfile.uefiSettings"

# Azure PowerShell
Get-AzVM -ResourceGroupName "MyResourceGroup" -Name "MyVM" | Select-Object -ExpandProperty SecurityProfile
```

#### Applying Mitigations to Azure VMs

1. **Create VM snapshot** before applying mitigations
2. **Apply Windows updates** to the VM
3. **Apply mitigations** using standard procedures
4. **Verify boot attestation** after mitigations

```powershell
# Inside Azure VM
# Same mitigation commands as physical machines
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Secureboot /v AvailableUpdates /t REG_DWORD /d 0x140 /f
Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update"
Restart-Computer
```

#### Azure-Specific Considerations

- Azure manages firmware updates automatically
- Boot diagnostics can detect Secure Boot failures
- Azure Backup recommended before mitigations
- Test in Azure DevTest Labs first

### AWS Virtual Machines (EC2)

#### Nitro System Secure Boot

AWS Nitro-based instances support UEFI Secure Boot:

| Instance Type | Secure Boot Support |
|---------------|---------------------|
| Nitro-based (most current gen) | Supported |
| Xen-based (older) | Not supported |

#### Enabling Secure Boot on EC2

```bash
# AWS CLI - Create instance with UEFI boot
aws ec2 run-instances \
  --image-id ami-xxxxxxxx \
  --instance-type m5.large \
  --boot-mode uefi
```

#### EC2 Considerations

- Use UEFI-compatible AMIs
- Create AMI backup before mitigations
- Windows Server AMIs from AWS Marketplace are pre-configured
- Apply standard Windows mitigations inside the instance

---

## Windows Server Mitigation

### Windows Server Version Support

| Server Version | Mitigation Support | Notes |
|----------------|-------------------|-------|
| Windows Server 2022 | Full support | Recommended |
| Windows Server 2019 | Full support | |
| Windows Server 2016 | Partial support | Some limitations |
| Windows Server 2012 R2 | Limited | TPM measurement issues |
| Windows Server 2012 | Limited | TPM 2.0 compatibility issues |

### Known Issues with Older Servers

**Windows Server 2012/2012 R2 with TPM 2.0**:
- July 2024 updates block Mitigations #2 and #3
- Due to TPM measurement compatibility issues
- Wait for firmware updates from hardware vendor

### Server Core Installations

Apply mitigations via command line (no GUI required):

```cmd
:: Check Secure Boot status
powershell -Command "Confirm-SecureBootUEFI"

:: Apply Mitigations 1 & 2
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Secureboot /v AvailableUpdates /t REG_DWORD /d 0x140 /f

:: Run the scheduled task
schtasks /Run /TN "\Microsoft\Windows\PI\Secure-Boot-Update"

:: Restart
shutdown /r /t 60
```

### Failover Cluster Considerations

For Windows Server Failover Clusters:

1. **Plan maintenance window** for cluster-wide updates
2. **Update one node at a time** with proper failover
3. **Verify cluster health** between node updates
4. **Apply mitigations in sequence**:
   - Apply Mitigations 1 & 2 to all nodes first
   - Verify cluster stability
   - Then apply Mitigations 3 & 4

```powershell
# On each cluster node (one at a time)
# 1. Pause the node
Suspend-ClusterNode -Name "NodeName" -Drain

# 2. Apply mitigations
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Secureboot /v AvailableUpdates /t REG_DWORD /d 0x140 /f
Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update"
Restart-Computer

# 3. After restart, resume the node
Resume-ClusterNode -Name "NodeName"

# 4. Verify cluster health before proceeding to next node
Get-ClusterNode | Select-Object Name, State
```

### Hyper-V Host Servers

For Hyper-V hosts running Windows Server:

1. **Schedule maintenance window** for host and VMs
2. **Migrate VMs** to other hosts or shut down
3. **Apply host mitigations** first
4. **Verify host boots properly**
5. **Then apply mitigations to guest VMs**

```powershell
# Migrate VMs before host maintenance
Get-VM | Where-Object State -eq 'Running' | Move-VM -DestinationHost "AlternateHost"

# Or save VM state
Get-VM | Where-Object State -eq 'Running' | Save-VM

# Apply host mitigations
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Secureboot /v AvailableUpdates /t REG_DWORD /d 0x140 /f
Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update"
Restart-Computer
```

### Domain Controller Considerations

For Active Directory Domain Controllers:

1. **Never apply mitigations to all DCs simultaneously**
2. **Start with one DC** in a non-critical site
3. **Verify AD replication** after each DC update
4. **Keep at least one DC untouched** until fully tested

```powershell
# Verify AD replication health before starting
repadmin /replsummary

# After applying mitigations, verify replication
repadmin /showrepl
dcdiag /v
```

### SQL Server Considerations

For servers running SQL Server:

1. **Stop SQL services** before applying mitigations
2. **Verify database integrity** after restart
3. **Consider AlwaysOn Availability Groups** failover planning

```powershell
# Stop SQL services
Stop-Service -Name "MSSQLSERVER"
Stop-Service -Name "SQLSERVERAGENT"

# Apply mitigations
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Secureboot /v AvailableUpdates /t REG_DWORD /d 0x140 /f
Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update"
Restart-Computer

# After restart, verify SQL starts properly
Get-Service -Name "MSSQLSERVER" | Select-Object Name, Status
```

---

## Enterprise Deployment Strategy

### Recommended Deployment Phases

#### Phase 1: Assessment and Testing (Weeks 1-4)

1. **Inventory**
   - Document all hardware models in environment
   - Identify firmware versions and Secure Boot status
   - Catalog boot media (ISO images, USB drives, PXE servers)
   - Identify all virtual machine platforms

2. **Lab Testing**
   - Test at least one device of each hardware type
   - Test each VM platform (Hyper-V, VMware, Azure, etc.)
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
   - Azure Update Management

#### Phase 3: Boot Media and Server Refresh (Weeks 8-16)

1. **Update installation media**
   - Download latest Windows ISOs
   - Recreate USB installation drives
   - Update PXE/HTTP boot images
   - Refresh WinRE partitions
   - Update VM templates

2. **Test updated media**
   - Verify boot on mitigated devices
   - Test recovery scenarios
   - Test VM deployments

3. **Plan for regular updates**
   - Establish twice-yearly refresh cycle

#### Phase 4: Revocation Deployment - Mitigations 3 & 4 (After Phase 3 Complete)

**Do not proceed until**:
- All boot media updated
- WinRE updated on all devices
- Recovery procedures tested
- All VM templates updated

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

### VM-Specific Verification

```powershell
# Hyper-V VM Verification (run on host)
Get-VM | ForEach-Object {
    $fw = Get-VMFirmware -VMName $_.Name
    [PSCustomObject]@{
        VMName = $_.Name
        SecureBoot = $fw.SecureBoot
        Template = $fw.SecureBootTemplate
        State = $_.State
    }
} | Format-Table

# Inside VM - verify same as physical
Confirm-SecureBootUEFI
```

### Compliance Reporting

Create a PowerShell script for fleet-wide reporting:

```powershell
$results = @{
    ComputerName = $env:COMPUTERNAME
    IsVirtualMachine = (Get-WmiObject -Class Win32_ComputerSystem).Model -match "Virtual|VMware|HVM"
    SecureBootEnabled = Confirm-SecureBootUEFI
    PCA2023Enrolled = ([System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI db).bytes) -match 'Windows UEFI CA 2023')
    MitigationStatus = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Secureboot" -Name "AvailableUpdates" -ErrorAction SilentlyContinue).AvailableUpdates
    FirmwareVersion = (Get-WmiObject -Class Win32_BIOS).SMBIOSBIOSVersion
    OSVersion = (Get-WmiObject -Class Win32_OperatingSystem).Caption
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

### Scenario 3: VM Won't Boot After Host Mitigation

**Hyper-V**:
```powershell
# Disable Secure Boot for the VM
Set-VMFirmware -VMName "VMName" -EnableSecureBoot Off

# Boot the VM and apply mitigations inside
Start-VM -VMName "VMName"

# After mitigations applied inside VM, re-enable Secure Boot
Set-VMFirmware -VMName "VMName" -EnableSecureBoot On
```

**VMware**:
1. Edit VM settings → VM Options → Boot Options
2. Temporarily disable Secure Boot
3. Apply mitigations inside VM
4. Re-enable Secure Boot

### Scenario 4: Cluster Node Won't Boot

1. **Remove node from cluster**
   ```powershell
   # From another node
   Remove-ClusterNode -Name "FailedNode" -Force
   ```

2. **Recover the node** using recovery media
3. **Re-add to cluster** after successful boot
   ```powershell
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

## Known Issues and Troubleshooting

### Known Firmware Compatibility Issues

| Issue | Affected Systems | Resolution |
|-------|------------------|------------|
| TPM 2.0 measurement failure | Windows Server 2012/2012 R2 | July 2024 update blocks mitigations; wait for firmware update |
| Boot failure after Mitigation 3 | Various OEM systems | Check KB5025885 for specific models |
| BitLocker recovery triggered | All TPM-based systems | Normal behavior; save recovery keys beforehand |
| Hyper-V VM boot failure | Gen 2 VMs with old template | Update VM firmware settings |

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

#### Problem: "VM fails to boot after host update"

**Cause**: VM Secure Boot template mismatch.

**Solution** (Hyper-V):
```powershell
# Check current template
Get-VMFirmware -VMName "VMName" | Select-Object SecureBootTemplate

# Set correct template
Set-VMFirmware -VMName "VMName" -SecureBootTemplate "MicrosoftWindows"
```

#### Problem: "BitLocker recovery required after every boot"

**Cause**: TPM PCR values changed by Secure Boot updates.

**Solution**:
```powershell
# Suspend BitLocker temporarily
Suspend-BitLocker -MountPoint "C:" -RebootCount 3

# Apply mitigations
# BitLocker will re-seal to new PCR values after mitigations complete
Resume-BitLocker -MountPoint "C:"
```

### Diagnostic Commands

```powershell
# Complete system information
Get-ComputerInfo | Select-Object *SecureBoot*, *UEFI*, *Firmware*

# Check all Secure Boot variables
Get-SecureBootUEFI -Name PK
Get-SecureBootUEFI -Name KEK
Get-SecureBootUEFI -Name db
Get-SecureBootUEFI -Name dbx

# Check event log for Secure Boot events
Get-WinEvent -LogName "Microsoft-Windows-Kernel-Boot/Operational" |
    Where-Object {$_.Message -like "*Secure Boot*"} |
    Select-Object -First 20

# VM-specific diagnostics (run on VM)
Get-WmiObject -Class Win32_ComputerSystem | Select-Object Model, Manufacturer
```

---

## Resources and References

### Microsoft Official Documentation

- [Enterprise Deployment Guidance for CVE-2023-24932](https://support.microsoft.com/en-us/topic/enterprise-deployment-guidance-for-cve-2023-24932-88b8f034-20b7-4a45-80cb-c6049b0f9967)
- [How to manage Windows Boot Manager revocations for CVE-2023-24932](https://support.microsoft.com/en-us/topic/how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023-24932-41a975df-beb2-40c1-99a3-b3ff139f832d)
- [Revoking vulnerable Windows boot managers](https://techcommunity.microsoft.com/blog/windows-itpro-blog/revoking-vulnerable-windows-boot-managers/4121735)

### Virtual Machine Documentation

- [Hyper-V Secure Boot](https://docs.microsoft.com/en-us/windows-server/virtualization/hyper-v/learn-more/generation-2-virtual-machine-security-settings-for-hyper-v)

### Community Resources

- [GARYTOWN ConfigMgr Scripts](https://garytown.com/powershell-script-kb5025885-how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023-24932)
- [AJ's Tech Chatter - BlackLotus Remediation](https://anthonyfontanez.com/index.php/2025/05/18/dealing-with-cve-2023-24932-aka-remediating-blacklotus/)

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

### Hyper-V - Check VM Secure Boot

```powershell
Get-VMFirmware -VMName "VMName" | Select-Object SecureBoot, SecureBootTemplate
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
| **SVN** | Secure Version Number - prevents rollback attacks |
| **WinRE** | Windows Recovery Environment |
| **vTPM** | Virtual Trusted Platform Module |
| **Trusted Launch** | Azure security feature with Secure Boot and vTPM |

---

**Document Version:** 1.1
**Last Updated:** 2026-01-28
**Classification:** Internal Use
**Review Cycle:** Quarterly until June 2026

**Disclaimer:** This document is provided for informational purposes. Always test procedures in a non-production environment and consult official Microsoft documentation for the latest guidance.
