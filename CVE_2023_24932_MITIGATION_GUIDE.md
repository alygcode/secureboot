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

### Critical: Gen 1 vs Gen 2 Virtual Machines

**Generation 1 VMs are NOT affected by CVE-2023-24932 mitigations.** This is because Gen 1 VMs use legacy BIOS boot, not UEFI Secure Boot.

| VM Generation | Firmware Type | Secure Boot | Mitigations Required? |
|---------------|---------------|-------------|----------------------|
| **Generation 1** | BIOS (Legacy) | Not Supported | **NO** - Not applicable |
| **Generation 2** | UEFI | Supported | **YES** - If Secure Boot enabled |

#### How to Identify VM Generation

**Hyper-V (PowerShell on host):**
```powershell
# List all VMs with generation
Get-VM | Select-Object Name, Generation, State | Format-Table

# Check specific VM
Get-VM -Name "VMName" | Select-Object Name, Generation
```

**Inside the VM:**
```powershell
# Check firmware type
$firmware = Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty BootupState
$biosInfo = Get-WmiObject -Class Win32_BIOS

# If Secure Boot cmdlet works, it's UEFI (Gen 2)
try {
    $result = Confirm-SecureBootUEFI -ErrorAction Stop
    Write-Host "UEFI Firmware (Gen 2 VM) - Secure Boot: $result"
}
catch {
    Write-Host "BIOS Firmware (Gen 1 VM) - Secure Boot not supported"
}
```

**VMware (vSphere/PowerCLI):**
```powershell
# Check firmware type
Get-VM "VMName" | Get-AdvancedSetting -Name "firmware" | Select-Object Value
# "efi" = UEFI (mitigations apply)
# "bios" = Legacy (mitigations not applicable)
```

### VMs Without Secure Boot Enabled

**If Secure Boot is disabled, no mitigations are required.** The CVE-2023-24932 vulnerability only affects systems using Secure Boot.

#### Identifying VMs Without Secure Boot

**Script to audit all Hyper-V VMs:**
```powershell
# Run on Hyper-V host
$results = Get-VM | ForEach-Object {
    $vm = $_
    $fw = $null
    $secureBootStatus = "N/A"

    if ($vm.Generation -eq 2) {
        try {
            $fw = Get-VMFirmware -VMName $vm.Name -ErrorAction Stop
            $secureBootStatus = $fw.SecureBoot
        }
        catch {
            $secureBootStatus = "Error: $_"
        }
    }

    [PSCustomObject]@{
        VMName = $vm.Name
        Generation = $vm.Generation
        State = $vm.State
        SecureBoot = $secureBootStatus
        MitigationRequired = if ($vm.Generation -eq 1) { "No (Gen 1)" }
                            elseif ($secureBootStatus -eq "Off") { "No (SB Disabled)" }
                            elseif ($secureBootStatus -eq "On") { "YES" }
                            else { "Unknown" }
    }
}

$results | Format-Table -AutoSize

# Export for reporting
$results | Export-Csv -Path ".\VM-SecureBoot-Audit.csv" -NoTypeInformation
```

#### Decision Matrix for VMs

| Scenario | Action Required |
|----------|-----------------|
| Gen 1 VM (any hypervisor) | **None** - BIOS boot, not affected |
| Gen 2 VM with Secure Boot **OFF** | **None** - Not vulnerable to this CVE |
| Gen 2 VM with Secure Boot **ON** | **Apply mitigations** inside the VM |
| Gen 2 VM template | **Update template** with mitigations applied |
| Gen 2 VM being migrated VMware→Hyper-V | Apply mitigations **after** migration |

#### When to Enable Secure Boot vs. Leave Disabled

Consider enabling Secure Boot on Gen 2 VMs for security benefits, but weigh the implications:

**Enable Secure Boot if:**
- Running production Windows workloads
- Compliance requirements mandate it
- VM hosts sensitive data
- Part of a security-hardened deployment

**May leave Secure Boot disabled if:**
- Development/test environment
- Running unsigned boot components
- Compatibility issues with specific software
- Short-lived ephemeral VMs

### Reducing Reboot Count with Combined Registry Values

The CVE-2023-24932 mitigations normally require **4 separate reboots** (one per mitigation). Using combined registry values reduces this to **2 reboots**:

| Approach | Reboots Required | Registry Values |
|----------|------------------|-----------------|
| Individual mitigations | 4 reboots | 0x40, reboot, 0x100, reboot, 0x80, reboot, 0x200, reboot |
| Combined Phase 1 + Phase 2 | 2 reboots | 0x140, reboot, 0x280, reboot |

**Why Combined Values Work:**
- `0x140` = `0x40` (DB update) + `0x100` (Boot manager) applied together, one reboot
- `0x280` = `0x80` (DBX revocation) + `0x200` (SVN update) applied together, one reboot

**Recommended Deployment:**
```powershell
# Phase 1: Apply Mitigations 1 & 2 together (1 reboot)
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Secureboot /v AvailableUpdates /t REG_DWORD /d 0x140 /f
Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update"
Restart-Computer

# [After reboot, verify M1M2 complete, update boot media]

# Phase 2: Apply Mitigations 3 & 4 together (1 reboot)
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Secureboot /v AvailableUpdates /t REG_DWORD /d 0x280 /f
Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update"
Restart-Computer
```

**Important:** You cannot apply all 4 mitigations in a single reboot. Mitigations 1 & 2 must complete before 3 & 4 can be applied.

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

### Deployment Method Selection Guide

Choosing the right deployment method is critical for a successful rollout. The table below provides a quick comparison, followed by detailed guidance for each scenario.

#### Quick Comparison Matrix

| Method | Best For | BitLocker Handling | Rollback Control | Complexity | Recommended Priority |
|--------|----------|-------------------|------------------|------------|---------------------|
| **SCCM Task Sequence** | Full control, high-risk systems | **Built-in suspension** | Excellent | High | **1st Choice** (when available) |
| **SCCM Compliance Baseline** | Automated compliance monitoring | Manual prerequisite | Good | Medium | Monitoring companion |
| **SCCM Application** | Standard deployments | Via script | Good | Medium | 2nd Choice (SCCM environments) |
| **Intune Win32 App** | Cloud-managed devices | Via script | Limited | Medium | 1st Choice (Intune-only) |
| **Intune Proactive Remediation** | Compliance + auto-fix | Via script | Limited | Low | Monitoring + remediation |
| **Intune PowerShell Script** | Simple deployments | Via script | None | Low | Quick deployments |
| **GPO Startup Script** | On-premises, no SCCM/Intune | Via script | None | Low | Last resort |
| **GPO Registry Preference** | Partial automation | **None** | None | Low | **Not recommended alone** |

---

#### Detailed Deployment Method Recommendations

##### **1. SCCM Task Sequence - RECOMMENDED FOR CRITICAL SYSTEMS**

**Why Task Sequence is often the best choice:**

The SCCM Task Sequence method provides the **most comprehensive control** and is **strongly recommended** for:

| Scenario | Why Task Sequence |
|----------|-------------------|
| **BitLocker-encrypted systems** | Built-in `Suspend-BitLocker` step with configurable reboot count prevents recovery key prompts |
| **Production servers** | Granular step-by-step execution with checkpoints and rollback capability |
| **Mission-critical workstations** | Pre-flight checks, verification steps, and conditional logic |
| **Failover clusters** | Can integrate with cluster-aware updating and maintenance windows |
| **Complex environments** | Supports multiple conditions, dependencies, and custom logic |
| **Compliance requirements** | Full audit trail with task sequence execution history |

**Key advantages of Task Sequence:**

1. **BitLocker Integration**: The `Suspend-BitLocker -RebootCount 3` step is built into the sequence, ensuring BitLocker is suspended **before** any registry changes. Other methods require this as a prerequisite script.

2. **Atomic Operations**: If any step fails, the sequence can halt, roll back, or notify administrators before causing boot issues.

3. **Pre-flight Validation**: Built-in checks verify Secure Boot is enabled, Windows version is compatible, and firmware meets requirements.

4. **Phased Execution**: Natural support for running M1M2, waiting for verification, then running M3M4 in a controlled manner.

5. **State Capture**: Can store pre-mitigation state and automatically restore if issues occur.

**When to choose Task Sequence:**
```
✅ You have SCCM/ConfigMgr infrastructure
✅ Systems have BitLocker enabled
✅ You need maximum control and visibility
✅ Deploying to servers or critical workstations
✅ You want built-in rollback capability
✅ Compliance requires detailed audit trails
```

**When Task Sequence may be overkill:**
```
❌ Simple lab/test environments
❌ Small number of devices (<50)
❌ No SCCM infrastructure
❌ Time-constrained with low-risk devices
```

---

##### **2. SCCM Compliance Baseline - MONITORING & REPORTING**

**Use Compliance Baselines for:**

| Purpose | Description |
|---------|-------------|
| **Continuous monitoring** | Regularly checks mitigation status across fleet |
| **Compliance reporting** | Generates reports for auditors and management |
| **Auto-remediation** | Can trigger remediation scripts when non-compliant |
| **Dashboard visibility** | Integrates with SCCM reporting and Power BI |

**Best practice - Combine with Task Sequence:**
```
1. Deploy mitigations via Task Sequence (controlled rollout)
2. Monitor compliance via Baseline (ongoing verification)
3. Catch missed devices with Baseline auto-remediation
```

**Baseline alone is suitable for:**
```
✅ Environments where Task Sequence isn't feasible
✅ Low-risk devices (non-production, non-critical)
✅ Devices that may have missed initial deployment
✅ Ongoing compliance verification after initial rollout
```

**Limitations of Baseline-only deployment:**
```
⚠️ BitLocker suspension is in remediation script (less reliable)
⚠️ No step-by-step visibility during application
⚠️ Less granular control over timing and sequence
⚠️ Detection/remediation cycle can be slow (evaluation schedules)
```

---

##### **3. SCCM Application Package - STANDARD DEPLOYMENT**

**Use Application deployment when:**

| Scenario | Reason |
|----------|--------|
| Familiar deployment model | IT team prefers application-based deployments |
| Software Center availability | Users can self-service if approved |
| Supersedence tracking | Track M1M2 → M3M4 as application versions |
| Standard change management | Integrates with existing app deployment workflows |

**Application deployment is appropriate for:**
```
✅ Organizations standardized on SCCM Application model
✅ When Task Sequences are reserved for OS deployment only
✅ Devices with standard configurations
✅ When Software Center self-service is desired
```

**Considerations:**
```
⚠️ BitLocker handling is via install script (ensure it runs first)
⚠️ Less visibility into individual steps vs Task Sequence
⚠️ Detection method must be robust to avoid re-running
```

---

##### **4. Intune Win32 App - CLOUD-MANAGED DEVICES**

**Primary choice for Intune-managed environments:**

| Scenario | Why Win32 App |
|----------|---------------|
| **Azure AD joined devices** | Native Intune deployment method |
| **Co-managed with Intune workload** | When Software Updates workload is Intune |
| **Remote/hybrid workforce** | Devices connect directly to Intune |
| **Modern management** | Aligns with cloud-first strategy |

**When to use Win32 App:**
```
✅ Intune is primary management platform
✅ Devices are Azure AD joined or hybrid joined with Intune enrollment
✅ No SCCM infrastructure or co-management with Intune workload
✅ Need deployment tracking via Intune portal
```

**Important considerations:**
```
⚠️ BitLocker suspension is in install script (less atomic than TS)
⚠️ Reboot handling: Configure "Device restart behavior" appropriately
⚠️ Detection script must be accurate to prevent redeployment loops
⚠️ Limited rollback capability compared to Task Sequence
```

**Intune deployment tip:**
Configure the application with:
- Device restart behavior: **Intune will force a mandatory device restart**
- Or use **soft reboot (exit code 3010)** with user notification

---

##### **5. Intune Proactive Remediation - MONITOR + AUTO-FIX**

**Use Proactive Remediation for:**

| Purpose | Benefit |
|---------|---------|
| **Fleet-wide monitoring** | Runs on schedule across all devices |
| **Self-healing** | Automatically fixes non-compliant devices |
| **Compliance analytics** | Rich reporting in Endpoint Analytics |
| **Low-touch operation** | Set and forget with dashboards |

**Best practice - Combine approaches:**
```
1. Initial deployment via Win32 App (controlled rollout)
2. Ongoing monitoring via Proactive Remediation
3. Auto-remediation catches missed/new devices
```

**Proactive Remediation alone is suitable for:**
```
✅ Catching devices missed by initial deployment
✅ New devices that need mitigation after enrollment
✅ Ongoing compliance verification
✅ Environments wanting minimal admin intervention
```

**Limitations:**
```
⚠️ Runs on schedule (not immediate like targeted deployment)
⚠️ Less suitable for tightly controlled rollouts
⚠️ BitLocker handling depends on remediation script quality
```

---

##### **6. Intune PowerShell Script - SIMPLE DEPLOYMENT**

**Use for:**
- Quick deployment to small groups
- Testing/pilot groups
- Environments with simple requirements

**Limitations:**
```
⚠️ Scripts run once and aren't re-evaluated
⚠️ No built-in detection/rerun capability
⚠️ Limited reporting (success/failure only)
⚠️ No rollback mechanism
```

**Recommendation:** Use Win32 App or Proactive Remediation instead for production.

---

##### **7. GPO Deployment - TRADITIONAL ON-PREMISES**

**Use GPO when:**
```
✅ No SCCM or Intune infrastructure
✅ Traditional Active Directory environment
✅ Simple deployment requirements
✅ Limited management tooling
```

**GPO Method Comparison:**

| GPO Method | Reliability | BitLocker | Recommendation |
|------------|-------------|-----------|----------------|
| **Startup Script** | Good | Via script | **Recommended GPO method** |
| **Scheduled Task** | Good | Via script | Alternative to startup |
| **Registry Preference** | Partial | **None** | **Not recommended alone** |

**Why GPO Registry Preference is NOT recommended alone:**

The GPO Registry Preference method **only sets the registry value** - it does NOT:
- Suspend BitLocker (will cause recovery key prompts)
- Trigger the scheduled task (mitigations won't apply)
- Handle errors or verification

**If using GPO, always use the Startup Script method** which includes:
1. BitLocker suspension
2. Registry modification
3. Scheduled task trigger
4. Logging for troubleshooting

---

#### Decision Flowchart

Use this flowchart to select your deployment method:

```
                    ┌─────────────────────┐
                    │  Do you have SCCM?  │
                    └──────────┬──────────┘
                               │
              ┌────────────────┴────────────────┐
              │                                 │
             YES                               NO
              │                                 │
              ▼                                 ▼
    ┌─────────────────────┐         ┌─────────────────────┐
    │ Are devices BitLocker│         │  Do you have Intune? │
    │ encrypted or critical?│         └──────────┬──────────┘
    └──────────┬──────────┘                      │
               │                    ┌────────────┴────────────┐
    ┌──────────┴──────────┐         │                         │
    │                     │        YES                       NO
   YES                   NO         │                         │
    │                     │         ▼                         ▼
    ▼                     ▼  ┌─────────────────┐    ┌─────────────────┐
┌─────────────┐  ┌─────────────┐│ Win32 App for  │    │  GPO Startup    │
│ TASK SEQUENCE │  │ Compliance   ││ deployment +   │    │  Script         │
│ (Recommended)│  │ Baseline or  ││ Proactive      │    │                 │
│              │  │ Application  ││ Remediation for│    │                 │
│              │  │              ││ monitoring     │    │                 │
└─────────────┘  └─────────────┘└─────────────────┘    └─────────────────┘
```

---

#### Recommended Deployment Combinations

**Enterprise with SCCM (Recommended):**
| Phase | Method | Purpose |
|-------|--------|---------|
| Pilot | Task Sequence | Controlled testing with full visibility |
| Production | Task Sequence | Phased rollout with BitLocker handling |
| Monitoring | Compliance Baseline | Ongoing compliance verification |
| Reporting | SCCM Reports | Executive dashboards and audit trails |

**Cloud-First with Intune:**
| Phase | Method | Purpose |
|-------|--------|---------|
| Pilot | Win32 App (targeted group) | Test deployment process |
| Production | Win32 App (phased rings) | Controlled rollout |
| Monitoring | Proactive Remediation | Ongoing compliance + auto-fix |
| Reporting | Endpoint Analytics | Compliance dashboards |

**Traditional On-Premises:**
| Phase | Method | Purpose |
|-------|--------|---------|
| Pilot | Manual via PowerShell | Test commands |
| Production | GPO Startup Script | Automated deployment |
| Monitoring | PowerShell + scheduled task | Regular compliance checks |
| Reporting | Custom scripts | Generate compliance reports |

---

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

### Configuration Manager (SCCM/ConfigMgr) Deployment

Reference scripts available at: [garytown/ConfigMgr/Baselines/CVE-2023-24932](https://github.com/garytown/ConfigMgr)

#### SCCM Collections for Targeting

Create collections to target devices based on mitigation status:

```powershell
# Collection Query - Devices with Secure Boot Enabled
select SMS_R_SYSTEM.ResourceID, SMS_R_SYSTEM.ResourceType, SMS_R_SYSTEM.Name, SMS_R_SYSTEM.SMSUniqueIdentifier, SMS_R_SYSTEM.ResourceDomainORWorkgroup, SMS_R_SYSTEM.Client
from SMS_R_System
inner join SMS_G_System_FIRMWARE on SMS_G_System_FIRMWARE.ResourceID = SMS_R_System.ResourceId
where SMS_G_System_FIRMWARE.SecureBoot = 1

# Collection Query - Virtual Machines (Hyper-V)
select SMS_R_SYSTEM.ResourceID, SMS_R_SYSTEM.ResourceType, SMS_R_SYSTEM.Name, SMS_R_SYSTEM.SMSUniqueIdentifier
from SMS_R_System
inner join SMS_G_System_COMPUTER_SYSTEM on SMS_G_System_COMPUTER_SYSTEM.ResourceID = SMS_R_System.ResourceId
where SMS_G_System_COMPUTER_SYSTEM.Manufacturer = "Microsoft Corporation"
and SMS_G_System_COMPUTER_SYSTEM.Model = "Virtual Machine"

# Collection Query - VMware Virtual Machines
select SMS_R_SYSTEM.ResourceID, SMS_R_SYSTEM.ResourceType, SMS_R_SYSTEM.Name, SMS_R_SYSTEM.SMSUniqueIdentifier
from SMS_R_System
inner join SMS_G_System_COMPUTER_SYSTEM on SMS_G_System_COMPUTER_SYSTEM.ResourceID = SMS_R_System.ResourceId
where SMS_G_System_COMPUTER_SYSTEM.Manufacturer = "VMware, Inc."
```

#### SCCM Compliance Baseline - Mitigation 1 & 2 Detection

**Detection Script** (CI_Detect_CVE2023_24932_M1M2.ps1):
```powershell
<#
.SYNOPSIS
    Detects if CVE-2023-24932 Mitigations 1 & 2 are applied
.DESCRIPTION
    Checks for Windows UEFI CA 2023 in Secure Boot DB and new boot manager
.NOTES
    Return "Compliant" or "Non-Compliant"
#>

try {
    # Check if Secure Boot is enabled
    $secureBootEnabled = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
    if (-not $secureBootEnabled) {
        Write-Output "Non-Compliant: Secure Boot not enabled"
        exit 1
    }

    # Check Mitigation 1: PCA2023 in DB
    $dbBytes = (Get-SecureBootUEFI db -ErrorAction Stop).bytes
    $dbString = [System.Text.Encoding]::ASCII.GetString($dbBytes)
    $pca2023Enrolled = $dbString -match 'Windows UEFI CA 2023'

    if (-not $pca2023Enrolled) {
        Write-Output "Non-Compliant: Windows UEFI CA 2023 not in DB"
        exit 1
    }

    # Check Mitigation 2: New boot manager
    $efiPath = "$env:SystemDrive\EFI\Microsoft\Boot\bootmgfw.efi"
    if (-not (Test-Path $efiPath)) {
        # Try mounting EFI partition
        $null = mountvol S: /s 2>$null
        $efiPath = "S:\EFI\Microsoft\Boot\bootmgfw.efi"
    }

    if (Test-Path $efiPath) {
        $sig = Get-AuthenticodeSignature $efiPath -ErrorAction SilentlyContinue
        if ($sig.SignerCertificate.Subject -match "Windows UEFI CA 2023") {
            Write-Output "Compliant: Mitigations 1 & 2 applied"
            exit 0
        }
    }

    # Check registry for pending updates
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Secureboot"
    $availableUpdates = (Get-ItemProperty -Path $regPath -Name AvailableUpdates -ErrorAction SilentlyContinue).AvailableUpdates

    if ($availableUpdates -eq 0 -or $null -eq $availableUpdates) {
        Write-Output "Compliant: All mitigations complete"
        exit 0
    }

    Write-Output "Non-Compliant: Mitigations pending (AvailableUpdates: $availableUpdates)"
    exit 1
}
catch {
    Write-Output "Non-Compliant: Error checking status - $_"
    exit 1
}
```

**Remediation Script** (CI_Remediate_CVE2023_24932_M1M2.ps1):
```powershell
<#
.SYNOPSIS
    Applies CVE-2023-24932 Mitigations 1 & 2
.DESCRIPTION
    Sets registry value and triggers Secure Boot update task
.NOTES
    Requires reboot to complete. Returns exit code 3010 for soft reboot.
#>

$LogPath = "$env:ProgramData\Microsoft\CVE-2023-24932"
$LogFile = "$LogPath\Remediation_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $Message" | Out-File -FilePath $LogFile -Append
    Write-Output $Message
}

try {
    # Create log directory
    if (-not (Test-Path $LogPath)) {
        New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
    }

    Write-Log "Starting CVE-2023-24932 Mitigation 1 & 2 remediation"

    # Verify Secure Boot is enabled
    $secureBootEnabled = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
    if (-not $secureBootEnabled) {
        Write-Log "ERROR: Secure Boot is not enabled. Cannot apply mitigations."
        exit 1
    }

    # Check current status
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Secureboot"
    $currentValue = (Get-ItemProperty -Path $regPath -Name AvailableUpdates -ErrorAction SilentlyContinue).AvailableUpdates
    Write-Log "Current AvailableUpdates value: $currentValue"

    # Apply Mitigations 1 + 2 (0x140 = 0x40 + 0x100)
    $targetValue = 0x140
    Write-Log "Setting AvailableUpdates to 0x140 (Mitigations 1 + 2)"

    Set-ItemProperty -Path $regPath -Name AvailableUpdates -Value $targetValue -Type DWord -Force
    Write-Log "Registry value set successfully"

    # Trigger the scheduled task
    Write-Log "Triggering Secure-Boot-Update scheduled task"
    $task = Get-ScheduledTask -TaskName "Secure-Boot-Update" -TaskPath "\Microsoft\Windows\PI\" -ErrorAction Stop
    Start-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath

    # Wait for task to complete
    Start-Sleep -Seconds 10
    $taskInfo = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath
    Write-Log "Task last run result: $($taskInfo.LastTaskResult)"

    Write-Log "Remediation complete. Reboot required to finalize mitigations."

    # Return 3010 (soft reboot required)
    exit 3010
}
catch {
    Write-Log "ERROR: Remediation failed - $_"
    exit 1
}
```

#### SCCM Compliance Baseline - Mitigation 3 & 4 Detection

**Detection Script** (CI_Detect_CVE2023_24932_M3M4.ps1):
```powershell
<#
.SYNOPSIS
    Detects if CVE-2023-24932 Mitigations 3 & 4 are applied
.DESCRIPTION
    Checks for DBX revocation and SVN update
.NOTES
    Only run this AFTER Mitigations 1 & 2 are confirmed and boot media updated
#>

try {
    # Check if M1M2 are already applied
    $dbBytes = (Get-SecureBootUEFI db -ErrorAction Stop).bytes
    $dbString = [System.Text.Encoding]::ASCII.GetString($dbBytes)

    if (-not ($dbString -match 'Windows UEFI CA 2023')) {
        Write-Output "Non-Compliant: Mitigations 1 & 2 must be applied first"
        exit 1
    }

    # Check registry for completion status
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Secureboot"
    $availableUpdates = (Get-ItemProperty -Path $regPath -Name AvailableUpdates -ErrorAction SilentlyContinue).AvailableUpdates

    if ($availableUpdates -eq 0 -or $null -eq $availableUpdates) {
        Write-Output "Compliant: All mitigations (including 3 & 4) complete"
        exit 0
    }

    # Check if only M3M4 pending (0x80 + 0x200 = 0x280)
    if (($availableUpdates -band 0x280) -ne 0) {
        Write-Output "Non-Compliant: Mitigations 3 & 4 pending"
        exit 1
    }

    Write-Output "Compliant: Mitigations 3 & 4 applied"
    exit 0
}
catch {
    Write-Output "Non-Compliant: Error checking status - $_"
    exit 1
}
```

**Remediation Script** (CI_Remediate_CVE2023_24932_M3M4.ps1):
```powershell
<#
.SYNOPSIS
    Applies CVE-2023-24932 Mitigations 3 & 4 (DBX revocation + SVN)
.DESCRIPTION
    WARNING: This is IRREVERSIBLE. Old boot media will stop working.
.NOTES
    Only deploy after confirming boot media has been updated.
#>

$LogPath = "$env:ProgramData\Microsoft\CVE-2023-24932"
$LogFile = "$LogPath\Remediation_M3M4_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $Message" | Out-File -FilePath $LogFile -Append
    Write-Output $Message
}

try {
    if (-not (Test-Path $LogPath)) {
        New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
    }

    Write-Log "Starting CVE-2023-24932 Mitigation 3 & 4 remediation"
    Write-Log "WARNING: This operation is IRREVERSIBLE"

    # Verify M1M2 are already applied
    $dbBytes = (Get-SecureBootUEFI db -ErrorAction Stop).bytes
    $dbString = [System.Text.Encoding]::ASCII.GetString($dbBytes)

    if (-not ($dbString -match 'Windows UEFI CA 2023')) {
        Write-Log "ERROR: Mitigations 1 & 2 must be applied first. Aborting."
        exit 1
    }

    Write-Log "Mitigations 1 & 2 confirmed. Proceeding with 3 & 4."

    # Apply Mitigations 3 + 4 (0x280 = 0x80 + 0x200)
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Secureboot"
    Set-ItemProperty -Path $regPath -Name AvailableUpdates -Value 0x280 -Type DWord -Force
    Write-Log "Registry set to 0x280 (Mitigations 3 + 4)"

    # Trigger scheduled task
    $task = Get-ScheduledTask -TaskName "Secure-Boot-Update" -TaskPath "\Microsoft\Windows\PI\" -ErrorAction Stop
    Start-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath
    Start-Sleep -Seconds 10

    Write-Log "Remediation complete. Reboot required."
    exit 3010
}
catch {
    Write-Log "ERROR: Remediation failed - $_"
    exit 1
}
```

#### SCCM Task Sequence for Mitigation Deployment

Create a Task Sequence with the following steps:

**Task Sequence Steps:**

1. **Check Prerequisites** (PowerShell)
```powershell
# TS Step: Check Prerequisites
$secureBootEnabled = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
if (-not $secureBootEnabled) {
    Write-Host "Secure Boot not enabled - skipping mitigations"
    $tsenv = New-Object -ComObject Microsoft.SMS.TSEnvironment
    $tsenv.Value("SkipMitigations") = "True"
}
else {
    $tsenv = New-Object -ComObject Microsoft.SMS.TSEnvironment
    $tsenv.Value("SkipMitigations") = "False"
}
```

2. **Suspend BitLocker** (PowerShell) - Condition: SkipMitigations != True
```powershell
# TS Step: Suspend BitLocker
$bitlockerVolume = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
if ($bitlockerVolume.ProtectionStatus -eq "On") {
    Suspend-BitLocker -MountPoint "C:" -RebootCount 3
    Write-Host "BitLocker suspended for 3 reboots"
}
```

3. **Apply Mitigations 1 & 2** (PowerShell) - Condition: SkipMitigations != True
```powershell
# TS Step: Apply Mitigations 1 & 2
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Secureboot"
Set-ItemProperty -Path $regPath -Name AvailableUpdates -Value 0x140 -Type DWord -Force

# Trigger update task
Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update"
Start-Sleep -Seconds 15
```

4. **Restart Computer** - Standard TS action

5. **Verify Mitigations** (PowerShell) - After restart
```powershell
# TS Step: Verify Mitigations
$dbBytes = (Get-SecureBootUEFI db).bytes
$dbString = [System.Text.Encoding]::ASCII.GetString($dbBytes)

if ($dbString -match 'Windows UEFI CA 2023') {
    Write-Host "SUCCESS: Mitigations 1 & 2 applied"
    $tsenv = New-Object -ComObject Microsoft.SMS.TSEnvironment
    $tsenv.Value("MitigationSuccess") = "True"
}
else {
    Write-Host "FAILED: Mitigations not applied"
    $tsenv.Value("MitigationSuccess") = "False"
}
```

#### SCCM Application Deployment Package

Create an Application with detection method and installation script:

**Detection Method** (PowerShell):
```powershell
$dbBytes = (Get-SecureBootUEFI db -ErrorAction SilentlyContinue).bytes
if ($dbBytes) {
    $dbString = [System.Text.Encoding]::ASCII.GetString($dbBytes)
    if ($dbString -match 'Windows UEFI CA 2023') {
        Write-Host "Detected"
        exit 0
    }
}
exit 1
```

**Installation Script** (Install-CVE2023-24932-Mitigation.ps1):
```powershell
<#
.SYNOPSIS
    SCCM Application installer for CVE-2023-24932 mitigations
.PARAMETER MitigationPhase
    1 = Mitigations 1 & 2 only (safe, reversible)
    2 = Mitigations 3 & 4 (IRREVERSIBLE - only after boot media updated)
#>
param(
    [Parameter(Mandatory=$false)]
    [ValidateSet(1,2)]
    [int]$MitigationPhase = 1
)

$ExitCode = 0
$LogPath = "$env:ProgramData\Microsoft\CVE-2023-24932"
$LogFile = "$LogPath\Install_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $Message" | Out-File -FilePath $LogFile -Append
}

try {
    New-Item -ItemType Directory -Path $LogPath -Force -ErrorAction SilentlyContinue | Out-Null
    Write-Log "Starting installation - Phase $MitigationPhase"

    # Verify Secure Boot
    if (-not (Confirm-SecureBootUEFI -ErrorAction SilentlyContinue)) {
        Write-Log "Secure Boot not enabled - exiting"
        exit 0  # Success - not applicable
    }

    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Secureboot"

    switch ($MitigationPhase) {
        1 {
            Write-Log "Applying Mitigations 1 & 2 (0x140)"
            Set-ItemProperty -Path $regPath -Name AvailableUpdates -Value 0x140 -Type DWord -Force
        }
        2 {
            # Verify M1M2 complete first
            $dbBytes = (Get-SecureBootUEFI db).bytes
            $dbString = [System.Text.Encoding]::ASCII.GetString($dbBytes)
            if (-not ($dbString -match 'Windows UEFI CA 2023')) {
                Write-Log "ERROR: M1M2 not complete. Cannot proceed with M3M4."
                exit 1
            }
            Write-Log "Applying Mitigations 3 & 4 (0x280) - IRREVERSIBLE"
            Set-ItemProperty -Path $regPath -Name AvailableUpdates -Value 0x280 -Type DWord -Force
        }
    }

    # Trigger update
    Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update"
    Start-Sleep -Seconds 10

    Write-Log "Installation complete - reboot required"
    $ExitCode = 3010  # Soft reboot required
}
catch {
    Write-Log "ERROR: $_"
    $ExitCode = 1
}

exit $ExitCode
```

### Intune Deployment

#### Intune Win32 App Package

**Package Structure:**
```
CVE-2023-24932-Mitigation/
├── Install-CVE2023-24932.ps1      # Install script
├── Detect-CVE2023-24932.ps1       # Detection script
├── Uninstall-CVE2023-24932.ps1    # Uninstall (informational only)
└── CVE2023-24932.intunewin        # Packaged app
```

**Install Script** (Install-CVE2023-24932.ps1):
```powershell
<#
.SYNOPSIS
    Intune Win32 App - Applies CVE-2023-24932 Mitigations 1 & 2
.DESCRIPTION
    Deployed via Intune as Win32 app. Applies safe mitigations only.
    Mitigations 3 & 4 require separate deployment after boot media update.
#>

$LogPath = "$env:ProgramData\Microsoft\IntuneManagementExtension\Logs"
$LogFile = "$LogPath\CVE-2023-24932_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $Message" | Tee-Object -FilePath $LogFile -Append
}

try {
    Write-Log "=== CVE-2023-24932 Mitigation Installation Started ==="

    # Check if device is virtual or physical
    $computerSystem = Get-WmiObject -Class Win32_ComputerSystem
    $isVirtual = $computerSystem.Model -match "Virtual|VMware|HVM|Xen"
    Write-Log "Device Type: $(if ($isVirtual) {'Virtual Machine'} else {'Physical'})"
    Write-Log "Manufacturer: $($computerSystem.Manufacturer)"
    Write-Log "Model: $($computerSystem.Model)"

    # Check Secure Boot status
    $secureBootEnabled = $false
    try {
        $secureBootEnabled = Confirm-SecureBootUEFI
    }
    catch {
        Write-Log "Secure Boot check failed: $_"
    }

    if (-not $secureBootEnabled) {
        Write-Log "Secure Boot is NOT enabled. Mitigations not applicable."
        Write-Log "This device does not require Secure Boot mitigations."
        # Create marker file indicating device was processed
        $markerPath = "$env:ProgramData\Microsoft\CVE-2023-24932"
        New-Item -ItemType Directory -Path $markerPath -Force -ErrorAction SilentlyContinue | Out-Null
        "SecureBootDisabled" | Out-File "$markerPath\status.txt" -Force
        exit 0  # Success - not applicable
    }

    Write-Log "Secure Boot is ENABLED. Proceeding with mitigations."

    # Check current mitigation status
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Secureboot"
    $currentStatus = (Get-ItemProperty -Path $regPath -Name AvailableUpdates -ErrorAction SilentlyContinue).AvailableUpdates
    Write-Log "Current AvailableUpdates: $currentStatus"

    # Check if PCA2023 already enrolled
    $dbBytes = (Get-SecureBootUEFI db -ErrorAction SilentlyContinue).bytes
    if ($dbBytes) {
        $dbString = [System.Text.Encoding]::ASCII.GetString($dbBytes)
        if ($dbString -match 'Windows UEFI CA 2023') {
            Write-Log "Windows UEFI CA 2023 already enrolled. Mitigations 1 & 2 complete."
            exit 0
        }
    }

    # Suspend BitLocker if enabled
    $bitlockerVolume = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
    if ($bitlockerVolume -and $bitlockerVolume.ProtectionStatus -eq "On") {
        Write-Log "Suspending BitLocker for 3 reboots"
        Suspend-BitLocker -MountPoint "C:" -RebootCount 3
    }

    # Apply Mitigations 1 + 2
    Write-Log "Setting AvailableUpdates to 0x140 (Mitigations 1 + 2)"
    Set-ItemProperty -Path $regPath -Name AvailableUpdates -Value 0x140 -Type DWord -Force

    # Verify registry was set
    $newStatus = (Get-ItemProperty -Path $regPath -Name AvailableUpdates).AvailableUpdates
    Write-Log "New AvailableUpdates value: $newStatus (expected: 320 / 0x140)"

    # Trigger the scheduled task
    Write-Log "Triggering Secure-Boot-Update scheduled task"
    $task = Get-ScheduledTask -TaskName "Secure-Boot-Update" -TaskPath "\Microsoft\Windows\PI\" -ErrorAction Stop
    Start-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath
    Start-Sleep -Seconds 15

    # Check task result
    $taskInfo = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath
    Write-Log "Task last run time: $($taskInfo.LastRunTime)"
    Write-Log "Task last result: $($taskInfo.LastTaskResult)"

    # Create status marker
    $markerPath = "$env:ProgramData\Microsoft\CVE-2023-24932"
    New-Item -ItemType Directory -Path $markerPath -Force -ErrorAction SilentlyContinue | Out-Null
    @{
        AppliedDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Phase = "M1M2"
        Status = "PendingReboot"
    } | ConvertTo-Json | Out-File "$markerPath\status.json" -Force

    Write-Log "Installation complete. REBOOT REQUIRED to finalize mitigations."
    Write-Log "=== Installation Finished ==="

    exit 3010  # Soft reboot required
}
catch {
    Write-Log "ERROR: Installation failed - $_"
    Write-Log $_.ScriptStackTrace
    exit 1
}
```

**Detection Script** (Detect-CVE2023-24932.ps1):
```powershell
<#
.SYNOPSIS
    Intune Detection Script for CVE-2023-24932 Mitigations
.DESCRIPTION
    Returns exit 0 if mitigations applied OR if device doesn't need them
#>

try {
    # Check if Secure Boot is enabled
    $secureBootEnabled = $false
    try {
        $secureBootEnabled = Confirm-SecureBootUEFI
    }
    catch {
        # Secure Boot not supported
    }

    if (-not $secureBootEnabled) {
        # Device doesn't need mitigations - check for marker file
        $markerFile = "$env:ProgramData\Microsoft\CVE-2023-24932\status.txt"
        if (Test-Path $markerFile) {
            Write-Host "Detected: Secure Boot disabled - mitigations not required"
            exit 0
        }
        exit 1  # Need to run installer to create marker
    }

    # Check if PCA2023 is enrolled
    $dbBytes = (Get-SecureBootUEFI db -ErrorAction SilentlyContinue).bytes
    if ($dbBytes) {
        $dbString = [System.Text.Encoding]::ASCII.GetString($dbBytes)
        if ($dbString -match 'Windows UEFI CA 2023') {
            Write-Host "Detected: Windows UEFI CA 2023 enrolled"
            exit 0
        }
    }

    # Not detected
    exit 1
}
catch {
    exit 1
}
```

#### Intune Proactive Remediations

**Remediation Package 1: Mitigations 1 & 2**

**Detection Script** (ProactiveRemediation-Detect-M1M2.ps1):
```powershell
<#
.SYNOPSIS
    Proactive Remediation - Detect if M1M2 mitigations needed
#>

try {
    # Skip if Secure Boot not enabled
    if (-not (Confirm-SecureBootUEFI -ErrorAction SilentlyContinue)) {
        Write-Host "Secure Boot not enabled - compliant (not applicable)"
        exit 0
    }

    # Check for PCA2023
    $dbBytes = (Get-SecureBootUEFI db).bytes
    $dbString = [System.Text.Encoding]::ASCII.GetString($dbBytes)

    if ($dbString -match 'Windows UEFI CA 2023') {
        Write-Host "Compliant: Windows UEFI CA 2023 enrolled"
        exit 0
    }

    Write-Host "Non-compliant: Mitigations 1 & 2 needed"
    exit 1
}
catch {
    Write-Host "Error: $_"
    exit 1
}
```

**Remediation Script** (ProactiveRemediation-Remediate-M1M2.ps1):
```powershell
<#
.SYNOPSIS
    Proactive Remediation - Apply M1M2 mitigations
#>

$LogPath = "$env:ProgramData\Microsoft\CVE-2023-24932"
$LogFile = "$LogPath\ProactiveRemediation_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

function Write-Log {
    param([string]$Message)
    "$((Get-Date).ToString('s')) - $Message" | Out-File -FilePath $LogFile -Append
}

try {
    New-Item -ItemType Directory -Path $LogPath -Force -ErrorAction SilentlyContinue | Out-Null
    Write-Log "Starting Proactive Remediation for CVE-2023-24932"

    # Double-check Secure Boot
    if (-not (Confirm-SecureBootUEFI)) {
        Write-Log "Secure Boot not enabled - skipping"
        Write-Host "Secure Boot not enabled"
        exit 0
    }

    # Suspend BitLocker
    $blv = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
    if ($blv -and $blv.ProtectionStatus -eq "On") {
        Write-Log "Suspending BitLocker"
        Suspend-BitLocker -MountPoint "C:" -RebootCount 3
    }

    # Apply mitigations
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Secureboot"
    Set-ItemProperty -Path $regPath -Name AvailableUpdates -Value 0x140 -Type DWord -Force
    Write-Log "Set AvailableUpdates to 0x140"

    # Trigger task
    Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update"
    Start-Sleep -Seconds 10
    Write-Log "Triggered Secure-Boot-Update task"

    Write-Host "Remediation applied - reboot required"
    Write-Log "Remediation complete"
    exit 0
}
catch {
    Write-Log "ERROR: $_"
    Write-Host "Remediation failed: $_"
    exit 1
}
```

**Remediation Package 2: Compliance Reporting**

**Detection Script** (ProactiveRemediation-Inventory.ps1):
```powershell
<#
.SYNOPSIS
    Proactive Remediation - Inventory CVE-2023-24932 status for reporting
.DESCRIPTION
    Always returns "compliant" but outputs detailed status for Intune analytics
#>

$output = @{
    ComputerName = $env:COMPUTERNAME
    Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
}

try {
    # Device info
    $cs = Get-WmiObject Win32_ComputerSystem
    $output.IsVirtual = $cs.Model -match "Virtual|VMware|HVM|Xen"
    $output.Manufacturer = $cs.Manufacturer
    $output.Model = $cs.Model

    # Secure Boot status
    try {
        $output.SecureBootEnabled = Confirm-SecureBootUEFI
    }
    catch {
        $output.SecureBootEnabled = $false
        $output.SecureBootError = $_.Exception.Message
    }

    if ($output.SecureBootEnabled) {
        # Check mitigations
        $dbBytes = (Get-SecureBootUEFI db -ErrorAction Stop).bytes
        $dbString = [System.Text.Encoding]::ASCII.GetString($dbBytes)
        $output.PCA2023Enrolled = $dbString -match 'Windows UEFI CA 2023'

        # Registry status
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Secureboot"
        $availableUpdates = (Get-ItemProperty -Path $regPath -Name AvailableUpdates -ErrorAction SilentlyContinue).AvailableUpdates
        $output.AvailableUpdates = $availableUpdates

        # Determine status
        if ($output.PCA2023Enrolled -and ($availableUpdates -eq 0 -or $null -eq $availableUpdates)) {
            $output.MitigationStatus = "Complete"
        }
        elseif ($output.PCA2023Enrolled) {
            $output.MitigationStatus = "M1M2Complete-M3M4Pending"
        }
        else {
            $output.MitigationStatus = "NotStarted"
        }
    }
    else {
        $output.MitigationStatus = "NotApplicable-SecureBootDisabled"
    }

    # Output for Intune analytics
    $json = $output | ConvertTo-Json -Compress
    Write-Host $json
    exit 0  # Always compliant - this is for reporting only
}
catch {
    $output.Error = $_.Exception.Message
    Write-Host ($output | ConvertTo-Json -Compress)
    exit 0
}
```

#### Intune PowerShell Script Deployment

For simpler deployment, use Intune's native PowerShell script feature:

**Script Settings:**
- Run this script using the logged-on credentials: No
- Enforce script signature check: No
- Run script in 64-bit PowerShell: Yes

**Script Content** (Intune-Deploy-CVE2023-24932.ps1):
```powershell
<#
.SYNOPSIS
    Intune PowerShell Script - CVE-2023-24932 Mitigation Deployment
.DESCRIPTION
    Deploys Mitigations 1 & 2 via Intune PowerShell script.
    Runs in SYSTEM context.
#>

# Transcript for troubleshooting
$TranscriptPath = "$env:ProgramData\Microsoft\IntuneManagementExtension\Logs\CVE2023-24932_Transcript.log"
Start-Transcript -Path $TranscriptPath -Force

Write-Host "=== CVE-2023-24932 Mitigation Script ==="
Write-Host "Computer: $env:COMPUTERNAME"
Write-Host "Date: $(Get-Date)"

try {
    # Check Secure Boot
    $secureBootEnabled = $false
    try {
        $secureBootEnabled = Confirm-SecureBootUEFI
        Write-Host "Secure Boot Status: $secureBootEnabled"
    }
    catch {
        Write-Host "Secure Boot check error: $_"
    }

    if (-not $secureBootEnabled) {
        Write-Host "Secure Boot not enabled. No action required."
        Stop-Transcript
        exit 0
    }

    # Check current status
    $dbBytes = (Get-SecureBootUEFI db).bytes
    $dbString = [System.Text.Encoding]::ASCII.GetString($dbBytes)

    if ($dbString -match 'Windows UEFI CA 2023') {
        Write-Host "Windows UEFI CA 2023 already enrolled. Mitigations complete."
        Stop-Transcript
        exit 0
    }

    Write-Host "Applying Mitigations 1 & 2..."

    # Suspend BitLocker
    $blv = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
    if ($blv -and $blv.ProtectionStatus -eq "On") {
        Write-Host "Suspending BitLocker"
        Suspend-BitLocker -MountPoint "C:" -RebootCount 3
    }

    # Set registry
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Secureboot"
    Set-ItemProperty -Path $regPath -Name AvailableUpdates -Value 0x140 -Type DWord -Force
    Write-Host "Registry set to 0x140"

    # Trigger update
    Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update"
    Write-Host "Scheduled task triggered"

    # Schedule reboot (optional - Intune can handle this)
    # shutdown /r /t 3600 /c "CVE-2023-24932 mitigation - reboot in 1 hour"

    Write-Host "Mitigation applied. Reboot required."
    Stop-Transcript
    exit 0
}
catch {
    Write-Host "ERROR: $_"
    Stop-Transcript
    exit 1
}
```

### Group Policy (GPO) Deployment

For environments using Group Policy:

#### GPO Startup Script Method

Create a Computer Startup Script:

**Script** (GPO-CVE2023-24932-Startup.ps1):
```powershell
<#
.SYNOPSIS
    GPO Startup Script for CVE-2023-24932 Mitigations
.DESCRIPTION
    Runs at computer startup to apply mitigations if not already applied.
    Log file: C:\Windows\Logs\CVE-2023-24932-GPO.log
#>

$LogFile = "C:\Windows\Logs\CVE-2023-24932-GPO.log"

function Write-Log {
    param([string]$Message)
    "$((Get-Date).ToString('s')) - $Message" | Out-File -FilePath $LogFile -Append
}

try {
    Write-Log "=== GPO Startup Script Execution ==="

    # Skip if not Secure Boot
    if (-not (Confirm-SecureBootUEFI -ErrorAction SilentlyContinue)) {
        Write-Log "Secure Boot not enabled - skipping"
        exit 0
    }

    # Check if already complete
    $dbBytes = (Get-SecureBootUEFI db).bytes
    $dbString = [System.Text.Encoding]::ASCII.GetString($dbBytes)

    if ($dbString -match 'Windows UEFI CA 2023') {
        Write-Log "Mitigations already applied"
        exit 0
    }

    Write-Log "Applying Mitigations 1 & 2"

    # Suspend BitLocker
    $blv = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
    if ($blv -and $blv.ProtectionStatus -eq "On") {
        Suspend-BitLocker -MountPoint "C:" -RebootCount 2
        Write-Log "BitLocker suspended"
    }

    # Apply mitigations
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Secureboot"
    Set-ItemProperty -Path $regPath -Name AvailableUpdates -Value 0x140 -Type DWord -Force

    # Trigger task
    Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update"

    Write-Log "Mitigations applied - will complete on next reboot"
    exit 0
}
catch {
    Write-Log "ERROR: $_"
    exit 1
}
```

#### GPO Scheduled Task Method

Create a GPO with a Scheduled Task (Computer Configuration > Preferences > Control Panel Settings > Scheduled Tasks):

**Task Settings:**
- Name: CVE-2023-24932 Mitigation
- Trigger: At startup, delay 5 minutes
- Action: Start a program
- Program: powershell.exe
- Arguments: `-ExecutionPolicy Bypass -NoProfile -File "\\domain.com\NETLOGON\Scripts\CVE2023-24932-Mitigation.ps1"`
- Run as: SYSTEM
- Run with highest privileges: Yes

#### GPO Registry Preferences (Alternative)

For direct registry deployment without scripts:

**Computer Configuration > Preferences > Windows Settings > Registry**

| Action | Hive | Key Path | Value Name | Type | Value |
|--------|------|----------|------------|------|-------|
| Update | HKLM | SYSTEM\CurrentControlSet\Control\Secureboot | AvailableUpdates | REG_DWORD | 0x140 |

**Item-Level Targeting:**
- Add targeting for: "The computer is a member of the security group" → "CVE-2023-24932-Mitigation-Enabled"

**Note:** Registry preference alone won't trigger the scheduled task. Combine with a startup script or scheduled task to run `Start-ScheduledTask`.

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
