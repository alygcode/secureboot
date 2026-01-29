# Enterprise Deployment Guide for CVE-2023-24932

Deployment strategies and scripts for SCCM, Intune, and Group Policy environments.

## Deployment Method Selection

### Quick Comparison Matrix

| Method | Best For | BitLocker Handling | Rollback Control | Complexity |
|--------|----------|-------------------|------------------|------------|
| **Firmware-Led (OEM BIOS)** | Dell/Lenovo fleets | N/A (pre-boot) | N/A | Low |
| **SCCM Task Sequence** | High-risk systems | Built-in suspension | Excellent | High |
| **SCCM Compliance Baseline** | Automated monitoring | Manual prerequisite | Good | Medium |
| **SCCM Application** | Standard deployments | Via script | Good | Medium |
| **Intune Win32 App** | Cloud-managed devices | Via script | Limited | Medium |
| **Intune Proactive Remediation** | Compliance + auto-fix | Via script | Limited | Low |
| **GPO Startup Script** | On-premises, no SCCM/Intune | Via script | None | Low |

### Decision Flowchart

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
    │ BitLocker or        │         │  Do you have Intune? │
    │ critical systems?   │         └──────────┬──────────┘
    └──────────┬──────────┘                    │
               │                    ┌──────────┴──────────┐
    ┌──────────┴──────────┐         │                     │
   YES                   NO        YES                   NO
    │                     │         │                     │
    ▼                     ▼         ▼                     ▼
┌─────────────┐  ┌─────────────┐ ┌─────────────┐  ┌─────────────┐
│ TASK        │  │ Compliance  │ │ Win32 App + │  │ GPO Startup │
│ SEQUENCE    │  │ Baseline or │ │ Proactive   │  │ Script      │
│             │  │ Application │ │ Remediation │  │             │
└─────────────┘  └─────────────┘ └─────────────┘  └─────────────┘
```

---

## Firmware-Led Deployment (OEM BIOS Updates)

For organizations with Dell or Lenovo hardware, OEM BIOS updates that include the Windows UEFI CA 2023 and KEK 2K CA 2023 certificates natively can simplify the transition. The firmware delivers the 2023 keys at the BIOS level, eliminating the need for Mitigation 1 (DB enrollment via Windows).

### OEM Readiness Summary

| OEM | Status | Management Tool | Notes |
|-----|--------|----------------|-------|
| **Dell** | Shipping 2023 certs since late 2024; all sustaining platforms by end 2025 | Dell Command Update, SCCM driver packs | Dual-certificate strategy (2011 + 2023). No end date announced for dual support. |
| **Lenovo** | Proactively included across all systems | Lenovo System Update, Thin Installer | Transition without disabling Secure Boot. |
| **HP** | Many devices still 2011-only (as of mid-2025) | HP Sure Start, HP Client Management | Sure Start devices need specific BIOS updates. Check HP support per model. |

### When to Use Firmware-Led

```
Use Firmware-Led when:
  - Fleet is predominantly Dell or Lenovo
  - BIOS management tools are already deployed (DCU, Thin Installer)
  - You want to reduce the number of Windows-side registry steps
  - New devices are being provisioned (keys present from factory)

Use Windows-Led instead when:
  - HP devices or mixed OEM fleet
  - No BIOS management infrastructure
  - Virtual machines (firmware keys managed by hypervisor)
  - Devices at End of Service Life (may not get BIOS updates)
```

### Firmware-Led Deployment Strategy

#### Phase 1: BIOS Inventory and Update

1. **Inventory BIOS versions** across the fleet:

```powershell
# Collect OEM and BIOS info for fleet analysis
$info = [PSCustomObject]@{
    ComputerName = $env:COMPUTERNAME
    Manufacturer = (Get-WmiObject Win32_ComputerSystem).Manufacturer
    Model = (Get-WmiObject Win32_ComputerSystem).Model
    BIOSVersion = (Get-WmiObject Win32_BIOS).SMBIOSBIOSVersion
    BIOSDate = (Get-WmiObject Win32_BIOS).ReleaseDate
}
$info | ConvertTo-Json
```

2. **Deploy BIOS updates** using OEM tools:

**Dell (via SCCM):**
- Download Dell BIOS packages from Dell TechDirect
- Create SCCM Application or Task Sequence step
- Use Dell Command Update CLI: `dcu-cli.exe /applyUpdates -updateType=bios -reboot=enable`

**Dell (via Intune):**
- Package Dell Command Update as Win32 app
- Or use Dell BIOS Update .exe with `/s /r` silent switches

**Lenovo (via SCCM):**
- Download from Lenovo Update Retriever
- Use Thin Installer: `ThinInstaller.exe /CM /INCLUDEREBOOTPACKAGES 3`

**Lenovo (via Intune):**
- Package Lenovo System Update or Thin Installer as Win32 app
- Or use Lenovo BIOS Update Utility with `/SILENT` switch

3. **Verify keys after BIOS update**:

```powershell
.\scripts\verification\Test-OEMFirmwareKeys.ps1
```

#### Phase 2: Apply Remaining Mitigations (M2-M4)

After BIOS updates are deployed and keys verified, apply the remaining Windows-side mitigations using any deployment method (SCCM, Intune, GPO):

- **M2 only** (0x100) — Boot manager update
- Then after boot media refresh: **M3 + M4** (0x280) — Revocation and SVN

> **Tip:** You can safely use the combined 0x140 value even if M1 is firmware-delivered. Windows detects the existing DB entry and skips M1 automatically.

#### Hybrid Fleet Strategy

For organizations with mixed Dell/Lenovo and HP hardware:

| Device Type | Strategy |
|-------------|----------|
| Dell (with 2023 BIOS) | Firmware-Led: BIOS update → verify keys → M2 → M3M4 |
| Lenovo (with 2023 BIOS) | Firmware-Led: BIOS update → verify keys → M2 → M3M4 |
| HP (2011-only BIOS) | Windows-Led: M1M2 via registry → M3M4 |
| VMs (any hypervisor) | Windows-Led: M1M2 via registry → M3M4 |
| EoSL devices | Windows-Led or evaluate retirement |

Use SCCM collections or Intune dynamic groups to segment by manufacturer:

```sql
-- SCCM: Dell devices with 2023 keys (firmware-led candidates)
select SMS_R_SYSTEM.ResourceID, SMS_R_SYSTEM.Name
from SMS_R_System
inner join SMS_G_System_COMPUTER_SYSTEM on SMS_G_System_COMPUTER_SYSTEM.ResourceID = SMS_R_System.ResourceId
where SMS_G_System_COMPUTER_SYSTEM.Manufacturer LIKE "Dell%"
```

---

## Recommended Deployment Phases

### Phase 1: Assessment and Testing (Weeks 1-4)

1. **Inventory**
   - Document all hardware models **and OEM manufacturer** (Dell, HP, Lenovo)
   - Identify firmware versions and Secure Boot status
   - **Check OEM firmware for 2023 keys** (see `Test-OEMFirmwareKeys.ps1`)
   - Catalog boot media (ISO images, USB drives, PXE servers)
   - Identify all virtual machine platforms

2. **Lab Testing**
   - Test at least one device of each hardware type
   - Test each VM platform (Hyper-V, VMware, Azure)
   - Apply Mitigations 1 and 2 only
   - Document any issues

3. **Review Known Issues**
   - Check KB5025885 for firmware compatibility issues
   - Contact OEM vendors for identified problems

### Phase 2: Initial Deployment - M1 & M2 (Weeks 5-12)

1. **Pilot Group** (5% of devices)
2. **Monitor and validate** pilot devices for 2 weeks
3. **Broader deployment** using selected method

### Phase 3: Boot Media and Server Refresh (Weeks 8-16)

1. **Update installation media**
2. **Test updated media**
3. **Plan for regular updates**

### Phase 4: Revocation Deployment - M3 & M4 (After Phase 3 Complete)

**Do not proceed until**:
- All boot media updated
- WinRE updated on all devices
- Recovery procedures tested
- All VM templates updated

---

## SCCM Deployment

### Scripts Location

All SCCM scripts are in `scripts/sccm/`:
- `CI_Detect_M1M2.ps1` - Compliance detection for Phase 1
- `CI_Remediate_M1M2.ps1` - Compliance remediation for Phase 1
- `CI_Detect_M3M4.ps1` - Compliance detection for Phase 2
- `CI_Remediate_M3M4.ps1` - Compliance remediation for Phase 2
- `TS_Apply_Mitigations.ps1` - Task Sequence script

### SCCM Collections

Create collections to target devices:

```sql
-- Devices with Secure Boot Enabled
select SMS_R_SYSTEM.ResourceID, SMS_R_SYSTEM.Name
from SMS_R_System
inner join SMS_G_System_FIRMWARE on SMS_G_System_FIRMWARE.ResourceID = SMS_R_System.ResourceId
where SMS_G_System_FIRMWARE.SecureBoot = 1

-- Hyper-V Virtual Machines
select SMS_R_SYSTEM.ResourceID, SMS_R_SYSTEM.Name
from SMS_R_System
inner join SMS_G_System_COMPUTER_SYSTEM on SMS_G_System_COMPUTER_SYSTEM.ResourceID = SMS_R_System.ResourceId
where SMS_G_System_COMPUTER_SYSTEM.Manufacturer = "Microsoft Corporation"
and SMS_G_System_COMPUTER_SYSTEM.Model = "Virtual Machine"

-- VMware Virtual Machines
select SMS_R_SYSTEM.ResourceID, SMS_R_SYSTEM.Name
from SMS_R_System
inner join SMS_G_System_COMPUTER_SYSTEM on SMS_G_System_COMPUTER_SYSTEM.ResourceID = SMS_R_System.ResourceId
where SMS_G_System_COMPUTER_SYSTEM.Manufacturer = "VMware, Inc."
```

### Task Sequence Deployment

Recommended for BitLocker-encrypted or critical systems.

**Task Sequence Steps:**

1. **Check Prerequisites**
   - Run `TS_Apply_Mitigations.ps1 -MitigationPhase 1`
   - Sets TS variable `SkipMitigations` if Secure Boot disabled

2. **Suspend BitLocker** (Condition: SkipMitigations != True)
   ```powershell
   Suspend-BitLocker -MountPoint "C:" -RebootCount 3
   ```

3. **Apply Mitigations** (Condition: SkipMitigations != True)
   - Script applies registry and triggers scheduled task

4. **Restart Computer**

5. **Verify Mitigations**
   - Sets TS variable `MitigationSuccess`

### Compliance Baseline Deployment

Create a Configuration Item with:
- **Detection Script**: `CI_Detect_M1M2.ps1`
- **Remediation Script**: `CI_Remediate_M1M2.ps1`
- **Compliance Rule**: Script returns "Compliant"
- **Remediation**: Run remediation script when non-compliant

---

## Intune Deployment

### Scripts Location

All Intune scripts are in `scripts/intune/`:
- `Install-CVE2023-24932.ps1` - Win32 app installer
- `Detect-CVE2023-24932.ps1` - Win32 app detection
- `ProactiveRemediation-Detect-M1M2.ps1` - Proactive detection
- `ProactiveRemediation-Remediate-M1M2.ps1` - Proactive remediation
- `ProactiveRemediation-Inventory.ps1` - Fleet reporting

### Win32 App Deployment

1. **Package the scripts** using IntuneWinAppUtil:
   ```cmd
   IntuneWinAppUtil.exe -c .\scripts\intune -s Install-CVE2023-24932.ps1 -o .\output
   ```

2. **Create Win32 App in Intune**:
   - Install command: `powershell.exe -ExecutionPolicy Bypass -File Install-CVE2023-24932.ps1`
   - Detection script: `Detect-CVE2023-24932.ps1`
   - Device restart behavior: Intune will force mandatory restart

3. **Assignment**:
   - Assign to device groups
   - Use deployment rings for phased rollout

### Proactive Remediation

Create a Proactive Remediation script package:

| Setting | Value |
|---------|-------|
| Detection script | `ProactiveRemediation-Detect-M1M2.ps1` |
| Remediation script | `ProactiveRemediation-Remediate-M1M2.ps1` |
| Run as | System |
| 64-bit PowerShell | Yes |
| Schedule | Daily or weekly |

### Best Practice: Combined Approach

1. **Initial deployment** via Win32 App (controlled rollout)
2. **Ongoing monitoring** via Proactive Remediation
3. **Fleet reporting** via Inventory script

---

## Group Policy Deployment

### Scripts Location

All GPO scripts are in `scripts/gpo/`:
- `GPO-Startup-M1M2.ps1` - Startup script for Phase 1
- `GPO-Startup-M3M4.ps1` - Startup script for Phase 2

### GPO Startup Script Deployment

1. **Copy script** to SYSVOL:
   ```
   \\domain.com\NETLOGON\Scripts\CVE-2023-24932\
   ```

2. **Create GPO**:
   - Computer Configuration > Policies > Windows Settings > Scripts > Startup
   - Add PowerShell script: `GPO-Startup-M1M2.ps1`

3. **Link GPO** to target OUs

### GPO Considerations

- Scripts log to: `C:\Windows\Logs\CVE-2023-24932-GPO.log`
- BitLocker suspension is included in the script
- Apply to test OU first

> ⚠️ **Warning**: GPO Registry Preferences alone are NOT recommended. They only set the registry value without triggering the scheduled task or suspending BitLocker.

---

## Windows Server Considerations

### Server Version Support

| Server Version | Support Level | Notes |
|----------------|---------------|-------|
| Windows Server 2022 | Full | Recommended |
| Windows Server 2019 | Full | |
| Windows Server 2016 | Partial | Some limitations |
| Windows Server 2012 R2 | Limited | TPM measurement issues |

### Failover Cluster Deployment

1. **Plan maintenance window** for cluster-wide updates
2. **Update one node at a time** with proper failover:

```powershell
# On each cluster node (one at a time)
# 1. Pause the node
Suspend-ClusterNode -Name "NodeName" -Drain

# 2. Apply mitigations (inside paused node)
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Secureboot /v AvailableUpdates /t REG_DWORD /d 0x140 /f
Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update"
Restart-Computer

# 3. After restart, resume the node
Resume-ClusterNode -Name "NodeName"

# 4. Verify cluster health before next node
Get-ClusterNode | Select-Object Name, State
```

### Domain Controller Deployment

1. **Never apply mitigations to all DCs simultaneously**
2. **Start with one DC** in a non-critical site
3. **Verify AD replication** after each DC update:

```powershell
repadmin /replsummary
repadmin /showrepl
dcdiag /v
```

### Hyper-V Host Deployment

1. **Schedule maintenance window** for host and VMs
2. **Migrate VMs** before host maintenance:

```powershell
Get-VM | Where-Object State -eq 'Running' | Move-VM -DestinationHost "AlternateHost"
# Or save VM state
Get-VM | Where-Object State -eq 'Running' | Save-VM
```

3. **Apply host mitigations** first
4. **Then apply mitigations to guest VMs**

---

## Monitoring Progress

### Registry Status Check

```powershell
$status = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Secureboot" -Name "AvailableUpdates" -ErrorAction SilentlyContinue
$status.AvailableUpdates

# Value meanings:
# 0x000 = All mitigations complete
# 0x040 = Mitigation 1 pending
# 0x100 = Mitigation 2 pending
# 0x080 = Mitigation 3 pending
# 0x200 = Mitigation 4 pending
```

### Fleet Reporting Script

Use `scripts/verification/Get-FleetMitigationReport.ps1` for collecting status across your fleet.

---

## Recommended Deployment Combinations

### Enterprise with SCCM

| Phase | Method | Purpose |
|-------|--------|---------|
| BIOS Update | Dell DCU / Lenovo TI | Firmware-led key delivery (Dell/Lenovo) |
| Pilot | Task Sequence | Controlled testing |
| Production | Task Sequence | Phased rollout with BitLocker handling |
| Monitoring | Compliance Baseline | Ongoing verification |
| Reporting | SCCM Reports | Executive dashboards |

### Cloud-First with Intune

| Phase | Method | Purpose |
|-------|--------|---------|
| BIOS Update | Dell DCU / Lenovo SU (Win32 app) | Firmware-led key delivery (Dell/Lenovo) |
| Pilot | Win32 App (targeted group) | Test deployment |
| Production | Win32 App (phased rings) | Controlled rollout |
| Monitoring | Proactive Remediation | Ongoing compliance |
| Reporting | Endpoint Analytics | Compliance dashboards |

### Traditional On-Premises

| Phase | Method | Purpose |
|-------|--------|---------|
| Pilot | Manual via PowerShell | Test commands |
| Production | GPO Startup Script | Automated deployment |
| Monitoring | Scheduled PowerShell | Regular compliance checks |
| Reporting | Custom scripts | Generate compliance reports |

### Firmware-Led (Dell/Lenovo Fleet)

| Phase | Method | Purpose |
|-------|--------|---------|
| BIOS Update | OEM tool (DCU, Thin Installer) | Deliver 2023 keys via firmware |
| Verify Keys | `Test-OEMFirmwareKeys.ps1` | Confirm keys present |
| M2 Deployment | Any method (SCCM/Intune/GPO) | Boot manager update only |
| Media Refresh | Manual or scripted | Update WinRE and boot ISOs |
| M3M4 Deployment | Any method | Revocation + SVN (irreversible) |

---

## Next Steps

- **[Mitigation Procedures](MITIGATION_PROCEDURES.md)** - Step-by-step commands
- **[VM Guidance](VM_GUIDANCE.md)** - Virtual machine considerations
- **[Troubleshooting](TROUBLESHOOTING.md)** - Recovery and known issues
