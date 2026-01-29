# Enterprise Deployment Guide for CVE-2023-24932

Deployment strategies and scripts for SCCM, Intune, and Group Policy environments.

## Deployment Method Selection

### Quick Comparison Matrix

| Method | Best For | BitLocker Handling | Rollback Control | Complexity |
|--------|----------|-------------------|------------------|------------|
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

## Recommended Deployment Phases

### Phase 1: Assessment and Testing (Weeks 1-4)

1. **Inventory**
   - Document all hardware models
   - Identify firmware versions and Secure Boot status
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
| Pilot | Task Sequence | Controlled testing |
| Production | Task Sequence | Phased rollout with BitLocker handling |
| Monitoring | Compliance Baseline | Ongoing verification |
| Reporting | SCCM Reports | Executive dashboards |

### Cloud-First with Intune

| Phase | Method | Purpose |
|-------|--------|---------|
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

---

## Next Steps

- **[Mitigation Procedures](MITIGATION_PROCEDURES.md)** - Step-by-step commands
- **[VM Guidance](VM_GUIDANCE.md)** - Virtual machine considerations
- **[Troubleshooting](TROUBLESHOOTING.md)** - Recovery and known issues
