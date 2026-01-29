# Virtual Machine Guidance for CVE-2023-24932

Special considerations for applying CVE-2023-24932 mitigations to virtual machines.

## Quick Reference: Do I Need to Act?

| VM Type | Secure Boot | Action Required |
|---------|-------------|-----------------|
| **Gen 1 VM (any hypervisor)** | Not supported | **NO** - BIOS boot, not affected |
| **Gen 2 VM with Secure Boot OFF** | Disabled | **NO** - Not vulnerable |
| **Gen 2 VM with Secure Boot ON** | Enabled | **YES** - Apply mitigations inside VM |
| **VM Template** | N/A | **Update template** with mitigations |

---

## Identifying VM Generation and Secure Boot Status

### Inside the VM (Universal)

```powershell
# Check if Secure Boot is enabled (works on any VM or physical)
try {
    $result = Confirm-SecureBootUEFI -ErrorAction Stop
    Write-Host "UEFI Firmware (Gen 2 VM) - Secure Boot: $result"
}
catch {
    Write-Host "BIOS Firmware (Gen 1 VM) - Secure Boot not supported"
}
```

### Hyper-V (From Host)

```powershell
# List all VMs with generation
Get-VM | Select-Object Name, Generation, State | Format-Table

# Check specific VM
Get-VM -Name "VMName" | Select-Object Name, Generation

# Check Secure Boot status for Gen 2 VMs
Get-VMFirmware -VMName "VMName" | Select-Object SecureBoot, SecureBootTemplate
```

### VMware (PowerCLI)

```powershell
# Check firmware type
Get-VM "VMName" | Get-AdvancedSetting -Name "firmware" | Select-Object Value
# "efi" = UEFI (mitigations may apply)
# "bios" = Legacy (mitigations not applicable)
```

---

## Hyper-V Virtual Machines

### Audit All VMs Script

Run this on your Hyper-V host to identify which VMs need mitigations:

```powershell
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

Or use the provided script:
```powershell
.\scripts\verification\Test-HyperV-VMs.ps1
```

### Secure Boot Templates

| Template | Secure Boot Default | Use Case |
|----------|---------------------|----------|
| Microsoft Windows | Enabled | Windows VMs |
| Microsoft UEFI Certificate Authority | Enabled | Third-party/Linux |
| Open Source Shielded VM | Enabled | Custom CA |

### Applying Mitigations to Hyper-V VMs

1. **Update the Hyper-V host first** with latest Windows updates
2. **Apply mitigations inside the VM** using standard procedures:

```powershell
# Inside the VM - Apply Phase 1
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Secureboot /v AvailableUpdates /t REG_DWORD /d 0x140 /f
Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update"
Restart-Computer
```

### VM Won't Boot After Mitigation

```powershell
# Temporarily disable Secure Boot for the VM
Set-VMFirmware -VMName "VMName" -EnableSecureBoot Off

# Boot the VM and apply mitigations inside
Start-VM -VMName "VMName"

# After mitigations applied, re-enable Secure Boot
Set-VMFirmware -VMName "VMName" -EnableSecureBoot On
```

---

## VMware Virtual Machines

### Version Requirements

| Version | Secure Boot Support |
|---------|---------------------|
| vSphere 6.5+ | Supported |
| Workstation 15+ | Supported |
| Fusion 11+ | Supported |

**Note:** VM Hardware version 13+ required for Secure Boot.

### Check Secure Boot Status

```powershell
# Inside the VM
Confirm-SecureBootUEFI

# Via PowerCLI
Get-VM "VMName" | Get-AdvancedSetting -Name "firmware" | Select-Object Name, Value
```

### VMware Considerations

- vSphere hosts do not require separate mitigation (different boot chain)
- Guest OS mitigations are independent of host
- Update VMware Tools after applying mitigations

### Recovery: VM Won't Boot

1. Edit VM settings → VM Options → Boot Options
2. Temporarily disable Secure Boot
3. Apply mitigations inside VM
4. Re-enable Secure Boot

---

## Azure Virtual Machines

### Trusted Launch VMs

Azure Trusted Launch VMs support:
- Secure Boot
- vTPM (Virtual Trusted Platform Module)
- Boot integrity attestation

### Check Azure VM Secure Boot

```powershell
# Azure CLI
az vm show --resource-group MyResourceGroup --name MyVM --query "securityProfile.uefiSettings"

# Azure PowerShell
Get-AzVM -ResourceGroupName "MyResourceGroup" -Name "MyVM" | Select-Object -ExpandProperty SecurityProfile
```

### Applying Mitigations to Azure VMs

1. **Create VM snapshot** before applying mitigations
2. **Apply Windows updates** to the VM
3. **Apply mitigations** using standard procedures
4. **Verify boot attestation** after mitigations

```powershell
# Inside Azure VM - same commands as physical
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Secureboot /v AvailableUpdates /t REG_DWORD /d 0x140 /f
Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update"
Restart-Computer
```

### Azure-Specific Considerations

- Azure manages firmware updates automatically
- Boot diagnostics can detect Secure Boot failures
- Azure Backup recommended before mitigations
- Test in Azure DevTest Labs first

---

## AWS EC2 Instances

### Nitro System Secure Boot

| Instance Type | Secure Boot Support |
|---------------|---------------------|
| Nitro-based (most current gen) | Supported |
| Xen-based (older) | Not supported |

### Enabling Secure Boot on EC2

```bash
# AWS CLI - Create instance with UEFI boot
aws ec2 run-instances \
  --image-id ami-xxxxxxxx \
  --instance-type m5.large \
  --boot-mode uefi
```

### EC2 Considerations

- Use UEFI-compatible AMIs
- Create AMI backup before mitigations
- Windows Server AMIs from AWS Marketplace are pre-configured
- Apply standard Windows mitigations inside the instance

---

## Reducing Reboot Count

Using combined registry values reduces reboots from 4 to 2:

| Approach | Reboots Required | Registry Values |
|----------|------------------|-----------------|
| Individual mitigations | 4 reboots | 0x40, 0x100, 0x80, 0x200 |
| Combined Phase 1 + Phase 2 | 2 reboots | 0x140, then 0x280 |

```powershell
# Phase 1: Apply Mitigations 1 & 2 together (1 reboot)
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Secureboot /v AvailableUpdates /t REG_DWORD /d 0x140 /f
Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update"
Restart-Computer

# [After reboot, verify and update boot media]

# Phase 2: Apply Mitigations 3 & 4 together (1 reboot)
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Secureboot /v AvailableUpdates /t REG_DWORD /d 0x280 /f
Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update"
Restart-Computer
```

---

## VM Template Updates

After mitigations are complete, update your VM templates:

1. Apply all mitigations to a template VM
2. Sysprep if using Windows
3. Export as new template
4. Update deployment scripts to use new template
5. Retire old templates

---

## When to Enable vs. Disable Secure Boot

### Enable Secure Boot if:
- Running production Windows workloads
- Compliance requirements mandate it
- VM hosts sensitive data
- Part of a security-hardened deployment

### May Leave Secure Boot Disabled if:
- Development/test environment
- Running unsigned boot components
- Compatibility issues with specific software
- Short-lived ephemeral VMs

---

## Next Steps

- **[Mitigation Procedures](MITIGATION_PROCEDURES.md)** - Step-by-step commands
- **[Enterprise Deployment](ENTERPRISE_DEPLOYMENT.md)** - SCCM, Intune, GPO
- **[Troubleshooting](TROUBLESHOOTING.md)** - Recovery procedures
