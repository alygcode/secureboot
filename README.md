# Secure Boot Management

This repository contains documentation, scripts, and guidelines for managing Secure Boot certificates and applying CVE-2023-24932 mitigations.

## Quick Start

**For most users, start here:**

1. **[Overview](docs/OVERVIEW.md)** - Understand what CVE-2023-24932 is and why you need to act
2. **[Mitigation Procedures](docs/MITIGATION_PROCEDURES.md)** - Step-by-step commands to apply mitigations

## Documentation

| Document | Description |
|----------|-------------|
| **[Overview](docs/OVERVIEW.md)** | Executive summary, threat landscape, timeline, and key decisions |
| **[Mitigation Procedures](docs/MITIGATION_PROCEDURES.md)** | Step-by-step commands for applying mitigations |
| **[VM Guidance](docs/VM_GUIDANCE.md)** | Hyper-V, VMware, Azure, and AWS virtual machine considerations |
| **[Enterprise Deployment](docs/ENTERPRISE_DEPLOYMENT.md)** | SCCM, Intune, and Group Policy deployment strategies |
| **[Troubleshooting](docs/TROUBLESHOOTING.md)** | Recovery procedures, known issues, and diagnostic commands |

## Scripts

Ready-to-use deployment and verification scripts:

```
scripts/
├── sccm/                    # SCCM/ConfigMgr scripts
│   ├── CI_Detect_M1M2.ps1       # Compliance detection - Phase 1
│   ├── CI_Remediate_M1M2.ps1    # Compliance remediation - Phase 1
│   ├── CI_Detect_M3M4.ps1       # Compliance detection - Phase 2
│   ├── CI_Remediate_M3M4.ps1    # Compliance remediation - Phase 2
│   └── TS_Apply_Mitigations.ps1 # Task Sequence script
├── intune/                  # Microsoft Intune scripts
│   ├── Install-CVE2023-24932.ps1              # Win32 app installer
│   ├── Detect-CVE2023-24932.ps1               # Win32 app detection
│   ├── ProactiveRemediation-Detect-M1M2.ps1   # Proactive detection
│   ├── ProactiveRemediation-Remediate-M1M2.ps1 # Proactive remediation
│   └── ProactiveRemediation-Inventory.ps1     # Fleet reporting
├── gpo/                     # Group Policy scripts
│   ├── GPO-Startup-M1M2.ps1     # Startup script - Phase 1
│   └── GPO-Startup-M3M4.ps1     # Startup script - Phase 2
└── verification/            # Verification and reporting scripts
    ├── Verify-MitigationStatus.ps1    # Local status check
    ├── Get-FleetMitigationReport.ps1  # Fleet-wide reporting
    ├── Test-HyperV-VMs.ps1            # Hyper-V VM audit
    └── Test-OEMFirmwareKeys.ps1       # OEM firmware key check (Dell/HP/Lenovo)
```

## Critical Dates

| Certificate | Expiration | Impact |
|-------------|------------|--------|
| KEK CA 2011 | June 2026 | Cannot receive DBX updates |
| PCA 2011 | October 2026 | Boot failure for unsigned components |
| UEFI CA 2011 | June 2026 | Third-party boot component failures |

## Quick Decision Guide

```
Is Secure Boot enabled?
├── NO → No action required
└── YES → What type of system?
    ├── Gen 1 VM / BIOS → No action required
    └── Gen 2 VM / UEFI / Physical
        ├── Dell/Lenovo with recent BIOS? → Firmware-Led path (verify keys, then M2-M4)
        ├── HP or older hardware? → Windows-Led path (M1-M4)
        └── Virtual machine? → Windows-Led path (M1-M4)
```

## Quick Reference Commands

### Check Secure Boot Status
```powershell
Confirm-SecureBootUEFI
```

### Apply Phase 1 (Safe, Reversible)
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

### Apply Phase 2 (IRREVERSIBLE - after updating boot media)
```cmd
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Secureboot /v AvailableUpdates /t REG_DWORD /d 0x280 /f
```
```powershell
Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update"
Restart-Computer
```

## Legacy Documentation

The original comprehensive guide is still available:
- **[CVE-2023-24932 Mitigation Guide](CVE_2023_24932_MITIGATION_GUIDE.md)** - Complete reference (single document)

## Contributing

Contributions are welcome! Please ensure any documentation updates maintain technical accuracy and follow security best practices.
