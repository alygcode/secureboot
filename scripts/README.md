# CVE-2023-24932 Deployment Scripts

Ready-to-use PowerShell scripts for deploying CVE-2023-24932 mitigations.

## Directory Structure

```
scripts/
├── sccm/                    # SCCM/ConfigMgr scripts
├── intune/                  # Microsoft Intune scripts
├── gpo/                     # Group Policy scripts
└── verification/            # Verification and reporting
```

## SCCM Scripts

| Script | Purpose |
|--------|---------|
| `CI_Detect_M1M2.ps1` | Compliance Baseline detection for Mitigations 1 & 2 |
| `CI_Remediate_M1M2.ps1` | Compliance Baseline remediation for Mitigations 1 & 2 |
| `CI_Detect_M3M4.ps1` | Compliance Baseline detection for Mitigations 3 & 4 |
| `CI_Remediate_M3M4.ps1` | Compliance Baseline remediation for Mitigations 3 & 4 |
| `TS_Apply_Mitigations.ps1` | Task Sequence script with BitLocker handling |

### Usage

**Compliance Baseline:**
1. Create Configuration Item with detection/remediation scripts
2. Create Baseline with the Configuration Item
3. Deploy to target collection

**Task Sequence:**
1. Add PowerShell step calling `TS_Apply_Mitigations.ps1`
2. Use `-MitigationPhase 1` for safe mitigations
3. Use `-MitigationPhase 2` for irreversible mitigations

## Intune Scripts

| Script | Purpose |
|--------|---------|
| `Install-CVE2023-24932.ps1` | Win32 app installer |
| `Detect-CVE2023-24932.ps1` | Win32 app detection script |
| `ProactiveRemediation-Detect-M1M2.ps1` | Proactive Remediation detection |
| `ProactiveRemediation-Remediate-M1M2.ps1` | Proactive Remediation script |
| `ProactiveRemediation-Inventory.ps1` | Fleet-wide status reporting |

### Usage

**Win32 App:**
1. Package with IntuneWinAppUtil:
   ```cmd
   IntuneWinAppUtil.exe -c .\intune -s Install-CVE2023-24932.ps1 -o .\output
   ```
2. Upload to Intune as Win32 app
3. Set detection script to `Detect-CVE2023-24932.ps1`

**Proactive Remediation:**
1. Create script package with detection and remediation scripts
2. Assign to device groups
3. Monitor results in Endpoint Analytics

## GPO Scripts

| Script | Purpose |
|--------|---------|
| `GPO-Startup-M1M2.ps1` | Computer Startup script for Phase 1 |
| `GPO-Startup-M3M4.ps1` | Computer Startup script for Phase 2 |

### Usage

1. Copy scripts to `\\domain\NETLOGON\Scripts\`
2. Create GPO: Computer Configuration > Policies > Windows Settings > Scripts > Startup
3. Add PowerShell script
4. Link GPO to target OUs

**Logs:** `C:\Windows\Logs\CVE-2023-24932-GPO.log`

## Verification Scripts

| Script | Purpose |
|--------|---------|
| `Verify-MitigationStatus.ps1` | Comprehensive local status check |
| `Get-FleetMitigationReport.ps1` | JSON output for fleet collection |
| `Test-HyperV-VMs.ps1` | Audit Hyper-V VMs for Secure Boot status |

### Usage

```powershell
# Local verification
.\verification\Verify-MitigationStatus.ps1

# Fleet reporting (collect via remoting or SCCM)
.\verification\Get-FleetMitigationReport.ps1 | ConvertFrom-Json

# Hyper-V VM audit (run on host)
.\verification\Test-HyperV-VMs.ps1 | Export-Csv -Path "VM-Audit.csv"
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success / Compliant / Not applicable |
| 1 | Error / Non-compliant |
| 3010 | Success - Reboot required |

## BitLocker Handling

All scripts automatically suspend BitLocker when needed:
- Suspend for 2-3 reboots
- BitLocker will re-seal after mitigations complete
- Always backup recovery keys before deploying

## Logging

| Deployment Method | Log Location |
|------------------|--------------|
| SCCM | `C:\ProgramData\Microsoft\CVE-2023-24932\` |
| Intune | `C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\` |
| GPO | `C:\Windows\Logs\CVE-2023-24932-GPO.log` |
