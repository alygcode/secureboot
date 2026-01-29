# CVE-2023-24932 and June 2026 Secure Boot Certificate Expiration

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

## The Four Mitigations

| Mitigation | Registry Value | Description | Reversible? |
|------------|----------------|-------------|-------------|
| **M1** | 0x40 | Add Windows UEFI CA 2023 to DB | Yes |
| **M2** | 0x100 | Deploy new boot manager signed with PCA2023 | Yes |
| **M3** | 0x80 | Add PCA2011 to DBX (revocation) | **NO** |
| **M4** | 0x200 | Apply Secure Version Number (SVN) update | **NO** |

### Mitigation Phases

**Phase 1 (Safe):** Apply M1 + M2 together (registry value: 0x140)
- Adds new certificate and boot manager
- Fully reversible
- No risk to existing boot media

**Phase 2 (Irreversible):** Apply M3 + M4 together (registry value: 0x280)
- Revokes old certificates
- **Cannot be undone**
- Old boot media will stop working
- **Update all boot media BEFORE applying**

---

## Mitigation Paths

There are two paths to transition devices to the 2023 Secure Boot certificates:

### Path A: Windows-Led (Registry Mitigations)

The standard approach using Windows Update and registry-driven mitigations (M1-M4). This works on any hardware and is the method described in Microsoft KB5025885.

**Best for:** Mixed hardware fleets, VMs, devices without recent BIOS updates.

### Path B: Firmware-Led (OEM BIOS Updates)

Some OEMs ship BIOS/UEFI firmware updates that include the new 2023 certificates natively. When the firmware already contains the Windows UEFI CA 2023 and KEK 2K CA 2023, the transition is simplified — the new keys are present from first boot and no manual DB enrollment is needed.

**Best for:** Homogeneous fleets of Dell or Lenovo hardware, new device deployments, environments where BIOS updates are already managed.

#### OEM Firmware Readiness

| OEM | 2023 Certificate Status | Notes |
|-----|------------------------|-------|
| **Dell** | Shipping since late 2024 on new platforms; all sustaining platforms by end of 2025 | Dual-certificate strategy (2011 + 2023). Check if both `Windows UEFI CA 2023` and `KEK 2K CA 2023` are present. |
| **Lenovo** | Proactively included across all Lenovo systems | Updated UEFI firmware contains 2023 certificates. Transition without disabling Secure Boot. |
| **HP** | Lagging — many devices still ship 2011-only keys | HP Sure Start devices may require specific BIOS updates. Check HP support for your model. |

> **Important:** Even with firmware-delivered keys, you still need to deploy a 2023-signed boot manager (Mitigation 2) and eventually apply the DBX revocation (Mitigation 3) and SVN update (Mitigation 4). Firmware-led delivery of keys replaces Mitigation 1 only.

---

## Quick Decision Guide

```
Is Secure Boot enabled?
├── NO → No action required (document this decision)
└── YES → What type of system?
    ├── Gen 1 VM / BIOS → No action required
    └── Gen 2 VM / UEFI / Physical
        ├── Dell/Lenovo with recent BIOS? → Firmware-Led path (verify keys, then M2-M4)
        ├── HP or older hardware? → Windows-Led path (M1-M4)
        ├── Virtual machine? → Windows-Led path (M1-M4)
        └── Legacy/EoSL system? → Evaluate Secure Boot requirement
```

---

## Next Steps

1. **[Mitigation Procedures](MITIGATION_PROCEDURES.md)** - Step-by-step commands (both paths)
2. **[VM Guidance](VM_GUIDANCE.md)** - Hyper-V, VMware, Azure, AWS
3. **[Enterprise Deployment](ENTERPRISE_DEPLOYMENT.md)** - SCCM, Intune, GPO, and firmware-led strategies
4. **[Troubleshooting](TROUBLESHOOTING.md)** - Recovery procedures and known issues

---

## Resources and References

### Microsoft Official Documentation

- [Enterprise Deployment Guidance for CVE-2023-24932](https://support.microsoft.com/en-us/topic/enterprise-deployment-guidance-for-cve-2023-24932-88b8f034-20b7-4a45-80cb-c6049b0f9967)
- [How to manage Windows Boot Manager revocations for CVE-2023-24932](https://support.microsoft.com/en-us/topic/how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023-24932-41a975df-beb2-40c1-99a3-b3ff139f832d)
- [Revoking vulnerable Windows boot managers](https://techcommunity.microsoft.com/blog/windows-itpro-blog/revoking-vulnerable-windows-boot-managers/4121735)

### Community Resources

- [GARYTOWN BlackLotus KB5025885 Scripts (GitHub)](https://github.com/gwblok/garytown/blob/master/BlackLotusKB5025885/readme.md)
- [GARYTOWN Blog - KB5025885 PowerShell Script](https://garytown.com/powershell-script-kb5025885-how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023-24932)

---

## Glossary

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
