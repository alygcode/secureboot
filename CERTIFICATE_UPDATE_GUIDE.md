# Secure Boot Certificate Update Guideline

## Table of Contents
1. [Overview](#overview)
2. [Certificate Types](#certificate-types)
3. [Prerequisites](#prerequisites)
4. [Backup Procedures](#backup-procedures)
5. [Certificate Update Procedures](#certificate-update-procedures)
6. [Verification](#verification)
7. [Recovery Procedures](#recovery-procedures)
8. [Security Best Practices](#security-best-practices)
9. [Troubleshooting](#troubleshooting)

## Overview

Secure Boot is a security standard developed to ensure that a device boots using only software that is trusted by the Original Equipment Manufacturer (OEM). This guideline provides comprehensive instructions for updating secure boot certificates safely and securely.

### Why Update Certificates?

- Certificate expiration
- Security vulnerabilities in existing certificates
- Adding support for new operating systems or bootloaders
- Compliance with updated security policies
- Key compromise or revocation

## Certificate Types

Secure Boot uses several types of certificates stored in UEFI firmware variables:

### Platform Key (PK)
- **Purpose**: The root of trust for the system
- **Owner**: Platform owner (typically the OEM or system owner)
- **Usage**: Signs updates to itself and the KEK database
- **Count**: Only one PK is active at a time

### Key Exchange Key (KEK)
- **Purpose**: Intermediate keys that can update signature databases
- **Owner**: Operating system vendors or platform owner
- **Usage**: Signs updates to DB and DBX databases
- **Count**: Multiple KEKs can be enrolled

### Signature Database (DB)
- **Purpose**: Contains trusted signing certificates and hashes
- **Owner**: Various trusted entities (OS vendors, hardware vendors)
- **Usage**: Authorizes bootloaders, drivers, and option ROMs
- **Count**: Multiple entries allowed

### Forbidden Signature Database (DBX)
- **Purpose**: Contains revoked certificates and hashes
- **Owner**: Various entities that can sign with KEK
- **Usage**: Blocks known compromised or malicious code
- **Count**: Multiple entries allowed

## Prerequisites

### Hardware Requirements
- UEFI firmware with Secure Boot support
- Access to UEFI/BIOS setup utility
- USB drive (for certificate files)

### Software Requirements
- Certificate generation tools (OpenSSL, sbsigntool, efi-readvar, efi-updatevar)
- Root/administrator access
- Backup storage for current certificates

### Knowledge Requirements
- Understanding of PKI (Public Key Infrastructure)
- UEFI firmware navigation
- Command-line operations
- Certificate formats (DER, PEM, ESL)

### Important Warnings
⚠️ **CRITICAL**: Incorrect certificate updates can render your system unbootable
⚠️ **Always create backups** before making any changes
⚠️ **Test procedures** in a non-production environment first
⚠️ **Have recovery media** ready before starting

## Backup Procedures

### 1. Backup Current Certificates

#### Linux Method
```bash
# Install required tools
sudo apt-get install efitools

# Create backup directory
mkdir -p ~/secureboot-backup/$(date +%Y%m%d)
cd ~/secureboot-backup/$(date +%Y%m%d)

# Backup all UEFI variables
efi-readvar -v PK -o PK.esl
efi-readvar -v KEK -o KEK.esl
efi-readvar -v db -o db.esl
efi-readvar -v dbx -o dbx.esl

# Verify backup
ls -lh *.esl

# Document current state
efi-readvar > current_state.txt
```

#### Windows Method
```powershell
# Run PowerShell as Administrator

# Check Secure Boot status
Confirm-SecureBootUEFI

# Note: Windows does not provide direct PowerShell commands to export
# Secure Boot certificates. Use one of these methods:
# 1. UEFI firmware interface to export certificates to USB
# 2. Vendor-specific tools (Dell, HP, Lenovo management software)
# 3. Boot to Linux and use efitools for backup
```

### 2. Create Recovery USB

```bash
# Create bootable USB with recovery tools
# Include:
# - Original certificates
# - Updated certificates
# - efitools utilities
# - Recovery instructions
```

### 3. Document Current Configuration

Create a detailed record of:
- Current firmware version
- Enabled Secure Boot state
- List of enrolled certificates
- Boot order
- Any custom security settings

## Certificate Update Procedures

### Method 1: Using UEFI Firmware Interface

#### Step 1: Enter UEFI Setup
1. Reboot the system
2. Press the firmware setup key (usually F2, F10, F12, Del, or Esc)
3. Navigate to Security or Boot section
4. Locate Secure Boot configuration

#### Step 2: Prepare for Update
1. Disable Secure Boot temporarily (required for some operations)
2. Note: Some firmware allows updates with Secure Boot enabled if signed properly

#### Step 3: Update Certificates

**Updating DB (Signature Database):**
1. Navigate to "Secure Boot" → "Advanced Options" → "DB Options"
2. Select "Enroll Signature" or "Append Signature"
3. Browse to your certificate file (.cer, .der, or .auth)
4. Select the certificate and confirm enrollment
5. Verify the certificate appears in the list

**Updating DBX (Forbidden Signature Database):**
1. Navigate to "Secure Boot" → "Advanced Options" → "DBX Options"
2. Select "Enroll Hash" or "Append Hash"
3. Load the DBX update file (usually from Microsoft or OEM)
4. Confirm the update

**Updating KEK (Key Exchange Key):**
1. Navigate to "Secure Boot" → "Advanced Options" → "KEK Options"
2. Select "Enroll KEK" or "Append KEK"
3. Browse to your KEK certificate file
4. Confirm enrollment
5. Verify KEK in the list

**Updating PK (Platform Key):**
⚠️ **EXTREME CAUTION**: Updating PK is the most critical operation

1. Navigate to "Secure Boot" → "Advanced Options" → "PK Options"
2. Select "Enroll PK" or "Replace PK"
3. Provide the new PK certificate
4. Confirm the operation
5. System may automatically enter Setup Mode if PK is cleared

#### Step 4: Re-enable Secure Boot
1. Navigate to Secure Boot settings
2. Set Secure Boot to "Enabled"
3. Save changes and exit
4. System will reboot

### Method 2: Using Linux Command Line

#### Prerequisites
```bash
# Install required packages
sudo apt-get update
sudo apt-get install efitools sbsigntool

# Verify system is in Setup Mode (for unsigned updates)
# or have properly signed update files
```

#### Generate New Certificates

```bash
# Set variables
COMMON_NAME="Your Name"
GUID=$(uuidgen)

# Generate PK
openssl req -new -x509 -newkey rsa:2048 -subj "/CN=$COMMON_NAME PK/" \
    -keyout PK.key -out PK.crt -days 3650 -nodes -sha256

# Generate KEK
openssl req -new -x509 -newkey rsa:2048 -subj "/CN=$COMMON_NAME KEK/" \
    -keyout KEK.key -out KEK.crt -days 3650 -nodes -sha256

# Generate db certificate
openssl req -new -x509 -newkey rsa:2048 -subj "/CN=$COMMON_NAME db/" \
    -keyout db.key -out db.crt -days 3650 -nodes -sha256

# Convert to EFI signature lists
cert-to-efi-sig-list -g $GUID PK.crt PK.esl
cert-to-efi-sig-list -g $GUID KEK.crt KEK.esl
cert-to-efi-sig-list -g $GUID db.crt db.esl

# Sign for authenticated updates
sign-efi-sig-list -k PK.key -c PK.crt PK PK.esl PK.auth
sign-efi-sig-list -k PK.key -c PK.crt KEK KEK.esl KEK.auth
sign-efi-sig-list -k KEK.key -c KEK.crt db db.esl db.auth
```

#### Update Certificates

```bash
# Method A: Using efi-updatevar (requires Setup Mode or signed updates)
sudo efi-updatevar -f db.auth db
sudo efi-updatevar -f KEK.auth KEK
sudo efi-updatevar -f PK.auth PK

# Method B: Using mokutil (for MOK - Machine Owner Key)
sudo mokutil --import db.crt
# Reboot and complete MOK enrollment in firmware

# Method C: Manual file placement (for some firmware - ADVANCED)
# WARNING: This method is dangerous and system-specific
# Replace [GUID] with actual GUID: 8be4df61-93ca-11d2-aa0d-00e098032b8c for db
# Example: db-8be4df61-93ca-11d2-aa0d-00e098032b8c
# This method is NOT recommended - use Method A or B instead
```

#### Append to Existing Database

```bash
# To add certificates without removing existing ones
sign-efi-sig-list -a -k KEK.key -c KEK.crt db db.esl db_append.auth
sudo efi-updatevar -a -f db_append.auth db
```

### Method 3: Using Windows Command Line

#### Prerequisites
```powershell
# Run as Administrator
# Install Windows SDK for signtool.exe
# or use manufacturer-specific tools
```

#### Update Process
```powershell
# Convert certificate to proper format
certutil -encode cert.der cert.cer

# For MOK enrollment (if using Shim)
# Copy certificate to EFI partition
Copy-Item cert.cer "E:\EFI\cert.cer"

# Reboot and enroll via firmware interface
```

## Verification

### Verify Secure Boot Status

#### Linux
```bash
# Check if Secure Boot is enabled
bootctl status | grep "Secure Boot"

# Check certificate enrollment
efi-readvar

# Verify specific certificate
efi-readvar -v db
```

#### Windows
```powershell
# Check Secure Boot status
Confirm-SecureBootUEFI

# Get Secure Boot configuration (returns True/False)
Get-SecureBootUEFI

# Note: Secure Boot certificates are not in Windows certificate store
# They must be viewed through UEFI firmware interface or by booting to Linux
```

### Test Boot Process

1. Reboot the system normally
2. System should boot without errors
3. Verify boot measurements if using TPM
4. Check system logs for Secure Boot violations

### Verify Signed Binaries

```bash
# Check bootloader signature
sbverify --list /boot/efi/EFI/ubuntu/shimx64.efi

# Verify kernel signature
sbverify --list /boot/vmlinuz-$(uname -r)

# Check against enrolled certificates
sbverify --cert db.crt /boot/efi/EFI/ubuntu/shimx64.efi
```

## Recovery Procedures

### Scenario 1: System Won't Boot After Update

#### Immediate Steps:
1. **Power off** the system completely
2. **Enter UEFI Setup** on next boot
3. **Disable Secure Boot** temporarily
4. Boot into operating system
5. Investigate the issue

#### Root Cause Analysis:
```bash
# Check system logs
journalctl -b -1  # Previous boot
dmesg | grep -i "secure\|efi"

# Verify certificate chain
efi-readvar -v db
```

### Scenario 2: Restore from Backup

#### Method 1: UEFI Interface
1. Enter UEFI Setup
2. Clear all Secure Boot keys (enters Setup Mode)
3. Manually enroll backed-up certificates
4. Re-enable Secure Boot

#### Method 2: Command Line
```bash
# Boot with Secure Boot disabled
# Navigate to backup directory
cd ~/secureboot-backup/[date]

# Restore certificates (requires Setup Mode or signed .auth files)
# If you have .auth (signed) files:
sudo efi-updatevar -f PK.auth PK
sudo efi-updatevar -f KEK.auth KEK
sudo efi-updatevar -f db.auth db
sudo efi-updatevar -f dbx.auth dbx

# If you only have .esl files, first enter Setup Mode by clearing PK
sudo efi-updatevar -c PK  # Or use firmware interface to clear PK
# Then restore with .esl files
sudo efi-updatevar -f PK.esl PK
sudo efi-updatevar -f KEK.esl KEK
sudo efi-updatevar -f db.esl db
sudo efi-updatevar -f dbx.esl dbx
```

### Scenario 3: Complete Reset

```bash
# Enter Setup Mode by clearing PK
# Method 1: Using efi-updatevar (if supported)
sudo efi-updatevar -c PK

# Method 2: If -c flag not available, try alternative
# WARNING: /dev/null method is implementation-dependent
# Prefer using firmware interface to clear PK

# Note: Some systems require using firmware setup to delete PK
# Navigate to: Security -> Secure Boot -> Clear All Keys

# Restore factory default certificates
# Usually available from firmware setup or manufacturer website
```

### Emergency Recovery

If system is completely unbootable:

1. **Use Recovery USB**
   - Boot from USB with recovery tools
   - Mount EFI partition
   - Restore backup certificates manually

2. **UEFI Shell**
   ```
   # From UEFI Shell
   fs0:
   cd EFI
   bcfg boot add 0 shimx64.efi "Ubuntu"
   ```

3. **Manufacturer Recovery**
   - Contact manufacturer support
   - Use manufacturer-provided recovery tools
   - May require service center assistance

## Security Best Practices

### Key Management

1. **Private Key Security**
   - Store private keys on encrypted, offline media
   - Use hardware security modules (HSM) for production
   - Never store private keys on the system being secured
   - Implement key rotation policies

2. **Certificate Lifecycle**
   - Document all certificates and their purposes
   - Set appropriate expiration dates (5-10 years typical)
   - Plan for certificate renewal before expiration
   - Maintain certificate inventory

3. **Access Control**
   - Limit who can update Secure Boot certificates
   - Require multiple approvals for PK updates
   - Log all certificate modifications
   - Use firmware setup passwords

### Operational Security

1. **Change Management**
   - Test all updates in non-production environment
   - Document update procedures
   - Schedule maintenance windows
   - Notify stakeholders

2. **Monitoring**
   - Monitor for Secure Boot violations
   - Track certificate expiration dates
   - Review boot logs regularly
   - Set up alerting for failures

3. **Compliance**
   - Follow organizational security policies
   - Meet regulatory requirements (NIST, ISO, etc.)
   - Document compliance evidence
   - Conduct periodic audits

### Update Strategy

1. **DBX Updates**
   - Apply DBX updates promptly (critical security)
   - Subscribe to vendor security bulletins
   - Test DBX updates before production deployment
   - Microsoft regularly releases DBX updates

2. **DB Updates**
   - Add new certificates as needed for new software
   - Remove unused/obsolete certificates periodically
   - Verify certificate authenticity before enrollment
   - Maintain minimal necessary certificate set

3. **KEK/PK Updates**
   - Only update when absolutely necessary
   - Require maximum authorization level
   - Have contingency plans ready
   - Consider impact on all enrolled certificates

## Troubleshooting

### Common Issues

#### Issue 1: "Secure Boot Violation" Error

**Symptoms:**
- System refuses to boot
- Error message about invalid signature

**Diagnosis:**
```bash
# Check what failed to verify
dmesg | grep -i "secure boot"
journalctl | grep -i "verification\|signature"
```

**Solutions:**
1. Verify the binary is signed with enrolled certificate
2. Check if certificate is properly enrolled in db
3. Ensure certificate hasn't expired
4. Verify certificate chain is complete

#### Issue 2: Cannot Enroll Certificate

**Symptoms:**
- UEFI rejects certificate enrollment
- "Access Denied" or "Write Protected" errors

**Diagnosis:**
- Check if Secure Boot is in Setup Mode (required for unsigned updates)
- Verify update is properly signed
- Check firmware write protection settings

**Solutions:**
```bash
# Check current mode
efi-readvar -v SetupMode

# If not in Setup Mode, clear PK to enter Setup Mode
# Method 1: Use clear command (preferred)
sudo efi-updatevar -c PK

# Method 2: Use firmware interface
# Reboot -> UEFI Setup -> Security -> Secure Boot -> Clear All Keys

# Re-enroll certificates after entering Setup Mode
```

#### Issue 3: Certificate Chain Errors

**Symptoms:**
- Certificate appears enrolled but verification fails
- Intermittent boot failures

**Diagnosis:**
```bash
# Verify certificate chain
openssl verify -CAfile KEK.crt db.crt

# Check certificate details
openssl x509 -in db.crt -text -noout
```

**Solutions:**
- Ensure all intermediate certificates are enrolled
- Verify certificate validity periods
- Check certificate signature algorithms (use SHA-256 minimum)

#### Issue 4: DBX Blocks Valid Software

**Symptoms:**
- Previously working software now blocked
- After DBX update, system won't boot certain components

**Diagnosis:**
```bash
# Check DBX contents
efi-readvar -v dbx

# Compare against software hash
sha256sum /boot/efi/EFI/ubuntu/shimx64.efi
```

**Solutions:**
1. Update blocked software to newer version
2. If false positive, remove specific DBX entry (requires KEK)
3. Contact software vendor for updated signatures

### Diagnostic Commands

```bash
# Complete system information
bootctl status

# Read all UEFI variables
efi-readvar

# Read specific variables
efi-readvar -v PK
efi-readvar -v KEK
efi-readvar -v db
efi-readvar -v dbx

# Check certificate details
openssl x509 -in cert.crt -text -noout

# Verify signature
sbverify --cert db.crt /path/to/binary

# Check TPM measurements (if applicable)
tpm2_pcrread sha256

# System logs
journalctl -b | grep -i "secure\|efi\|boot"
dmesg | grep -i "secure\|efi"
```

### Getting Help

1. **Documentation**
   - UEFI Specification: https://uefi.org/specifications
   - Distribution-specific guides (Ubuntu, RHEL, etc.)
   - Manufacturer documentation

2. **Community Support**
   - Distribution forums and mailing lists
   - Stack Exchange Unix/Linux
   - Manufacturer support forums

3. **Professional Support**
   - Contact your OS vendor
   - Hardware manufacturer support
   - Security consultants
   - Enterprise support contracts

## Appendix

### A. Certificate File Formats

- **DER**: Binary X.509 certificate
- **PEM**: Base64-encoded DER with headers
- **ESL**: EFI Signature List format
- **AUTH**: Authenticated variable update format

### B. Useful Resources

- UEFI Forum: https://uefi.org/
- Linux Foundation Secure Boot documentation
- Microsoft Secure Boot Key Updates: https://aka.ms/dbxupdate
- efitools documentation: https://git.kernel.org/pub/scm/linux/kernel/git/jejb/efitools.git

### C. Vendor-Specific Notes

#### Dell Systems
- F2 or F12 for firmware setup
- May require "Expert Key Management" mode
- BIOS updates can reset Secure Boot settings

#### HP Systems
- F10 for firmware setup
- Check "Custom Boot" options
- May need to disable "Legacy Support"

#### Lenovo Systems
- F1 or F2 for firmware setup
- Security Chip must be enabled
- May require supervisor password for changes

#### Microsoft Surface
- Volume Up + Power for UEFI
- Limited custom certificate support
- May require device reset for major changes

### D. Compliance Standards

- **NIST SP 800-147**: BIOS Protection Guidelines
- **NIST SP 800-193**: Platform Firmware Resiliency
- **TCG PC Client Platform**: Firmware Profile Specification
- **ISO/IEC 27001**: Information Security Management

### E. Glossary

- **UEFI**: Unified Extensible Firmware Interface
- **PKI**: Public Key Infrastructure
- **MOK**: Machine Owner Key
- **Shim**: First-stage bootloader for Secure Boot
- **TPM**: Trusted Platform Module
- **PCR**: Platform Configuration Register
- **ESP**: EFI System Partition

---

**Document Version:** 1.0  
**Last Updated:** 2026-01-28  
**Author:** Secure Boot Certificate Management Team  
**License:** CC BY-SA 4.0  

**Disclaimer:** This guideline is provided for informational purposes. Always consult official documentation for your specific hardware and software. The authors are not responsible for any system damage resulting from incorrect implementation of these procedures.
