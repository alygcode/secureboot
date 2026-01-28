# Secure Boot Management

This repository contains documentation and guidelines for managing secure boot certificates and configurations.

## Documentation

- **[CVE-2023-24932 Mitigation Guide](CVE_2023_24932_MITIGATION_GUIDE.md)** - Critical guidance for mitigating the BlackLotus UEFI bootkit vulnerability and preparing for June 2026 Secure Boot certificate expirations.
- **[Certificate Update Guide](CERTIFICATE_UPDATE_GUIDE.md)** - Comprehensive guideline for safely updating secure boot certificates including PK, KEK, DB, and DBX.

## Overview

Secure Boot is a security standard that ensures devices boot using only trusted software. This repository provides best practices and procedures for managing secure boot certificates throughout their lifecycle.

## Quick Links

### CVE-2023-24932 and June 2026 Mitigation
- [Executive Summary](CVE_2023_24932_MITIGATION_GUIDE.md#executive-summary)
- [Windows Mitigation Procedures](CVE_2023_24932_MITIGATION_GUIDE.md#windows-mitigation-procedures)
- [Linux Mitigation Procedures](CVE_2023_24932_MITIGATION_GUIDE.md#linux-mitigation-procedures)
- [Enterprise Deployment Strategy](CVE_2023_24932_MITIGATION_GUIDE.md#enterprise-deployment-strategy)

### Certificate Management
- [Understanding Certificate Types](CERTIFICATE_UPDATE_GUIDE.md#certificate-types)
- [Update Procedures](CERTIFICATE_UPDATE_GUIDE.md#certificate-update-procedures)
- [Backup and Recovery](CERTIFICATE_UPDATE_GUIDE.md#backup-procedures)
- [Troubleshooting](CERTIFICATE_UPDATE_GUIDE.md#troubleshooting)

## Contributing

Contributions are welcome! Please ensure any documentation updates maintain technical accuracy and follow security best practices.