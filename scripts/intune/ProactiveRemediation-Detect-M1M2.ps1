<#
.SYNOPSIS
    Proactive Remediation - Detect if M1M2 mitigations needed
.DESCRIPTION
    Intune Proactive Remediation detection script.
    Checks if CVE-2023-24932 Mitigations 1 & 2 are applied.
.NOTES
    Exit 0 = Compliant (no remediation needed)
    Exit 1 = Non-compliant (remediation will run)
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
