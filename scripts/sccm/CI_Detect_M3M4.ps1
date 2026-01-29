<#
.SYNOPSIS
    Detects if CVE-2023-24932 Mitigations 3 & 4 are applied
.DESCRIPTION
    SCCM Compliance Baseline detection script.
    Checks for DBX revocation and SVN update.
.NOTES
    Only run this AFTER Mitigations 1 & 2 are confirmed and boot media updated.
    For use with SCCM/ConfigMgr Compliance Baselines
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
