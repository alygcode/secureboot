<#
.SYNOPSIS
    Detects if CVE-2023-24932 Mitigations 1 & 2 are applied
.DESCRIPTION
    SCCM Compliance Baseline detection script.
    Checks for Windows UEFI CA 2023 in Secure Boot DB and new boot manager.
.NOTES
    Return "Compliant" or "Non-Compliant"
    For use with SCCM/ConfigMgr Compliance Baselines
#>

try {
    # Check if Secure Boot is enabled
    $secureBootEnabled = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
    if (-not $secureBootEnabled) {
        Write-Output "Non-Compliant: Secure Boot not enabled"
        exit 1
    }

    # Check Mitigation 1: PCA2023 in DB
    $dbBytes = (Get-SecureBootUEFI db -ErrorAction Stop).bytes
    $dbString = [System.Text.Encoding]::ASCII.GetString($dbBytes)
    $pca2023Enrolled = $dbString -match 'Windows UEFI CA 2023'

    if (-not $pca2023Enrolled) {
        Write-Output "Non-Compliant: Windows UEFI CA 2023 not in DB"
        exit 1
    }

    # Check Mitigation 2: New boot manager
    $efiPath = "$env:SystemDrive\EFI\Microsoft\Boot\bootmgfw.efi"
    if (-not (Test-Path $efiPath)) {
        # Try mounting EFI partition
        $null = mountvol S: /s 2>$null
        $efiPath = "S:\EFI\Microsoft\Boot\bootmgfw.efi"
    }

    if (Test-Path $efiPath) {
        $sig = Get-AuthenticodeSignature $efiPath -ErrorAction SilentlyContinue
        if ($sig.SignerCertificate.Subject -match "Windows UEFI CA 2023") {
            Write-Output "Compliant: Mitigations 1 & 2 applied"
            exit 0
        }
    }

    # Check registry for pending updates
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Secureboot"
    $availableUpdates = (Get-ItemProperty -Path $regPath -Name AvailableUpdates -ErrorAction SilentlyContinue).AvailableUpdates

    if ($availableUpdates -eq 0 -or $null -eq $availableUpdates) {
        Write-Output "Compliant: All mitigations complete"
        exit 0
    }

    Write-Output "Non-Compliant: Mitigations pending (AvailableUpdates: $availableUpdates)"
    exit 1
}
catch {
    Write-Output "Non-Compliant: Error checking status - $_"
    exit 1
}
