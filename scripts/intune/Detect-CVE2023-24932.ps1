<#
.SYNOPSIS
    Intune Detection Script for CVE-2023-24932 Mitigations
.DESCRIPTION
    Returns exit 0 if mitigations applied OR if device doesn't need them.
    Used with Intune Win32 App deployment.
.NOTES
    Detection logic:
    - Exit 0 (detected) = App installed or not applicable
    - Exit 1 (not detected) = App needs to be installed
#>

try {
    # Check if Secure Boot is enabled
    $secureBootEnabled = $false
    try {
        $secureBootEnabled = Confirm-SecureBootUEFI
    }
    catch {
        # Secure Boot not supported
    }

    if (-not $secureBootEnabled) {
        # Device doesn't need mitigations - check for marker file
        $markerFile = "$env:ProgramData\Microsoft\CVE-2023-24932\status.txt"
        if (Test-Path $markerFile) {
            Write-Host "Detected: Secure Boot disabled - mitigations not required"
            exit 0
        }
        exit 1  # Need to run installer to create marker
    }

    # Check if PCA2023 is enrolled
    $dbBytes = (Get-SecureBootUEFI db -ErrorAction SilentlyContinue).bytes
    if ($dbBytes) {
        $dbString = [System.Text.Encoding]::ASCII.GetString($dbBytes)
        if ($dbString -match 'Windows UEFI CA 2023') {
            Write-Host "Detected: Windows UEFI CA 2023 enrolled"
            exit 0
        }
    }

    # Not detected
    exit 1
}
catch {
    exit 1
}
