<#
.SYNOPSIS
    GPO Startup Script for CVE-2023-24932 Mitigations 3 & 4
.DESCRIPTION
    WARNING: IRREVERSIBLE - Only deploy after boot media is updated!
    Runs at computer startup to apply final mitigations.
.NOTES
    Log file: C:\Windows\Logs\CVE-2023-24932-GPO.log
    Deploy only to collection where M1M2 complete and boot media updated
#>

$LogFile = "C:\Windows\Logs\CVE-2023-24932-GPO.log"

function Write-Log {
    param([string]$Message)
    "$((Get-Date).ToString('s')) - $Message" | Out-File -FilePath $LogFile -Append
}

try {
    Write-Log "=== GPO Startup Script - M3M4 Execution ==="
    Write-Log "Computer: $env:COMPUTERNAME"
    Write-Log "WARNING: This applies IRREVERSIBLE mitigations"

    # Skip if not Secure Boot
    if (-not (Confirm-SecureBootUEFI -ErrorAction SilentlyContinue)) {
        Write-Log "Secure Boot not enabled - skipping"
        exit 0
    }

    # Verify M1M2 complete first
    $dbBytes = (Get-SecureBootUEFI db).bytes
    $dbString = [System.Text.Encoding]::ASCII.GetString($dbBytes)

    if (-not ($dbString -match 'Windows UEFI CA 2023')) {
        Write-Log "ERROR: Mitigations 1 & 2 not complete - cannot apply M3M4"
        exit 1
    }

    # Check if already complete
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Secureboot"
    $availableUpdates = (Get-ItemProperty -Path $regPath -Name AvailableUpdates -ErrorAction SilentlyContinue).AvailableUpdates

    if ($availableUpdates -eq 0 -or $null -eq $availableUpdates) {
        Write-Log "All mitigations already complete"
        exit 0
    }

    Write-Log "Applying Mitigations 3 & 4 (IRREVERSIBLE)"

    # Suspend BitLocker
    $blv = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
    if ($blv -and $blv.ProtectionStatus -eq "On") {
        Suspend-BitLocker -MountPoint "C:" -RebootCount 2
        Write-Log "BitLocker suspended"
    }

    # Apply mitigations
    Set-ItemProperty -Path $regPath -Name AvailableUpdates -Value 0x280 -Type DWord -Force
    Write-Log "Registry set to 0x280"

    # Trigger task
    Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update"
    Write-Log "Scheduled task triggered"

    Write-Log "Mitigations 3 & 4 applied - will complete on next reboot"
    exit 0
}
catch {
    Write-Log "ERROR: $_"
    exit 1
}
