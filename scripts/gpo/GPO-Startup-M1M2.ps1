<#
.SYNOPSIS
    GPO Startup Script for CVE-2023-24932 Mitigations 1 & 2
.DESCRIPTION
    Runs at computer startup to apply mitigations if not already applied.
    Deploy via: Computer Configuration > Policies > Windows Settings > Scripts > Startup
.NOTES
    Log file: C:\Windows\Logs\CVE-2023-24932-GPO.log
    Store script in: \\domain.com\NETLOGON\Scripts\ or SYSVOL
#>

$LogFile = "C:\Windows\Logs\CVE-2023-24932-GPO.log"

function Write-Log {
    param([string]$Message)
    "$((Get-Date).ToString('s')) - $Message" | Out-File -FilePath $LogFile -Append
}

try {
    Write-Log "=== GPO Startup Script Execution ==="
    Write-Log "Computer: $env:COMPUTERNAME"

    # Skip if not Secure Boot
    if (-not (Confirm-SecureBootUEFI -ErrorAction SilentlyContinue)) {
        Write-Log "Secure Boot not enabled - skipping"
        exit 0
    }

    Write-Log "Secure Boot is enabled"

    # Check if already complete
    $dbBytes = (Get-SecureBootUEFI db).bytes
    $dbString = [System.Text.Encoding]::ASCII.GetString($dbBytes)

    if ($dbString -match 'Windows UEFI CA 2023') {
        Write-Log "Mitigations 1 & 2 already applied"
        exit 0
    }

    Write-Log "Applying Mitigations 1 & 2"

    # Suspend BitLocker
    $blv = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
    if ($blv -and $blv.ProtectionStatus -eq "On") {
        Suspend-BitLocker -MountPoint "C:" -RebootCount 2
        Write-Log "BitLocker suspended for 2 reboots"
    }

    # Apply mitigations
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Secureboot"
    Set-ItemProperty -Path $regPath -Name AvailableUpdates -Value 0x140 -Type DWord -Force
    Write-Log "Registry set to 0x140"

    # Trigger task
    Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update"
    Write-Log "Scheduled task triggered"

    Write-Log "Mitigations applied - will complete on next reboot"
    exit 0
}
catch {
    Write-Log "ERROR: $_"
    exit 1
}
