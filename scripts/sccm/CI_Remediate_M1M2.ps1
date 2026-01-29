<#
.SYNOPSIS
    Applies CVE-2023-24932 Mitigations 1 & 2
.DESCRIPTION
    SCCM Compliance Baseline remediation script.
    Sets registry value and triggers Secure Boot update task.
.NOTES
    Requires reboot to complete. Returns exit code 3010 for soft reboot.
    For use with SCCM/ConfigMgr Compliance Baselines
#>

$LogPath = "$env:ProgramData\Microsoft\CVE-2023-24932"
$LogFile = "$LogPath\Remediation_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $Message" | Out-File -FilePath $LogFile -Append
    Write-Output $Message
}

try {
    # Create log directory
    if (-not (Test-Path $LogPath)) {
        New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
    }

    Write-Log "Starting CVE-2023-24932 Mitigation 1 & 2 remediation"

    # Verify Secure Boot is enabled
    $secureBootEnabled = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
    if (-not $secureBootEnabled) {
        Write-Log "ERROR: Secure Boot is not enabled. Cannot apply mitigations."
        exit 1
    }

    # Check current status
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Secureboot"
    $currentValue = (Get-ItemProperty -Path $regPath -Name AvailableUpdates -ErrorAction SilentlyContinue).AvailableUpdates
    Write-Log "Current AvailableUpdates value: $currentValue"

    # Suspend BitLocker if enabled
    $bitlockerVolume = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
    if ($bitlockerVolume -and $bitlockerVolume.ProtectionStatus -eq "On") {
        Write-Log "Suspending BitLocker for 3 reboots"
        Suspend-BitLocker -MountPoint "C:" -RebootCount 3
    }

    # Apply Mitigations 1 + 2 (0x140 = 0x40 + 0x100)
    $targetValue = 0x140
    Write-Log "Setting AvailableUpdates to 0x140 (Mitigations 1 + 2)"

    Set-ItemProperty -Path $regPath -Name AvailableUpdates -Value $targetValue -Type DWord -Force
    Write-Log "Registry value set successfully"

    # Trigger the scheduled task
    Write-Log "Triggering Secure-Boot-Update scheduled task"
    $task = Get-ScheduledTask -TaskName "Secure-Boot-Update" -TaskPath "\Microsoft\Windows\PI\" -ErrorAction Stop
    Start-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath

    # Wait for task to complete
    Start-Sleep -Seconds 10
    $taskInfo = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath
    Write-Log "Task last run result: $($taskInfo.LastTaskResult)"

    Write-Log "Remediation complete. Reboot required to finalize mitigations."

    # Return 3010 (soft reboot required)
    exit 3010
}
catch {
    Write-Log "ERROR: Remediation failed - $_"
    exit 1
}
