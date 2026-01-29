<#
.SYNOPSIS
    Intune Win32 App - Applies CVE-2023-24932 Mitigations 1 & 2
.DESCRIPTION
    Deployed via Intune as Win32 app. Applies safe mitigations only.
    Mitigations 3 & 4 require separate deployment after boot media update.
.NOTES
    Package this script with IntuneWinAppUtil.exe for Win32 app deployment.
    Detection script: Detect-CVE2023-24932.ps1
#>

$LogPath = "$env:ProgramData\Microsoft\IntuneManagementExtension\Logs"
$LogFile = "$LogPath\CVE-2023-24932_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $Message" | Tee-Object -FilePath $LogFile -Append
}

try {
    Write-Log "=== CVE-2023-24932 Mitigation Installation Started ==="

    # Check if device is virtual or physical
    $computerSystem = Get-WmiObject -Class Win32_ComputerSystem
    $isVirtual = $computerSystem.Model -match "Virtual|VMware|HVM|Xen"
    Write-Log "Device Type: $(if ($isVirtual) {'Virtual Machine'} else {'Physical'})"
    Write-Log "Manufacturer: $($computerSystem.Manufacturer)"
    Write-Log "Model: $($computerSystem.Model)"

    # Check Secure Boot status
    $secureBootEnabled = $false
    try {
        $secureBootEnabled = Confirm-SecureBootUEFI
    }
    catch {
        Write-Log "Secure Boot check failed: $_"
    }

    if (-not $secureBootEnabled) {
        Write-Log "Secure Boot is NOT enabled. Mitigations not applicable."
        Write-Log "This device does not require Secure Boot mitigations."
        # Create marker file indicating device was processed
        $markerPath = "$env:ProgramData\Microsoft\CVE-2023-24932"
        New-Item -ItemType Directory -Path $markerPath -Force -ErrorAction SilentlyContinue | Out-Null
        "SecureBootDisabled" | Out-File "$markerPath\status.txt" -Force
        exit 0  # Success - not applicable
    }

    Write-Log "Secure Boot is ENABLED. Proceeding with mitigations."

    # Check current mitigation status
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Secureboot"
    $currentStatus = (Get-ItemProperty -Path $regPath -Name AvailableUpdates -ErrorAction SilentlyContinue).AvailableUpdates
    Write-Log "Current AvailableUpdates: $currentStatus"

    # Check if PCA2023 already enrolled
    $dbBytes = (Get-SecureBootUEFI db -ErrorAction SilentlyContinue).bytes
    if ($dbBytes) {
        $dbString = [System.Text.Encoding]::ASCII.GetString($dbBytes)
        if ($dbString -match 'Windows UEFI CA 2023') {
            Write-Log "Windows UEFI CA 2023 already enrolled. Mitigations 1 & 2 complete."
            exit 0
        }
    }

    # Suspend BitLocker if enabled
    $bitlockerVolume = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
    if ($bitlockerVolume -and $bitlockerVolume.ProtectionStatus -eq "On") {
        Write-Log "Suspending BitLocker for 3 reboots"
        Suspend-BitLocker -MountPoint "C:" -RebootCount 3
    }

    # Apply Mitigations 1 + 2
    Write-Log "Setting AvailableUpdates to 0x140 (Mitigations 1 + 2)"
    Set-ItemProperty -Path $regPath -Name AvailableUpdates -Value 0x140 -Type DWord -Force

    # Verify registry was set
    $newStatus = (Get-ItemProperty -Path $regPath -Name AvailableUpdates).AvailableUpdates
    Write-Log "New AvailableUpdates value: $newStatus (expected: 320 / 0x140)"

    # Trigger the scheduled task
    Write-Log "Triggering Secure-Boot-Update scheduled task"
    $task = Get-ScheduledTask -TaskName "Secure-Boot-Update" -TaskPath "\Microsoft\Windows\PI\" -ErrorAction Stop
    Start-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath
    Start-Sleep -Seconds 15

    # Check task result
    $taskInfo = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath
    Write-Log "Task last run time: $($taskInfo.LastRunTime)"
    Write-Log "Task last result: $($taskInfo.LastTaskResult)"

    # Create status marker
    $markerPath = "$env:ProgramData\Microsoft\CVE-2023-24932"
    New-Item -ItemType Directory -Path $markerPath -Force -ErrorAction SilentlyContinue | Out-Null
    @{
        AppliedDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Phase = "M1M2"
        Status = "PendingReboot"
    } | ConvertTo-Json | Out-File "$markerPath\status.json" -Force

    Write-Log "Installation complete. REBOOT REQUIRED to finalize mitigations."
    Write-Log "=== Installation Finished ==="

    exit 3010  # Soft reboot required
}
catch {
    Write-Log "ERROR: Installation failed - $_"
    Write-Log $_.ScriptStackTrace
    exit 1
}
