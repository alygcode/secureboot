<#
.SYNOPSIS
    Applies CVE-2023-24932 Mitigations 3 & 4 (DBX revocation + SVN)
.DESCRIPTION
    SCCM Compliance Baseline remediation script.
    WARNING: This is IRREVERSIBLE. Old boot media will stop working.
.NOTES
    Only deploy after confirming boot media has been updated.
    For use with SCCM/ConfigMgr Compliance Baselines
#>

$LogPath = "$env:ProgramData\Microsoft\CVE-2023-24932"
$LogFile = "$LogPath\Remediation_M3M4_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $Message" | Out-File -FilePath $LogFile -Append
    Write-Output $Message
}

try {
    if (-not (Test-Path $LogPath)) {
        New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
    }

    Write-Log "Starting CVE-2023-24932 Mitigation 3 & 4 remediation"
    Write-Log "WARNING: This operation is IRREVERSIBLE"

    # Verify M1M2 are already applied
    $dbBytes = (Get-SecureBootUEFI db -ErrorAction Stop).bytes
    $dbString = [System.Text.Encoding]::ASCII.GetString($dbBytes)

    if (-not ($dbString -match 'Windows UEFI CA 2023')) {
        Write-Log "ERROR: Mitigations 1 & 2 must be applied first. Aborting."
        exit 1
    }

    Write-Log "Mitigations 1 & 2 confirmed. Proceeding with 3 & 4."

    # Suspend BitLocker if enabled
    $bitlockerVolume = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
    if ($bitlockerVolume -and $bitlockerVolume.ProtectionStatus -eq "On") {
        Write-Log "Suspending BitLocker for 3 reboots"
        Suspend-BitLocker -MountPoint "C:" -RebootCount 3
    }

    # Apply Mitigations 3 + 4 (0x280 = 0x80 + 0x200)
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Secureboot"
    Set-ItemProperty -Path $regPath -Name AvailableUpdates -Value 0x280 -Type DWord -Force
    Write-Log "Registry set to 0x280 (Mitigations 3 + 4)"

    # Trigger scheduled task
    $task = Get-ScheduledTask -TaskName "Secure-Boot-Update" -TaskPath "\Microsoft\Windows\PI\" -ErrorAction Stop
    Start-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath
    Start-Sleep -Seconds 10

    Write-Log "Remediation complete. Reboot required."
    exit 3010
}
catch {
    Write-Log "ERROR: Remediation failed - $_"
    exit 1
}
