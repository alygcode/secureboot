<#
.SYNOPSIS
    Proactive Remediation - Apply M1M2 mitigations
.DESCRIPTION
    Intune Proactive Remediation script.
    Applies CVE-2023-24932 Mitigations 1 & 2.
.NOTES
    Runs when detection script returns non-compliant.
    Logs to: C:\ProgramData\Microsoft\CVE-2023-24932\
#>

$LogPath = "$env:ProgramData\Microsoft\CVE-2023-24932"
$LogFile = "$LogPath\ProactiveRemediation_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

function Write-Log {
    param([string]$Message)
    "$((Get-Date).ToString('s')) - $Message" | Out-File -FilePath $LogFile -Append
}

try {
    New-Item -ItemType Directory -Path $LogPath -Force -ErrorAction SilentlyContinue | Out-Null
    Write-Log "Starting Proactive Remediation for CVE-2023-24932"

    # Double-check Secure Boot
    if (-not (Confirm-SecureBootUEFI)) {
        Write-Log "Secure Boot not enabled - skipping"
        Write-Host "Secure Boot not enabled"
        exit 0
    }

    # Suspend BitLocker
    $blv = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
    if ($blv -and $blv.ProtectionStatus -eq "On") {
        Write-Log "Suspending BitLocker"
        Suspend-BitLocker -MountPoint "C:" -RebootCount 3
    }

    # Apply mitigations
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Secureboot"
    Set-ItemProperty -Path $regPath -Name AvailableUpdates -Value 0x140 -Type DWord -Force
    Write-Log "Set AvailableUpdates to 0x140"

    # Trigger task
    Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update"
    Start-Sleep -Seconds 10
    Write-Log "Triggered Secure-Boot-Update task"

    Write-Host "Remediation applied - reboot required"
    Write-Log "Remediation complete"
    exit 0
}
catch {
    Write-Log "ERROR: $_"
    Write-Host "Remediation failed: $_"
    exit 1
}
