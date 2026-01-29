<#
.SYNOPSIS
    SCCM Task Sequence - Applies CVE-2023-24932 Mitigations
.DESCRIPTION
    Designed for SCCM Task Sequence deployment.
    Handles BitLocker suspension, mitigation application, and verification.
.PARAMETER MitigationPhase
    1 = Mitigations 1 & 2 only (safe, reversible)
    2 = Mitigations 3 & 4 (IRREVERSIBLE - only after boot media updated)
.NOTES
    Use with SCCM Task Sequence. Integrates with TS environment variables.
#>
param(
    [Parameter(Mandatory=$false)]
    [ValidateSet(1,2)]
    [int]$MitigationPhase = 1
)

$ExitCode = 0
$LogPath = "$env:ProgramData\Microsoft\CVE-2023-24932"
$LogFile = "$LogPath\TaskSequence_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $Message" | Out-File -FilePath $LogFile -Append
    Write-Output $Message
}

try {
    New-Item -ItemType Directory -Path $LogPath -Force -ErrorAction SilentlyContinue | Out-Null
    Write-Log "=== CVE-2023-24932 Task Sequence Started - Phase $MitigationPhase ==="

    # Try to get TS environment
    $tsEnv = $null
    try {
        $tsEnv = New-Object -ComObject Microsoft.SMS.TSEnvironment
        Write-Log "Running in Task Sequence context"
    }
    catch {
        Write-Log "Not running in Task Sequence context - standalone mode"
    }

    # Check Secure Boot
    $secureBootEnabled = $false
    try {
        $secureBootEnabled = Confirm-SecureBootUEFI
        Write-Log "Secure Boot Status: $secureBootEnabled"
    }
    catch {
        Write-Log "Secure Boot check failed: $_"
    }

    if (-not $secureBootEnabled) {
        Write-Log "Secure Boot not enabled. Skipping mitigations."
        if ($tsEnv) { $tsEnv.Value("SkipMitigations") = "True" }
        exit 0
    }

    if ($tsEnv) { $tsEnv.Value("SkipMitigations") = "False" }

    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Secureboot"

    switch ($MitigationPhase) {
        1 {
            Write-Log "Phase 1: Applying Mitigations 1 & 2"

            # Check if already complete
            $dbBytes = (Get-SecureBootUEFI db -ErrorAction SilentlyContinue).bytes
            if ($dbBytes) {
                $dbString = [System.Text.Encoding]::ASCII.GetString($dbBytes)
                if ($dbString -match 'Windows UEFI CA 2023') {
                    Write-Log "Mitigations 1 & 2 already applied"
                    if ($tsEnv) { $tsEnv.Value("MitigationSuccess") = "True" }
                    exit 0
                }
            }

            # Suspend BitLocker
            $blv = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
            if ($blv -and $blv.ProtectionStatus -eq "On") {
                Write-Log "Suspending BitLocker for 3 reboots"
                Suspend-BitLocker -MountPoint "C:" -RebootCount 3
            }

            # Apply mitigations
            Set-ItemProperty -Path $regPath -Name AvailableUpdates -Value 0x140 -Type DWord -Force
            Write-Log "Registry set to 0x140"

            # Trigger update
            Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update"
            Start-Sleep -Seconds 15
            Write-Log "Scheduled task triggered"

            $ExitCode = 3010  # Soft reboot required
        }
        2 {
            Write-Log "Phase 2: Applying Mitigations 3 & 4 (IRREVERSIBLE)"

            # Verify M1M2 complete
            $dbBytes = (Get-SecureBootUEFI db).bytes
            $dbString = [System.Text.Encoding]::ASCII.GetString($dbBytes)
            if (-not ($dbString -match 'Windows UEFI CA 2023')) {
                Write-Log "ERROR: M1M2 not complete. Cannot proceed with M3M4."
                if ($tsEnv) { $tsEnv.Value("MitigationSuccess") = "False" }
                exit 1
            }

            # Suspend BitLocker
            $blv = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
            if ($blv -and $blv.ProtectionStatus -eq "On") {
                Write-Log "Suspending BitLocker for 3 reboots"
                Suspend-BitLocker -MountPoint "C:" -RebootCount 3
            }

            # Apply mitigations
            Set-ItemProperty -Path $regPath -Name AvailableUpdates -Value 0x280 -Type DWord -Force
            Write-Log "Registry set to 0x280"

            # Trigger update
            Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update"
            Start-Sleep -Seconds 15
            Write-Log "Scheduled task triggered"

            $ExitCode = 3010
        }
    }

    Write-Log "Task Sequence step complete"
    if ($tsEnv) { $tsEnv.Value("MitigationSuccess") = "True" }
}
catch {
    Write-Log "ERROR: $_"
    if ($tsEnv) { $tsEnv.Value("MitigationSuccess") = "False" }
    $ExitCode = 1
}

Write-Log "=== Task Sequence Finished - Exit Code: $ExitCode ==="
exit $ExitCode
