<#
.SYNOPSIS
    Proactive Remediation - Inventory CVE-2023-24932 status for reporting
.DESCRIPTION
    Always returns "compliant" but outputs detailed status for Intune analytics.
    Use this for fleet-wide reporting on mitigation status.
.NOTES
    Deploy as detection-only (no remediation script).
    View results in Intune Endpoint Analytics.
#>

$output = @{
    ComputerName = $env:COMPUTERNAME
    Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
}

try {
    # Device info
    $cs = Get-WmiObject Win32_ComputerSystem
    $output.IsVirtual = $cs.Model -match "Virtual|VMware|HVM|Xen"
    $output.Manufacturer = $cs.Manufacturer
    $output.Model = $cs.Model

    # Secure Boot status
    try {
        $output.SecureBootEnabled = Confirm-SecureBootUEFI
    }
    catch {
        $output.SecureBootEnabled = $false
        $output.SecureBootError = $_.Exception.Message
    }

    if ($output.SecureBootEnabled) {
        # Check mitigations
        $dbBytes = (Get-SecureBootUEFI db -ErrorAction Stop).bytes
        $dbString = [System.Text.Encoding]::ASCII.GetString($dbBytes)
        $output.PCA2023Enrolled = $dbString -match 'Windows UEFI CA 2023'

        # Registry status
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Secureboot"
        $availableUpdates = (Get-ItemProperty -Path $regPath -Name AvailableUpdates -ErrorAction SilentlyContinue).AvailableUpdates
        $output.AvailableUpdates = $availableUpdates

        # Determine status
        if ($output.PCA2023Enrolled -and ($availableUpdates -eq 0 -or $null -eq $availableUpdates)) {
            $output.MitigationStatus = "Complete"
        }
        elseif ($output.PCA2023Enrolled) {
            $output.MitigationStatus = "M1M2Complete-M3M4Pending"
        }
        else {
            $output.MitigationStatus = "NotStarted"
        }
    }
    else {
        $output.MitigationStatus = "NotApplicable-SecureBootDisabled"
    }

    # Output for Intune analytics
    $json = $output | ConvertTo-Json -Compress
    Write-Host $json
    exit 0  # Always compliant - this is for reporting only
}
catch {
    $output.Error = $_.Exception.Message
    Write-Host ($output | ConvertTo-Json -Compress)
    exit 0
}
