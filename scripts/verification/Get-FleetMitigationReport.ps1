<#
.SYNOPSIS
    Generates a fleet-wide CVE-2023-24932 mitigation status report
.DESCRIPTION
    Collects mitigation status from local system for aggregation.
    Output is JSON format suitable for central collection.
.NOTES
    Use with SCCM, Intune, or PowerShell remoting for fleet collection.
    Example: Invoke-Command -ComputerName $computers -FilePath .\Get-FleetMitigationReport.ps1
#>

$results = @{
    ComputerName = $env:COMPUTERNAME
    Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    IsVirtualMachine = $false
    Manufacturer = $null
    Model = $null
    SecureBootEnabled = $false
    PCA2023Enrolled = $false
    AvailableUpdates = $null
    MitigationStatus = "Unknown"
    FirmwareVersion = $null
    OSVersion = $null
}

try {
    # Device info
    $cs = Get-WmiObject Win32_ComputerSystem
    $results.IsVirtualMachine = $cs.Model -match "Virtual|VMware|HVM|Xen"
    $results.Manufacturer = $cs.Manufacturer
    $results.Model = $cs.Model

    # BIOS info
    $bios = Get-WmiObject Win32_BIOS
    $results.FirmwareVersion = $bios.SMBIOSBIOSVersion

    # OS info
    $os = Get-WmiObject Win32_OperatingSystem
    $results.OSVersion = $os.Caption

    # Secure Boot
    try {
        $results.SecureBootEnabled = Confirm-SecureBootUEFI
    }
    catch {
        $results.SecureBootEnabled = $false
    }

    if ($results.SecureBootEnabled) {
        # Check PCA2023
        try {
            $dbBytes = (Get-SecureBootUEFI db).bytes
            $dbString = [System.Text.Encoding]::ASCII.GetString($dbBytes)
            $results.PCA2023Enrolled = $dbString -match 'Windows UEFI CA 2023'
        }
        catch {}

        # Registry status
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Secureboot"
        $results.AvailableUpdates = (Get-ItemProperty -Path $regPath -Name AvailableUpdates -ErrorAction SilentlyContinue).AvailableUpdates

        # Determine status
        if ($results.PCA2023Enrolled -and ($results.AvailableUpdates -eq 0 -or $null -eq $results.AvailableUpdates)) {
            $results.MitigationStatus = "Complete"
        }
        elseif ($results.PCA2023Enrolled) {
            $results.MitigationStatus = "M1M2Complete-M3M4Pending"
        }
        else {
            $results.MitigationStatus = "NotStarted"
        }
    }
    else {
        $results.MitigationStatus = "NotApplicable-SecureBootDisabled"
    }
}
catch {
    $results.Error = $_.Exception.Message
}

# Output as JSON for collection
$results | ConvertTo-Json -Compress
