<#
.SYNOPSIS
    Audits Hyper-V VMs for Secure Boot status and mitigation requirements
.DESCRIPTION
    Run on Hyper-V host to audit all VMs for Secure Boot configuration.
    Identifies which VMs require CVE-2023-24932 mitigations.
.EXAMPLE
    .\Test-HyperV-VMs.ps1
    .\Test-HyperV-VMs.ps1 | Export-Csv -Path "VM-Audit.csv" -NoTypeInformation
#>

[CmdletBinding()]
param()

Write-Host "=== Hyper-V VM Secure Boot Audit ===" -ForegroundColor Cyan
Write-Host ""

$results = Get-VM | ForEach-Object {
    $vm = $_
    $fw = $null
    $secureBootStatus = "N/A"
    $secureBootTemplate = "N/A"
    $mitigationRequired = "Unknown"

    if ($vm.Generation -eq 2) {
        try {
            $fw = Get-VMFirmware -VMName $vm.Name -ErrorAction Stop
            $secureBootStatus = $fw.SecureBoot
            $secureBootTemplate = $fw.SecureBootTemplate
        }
        catch {
            $secureBootStatus = "Error: $($_.Exception.Message)"
        }
    }

    # Determine if mitigation is required
    if ($vm.Generation -eq 1) {
        $mitigationRequired = "No (Gen 1 - BIOS)"
    }
    elseif ($secureBootStatus -eq "Off") {
        $mitigationRequired = "No (Secure Boot Disabled)"
    }
    elseif ($secureBootStatus -eq "On") {
        $mitigationRequired = "YES - Apply inside VM"
    }
    else {
        $mitigationRequired = "Unknown - Check manually"
    }

    [PSCustomObject]@{
        VMName = $vm.Name
        Generation = $vm.Generation
        State = $vm.State
        SecureBoot = $secureBootStatus
        SecureBootTemplate = $secureBootTemplate
        MitigationRequired = $mitigationRequired
    }
}

# Display results
$results | Format-Table -AutoSize

# Summary
Write-Host ""
Write-Host "=== Summary ===" -ForegroundColor Cyan
$total = $results.Count
$requireMitigation = ($results | Where-Object { $_.MitigationRequired -like "YES*" }).Count
$gen1 = ($results | Where-Object { $_.Generation -eq 1 }).Count
$sbDisabled = ($results | Where-Object { $_.MitigationRequired -like "*Disabled*" }).Count

Write-Host "Total VMs: $total"
Write-Host "Gen 1 VMs (no action needed): $gen1" -ForegroundColor Green
Write-Host "Gen 2 with Secure Boot OFF (no action needed): $sbDisabled" -ForegroundColor Green
Write-Host "Gen 2 with Secure Boot ON (REQUIRE mitigations): $requireMitigation" -ForegroundColor $(if ($requireMitigation -gt 0) { "Yellow" } else { "Green" })

$results
