<#
.SYNOPSIS
    Retrieves the history of applied Microsoft monthly updates, hotfixes, patches, and 3rd-party updates.

.DESCRIPTION
    This script collects update data from multiple sources:
    - Win32_QuickFixEngineering (Hotfixes)
    - Windows Update History (Microsoft updates)
    - Registry keys for 3rd-party MSI or WSUS updates
    - WMI and CIM objects for comprehensive results

.OUTPUTS
    Displays results in a table and optionally exports to CSV.

.EXAMPLE
    .\Get-SystemUpdateHistory.ps1
    Retrieves and displays all updates installed on the local system.

.EXAMPLE
    .\Get-SystemUpdateHistory.ps1 -ExportCSV "C:\Reports\UpdateHistory.csv"
    Exports update history to a CSV file.
#>

param (
    [string]$ExportCSV = ""
)

Write-Host "Collecting system update history... This may take a few moments.`n" -ForegroundColor Cyan

# --- 1. Get Hotfixes (QFEs) ---
Write-Host "Gathering Hotfix information (Win32_QuickFixEngineering)..." -ForegroundColor Yellow
$Hotfixes = Get-WmiObject -Class Win32_QuickFixEngineering | Select-Object `
    @{N='Type';E={'Hotfix'}},
    @{N='KB';E={$_.HotFixID}},
    @{N='Description';E={$_.Description}},
    @{N='InstalledBy';E={$_.InstalledBy}},
    @{N='InstalledOn';E={$_.InstalledOn}},
    @{N='Source';E={'WMI'}}

# --- 2. Get Windows Update History (Microsoft Updates) ---
Write-Host "Gathering Microsoft Update history (Get-WmiObject Win32_ReliabilityRecords)..." -ForegroundColor Yellow
try {
    $WUHistory = Get-WmiObject -Namespace "root\cimv2" -Class "Win32_ReliabilityRecords" -ErrorAction SilentlyContinue |
        Where-Object { $_.SourceName -eq "Microsoft-Windows-WindowsUpdateClient" -and $_.Message -match "Installed" } |
        Select-Object `
            @{N='Type';E={'Microsoft Update'}},
            @{N='KB';E={($_.Message -split 'KB')[1] -split '\s' | Select-Object -First 1}},
            @{N='Description';E={$_.Message}},
            @{N='InstalledBy';E={$_.User}},
            @{N='InstalledOn';E={[datetime]::Parse($_.TimeGenerated)}},
            @{N='Source';E={'ReliabilityRecords'}}
}
catch {
    Write-Warning "Unable to retrieve Microsoft Update history from Reliability Records."
}

# --- 3. Get Installed Products (3rd-party MSI-based updates) ---
Write-Host "Gathering 3rd-party updates (MSI Installed Products)..." -ForegroundColor Yellow
$ThirdParty = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*,
                               HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -and $_.DisplayName -notmatch 'Update for Microsoft|Hotfix|Security Update|KB' } |
    Select-Object `
        @{N='Type';E={'3rd Party'}},
        @{N='KB';E={'N/A'}},
        @{N='Description';E={$_.DisplayName}},
        @{N='InstalledBy';E={$_.Publisher}},
        @{N='InstalledOn';E={if ($_.InstallDate) {([datetime]::ParseExact($_.InstallDate, 'yyyyMMdd', $null))} else { $null }}},
        @{N='Source';E={'Registry'}}

# --- 4. Combine Results ---
$AllUpdates = @()
if ($Hotfixes) { $AllUpdates += $Hotfixes }
if ($WUHistory) { $AllUpdates += $WUHistory }
if ($ThirdParty) { $AllUpdates += $ThirdParty }

# --- 5. Sort and Display ---
$AllUpdates = $AllUpdates | Sort-Object InstalledOn -Descending

Write-Host "`n=== Installed Updates Summary ===`n" -ForegroundColor Green
$AllUpdates | Format-Table -AutoSize Type, KB, Description, InstalledBy, InstalledOn, Source

# --- 6. Optional Export to CSV ---
if ($ExportCSV) {
    try {
        $AllUpdates | Export-Csv -Path $ExportCSV -NoTypeInformation -Encoding UTF8
        Write-Host "`nReport exported successfully to $ExportCSV" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to export report to CSV. Check path and permissions."
    }
}
