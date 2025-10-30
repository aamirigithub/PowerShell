<#
.SYNOPSIS
    Collects Microsoft and 3rd-party update history from multiple Windows servers,
    authenticates securely, and generates a consolidated report.

.DESCRIPTION
    This script retrieves installed updates (hotfixes, patches, and 3rd-party updates)
    from local or remote Windows systems using PowerShell Remoting and WMI/CIM.
    Results are consolidated into one CSV summary file for enterprise reporting.

.PARAMETER ServerList
    Path to a text file containing one server name per line.

.PARAMETER ExportCSV
    Path to export the consolidated CSV report.

.EXAMPLE
    .\Get-ConsolidatedUpdateHistory.ps1 -ServerList "C:\Servers.txt" -ExportCSV "C:\Reports\Updates_All.csv"
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$ServerList,

    [Parameter(Mandatory=$true)]
    [string]$ExportCSV
)

Write-Host "`n=== Windows Update & Patch Audit Script ===`n" -ForegroundColor Cyan

# --- Step 1: Import Server List ---
if (-Not (Test-Path $ServerList)) {
    Write-Host "Server list file not found: $ServerList" -ForegroundColor Red
    exit
}

$Servers = Get-Content -Path $ServerList | Where-Object { $_ -and $_ -notmatch '^#' }
if ($Servers.Count -eq 0) {
    Write-Host "No valid servers found in list." -ForegroundColor Red
    exit
}

# --- Step 2: Get User Credentials ---
$Cred = Get-Credential -Message "Enter domain or local credentials for remote connection"

# --- Step 3: Define Remote ScriptBlock ---
$ScriptBlock = {
    param()

    $ComputerName = $env:COMPUTERNAME
    $Result = @()

    # --- Hotfixes ---
    try {
        $Hotfixes = Get-WmiObject -Class Win32_QuickFixEngineering -ErrorAction Stop | Select-Object `
            @{N='Server';E={$ComputerName}},
            @{N='Type';E={'Hotfix'}},
            @{N='KB';E={$_.HotFixID}},
            @{N='Description';E={$_.Description}},
            @{N='InstalledBy';E={$_.InstalledBy}},
            @{N='InstalledOn';E={$_.InstalledOn}},
            @{N='Source';E={'WMI'}}
        $Result += $Hotfixes
    } catch {
        Write-Warning "[$ComputerName] Failed to get Hotfix data."
    }

    # --- Microsoft Update History ---
    try {
        $WUHistory = Get-WmiObject -Namespace "root\cimv2" -Class "Win32_ReliabilityRecords" -ErrorAction Stop |
            Where-Object { $_.SourceName -eq "Microsoft-Windows-WindowsUpdateClient" -and $_.Message -match "Installed" } |
            Select-Object `
                @{N='Server';E={$ComputerName}},
                @{N='Type';E={'Microsoft Update'}},
                @{N='KB';E={($_.Message -split 'KB')[1] -split '\s' | Select-Object -First 1}},
                @{N='Description';E={$_.Message}},
                @{N='InstalledBy';E={$_.User}},
                @{N='InstalledOn';E={[datetime]::Parse($_.TimeGenerated)}},
                @{N='Source';E={'ReliabilityRecords'}}
        $Result += $WUHistory
    } catch {
        Write-Warning "[$ComputerName] Failed to get Windows Update History."
    }

    # --- 3rd Party Updates (MSI) ---
    try {
        $ThirdParty = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*,
                                       HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -and $_.DisplayName -notmatch 'Update for Microsoft|Hotfix|Security Update|KB' } |
            Select-Object `
                @{N='Server';E={$ComputerName}},
                @{N='Type';E={'3rd Party'}},
                @{N='KB';E={'N/A'}},
                @{N='Description';E={$_.DisplayName}},
                @{N='InstalledBy';E={$_.Publisher}},
                @{N='InstalledOn';E={if ($_.InstallDate) {([datetime]::ParseExact($_.InstallDate, 'yyyyMMdd', $null))} else { $null }}},
                @{N='Source';E={'Registry'}}
        $Result += $ThirdParty
    } catch {
        Write-Warning "[$ComputerName] Failed to get 3rd-party updates."
    }

    return $Result
}

# --- Step 4: Process Each Server ---
$AllResults = @()
foreach ($Server in $Servers) {
    Write-Host "`nConnecting to $Server ..." -ForegroundColor Yellow
    try {
        $Data = Invoke-Command -ComputerName $Server -Credential $Cred -ScriptBlock $ScriptBlock -ErrorAction Stop
        if ($Data) {
            Write-Host "✅ Successfully collected data from $Server" -ForegroundColor Green
            $AllResults += $Data
        } else {
            Write-Warning "⚠️ No update data returned from $Server"
        }
    } catch {
        Write-Warning "❌ Failed to connect to $Server. Error: $($_.Exception.Message)"
    }
}

# --- Step 5: Consolidate and Export ---
if ($AllResults.Count -gt 0) {
    $AllResults = $AllResults | Sort-Object Server, InstalledOn -Descending
    $AllResults | Export-Csv -Path $ExportCSV -NoTypeInformation -Encoding UTF8

    Write-Host "`n=== Consolidated Report Generated ===" -ForegroundColor Cyan
    Write-Host "Total Servers Processed: $($Servers.Count)" -ForegroundColor Gray
    Write-Host "Total Updates Found: $($AllResults.Count)" -ForegroundColor Gray
    Write-Host "Report Path: $ExportCSV" -ForegroundColor Green
} else {
    Write-Host "No data collected. Please verify server access or credentials." -ForegroundColor Red
}
