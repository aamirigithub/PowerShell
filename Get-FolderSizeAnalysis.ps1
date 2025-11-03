<#
.SYNOPSIS
    Scans C:\ drive to find folder sizes, identifies the largest folder,
    and lists file type distribution in that folder.

.DESCRIPTION
    This script recursively analyzes the C:\ drive.
    It calculates total size per top-level folder, finds the largest one,
    and reports on the most common file types (by count and total size).

.EXAMPLE
    .\Get-FolderSizeAnalysis.ps1

.EXAMPLE
    .\Get-FolderSizeAnalysis.ps1 -ExportCSV "C:\Reports\FolderAnalysis.csv"
#>

param(
    [string]$Drive = "C:\",
    [string]$ExportCSV = ""
)

Write-Host "`n=== Folder Size and File Type Analysis ===" -ForegroundColor Cyan
Write-Host "Scanning drive: $Drive`n" -ForegroundColor Yellow

# --- Step 1: Get Top-Level Folders ---
$Folders = Get-ChildItem -Path $Drive -Directory -ErrorAction SilentlyContinue
if (-not $Folders) {
    Write-Host "No folders found or access denied on drive $Drive" -ForegroundColor Red
    exit
}

$FolderReport = @()

# --- Step 2: Calculate Folder Sizes ---
foreach ($Folder in $Folders) {
    Write-Host "Analyzing $($Folder.FullName) ..." -ForegroundColor Gray
    try {
        $Size = (Get-ChildItem -Path $Folder.FullName -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
        $FolderReport += [PSCustomObject]@{
            FolderName = $Folder.FullName
            SizeGB     = [math]::Round($Size / 1GB, 2)
        }
    } catch {
        Write-Warning "Failed to calculate size for $($Folder.FullName): $($_.Exception.Message)"
    }
}

# --- Step 3: Identify the Largest Folder ---
$Largest = $FolderReport | Sort-Object SizeGB -Descending | Select-Object -First 1

Write-Host "`n=== Largest Folder Identified ===" -ForegroundColor Green
Write-Host ("Folder: {0}" -f $Largest.FolderName)
Write-Host ("Size: {0} GB" -f $Largest.SizeGB)

# --- Step 4: Analyze File Types in Largest Folder ---
Write-Host "`nAnalyzing file types in $($Largest.FolderName)..." -ForegroundColor Yellow
try {
    $FileTypeReport = Get-ChildItem -Path $Largest.FolderName -Recurse -File -ErrorAction SilentlyContinue |
        Group-Object Extension | Sort-Object Count -Descending | ForEach-Object {
            $Ext = if ($_.Name) { $_.Name } else { "[No Extension]" }
            $Size = ($_.Group | Measure-Object -Property Length -Sum).Sum
            [PSCustomObject]@{
                Extension = $Ext
                FileCount = $_.Count
                TotalSizeMB = [math]::Round($Size / 1MB, 2)
            }
        }

    Write-Host "`n=== File Type Distribution in Largest Folder ===" -ForegroundColor Cyan
    $FileTypeReport | Format-Table -AutoSize
} catch {
    Write-Warning "Error analyzing file types in $($Largest.FolderName)"
}

# --- Step 5: Optional CSV Export ---
if ($ExportCSV) {
    try {
        $FolderReport | Export-Csv -Path $ExportCSV -NoTypeInformation -Encoding UTF8
        Write-Host "`nFolder size report exported to: $ExportCSV" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to export report to CSV."
    }
}

# --- Step 6: Summary Output ---
Write-Host "`n=== Summary ===" -ForegroundColor Cyan
Write-Host "Total Folders Scanned: $($FolderReport.Count)"
Write-Host "Largest Folder: $($Largest.FolderName) ($($Largest.SizeGB) GB)"
Write-Host "Most Common File Type in Largest Folder: $($FileTypeReport[0].Extension) ($($FileTypeReport[0].FileCount) files)"
