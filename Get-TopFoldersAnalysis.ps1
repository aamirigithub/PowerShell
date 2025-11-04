<#
.SYNOPSIS
    Recursively scans the entire C:\ drive and lists the Top N largest folders with their sizes.
    Also analyzes file types in the single largest folder.

.DESCRIPTION
    This script calculates the total size of all folders on a drive recursively.
    It reports the Top N largest folders, and analyzes file type distribution in the largest one.

.PARAMETER Drive
    The drive or folder path to analyze (default is C:\)

.PARAMETER TopN
    Number of top largest folders to display (default is 10)

.PARAMETER ExportCSV
    Optional path to export results to CSV.

.EXAMPLE
    .\Get-TopFoldersAnalysis.ps1 -Drive "C:\" -TopN 10

.EXAMPLE
    .\Get-TopFoldersAnalysis.ps1 -Drive "D:\" -TopN 20 -ExportCSV "C:\Reports\DDrive_TopFolders.csv"
#>

param(
    [string]$Drive = "C:\",
    [int]$TopN = 10,
    [string]$ExportCSV = ""
)

Write-Host "`n=== Recursive Folder Size Analysis ===" -ForegroundColor Cyan
Write-Host "Scanning recursively: $Drive" -ForegroundColor Yellow

# --- Step 1: Get All Folders Recursively ---
try {
    $AllFolders = Get-ChildItem -Path $Drive -Directory -Recurse -ErrorAction SilentlyContinue
    if (-not $AllFolders) {
        Write-Host "No folders found or access denied in $Drive" -ForegroundColor Red
        exit
    }
} catch {
    Write-Host "Error scanning drive $Drive: $($_.Exception.Message)" -ForegroundColor Red
    exit
}

# --- Step 2: Measure Size of Each Folder ---
$FolderReport = @()

foreach ($Folder in $AllFolders) {
    try {
        $Size = (Get-ChildItem -Path $Folder.FullName -Recurse -ErrorAction SilentlyContinue | 
                 Measure-Object -Property Length -Sum).Sum
        $FolderReport += [PSCustomObject]@{
            FolderName = $Folder.FullName
            SizeGB     = [math]::Round($Size / 1GB, 2)
        }
    } catch {
        Write-Warning "Failed to calculate size for $($Folder.FullName): $($_.Exception.Message)"
    }
}

# --- Step 3: Sort and Display Top N Largest Folders ---
$TopFolders = $FolderReport | Sort-Object SizeGB -Descending | Select-Object -First $TopN

Write-Host "`n=== Top $TopN Largest Folders ===" -ForegroundColor Green
$TopFolders | Format-Table -AutoSize FolderName, SizeGB

# --- Step 4: Analyze File Types in the Largest Folder ---
$LargestFolder = $TopFolders | Select-Object -First 1
Write-Host "`nAnalyzing file types in largest folder: $($LargestFolder.FolderName)" -ForegroundColor Yellow

try {
    $FileTypeReport = Get-ChildItem -Path $LargestFolder.FolderName -Recurse -File -ErrorAction SilentlyContinue |
        Group-Object Extension | Sort-Object Count -Descending | ForEach-Object {
            $Ext = if ($_.Name) { $_.Name } else { "[No Extension]" }
            $Size = ($_.Group | Measure-Object -Property Length -Sum).Sum
            [PSCustomObject]@{
                Extension   = $Ext
                FileCount   = $_.Count
                TotalSizeMB = [math]::Round($Size / 1MB, 2)
            }
        }

    Write-Host "`n=== File Type Distribution in $($LargestFolder.FolderName) ===" -ForegroundColor Cyan
    $FileTypeReport | Format-Table -AutoSize
} catch {
    Write-Warning "Error analyzing file types in $($LargestFolder.FolderName)"
}

# --- Step 5: Optional Export ---
if ($ExportCSV) {
    try {
        $TopFolders | Export-Csv -Path $ExportCSV -NoTypeInformation -Encoding UTF8
        Write-Host "`nTop $TopN folder report exported to: $ExportCSV" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to export report to CSV."
    }
}

# --- Step 6: Summary ---
Write-Host "`n=== Summary ===" -ForegroundColor Cyan
Write-Host "Drive Scanned: $Drive"
Write-Host "Total Folders Scanned: $($FolderReport.Count)"
Write-Host "Top $TopN Folders Listed"
Write-Host ("Largest Folder: {0} ({1} GB)" -f $LargestFolder.FolderName, $LargestFolder.SizeGB)
Write-Host ("Most Common File Type in Largest Folder: {0}" -f $FileTypeReport[0].Extension)
