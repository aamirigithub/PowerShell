<#
.SYNOPSIS
    Recursively scans a drive (default C:\) and lists the Top N largest folders with their sizes.
    Also analyzes file types in the largest folder.

.DESCRIPTION
    This script measures only files (ignores folder objects).
    It includes error handling and progress tracking for large drives.

.EXAMPLE
    .\Get-TopFoldersAnalysis.ps1 -Drive 'C:\' -TopN 10
#>

param(
    [string]$Drive = 'C:\',
    [int]$TopN = 10,
    [string]$ExportCSV = ''
)

Write-Host "`n=== Recursive Folder Size Analysis ===" -ForegroundColor Cyan
Write-Host "Scanning recursively: $Drive" -ForegroundColor Yellow

# Step 1: Get all folders recursively
try {
    $AllFolders = Get-ChildItem -Path $Drive -Directory -Recurse -ErrorAction SilentlyContinue
    if (-not $AllFolders) {
        Write-Host "No folders found or access denied in $Drive" -ForegroundColor Red
        exit
    }
} catch {
    Write-Host "Error scanning drive $Drive $($_.Exception.Message)" -ForegroundColor Red
    exit
}

$FolderReport = @()
$Counter = 0
$Total = $AllFolders.Count

# Step 2: Measure folder sizes
foreach ($Folder in $AllFolders) {
    $Counter++
    Write-Progress -Activity "Calculating folder sizes..." -Status "Processing $($Folder.FullName)" -PercentComplete (($Counter / $Total) * 100)
    try {
        # Only count files, ignore directories
        $Files = Get-ChildItem -Path $Folder.FullName -Recurse -File -ErrorAction SilentlyContinue
        if ($Files) {
            $Size = ($Files | Measure-Object -Property Length -Sum).Sum
        } else {
            $Size = 0
        }

        $FolderReport += [PSCustomObject]@{
            FolderName = $Folder.FullName
            SizeGB     = [math]::Round($Size / 1GB, 3)
        }
    } catch {
        Write-Warning "Failed to calculate size for $($Folder.FullName): $($_.Exception.Message)"
    }
}

# Step 3: Sort and display Top N largest folders
$TopFolders = $FolderReport | Sort-Object SizeGB -Descending | Select-Object -First $TopN

Write-Host "`n=== Top $TopN Largest Folders ===" -ForegroundColor Green
$TopFolders | Format-Table -AutoSize FolderName, SizeGB

# Step 4: Analyze file types in the largest folder
$LargestFolder = $TopFolders | Select-Object -First 1
if ($null -ne $LargestFolder) {
    Write-Host "`nAnalyzing file types in largest folder: $($LargestFolder.FolderName)" -ForegroundColor Yellow

    try {
        $FileTypeReport = Get-ChildItem -Path $LargestFolder.FolderName -Recurse -File -ErrorAction SilentlyContinue |
            Group-Object Extension | Sort-Object Count -Descending | ForEach-Object {
                $Ext = if ($_.Name) { $_.Name } else { '[No Extension]' }
                $Size = ($_.Group | Measure-Object -Property Length -Sum).Sum
                [PSCustomObject]@{
                    Extension   = $Ext
                    FileCount   = $_.Count
                    TotalSizeMB = [math]::Round($Size / 1MB, 2)
                }
            }

        if ($FileTypeReport) {
            Write-Host "`n=== File Type Distribution in Largest Folder ===" -ForegroundColor Cyan
            $FileTypeReport | Format-Table -AutoSize
        } else {
            Write-Host "No files found in largest folder." -ForegroundColor DarkYellow
        }
    } catch {
        Write-Warning "Error analyzing file types in $($LargestFolder.FolderName)"
    }
}

# Step 5: Optional export
if ($ExportCSV) {
    try {
        $TopFolders | Export-Csv -Path $ExportCSV -NoTypeInformation -Encoding UTF8
        Write-Host "`nTop $TopN folder report exported to: $ExportCSV" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to export report to CSV."
    }
}

# Step 6: Summary
Write-Host "`n=== Summary ===" -ForegroundColor Cyan
Write-Host "Drive Scanned: $Drive"
Write-Host "Total Folders Scanned: $($FolderReport.Count)"
Write-Host "Top $TopN Folders Listed"
if ($LargestFolder) {
    Write-Host ("Largest Folder: {0} ({1} GB)" -f $LargestFolder.FolderName, $LargestFolder.SizeGB)
}
