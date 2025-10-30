<#
.SYNOPSIS
Compares SCCM client’s detected software updates against locally installed Windows updates.

.DESCRIPTION
Pulls data from:
- SCCM WMI class (CCM_SoftwareUpdate)
- Windows Update history (Get-WUHistory)
- Windows HotFix list (Get-HotFix)

Then compares which KBs SCCM thinks are required vs installed locally.

.Author: Aamir’s Assistant (GPT-5)
.Version: 1.0
#>

Write-Host "Collecting SCCM and Windows Update information..." -ForegroundColor Cyan

# --- 1. Get updates SCCM THINKS are required or missing ---
$SCCMUpdates = Get-WmiObject -Namespace "root\ccm\ClientSDK" -Class CCM_SoftwareUpdate `
    -ErrorAction SilentlyContinue |
    Where-Object { $_.EvaluationState -eq 0 -or $_.EvaluationState -eq 1 } | # 0=Unknown, 1=NotRequired, 2=Required, etc.
    Select-Object ArticleID, BulletinID, Name, EvaluationState, ComplianceState

# --- 2. Get installed updates from Windows ---
$InstalledHotFixes = Get-HotFix | Select-Object HotFixID, InstalledOn
$WUHistory = Get-WUHistory | Select-Object Title, Date, ResultCode

# --- 3. Compare SCCM vs Installed ---
$MissingFromWindows = @()
$InstalledButNotInSCCM = @()

foreach ($update in $SCCMUpdates) {
    if ($InstalledHotFixes.HotFixID -contains ("KB" + $update.ArticleID)) {
        # Match found, installed
        continue
    } else {
        $MissingFromWindows += $update
    }
}

foreach ($hotfix in $InstalledHotFixes) {
    $kb = $hotfix.HotFixID -replace "KB", ""
    if ($SCCMUpdates.ArticleID -notcontains $kb) {
        $InstalledButNotInSCCM += $hotfix
    }
}

# --- 4. Display Results ---
Write-Host "`n========= SCCM Shows as Missing =========" -ForegroundColor Yellow
if ($MissingFromWindows.Count -gt 0) {
    $MissingFromWindows | Select-Object ArticleID, Name, EvaluationState | Format-Table -AutoSize
} else {
    Write-Host "✅ No SCCM-reported missing updates detected."
}

Write-Host "`n========= Installed But Not in SCCM =========" -ForegroundColor Yellow
if ($InstalledButNotInSCCM.Count -gt 0) {
    $InstalledButNotInSCCM | Format-Table HotFixID, InstalledOn -AutoSize
} else {
    Write-Host "✅ No orphaned or manually installed updates found."
}

Write-Host "`n========= Summary =========" -ForegroundColor Cyan
Write-Host "SCCM-detected updates count: $($SCCMUpdates.Count)"
Write-Host "Hotfixes installed (Get-HotFix): $($InstalledHotFixes.Count)"
Write-Host "Windows Update History entries: $($WUHistory.Count)"

Write-Host "`nDone! Compare results above to verify compliance discrepancies." -ForegroundColor Green
