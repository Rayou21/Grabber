# 🛡️ Grabber – Windows Security Log Extractor (PowerShell)

![PowerShell](https://img.shields.io/badge/PowerShell-5+-blue?logo=powershell)
![Windows](https://img.shields.io/badge/OS-Windows%2010%2F11-green?logo=windows)
![JSON](https://img.shields.io/badge/Output-JSON-orange?logo=json)
![HTML](https://img.shields.io/badge/Report-HTML-purple)
![License](https://img.shields.io/badge/License-MIT-lightgrey)

Grabber is a PowerShell tool designed to extract, analyze, and visualize **Windows Security logs**.  
It generates:

- A **JSON file** containing all matching events  
- A **JSON statistics file** summarizing event counts  
- A **full HTML report** including:
  - Summary  
  - Event statistics  
  - Last 20 events  
  - Detection rules  
  - Correlation alerts  
  - Optional Sysmon summary  

This tool is ideal for **blue-team learning**, **SOC analysis**, and **Windows security auditing**.

---

## 📝 Overview

Grabber helps identify:

- 🔐 Authentication attempts (success, failure, explicit credentials)  
- 🚨 Privilege-related events (special privileges, admin-like activity)  
- 👤 Account operations (creation, group membership changes)  
- ⚙️ Process creation (potentially suspicious activity)  
- 🧩 Correlated attack patterns (logon → privilege → account change)  
- 🧠 Simple detections (brute force, privilege escalation, etc.)  

It provides a **clean HTML report** for quick review and portfolio demonstration.

---

## ✨ Features

- **Security log extraction** using `Get-WinEvent`
- **Time range filtering** (`-Hours`)
- **User filtering** (`-User`)
- **Custom Event IDs** (`-EventIDsOverride`)
- **JSON export** (full logs + stats)
- **HTML report generation**
- **Detection engine** (brute force, privilege escalation, account creation)
- **Correlation engine** (4624 + 4672 + 4720/4728)
- **Sysmon summary** (if installed)
- **Console alerts** with severity colors
- **Non-destructive** (read-only)

---

## 📊 Default Event IDs

| Event ID | Description |
|----------|-------------|
| 4624 | Successful logon |
| 4625 | Failed logon |
| 4672 | Special privileges assigned |
| 4688 | New process created |
| 4720 | User account created |
| 4728 | User added to a security group |
| 4648 | Logon using explicit credentials |
| 1149 | Successful RDP connection |

Override example:

```powershell
-EventIDsOverride 4625,4688
```

---

## 💻 Script – Grabber.ps1

````powershell
# Grabber - Windows Security Log Extractor
# Improved Version (B)
# Author: Ryan
# Usage: Run PowerShell as Administrator

param(
    [int]$Hours = 24,
    [string]$User,
    [int[]]$EventIDsOverride
)

# Admin check
$IsAdmin = (
    [Security.Principal.WindowsPrincipal]::new(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    )
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $IsAdmin) {
    Write-Host "[ERROR] Run as Administrator." -ForegroundColor Red
    exit
}

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$StartTime = (Get-Date).AddHours(-$Hours)

# Default Event IDs (added 4624 for correlation)
$EventIDs = 4624, 4625, 4672, 4688, 4720, 4728, 4648, 1149
if ($EventIDsOverride) { $EventIDs = $EventIDsOverride }

# Retrieve Security logs
$Logs = Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = $EventIDs
    StartTime = $StartTime
} -ErrorAction SilentlyContinue |
Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message

# Optional user filter
if ($User) {
    $Logs = $Logs | Where-Object { $_.Message -match $User }
}

# Export logs JSON
$OutputPath = "$env:USERPROFILE\Desktop\logs_compromission_$Timestamp.json"
$Logs | ConvertTo-Json -Depth 6 | Out-File $OutputPath

# Generate statistics
$Stats = $Logs | Group-Object Id | Select-Object Name, Count
$StatsPath = "$env:USERPROFILE\Desktop\stats_$Timestamp.json"
$Stats | ConvertTo-Json | Out-File $StatsPath

# Select last 20 events
$RecentLogs = $Logs | Sort-Object TimeCreated -Descending | Select-Object -First 20

# --- Simple detections & correlation ---

$Detections = @()

# Helper: get count for a given Event ID
function Get-EventCount {
    param([int]$Id)
    $match = $Stats | Where-Object { [int]$_.Name -eq $Id }
    if ($match) { return [int]$match.Count } else { return 0 }
}

$idsPresent = $Stats.Name

# Rule 1: Brute force (many failed logons 4625)
$failedCount = Get-EventCount -Id 4625
if ($failedCount -gt 10) {
    $Detections += [PSCustomObject]@{
        Severity    = 'High'
        Type        = 'Brute force suspected'
        Description = "Detected $failedCount failed logon attempts (Event ID 4625)."
    }
}

# Rule 2: New account created (4720)
if ($idsPresent -contains '4720') {
    $Detections += [PSCustomObject]@{
        Severity    = 'Medium'
        Type        = 'Account creation'
        Description = "At least one user account creation detected (Event ID 4720)."
    }
}

# Rule 3: User added to privileged group (4728)
if ($idsPresent -contains '4728') {
    $Detections += [PSCustomObject]@{
        Severity    = 'High'
        Type        = 'Privilege escalation (group membership)'
        Description = "At least one user added to a security group (Event ID 4728)."
    }
}

# Rule 4: Many special privileges (4672)
$privCount = Get-EventCount -Id 4672
if ($privCount -gt 5) {
    $Detections += [PSCustomObject]@{
        Severity    = 'Medium'
        Type        = 'Frequent privileged logons'
        Description = "Detected $privCount logons with special privileges (Event ID 4672)."
    }
}

# Rule 5: Simple correlation chain (4624 + 4672 + (4720 or 4728))
if ( ($idsPresent -contains '4624') -and
     ($idsPresent -contains '4672') -and
     ( ($idsPresent -contains '4720') -or ($idsPresent -contains '4728') ) ) {

    $Detections += [PSCustomObject]@{
        Severity    = 'High'
        Type        = 'Privilege escalation chain'
        Description = "Logons, special privileges, and account/group changes detected in the same time window."
    }
}

# --- Optional Sysmon summary (if present) ---

$SysmonLogs = Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 200 -ErrorAction SilentlyContinue
if ($SysmonLogs) {
    $SysmonCount = $SysmonLogs.Count
    $SysmonSummaryHtml = "<p><strong>Sysmon events (last 200):</strong> $SysmonCount</p>"
} else {
    $SysmonSummaryHtml = "<p><strong>Sysmon:</strong> No Sysmon log found or no events available.</p>"
}

# --- Build detections HTML ---

if ($Detections.Count -gt 0) {
    $DetectionsHtmlItems = $Detections | ForEach-Object {
        "<li><strong>$($_.Severity)</strong> - $($_.Type): $($_.Description)</li>"
    }
    $DetectionsHtml = "<ul>$($DetectionsHtmlItems -join '')</ul>"
} else {
    $DetectionsHtml = "<p>No detections triggered for this time range.</p>"
}

# --- Convert tables to HTML fragments ---

$StatsTableHtml  = $Stats | ConvertTo-Html -Property Name, Count -Fragment
$RecentTableHtml = $RecentLogs | ConvertTo-Html -Property TimeCreated, Id, ProviderName, Message -Fragment

# --- Generate HTML report ---

$HtmlTitle = "Grabber - Windows Security Report"
$HtmlFile  = "$env:USERPROFILE\Desktop\report_compromission_$Timestamp.html"

$HtmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>$HtmlTitle</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #0f172a; color: #e5e7eb; }
        h1, h2 { color: #38bdf8; }
        .summary { margin-bottom: 20px; }
        table { border-collapse: collapse; width: 95%; margin-top: 10px; }
        th, td { border: 1px solid #4b5563; padding: 8px; text-align: left; }
        th { background-color: #1f2937; }
        tr:nth-child(even) { background-color: #111827; }
        .footer { margin-top: 30px; font-size: 0.9em; color: #9ca3af; }
        .detections { margin-top: 20px; padding: 10px; background-color: #111827; border: 1px solid #4b5563; }
    </style>
</head>
<body>
    <h1>$HtmlTitle</h1>

    <div class="summary">
        <p><strong>Generated at:</strong> $((Get-Date).ToString("yyyy-MM-dd HH:mm:ss"))</p>
        <p><strong>Time range:</strong> Last $Hours hour(s)</p>
        <p><strong>Total events:</strong> $($Logs.Count)</p>
        $SysmonSummaryHtml
    </div>

    <div class="detections">
        <h2>Detections & Alerts</h2>
        $DetectionsHtml
    </div>

    <h2>Event statistics by ID</h2>
    $StatsTableHtml

    <h2>Last 20 Events</h2>
    $RecentTableHtml

    <div class="footer">
        <p>Report generated by Grabber (Ryan) - PowerShell log extractor.</p>
    </div>
</body>
</html>
"@

$HtmlContent | Out-File -FilePath $HtmlFile -Encoding UTF8

# --- Console output ---

Write-Host "Logs exported to: $OutputPath"
Write-Host "Stats exported to: $StatsPath"
Write-Host "HTML report exported to: $HtmlFile"

if ($Detections.Count -gt 0) {
    Write-Host "`nDetections:" -ForegroundColor Yellow
    foreach ($d in $Detections) {
        $color = switch ($d.Severity) {
            'High'   { 'Red' }
            'Medium' { 'Yellow' }
            default  { 'Cyan' }
        }
        Write-Host ("[{0}] {1} - {2}" -f $d.Severity, $d.Type, $d.Description) -ForegroundColor $color
    }
} else {
    Write-Host "No detections triggered for this time range." -ForegroundColor Green
}
````

---
## 🚀 Usage

### Default (last 24 hours)
```powershell
.\Grabber.ps1
```

### Custom time range
```powershell
.\Grabber.ps1 -Hours 72
```

### Filter by user
```powershell
.\Grabber.ps1 -User "ryan"
```

### Custom Event IDs
```powershell
.\Grabber.ps1 -EventIDsOverride 4625,4688
```

---

## 📂 Output files

- `logs_compromission_YYYYMMDD_HHMMSS.json` — full extracted events  
- `stats_YYYYMMDD_HHMMSS.json` — event count per Event ID  
- `report_compromission_YYYYMMDD_HHMMSS.html` — full HTML report (summary, stats, detections, correlation, last events)

---

## 🔮 Future improvements

- Graphs in HTML (bar charts, pie charts)  
- Timeline visualization  
- Advanced correlation engine  
- Sysmon deep integration  
- Real-time monitoring mode  

---

## 📄 License

MIT License – free to use, modify, and learn from.

