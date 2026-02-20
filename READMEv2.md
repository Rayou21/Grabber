# 🛡️ Grabber – Windows Security Log Extractor (PowerShell)

![PowerShell](https://img.shields.io/badge/PowerShell-5+-blue?logo=powershell)
![Windows](https://img.shields.io/badge/OS-Windows%2010%2F11-green?logo=windows)
![JSON](https://img.shields.io/badge/Output-JSON-orange?logo=json)
![License](https://img.shields.io/badge/License-MIT-lightgrey)

Grabber is a PowerShell script that extracts **Windows Security** events, filters them by **time range**, **event IDs**, and optionally **user**, then exports:

- A detailed **JSON log file** of all matching events  
- A **JSON statistics file** summarizing counts per Event ID  

It is designed as a **blue-team / SOC learning tool**, to quickly review authentication attempts, privilege use, and account changes without digging manually in Event Viewer.

---

## 📝 Overview

Grabber helps you quickly identify:

- 🔐 **Authentication attempts** (failed / explicit credentials)  
- 🚨 **Privilege-related events** (special privileges, admin-like activity)  
- 👤 **Account operations** (creation, group membership changes)  
- ⚙️ **Process creation** (potentially suspicious activity)  

Instead of manually browsing the Security log, you get:

- A **structured JSON file** you can parse, filter, and analyze  
- A **stats JSON file** to see which Event IDs are most frequent  

This script is part of a learning path in:

- Windows Administration  
- PowerShell scripting  
- Defensive Security / Blue Team  

---

## ✨ Features

- **Security log only**: reads from `LogName = 'Security'`  
- **Time range selection**: `-Hours` (default: last 24 hours)  
- **User filter**: `-User` (filter events whose message contains the username)  
- **Custom Event IDs**: `-EventIDsOverride` to override the default list  
- **Timestamped output files**: unique filenames per run  
- **Event statistics**: grouped by Event ID, exported to JSON  
- **Non-destructive**: read-only, no changes to the system  
- **Simple usage**: run once, get two JSON files on Desktop  

---

## 🎯 Default Event IDs Covered

| Event ID | Description |
|----------|------------|
| 4625 | Failed logon attempt |
| 4672 | Special privileges assigned to a new logon |
| 4688 | New process created |
| 4720 | User account created |
| 4728 | User added to a security group |
| 4648 | Logon using explicit credentials |
| 1149 | Successful RDP connection |

You can override this list with:

```powershell
-EventIDsOverride 4625,4688
```

---

## 💻 Script – Grabber.ps1

```powershell
# Grabber - Windows Security Log Extractor
# Improved Version (A)
# Author: Ryan
# Usage: Run PowerShell as Administrator

param(
    [int]$Hours = 24,
    [string]$User,
    [int[]]$EventIDsOverride
)

# Admin check
$IsAdmin = ([Security.Principal.WindowsPrincipal]
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $IsAdmin) {
    Write-Host "[ERROR] Run as Administrator." -ForegroundColor Red
    exit
}

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$StartTime = (Get-Date).AddHours(-$Hours)

# Default Event IDs
$EventIDs = 4625, 4672, 4688, 4720, 4728, 4648, 1149
if ($EventIDsOverride) { $EventIDs = $EventIDsOverride }

# Retrieve logs
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

Write-Host "Logs exported to: $OutputPath"
Write-Host "Stats exported to: $StatsPath"
```

---

## 🚀 Usage

### Basic usage (default: last 24 hours, default Event IDs)

```powershell
.\Grabber.ps1
```

### Custom time range (last 72 hours)

```powershell
.\Grabber.ps1 -Hours 72
```

### Filter by specific user

```powershell
.\Grabber.ps1 -User "ryan"
```

### Custom Event IDs only

```powershell
.\Grabber.ps1 -EventIDsOverride 4625,4688,4720
```

### Combine filters

```powershell
.\Grabber.ps1 -Hours 48 -User "Administrator" -EventIDsOverride 4625,4672,4688
```

---

## 📂 Output files

The script creates **two files** on the Desktop:

- `logs_compromission_YYYYMMDD_HHMMSS.json`  
  - Full list of matching events  
  - Each entry contains:  
    - `TimeCreated`  
    - `Id`  
    - `LevelDisplayName`  
    - `ProviderName`  
    - `Message`  

- `stats_YYYYMMDD_HHMMSS.json`  
  - Aggregated statistics per Event ID  
  - Example:
    ```json
    [
      { "Name": "4625", "Count": 12 },
      { "Name": "4688", "Count": 34 }
    ]
    ```

---

## 🧪 Example JSON analysis (PowerShell)

```powershell
# Load logs
$logs = Get-Content .\logs_compromission_*.json | ConvertFrom-Json

# Group by Event ID
$logs | Group-Object Id | Sort-Object Count -Descending

# Inspect all 4648 events
$logs | Where-Object { $_.Id -eq 4648 } | Format-List *

# Sort chronologically
$logs | Sort-Object TimeCreated | Format-Table -AutoSize
```

---

## 🧠 Typical interpretation examples

- **4625 (Failed logon)**  
  - Many 4625 from the same source could indicate brute-force attempts.  

- **4672 (Special privileges)**  
  - Appears when privileged accounts log in (e.g., local admin, SYSTEM).  

- **4688 (New process created)**  
  - Useful to spot suspicious binaries or unusual parent processes.  

- **4720 / 4728 (Account / group changes)**  
  - New accounts or privilege group membership changes can indicate lateral movement.  

---

## ⚙️ Requirements

- Windows 10 / 11  
- PowerShell 5+ or PowerShell 7  
- Run **PowerShell as Administrator**  
- Security auditing enabled for the relevant Event IDs  

---

## 🎓 Why this project

This script is part of a learning journey in:

- Windows Security event analysis  
- PowerShell scripting for blue-team tooling  
- Building small, focused tools that can be reused in labs and homelabs  

It’s intentionally simple, readable, and easy to extend.

---

## 🔮 Possible future improvements

- HTML or Markdown report generation  
- Severity scoring per event type  
- Sysmon integration (process-level visibility)  
- Real-time monitoring mode  
- Correlation between multiple Event IDs (e.g., 4625 → 4624 → 4672)  

---

## 📂 License

MIT License – free to use, modify, and adapt for learning or internal use.
