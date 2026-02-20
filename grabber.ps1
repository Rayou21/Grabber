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
