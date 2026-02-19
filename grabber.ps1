# Grabber - Windows Security Log Extractor
# Author: RyanB
# Usage: Run PowerShell as Administrator

$StartTime = (Get-Date).AddHours(-24)
$EventIDs = 4625, 4672, 4688, 4720, 4728, 4648, 1149

$Logs = Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = $EventIDs
    StartTime = $StartTime
} -ErrorAction SilentlyContinue |
Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message

$OutputPath = "$env:USERPROFILE\Desktop\logs_compromission.json"
$Logs | ConvertTo-Json -Depth 5 | Out-File $OutputPath

Write-Host "Analysis complete. File exported to: $OutputPath"
