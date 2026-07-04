<#
.SYNOPSIS
  Install (or remove) Knox as a Windows scheduled task that starts at boot.

.DESCRIPTION
  Registers a "KnoxMonitor" scheduled task that runs scripts/run-knox.ps1 at
  system startup with highest privileges (needed for raw ARP / nmap / DNS).
  Edit scripts/run-knox.ps1 first to configure. Requires Administrator.

.PARAMETER Uninstall
  Remove the scheduled task.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\install-service.ps1
  powershell -ExecutionPolicy Bypass -File .\install-service.ps1 -Uninstall
#>
[CmdletBinding()]
param([switch]$Uninstall)

$ErrorActionPreference = "Stop"
$taskName = "KnoxMonitor"
$log = Join-Path $env:TEMP "knox_service.log"
function Log($m) { "$m" | Tee-Object -FilePath $log -Append | Out-Null; Write-Host "$m" }
Set-Content -Path $log -Value "" -ErrorAction SilentlyContinue

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
         ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { Log "ERROR: must run as Administrator."; exit 1 }

if ($Uninstall) {
  if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
    Log "Removed scheduled task '$taskName'."
  } else {
    Log "No task '$taskName' to remove."
  }
  exit 0
}

$launcher = Join-Path $PSScriptRoot "run-knox.ps1"
$root = Split-Path -Parent $PSScriptRoot
if (-not (Test-Path $launcher)) { Log "ERROR: run-knox.ps1 not found."; exit 1 }

$action = New-ScheduledTaskAction -Execute "powershell.exe" `
  -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$launcher`"" `
  -WorkingDirectory $root
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries `
  -DontStopIfGoingOnBatteries -StartWhenAvailable `
  -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)

Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
  -Principal $principal -Settings $settings -Force -Description "Knox network monitor" | Out-Null

Log "Installed scheduled task '$taskName' (runs at startup as SYSTEM, highest privileges)."
Log "Edit scripts/run-knox.ps1 to configure. Start now with: Start-ScheduledTask -TaskName $taskName"
