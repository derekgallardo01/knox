<#
  Knox launcher - this is what the "KnoxMonitor" scheduled task runs at boot.
  Edit the environment variables below to configure the service, then
  (re)install with install-service.ps1. Runs the dashboard + monitor.
#>
$ErrorActionPreference = "Stop"

# --- Configuration (edit these) --------------------------------------------
# Dashboard login password (blank = no auth; recommended if binding beyond localhost).
$env:KNOX_PASSWORD   = ""
# Bind address for the dashboard. Use 0.0.0.0 to reach it from other devices.
$env:KNOX_WEB_HOST   = "127.0.0.1"
$env:KNOX_WEB_PORT   = "5000"
# Feature toggles (1 = on). Capture + DNS resolver are heavier / need port 53.
$env:KNOX_CAPTURE    = "0"
$env:KNOX_DNS_SERVER = "0"
$env:KNOX_PASSIVE    = "1"
# Subnets to scan (blank = auto-detect). e.g. "192.168.1.0/24,192.168.2.0/24"
# $env:KNOX_SUBNETS  = ""
# Push notifications: set an ntfy topic to get phone pushes on new devices.
# $env:KNOX_NTFY_TOPIC = ""

# --- Launch ----------------------------------------------------------------
$root = Split-Path -Parent $PSScriptRoot
$py = Join-Path $root ".venv\Scripts\python.exe"
if (-not (Test-Path $py)) { $py = "python" }  # fall back to PATH python
Set-Location $root
& $py -m knox serve
