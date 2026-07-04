<#
.SYNOPSIS
  Knox host hardening - block LAN access to sensitive local services.

.DESCRIPTION
  Adds inbound Windows Firewall BLOCK rules (grouped "Knox Hardening") that
  stop other devices on your LAN from reaching PostgreSQL and SMB on this PC.
  Scoped to the LAN subnet only, so loopback (localhost) and Docker/WSL
  virtual networks keep working - local apps and containers are unaffected.

  Windows Firewall block rules take precedence over allow rules, so these
  override the built-in "File and Printer Sharing" allow rules for LAN sources.

.PARAMETER LanCidr
  The LAN subnet to block from, e.g. 192.168.110.0/24. Auto-detected if omitted.

.PARAMETER Undo
  Remove all "Knox Hardening" rules (full rollback).

.EXAMPLE
  # Run elevated:
  powershell -ExecutionPolicy Bypass -File .\harden-firewall.ps1
  powershell -ExecutionPolicy Bypass -File .\harden-firewall.ps1 -Undo
#>
[CmdletBinding()]
param(
  [string]$LanCidr = "",
  [string]$VpnInterface = "NordLynx",
  [switch]$Undo
)

$ErrorActionPreference = "Stop"
$group = "Knox Hardening"
$log = Join-Path $env:TEMP "knox_harden.log"
function Log($m) { $line = "$m"; $line | Tee-Object -FilePath $log -Append | Out-Null; Write-Host $line }
Set-Content -Path $log -Value "" -ErrorAction SilentlyContinue

# --- Require elevation ---
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
         ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { Log "ERROR: must run as Administrator."; exit 1 }

# --- Undo path ---
if ($Undo) {
  $existing = Get-NetFirewallRule -Group $group -ErrorAction SilentlyContinue
  if ($existing) { $existing | Remove-NetFirewallRule; Log "Removed $($existing.Count) '$group' rule(s)." }
  else { Log "No '$group' rules to remove." }
  exit 0
}

# --- Auto-detect LAN subnet if not supplied ---
if (-not $LanCidr) {
  $route = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue |
           Sort-Object RouteMetric | Select-Object -First 1
  $ip = Get-NetIPAddress -InterfaceIndex $route.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.PrefixOrigin -ne "WellKnown" } | Select-Object -First 1
  $octets = $ip.IPAddress -split "\."
  $LanCidr = "$($octets[0]).$($octets[1]).$($octets[2]).0/$($ip.PrefixLength)"
}
Log "LAN scope: $LanCidr"

# --- Idempotency: clear prior Knox rules ---
Get-NetFirewallRule -Group $group -ErrorAction SilentlyContinue | Remove-NetFirewallRule

# --- Block rules ---
$rules = @(
  @{ Name = "Knox: Block PostgreSQL 5432 from LAN"; Port = 5432 },
  @{ Name = "Knox: Block SMB 445 from LAN";         Port = 445  },
  @{ Name = "Knox: Block NetBIOS 139 from LAN";     Port = 139  }
)
foreach ($r in $rules) {
  New-NetFirewallRule -DisplayName $r.Name -Group $group -Direction Inbound -Action Block `
    -Protocol TCP -LocalPort $r.Port -RemoteAddress $LanCidr -Profile Any -Enabled True | Out-Null
  Log "Added: $($r.Name)  (TCP $($r.Port) from $LanCidr)"
}

# --- VPN interface: block SMB on the VPN adapter (e.g. NordLynx) ---
# SMB has no business listening on a VPN tunnel. Scoped by interface, not
# address, so it applies whenever that adapter is up.
if ($VpnInterface -and (Get-NetAdapter -Name $VpnInterface -ErrorAction SilentlyContinue)) {
  foreach ($p in 445, 139) {
    New-NetFirewallRule -DisplayName "Knox: Block SMB $p on VPN ($VpnInterface)" -Group $group `
      -Direction Inbound -Action Block -Protocol TCP -LocalPort $p `
      -InterfaceAlias $VpnInterface -Profile Any -Enabled True | Out-Null
    Log "Added: Knox: Block SMB $p on VPN ($VpnInterface)"
  }
} elseif ($VpnInterface) {
  Log "VPN interface '$VpnInterface' not found - skipping VPN SMB rules."
}

Log "Done. Active '$group' rules:"
Get-NetFirewallRule -Group $group | ForEach-Object { Log "  - $($_.DisplayName)" }
