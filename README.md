# 🛡️ Knox — Home Network Security Monitor

Knox watches **your own LAN** and tells you every device connected to your
router. It discovers hosts by ARP-scanning the subnet, records them in a local
database, alerts you when an **unknown device joins**, scans open ports/services
with nmap, and shows everything on a local web dashboard.

> Defensive, single-network tool. Only scan networks you own or are authorized
> to monitor.

## Features

- **Device inventory** — every device on the LAN: IP, MAC, hostname, and vendor
  (resolved offline from the MAC's OUI, or inferred from the hostname for
  randomized MACs).
- **Passive auto-identification** — a continuous listener sniffs broadcast/
  multicast traffic (mDNS, SSDP, DHCP, NBNS, ARP) to auto-name and classify
  devices from what they announce (e.g. a device's DHCP hostname / vendor
  class), and to catch devices between active sweeps.
- **New-device alerts** — mark your known devices as *trusted*; get an alert
  (dashboard, rotating log file, optional ntfy phone push) when an
  unrecognized device appears.
- **Threat/anomaly detection** — ARP-spoofing (gateway MAC change, IP↔MAC
  conflicts), rogue-DHCP servers, a known device opening a **new** port, and
  exposed **risky services** (Telnet/RDP/SMB/databases). Alerts carry a
  severity (info / warning / critical).
- **Port & service scan** — nmap-based per-host scan for open ports, services,
  and versions.
- **Multi-subnet** — scan several subnets at once (`KNOX_SUBNETS`).
- **Web dashboard** — live device list with online/offline status, first/last
  seen, vendor/type icons, per-device detail (open ports + "Identified via"
  hints), and an alerts feed. Auto-refreshes; search/filter/trust/rename inline.

## How it finds devices

The primary engine is a **scapy ARP sweep** — every IP device on the subnet must
answer an ARP request, so this catches devices that ignore pings. If scapy/Npcap
isn't available it falls back to a **ping-sweep + `arp -a`** parse (set
`KNOX_FORCE_FALLBACK=1` to force it).

## Prerequisites (Windows)

- **Python 3.10+**
- **[Nmap for Windows](https://nmap.org/download.html)** — needed for port scans
  (also installs Npcap).
- **Npcap** — the packet driver scapy needs for raw ARP (bundled with Nmap and
  with Wireshark).

## Setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Usage

> **Run your terminal as Administrator.** Raw ARP sends and nmap OS/service
> detection require elevation on Windows.

```powershell
# One-shot discovery — print every device on the LAN
python -m knox scan

# Show configured vs. directly-scannable subnets
python -m knox subnets

# Passively listen (mDNS/SSDP/DHCP/NBNS/ARP) to auto-identify devices, live
python -m knox listen

# List devices recorded in the database
python -m knox devices

# Mark a device you recognize as trusted (so it won't alert)
python -m knox trust AA:BB:CC:DD:EE:FF --label "Derek's phone"

# nmap a host (by IP, by MAC from the DB, or 'all')
python -m knox nmap 192.168.1.1
python -m knox nmap all

# Run the monitor loop + dashboard together
python -m knox serve
# then open http://127.0.0.1:5000
```

## Configuration

All settings have sensible defaults and can be overridden with environment
variables (see [`knox/config.py`](knox/config.py)):

| Variable | Default | Meaning |
| --- | --- | --- |
| `KNOX_SUBNET` | auto-detect | CIDR to scan, e.g. `192.168.1.0/24` |
| `KNOX_SUBNETS` | — | Comma-separated CIDRs for multi-subnet scanning |
| `KNOX_PASSIVE` | `1` | Run the passive listener (mDNS/SSDP/DHCP/…) |
| `KNOX_SNIFF_IFACE` | auto | Interface to sniff (blank = primary adapter) |
| `KNOX_NTFY_TOPIC` | — | ntfy topic for phone push alerts (blank = off) |
| `KNOX_SCAN_INTERVAL` | `60` | Seconds between discovery sweeps |
| `KNOX_OFFLINE_AFTER` | `180` | Seconds without a sighting → offline |
| `KNOX_NMAP_INTERVAL` | `1800` | Seconds between nmap sweeps of known hosts |
| `KNOX_NMAP_ARGS` | `-sV --top-ports 100 -T4` | nmap arguments |
| `KNOX_WEB_HOST` / `KNOX_WEB_PORT` | `127.0.0.1` / `5000` | Dashboard bind |
| `KNOX_FORCE_FALLBACK` | `0` | Use ping+`arp -a` instead of scapy |

Runtime data (SQLite DB + log) is written to `data/` and is gitignored.

## Project layout

```
knox/
  __main__.py     CLI (scan | devices | trust | nmap | serve)
  config.py       settings + env overrides
  net.py          subnet auto-detection
  discovery.py    ARP sweep (scapy) + ping/arp-a fallback
  listener.py     passive sniffer (mDNS/SSDP/DHCP/NBNS/ARP) -> hints
  enrich.py       derive name/vendor/type from passive hints
  detect.py       threat/anomaly detection (ARP-spoof, rogue DHCP, ports)
  vendors.py      MAC OUI -> vendor (+ hostname inference)
  scanner.py      nmap wrapper
  store.py        SQLite persistence (devices, sightings, ports, alerts, hints)
  alerts.py       new-device detection + notifiers (log/ntfy)
  monitor.py      background discovery/scan loop + passive listener
  web/            Flask dashboard + JSON API
```

## Roadmap (out of scope for v1)

- Live packet capture / traffic analysis and per-device bandwidth.
- Phone push (ntfy/Pushover) and email notifiers (notifier interface is ready).
- Raspberry Pi deployment for always-on monitoring.
