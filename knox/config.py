"""Central configuration for Knox.

Values can be overridden with environment variables (prefixed ``KNOX_``) so you
don't have to edit source. The subnet is auto-detected at runtime when left
blank — see :mod:`knox.net`.
"""

from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def _load_dotenv(path: Path) -> None:
    """Load KEY=VALUE lines from a .env file into the environment (without
    overriding vars already set). Keeps secrets (e.g. the router password) in a
    gitignored file instead of the shell/source."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, val = line.split("=", 1)
                os.environ.setdefault(key.strip(), val.strip().strip('"').strip("'"))
    except OSError:
        pass


_load_dotenv(BASE_DIR / ".env")

# --- Paths -----------------------------------------------------------------
# Everything Knox writes (database + logs) lives in the project directory by
# default so it's easy to find and gitignore.
DATA_DIR = Path(os.environ.get("KNOX_DATA_DIR", BASE_DIR / "data"))
DB_PATH = Path(os.environ.get("KNOX_DB_PATH", DATA_DIR / "knox.db"))
LOG_PATH = Path(os.environ.get("KNOX_LOG_PATH", DATA_DIR / "knox.log"))


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default)


# --- Network ---------------------------------------------------------------
# Leave SUBNET blank to auto-detect the active adapter's /24 (recommended).
# Override with e.g. KNOX_SUBNET=192.168.1.0/24 if detection guesses wrong.
SUBNET = _env("KNOX_SUBNET", "").strip()

# Scan multiple subnets: a comma-separated list of CIDRs. Takes precedence over
# SUBNET when set, e.g. KNOX_SUBNETS=192.168.110.0/24,192.168.111.0/24
# NOTE: ARP discovery is link-local — a subnet is only scannable if this host is
# directly connected to it (see `knox subnets`). Remote subnets behind a router
# can't be ARP-enumerated.
SUBNETS = [s.strip() for s in _env("KNOX_SUBNETS", "").split(",") if s.strip()]

# Seconds to wait for ARP replies during a discovery sweep.
ARP_TIMEOUT = float(_env("KNOX_ARP_TIMEOUT", "3"))

# Force the no-Npcap fallback (ping-sweep + `arp -a`) even if scapy is present.
FORCE_FALLBACK = _env("KNOX_FORCE_FALLBACK", "0") == "1"


# --- Monitoring cadence ----------------------------------------------------
# How often the monitor loop runs a discovery sweep.
SCAN_INTERVAL = int(_env("KNOX_SCAN_INTERVAL", "60"))

# A device is considered offline if not seen for this many seconds.
OFFLINE_AFTER = int(_env("KNOX_OFFLINE_AFTER", "180"))

# How often the monitor runs an nmap port scan on known hosts (seconds).
NMAP_INTERVAL = int(_env("KNOX_NMAP_INTERVAL", "1800"))


# --- nmap ------------------------------------------------------------------
# Arguments passed to nmap for a per-host service scan. `-sV` = service/version
# detection on the top ports. Add `-O` for OS detection (requires admin).
NMAP_ARGS = _env("KNOX_NMAP_ARGS", "-sV --top-ports 100 -T4")


# --- Web dashboard ---------------------------------------------------------
WEB_HOST = _env("KNOX_WEB_HOST", "127.0.0.1")
WEB_PORT = int(_env("KNOX_WEB_PORT", "5000"))

# Optional login gate. Blank = no auth (fine for localhost-only). Set a
# password to require login — recommended before binding to 0.0.0.0.
PASSWORD = _env("KNOX_PASSWORD", "")
SECRET_KEY = _env("KNOX_SECRET_KEY", "").strip()


# --- Internet / WAN monitor ------------------------------------------------
# Periodically confirm the internet is reachable (TCP connect). Records up/down
# transitions and alerts on them.
WAN_CHECK = _env("KNOX_WAN_CHECK", "1") == "1"
WAN_HOST = _env("KNOX_WAN_HOST", "1.1.1.1")
WAN_PORT = int(_env("KNOX_WAN_PORT", "53"))


# --- Passive listener ------------------------------------------------------
# Continuously sniff broadcast/multicast traffic (mDNS/SSDP/DHCP/NBNS/ARP) to
# auto-identify devices. Needs Npcap + admin on Windows. Set KNOX_PASSIVE=0 to
# disable. SNIFF_IFACE is auto-selected (primary adapter) when blank.
PASSIVE = _env("KNOX_PASSIVE", "1") == "1"
SNIFF_IFACE = _env("KNOX_SNIFF_IFACE", "").strip()

# BPF capture filter — broadcast/multicast discovery protocols only.
SNIFF_FILTER = _env(
    "KNOX_SNIFF_FILTER",
    "arp or (udp and (port 5353 or port 1900 or port 67 or port 68 "
    "or port 137 or port 5355))",
)


# --- Traffic capture (M4) --------------------------------------------------
# Off by default (heavier). When on, capture IP flows to profile per-device
# bandwidth + what each device talks to. On a switched LAN this mainly sees
# THIS host's traffic + broadcast; full coverage needs a mirror port / running
# on the router or a Pi. Needs Npcap + admin.
CAPTURE = _env("KNOX_CAPTURE", "0") == "1"
CAPTURE_FILTER = _env("KNOX_CAPTURE_FILTER", "ip")
CAPTURE_FLUSH = int(_env("KNOX_CAPTURE_FLUSH", "10"))  # seconds between DB flushes


# --- DNS-logging resolver (Pi-hole-lite) -----------------------------------
# Off by default. When on, Knox runs a forwarding DNS server: point your
# router's DHCP DNS at this host and every device's domain lookups are logged
# per-device. Binding port 53 needs admin (use a high DNS_PORT to test).
DNS_SERVER = _env("KNOX_DNS_SERVER", "0") == "1"
DNS_BIND = _env("KNOX_DNS_BIND", "0.0.0.0")
DNS_PORT = int(_env("KNOX_DNS_PORT", "53"))
DNS_UPSTREAM = _env("KNOX_DNS_UPSTREAM", "1.1.1.1")


# --- Push notifications (ntfy) ---------------------------------------------
# Off by default. Set KNOX_NTFY_TOPIC to a topic name to get phone pushes when
# a new/unknown device joins. Install the free ntfy app and subscribe to the
# same topic. Nothing is sent anywhere until a topic is configured.
NTFY_SERVER = _env("KNOX_NTFY_SERVER", "https://ntfy.sh").rstrip("/")
NTFY_TOPIC = _env("KNOX_NTFY_TOPIC", "").strip()


# --- Router integration (per-device bandwidth) -----------------------------
# Credentials for polling the router's local API (e.g. Reyee/LuCI) for
# per-device bandwidth. Put these in a gitignored .env file, not the shell.
ROUTER_URL = _env("KNOX_ROUTER_URL", "http://192.168.110.1").rstrip("/")
ROUTER_USER = _env("KNOX_ROUTER_USER", "").strip()
ROUTER_PASSWORD = _env("KNOX_ROUTER_PASSWORD", "")
ROUTER_POLL = int(_env("KNOX_ROUTER_POLL", "10"))  # seconds between client-list polls


def ensure_dirs() -> None:
    """Create the data directory if it doesn't exist yet."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
