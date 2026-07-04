"""Central configuration for Knox.

Values can be overridden with environment variables (prefixed ``KNOX_``) so you
don't have to edit source. The subnet is auto-detected at runtime when left
blank — see :mod:`knox.net`.
"""

from __future__ import annotations

import os
from pathlib import Path

# --- Paths -----------------------------------------------------------------
# Everything Knox writes (database + logs) lives in the project directory by
# default so it's easy to find and gitignore.
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.environ.get("KNOX_DATA_DIR", BASE_DIR / "data"))
DB_PATH = Path(os.environ.get("KNOX_DB_PATH", DATA_DIR / "knox.db"))
LOG_PATH = Path(os.environ.get("KNOX_LOG_PATH", DATA_DIR / "knox.log"))


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default)


# --- Network ---------------------------------------------------------------
# Leave SUBNET blank to auto-detect the active adapter's /24 (recommended).
# Override with e.g. KNOX_SUBNET=192.168.1.0/24 if detection guesses wrong.
SUBNET = _env("KNOX_SUBNET", "").strip()

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


def ensure_dirs() -> None:
    """Create the data directory if it doesn't exist yet."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
