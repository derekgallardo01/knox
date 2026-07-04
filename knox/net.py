"""Local network detection.

Figures out which subnet Knox should sweep. Primary strategy uses the stdlib
``socket`` module to find the address of the active adapter (the one with the
default route); it falls back to parsing ``ipconfig`` on Windows.
"""

from __future__ import annotations

import ipaddress
import re
import socket
import subprocess
from typing import Optional

from . import config


def primary_ipv4() -> Optional[str]:
    """Return the IPv4 address of the adapter used to reach the internet.

    Opens a UDP socket toward a public address; no packets are actually sent,
    but the OS picks the outbound interface so ``getsockname`` reveals its IP.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()


def _netmask_for(ip: str) -> Optional[str]:
    """Best-effort netmask lookup for ``ip`` by parsing ``ipconfig`` (Windows)."""
    try:
        out = subprocess.run(
            ["ipconfig"], capture_output=True, text=True, timeout=10
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return None

    # ipconfig groups an adapter's IPv4 and its subnet mask a couple of lines
    # apart. Find the block containing our IP and grab the following mask.
    lines = out.splitlines()
    for i, line in enumerate(lines):
        if ip in line and "IPv4" in line:
            for follow in lines[i : i + 4]:
                m = re.search(r"Subnet Mask.*?:\s*([\d.]+)", follow)
                if m:
                    return m.group(1)
    return None


def detect_subnet() -> str:
    """Return the CIDR to scan, e.g. ``192.168.1.0/24``.

    Honors ``config.SUBNET`` when set. Otherwise auto-detects from the primary
    adapter, using its real netmask if we can find one, else assuming ``/24``
    (the near-universal home-network default).
    """
    if config.SUBNET:
        return config.SUBNET

    ip = primary_ipv4()
    if not ip:
        # Last-ditch guess; user can override via KNOX_SUBNET.
        return "192.168.1.0/24"

    mask = _netmask_for(ip)
    if mask:
        net = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
    else:
        net = ipaddress.IPv4Network(f"{ip}/24", strict=False)
    return str(net)


def configured_subnets() -> list[str]:
    """The list of subnets Knox should scan.

    Priority: ``KNOX_SUBNETS`` (multi) > ``KNOX_SUBNET`` (single) > auto-detect.
    """
    if config.SUBNETS:
        return config.SUBNETS
    if config.SUBNET:
        return [config.SUBNET]
    return [detect_subnet()]


def local_subnets() -> list[dict]:
    """Directly-connected IPv4 subnets (from ``ipconfig``), i.e. what's ARP-scannable.

    Returns dicts of ``{interface, ip, cidr}``. Skips loopback and APIPA
    (169.254.x) addresses. Virtual adapters (Docker/WSL/VPN) are included but
    flagged by their interface name so the caller can judge relevance.
    """
    try:
        out = subprocess.run(
            ["ipconfig"], capture_output=True, text=True, timeout=10
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return []

    results: list[dict] = []
    iface = "?"
    pending_ip: Optional[str] = None
    for line in out.splitlines():
        m = re.match(r"^(?P<name>[^\s].*adapter .*):\s*$", line, re.IGNORECASE)
        if m:
            iface = m.group("name").strip()
            pending_ip = None
            continue
        ipm = re.search(r"IPv4 Address.*?:\s*([\d.]+)", line)
        if ipm:
            pending_ip = ipm.group(1)
            continue
        maskm = re.search(r"Subnet Mask.*?:\s*([\d.]+)", line)
        if maskm and pending_ip:
            ip = pending_ip
            if not ip.startswith("169.254") and ip != "127.0.0.1":
                net = ipaddress.IPv4Network(f"{ip}/{maskm.group(1)}", strict=False)
                results.append({"interface": iface, "ip": ip, "cidr": str(net)})
            pending_ip = None
    return results


def gateway_ip(subnet: Optional[str] = None) -> Optional[str]:
    """Guess the router address (``.1`` of the subnet). Informational only."""
    subnet = subnet or detect_subnet()
    hosts = ipaddress.IPv4Network(subnet, strict=False).hosts()
    try:
        return str(next(iter(hosts)))
    except StopIteration:
        return None
