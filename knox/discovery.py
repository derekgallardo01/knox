"""Device discovery — the core "who's connected" engine.

Primary method: a scapy ARP broadcast sweep of the subnet. ARP is the most
reliable way to enumerate a LAN because every IP-speaking device must answer an
ARP request, even ones that silently drop pings.

Fallback method (no Npcap / scapy): ping-sweep the subnet to populate the OS
ARP cache, then parse ``arp -a``. Less reliable (misses ICMP-ignoring hosts)
but requires no special driver or privileges.
"""

from __future__ import annotations

import concurrent.futures
import ipaddress
import re
import socket
import subprocess
from dataclasses import dataclass, field
from typing import Optional

from . import config, net
from .vendors import infer_vendor, vendor_for


def valid_device_mac(mac: str) -> bool:
    """True if ``mac`` is a real unicast device MAC.

    Rejects empty, the all-zero/broadcast MACs, and multicast frames
    (``01:00:5E`` IPv4 multicast, ``33:33`` IPv6 multicast). Locally-administered
    / randomized MACs (phones) ARE valid — they're real devices.
    """
    if not mac:
        return False
    mac = mac.upper()
    if mac in ("00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"):
        return False
    if mac.startswith(("FF:FF:FF", "01:00:5E", "33:33")):
        return False
    return True


@dataclass
class Host:
    ip: str
    mac: str
    hostname: Optional[str] = None
    vendor: str = field(default="Unknown")

    def __post_init__(self) -> None:
        self.mac = self.mac.upper()
        if self.vendor == "Unknown":
            self.vendor = vendor_for(self.mac)


# --- scapy path ------------------------------------------------------------

def _scapy_available() -> bool:
    if config.FORCE_FALLBACK:
        return False
    try:
        import scapy.all  # noqa: F401
        return True
    except Exception:
        return False


def _arp_sweep_scapy(subnet: str, timeout: float) -> list[Host]:
    from scapy.all import ARP, Ether, srp  # imported lazily

    # One broadcast frame carrying an ARP "who-has" for the whole subnet.
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
    answered, _ = srp(packet, timeout=timeout, verbose=False)

    hosts: list[Host] = []
    for _sent, received in answered:
        hosts.append(Host(ip=received.psrc, mac=received.hwsrc))
    return hosts


# --- fallback path ---------------------------------------------------------

def _ping(ip: str) -> None:
    # Windows: -n 1 (one echo), -w 300 (300 ms timeout). We ignore the result;
    # the point is to populate the ARP cache.
    subprocess.run(
        ["ping", "-n", "1", "-w", "300", ip],
        capture_output=True,
        timeout=2,
    )


def _ping_sweep(subnet: str) -> None:
    hosts = [str(h) for h in ipaddress.IPv4Network(subnet, strict=False).hosts()]
    with concurrent.futures.ThreadPoolExecutor(max_workers=64) as pool:
        list(pool.map(_ping_safe, hosts))


def _ping_safe(ip: str) -> None:
    try:
        _ping(ip)
    except (OSError, subprocess.SubprocessError):
        pass


_ARP_LINE = re.compile(
    r"(?P<ip>\d+\.\d+\.\d+\.\d+)\s+(?P<mac>[0-9a-fA-F]{2}(?:[-:][0-9a-fA-F]{2}){5})"
)


def _is_real_host(ip: str, mac: str, network: ipaddress.IPv4Network) -> bool:
    """Filter out broadcast, multicast, and off-subnet ARP-cache noise.

    The OS ARP table is shared across every adapter and includes multicast
    pseudo-entries (IPv4 multicast MACs start ``01:00:5E``, plus the all-ones
    broadcast). We only want real unicast hosts on the subnet being scanned.
    """
    if not valid_device_mac(mac):
        return False
    try:
        addr = ipaddress.IPv4Address(ip)
    except ipaddress.AddressValueError:
        return False
    if addr.is_multicast or addr.is_loopback or ip.endswith(".255"):
        return False
    return addr in network


def _read_arp_table(subnet: str) -> list[Host]:
    try:
        out = subprocess.run(
            ["arp", "-a"], capture_output=True, text=True, timeout=10
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return []

    network = ipaddress.IPv4Network(subnet, strict=False)
    hosts: list[Host] = []
    for m in _ARP_LINE.finditer(out):
        ip = m.group("ip")
        mac = m.group("mac").replace("-", ":").upper()
        if _is_real_host(ip, mac, network):
            hosts.append(Host(ip=ip, mac=mac))
    return hosts


def _arp_sweep_fallback(subnet: str) -> list[Host]:
    _ping_sweep(subnet)
    return _read_arp_table(subnet)


# --- public API ------------------------------------------------------------

def _resolve_hostname(ip: str) -> Optional[str]:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (OSError, socket.herror):
        return None


def discover(
    subnet: Optional[str] = None,
    timeout: Optional[float] = None,
    resolve_hostnames: bool = True,
) -> list[Host]:
    """Discover live hosts on ``subnet``.

    Returns a de-duplicated list of :class:`Host`. Uses scapy ARP if available,
    otherwise the ping-sweep + arp-table fallback.
    """
    subnet = subnet or net.detect_subnet()
    timeout = config.ARP_TIMEOUT if timeout is None else timeout

    if _scapy_available():
        try:
            hosts = _arp_sweep_scapy(subnet, timeout)
        except PermissionError:
            # Raw sends need admin on Windows; drop to fallback rather than die.
            hosts = _arp_sweep_fallback(subnet)
        except Exception:
            hosts = _arp_sweep_fallback(subnet)
    else:
        hosts = _arp_sweep_fallback(subnet)

    # De-duplicate by MAC, preferring the first seen IP.
    by_mac: dict[str, Host] = {}
    for h in hosts:
        by_mac.setdefault(h.mac, h)
    result = list(by_mac.values())

    if resolve_hostnames:
        with concurrent.futures.ThreadPoolExecutor(max_workers=32) as pool:
            names = list(pool.map(lambda h: _resolve_hostname(h.ip), result))
        for host, name in zip(result, names):
            host.hostname = name
            # Now that we have a hostname, upgrade the vendor for randomized MACs.
            host.vendor = infer_vendor(host.mac, name)

    result.sort(key=lambda h: tuple(int(o) for o in h.ip.split(".")))
    return result


def discover_all(
    subnets: Optional[list[str]] = None,
    timeout: Optional[float] = None,
    resolve_hostnames: bool = True,
) -> list[Host]:
    """Discover hosts across multiple subnets, merged and de-duplicated by MAC.

    Defaults to the configured subnet list. Each subnet is swept independently
    (ARP is link-local, so only directly-connected subnets yield results).
    """
    subnets = subnets or net.configured_subnets()
    by_mac: dict[str, Host] = {}
    for subnet in subnets:
        for h in discover(subnet, timeout=timeout, resolve_hostnames=resolve_hostnames):
            by_mac.setdefault(h.mac, h)
    result = list(by_mac.values())
    result.sort(key=lambda h: tuple(int(o) for o in h.ip.split(".")))
    return result


def using_fallback() -> bool:
    """True if discovery will use the no-Npcap fallback path."""
    return not _scapy_available()
