"""Threat / anomaly detection.

Consumes the passive ARP/DHCP feed (from :mod:`knox.listener`) and nmap scan
results (from :mod:`knox.monitor`) and raises alerts via :class:`AlertManager`
for:

- **ARP spoofing** - the gateway's MAC changing, or one IP suddenly claimed by
  two different MACs within a short window (classic MITM signature).
- **Rogue DHCP** - a DHCP server offering leases from something other than the
  gateway.
- **New open port** - a previously-scanned device exposes a new port.
- **Risky service** - an exposed cleartext/admin/database service.

State that must survive restarts (the learned gateway MAC, known DHCP servers)
lives in the ``baseline`` table; short-lived conflict tracking is in-memory.
"""

from __future__ import annotations

import logging
import time
from typing import Optional

from . import net
from .alerts import AlertManager
from .store import Store

log = logging.getLogger("knox.detect")

# Seconds within which two different MACs on one IP count as a live conflict.
CONFLICT_WINDOW = 120

# port -> (label, severity)
RISKY_PORTS: dict[int, tuple[str, str]] = {
    21: ("FTP (cleartext)", "warning"),
    23: ("Telnet (cleartext)", "critical"),
    2323: ("Telnet/IoT (cleartext)", "critical"),
    25: ("SMTP", "warning"),
    # 135 (MSRPC) / 139 (NetBIOS) are on every Windows host — too noisy to flag.
    445: ("SMB", "warning"),
    512: ("rexec", "critical"),
    513: ("rlogin", "critical"),
    1433: ("MSSQL database", "critical"),
    3306: ("MySQL database", "critical"),
    5432: ("PostgreSQL database", "critical"),
    27017: ("MongoDB database", "critical"),
    6379: ("Redis (often unauth)", "critical"),
    9200: ("Elasticsearch", "critical"),
    11211: ("Memcached", "critical"),
    3389: ("RDP", "critical"),
    5900: ("VNC", "critical"),
    5555: ("Android ADB", "critical"),
}


class DetectionEngine:
    def __init__(self, store: Store, alerts: Optional[AlertManager] = None):
        self.store = store
        self.alerts = alerts or AlertManager(store)
        self.gateway_ips = {
            gw for s in net.configured_subnets() if (gw := net.gateway_ip(s))
        }
        # Cache the learned gateway MAC(s) so we don't hit the DB per ARP packet.
        self._gw_mac: dict[str, str] = {}
        for ip in self.gateway_ips:
            known = self.store.get_baseline(f"gateway_mac:{ip}")
            if known:
                self._gw_mac[ip] = known
        self._recent_ip_mac: dict[str, tuple[str, float]] = {}

    def _name(self, mac: str, ip: str) -> str:
        dev = self.store.get_device(mac)
        if dev:
            return dev["label"] or dev["hostname"] or dev["vendor"] or ip
        return ip

    # --- ARP feed ------------------------------------------------------------

    def on_arp(self, mac: str, ip: str) -> None:
        from .discovery import valid_device_mac

        if not valid_device_mac(mac) or not ip or ip == "0.0.0.0":
            return
        mac = mac.upper()

        if ip in self.gateway_ips:
            known = self._gw_mac.get(ip)
            if known is None:
                self._gw_mac[ip] = mac
                self.store.set_baseline(f"gateway_mac:{ip}", mac)
            elif known != mac:
                self.alerts.raise_alert(
                    "arp_spoof",
                    f"Gateway {ip} MAC changed from {known} to {mac} "
                    f"- possible ARP spoofing / man-in-the-middle.",
                    mac=mac,
                    severity="critical",
                )
                self._gw_mac[ip] = mac
                self.store.set_baseline(f"gateway_mac:{ip}", mac)
            return  # gateway handled; don't double-report below

        # Generic IP<->MAC conflict for non-gateway hosts.
        now = time.monotonic()
        prev = self._recent_ip_mac.get(ip)
        if prev and prev[0] != mac and (now - prev[1]) < CONFLICT_WINDOW:
            self.alerts.raise_alert(
                "ip_conflict",
                f"IP {ip} claimed by two MACs ({prev[0]} and {mac}) within "
                f"{CONFLICT_WINDOW}s - possible ARP spoofing.",
                mac=mac,
                severity="warning",
            )
        self._recent_ip_mac[ip] = (mac, now)

    # --- DHCP feed -----------------------------------------------------------

    def on_dhcp_server(self, server_ip: str, server_mac: str) -> None:
        if not server_ip or server_ip == "0.0.0.0":
            return
        if server_ip in self.gateway_ips:
            return  # the gateway serving DHCP is expected
        known = set(filter(None, (self.store.get_baseline("dhcp_servers") or "").split(",")))
        if server_ip in known:
            return
        known.add(server_ip)
        self.store.set_baseline("dhcp_servers", ",".join(sorted(known)))
        self.alerts.raise_alert(
            "rogue_dhcp",
            f"Rogue DHCP server at {server_ip} ({server_mac}) - not the gateway. "
            f"Could hijack new devices' network settings.",
            mac=server_mac.upper() if server_mac else None,
            severity="critical",
        )

    # --- Port-scan feed ------------------------------------------------------

    def on_ports(self, mac: str, ip: str, old_ports: list, new_ports: list) -> None:
        mac = mac.upper()
        name = self._name(mac, ip)
        old = {(p["port"], p.get("proto", "tcp")) for p in old_ports}
        new = {(p["port"], p.get("proto", "tcp")) for p in new_ports}

        # New open port (only after we have a prior baseline for this host).
        if old:
            for port, proto in sorted(new - old):
                self.alerts.raise_alert(
                    "new_port",
                    f"New open port {port}/{proto} on {name} ({ip}).",
                    mac=mac,
                    severity="warning",
                )

        # Risky services, flagged once per (device, port).
        for port, proto in sorted(new):
            info = RISKY_PORTS.get(port)
            if info:
                label, severity = info
                self.alerts.raise_alert(
                    "risky_service",
                    f"Exposed {label} on {name} ({ip}:{port}/{proto}).",
                    mac=mac,
                    severity=severity,
                )
