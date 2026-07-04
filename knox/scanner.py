"""nmap-based port/service scanning.

Wraps ``python-nmap`` to scan a single host for open ports, services, and
versions. Results are normalized to plain dicts and stored via
:class:`knox.store.Store`. Requires the nmap binary on PATH.
"""

from __future__ import annotations

import sys
from typing import Optional

from . import config
from .store import Store


class NmapUnavailable(RuntimeError):
    """Raised when the nmap binary or python-nmap module isn't usable."""


def _scanner():
    try:
        import nmap  # python-nmap
    except ImportError as e:  # pragma: no cover
        raise NmapUnavailable(
            "python-nmap not installed. Run: pip install python-nmap"
        ) from e
    try:
        return nmap.PortScanner()
    except Exception as e:  # nmap binary missing / not on PATH
        raise NmapUnavailable(
            "nmap binary not found on PATH. Install Nmap from nmap.org."
        ) from e


def scan_host(ip: str, args: Optional[str] = None) -> list[dict]:
    """Scan ``ip`` and return a list of open-port dicts.

    Each dict: ``{port, proto, service, version, state}``.
    """
    scanner = _scanner()
    scanner.scan(hosts=ip, arguments=args or config.NMAP_ARGS)

    ports: list[dict] = []
    if ip not in scanner.all_hosts():
        return ports

    host = scanner[ip]
    for proto in host.all_protocols():
        for port in sorted(host[proto].keys()):
            info = host[proto][port]
            if info.get("state") != "open":
                continue
            version = " ".join(
                filter(None, [info.get("product"), info.get("version")])
            ).strip()
            ports.append(
                {
                    "port": port,
                    "proto": proto,
                    "service": info.get("name") or None,
                    "version": version or None,
                    "state": info.get("state"),
                }
            )
    return ports


def _resolve_ip(store: Store, target: str) -> Optional[str]:
    """Map a MAC in the DB to its last-known IP; pass through anything else."""
    if ":" in target or "-" in target:  # looks like a MAC
        dev = store.get_device(target.replace("-", ":"))
        return dev["ip"] if dev else None
    return target


def scan_target(store: Store, target: str) -> int:
    """CLI helper: scan ``ip``, a ``mac`` from the DB, or ``all`` devices."""
    try:
        if target.lower() == "all":
            targets = [(d["mac"], d["ip"]) for d in store.devices() if d["ip"]]
        else:
            ip = _resolve_ip(store, target)
            if not ip:
                print(f"Could not resolve target '{target}'.", file=sys.stderr)
                return 1
            dev = store.get_device(target.replace("-", ":"))
            targets = [(dev["mac"] if dev else None, ip)]

        for mac, ip in targets:
            print(f"nmap {ip} ({config.NMAP_ARGS})...", file=sys.stderr)
            ports = scan_host(ip)
            if mac:
                store.replace_ports(mac, ports)
            if not ports:
                print(f"  {ip}: no open ports found.")
            for p in ports:
                svc = p["service"] or "?"
                ver = f" ({p['version']})" if p["version"] else ""
                print(f"  {ip}  {p['port']}/{p['proto']}  {svc}{ver}")
        return 0
    except NmapUnavailable as e:
        print(f"nmap error: {e}", file=sys.stderr)
        return 2
