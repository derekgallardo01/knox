"""Knox command-line interface.

Usage:
    python -m knox scan            # one-shot discovery, print device table
    python -m knox nmap <target>   # nmap scan a host (ip|mac|all)
    python -m knox serve           # run monitor loop + web dashboard
    python -m knox trust <mac>     # mark a device as known/trusted
    python -m knox devices         # list known devices from the database
"""

from __future__ import annotations

import argparse
import sys
from typing import Optional

from . import config, net


def _fmt_table(rows: list[list[str]], headers: list[str]) -> str:
    cols = list(zip(*([headers] + rows))) if rows else [[h] for h in headers]
    widths = [max(len(str(c)) for c in col) for col in cols]
    line = lambda cells: "  ".join(str(c).ljust(w) for c, w in zip(cells, widths))
    out = [line(headers), line(["-" * w for w in widths])]
    out += [line(r) for r in rows]
    return "\n".join(out)


def cmd_scan(args: argparse.Namespace) -> int:
    from .discovery import discover_all, using_fallback
    from .store import Store

    subnets = [args.subnet] if args.subnet else net.configured_subnets()
    mode = "fallback (ping + arp -a)" if using_fallback() else "scapy ARP sweep"
    print(f"Scanning {', '.join(subnets)}  [{mode}]...\n", file=sys.stderr)

    hosts = discover_all(subnets)
    if not hosts:
        print(
            "No devices found. On Windows, raw ARP needs an elevated terminal "
            "(Run as Administrator). Try again elevated, or set "
            "KNOX_FORCE_FALLBACK=1.",
            file=sys.stderr,
        )
        return 1

    store = Store()
    gateways = {net.gateway_ip(s) for s in subnets}
    rows = []
    for h in hosts:
        is_new = store.upsert_device(h.mac, h.ip, h.hostname, h.vendor)
        tag = "  (gateway)" if h.ip in gateways else ("  (NEW)" if is_new else "")
        rows.append([h.ip, h.mac, h.hostname or "-", h.vendor, tag.strip()])

    print(_fmt_table(rows, ["IP", "MAC", "Hostname", "Vendor", ""]))
    print(f"\n{len(hosts)} device(s) found.", file=sys.stderr)
    store.close()
    return 0


def cmd_subnets(args: argparse.Namespace) -> int:
    """Show which subnets are configured and which are directly scannable."""
    configured = net.configured_subnets()
    local = net.local_subnets()
    local_cidrs = {l["cidr"] for l in local}

    print("Configured to scan:")
    for s in configured:
        reach = "reachable (ARP)" if s in local_cidrs else "NOT directly connected"
        print(f"  {s:<20} {reach}")

    print("\nDirectly-connected subnets on this host (ARP-scannable):")
    rows = [[l["cidr"], l["ip"], l["interface"]] for l in local]
    if rows:
        print(_fmt_table(rows, ["CIDR", "This host's IP", "Interface"]))
    else:
        print("  (none detected)")
    print(
        "\nTip: set KNOX_SUBNETS=cidr1,cidr2 to scan multiple. Only subnets this "
        "host is directly connected to can be ARP-enumerated.",
        file=sys.stderr,
    )
    return 0


def cmd_devices(args: argparse.Namespace) -> int:
    from .store import Store

    store = Store()
    rows = []
    for d in store.devices():
        status = "trusted" if d["trusted"] else "unknown"
        rows.append(
            [
                d["ip"] or "-",
                d["mac"],
                d["hostname"] or "-",
                d["vendor"] or "-",
                status,
                d["last_seen"],
            ]
        )
    if not rows:
        print("No devices recorded yet. Run `python -m knox scan` first.")
        return 0
    print(_fmt_table(rows, ["IP", "MAC", "Hostname", "Vendor", "Status", "Last seen"]))
    store.close()
    return 0


def cmd_trust(args: argparse.Namespace) -> int:
    from .store import Store

    store = Store()
    if not store.get_device(args.mac):
        print(f"Unknown MAC {args.mac}. Run a scan first.", file=sys.stderr)
        return 1
    store.set_trusted(args.mac, not args.untrust)
    if args.label:
        store.set_label(args.mac, args.label)
    state = "untrusted" if args.untrust else "trusted"
    print(f"{args.mac.upper()} marked {state}.")
    store.close()
    return 0


def cmd_nmap(args: argparse.Namespace) -> int:
    from . import scanner
    from .store import Store

    store = Store()
    rc = scanner.scan_target(store, args.target)
    store.close()
    return rc


def cmd_listen(args: argparse.Namespace) -> int:
    import time

    from .alerts import AlertManager
    from .detect import DetectionEngine
    from .listener import PassiveListener, available
    from .store import Store

    if not available():
        print(
            "Passive listener unavailable: scapy/Npcap not usable. "
            "Install Npcap and run as Administrator.",
            file=sys.stderr,
        )
        return 2

    store = Store()
    detect = DetectionEngine(store, AlertManager(store))

    def show(mac, ip, source, key, value):
        print(f"  {source:<5} {key:<13} {mac}  {(ip or '-'):<15} {value}")

    print(
        "Passive listener running (Ctrl+C to stop). "
        "Watching DHCP/mDNS/SSDP/NBNS/ARP + anomalies...\n",
        file=sys.stderr,
    )
    listener = PassiveListener(store=store, observer=show, detect=detect)
    if not listener.start():
        print("Could not start listener — run the terminal as Administrator.", file=sys.stderr)
        return 2
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        listener.stop()
        store.close()
    return 0


def cmd_capture(args: argparse.Namespace) -> int:
    import time

    from .store import Store
    from .traffic import TrafficSniffer, available

    if not available():
        print(
            "Traffic capture unavailable: scapy/Npcap not usable. "
            "Install Npcap and run as Administrator.",
            file=sys.stderr,
        )
        return 2

    store = Store()
    sniffer = TrafficSniffer(store=store)
    if not sniffer.start():
        print("Could not start capture — run the terminal as Administrator.", file=sys.stderr)
        return 2
    print(
        "Capturing traffic (Ctrl+C to stop). Top talkers refresh every "
        f"{args.interval}s...\n",
        file=sys.stderr,
    )
    try:
        while True:
            time.sleep(args.interval)
            rows = store.conn.execute(
                "SELECT mac, remote_ip, remote_host, proto, dport, bytes "
                "FROM flows ORDER BY bytes DESC LIMIT ?",
                (args.top,),
            ).fetchall()
            print(f"--- top {args.top} flows ---")
            for r in rows:
                host = r["remote_host"] or r["remote_ip"]
                kb = r["bytes"] / 1024
                print(f"  {r['mac']}  ->  {host}:{r['dport']}/{r['proto']}  {kb:,.1f} KB")
            print()
    except KeyboardInterrupt:
        pass
    finally:
        sniffer.stop()
        store.close()
    return 0


def cmd_dns(args: argparse.Namespace) -> int:
    import time

    from . import config
    from .dnsserver import DnsServer
    from .store import Store

    if args.port:
        config.DNS_PORT = args.port

    store = Store()

    def show(client_ip, owner, domain):
        who = owner if owner != client_ip else client_ip
        print(f"  {client_ip:<15} {who:<20} {domain}")

    server = DnsServer(store=store, observer=show)
    if not server.start():
        print(
            f"Could not bind DNS on {config.DNS_BIND}:{config.DNS_PORT}. "
            "Port 53 needs Administrator; or pass --port 15353 to test.",
            file=sys.stderr,
        )
        return 2
    print(
        f"DNS resolver on {config.DNS_BIND}:{config.DNS_PORT} "
        f"-> {config.DNS_UPSTREAM} (Ctrl+C to stop). Logging lookups...\n",
        file=sys.stderr,
    )
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()
        store.close()
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    from .web.app import run_server

    run_server(start_monitor=not args.no_monitor)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="knox", description="Home network security monitor")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="one-shot discovery of all LAN devices")
    s.add_argument("--subnet", help="CIDR to scan (overrides configured subnets)")
    s.set_defaults(func=cmd_scan)

    sn = sub.add_parser("subnets", help="show configured vs. directly-scannable subnets")
    sn.set_defaults(func=cmd_subnets)

    d = sub.add_parser("devices", help="list devices recorded in the database")
    d.set_defaults(func=cmd_devices)

    t = sub.add_parser("trust", help="mark a device as known/trusted")
    t.add_argument("mac")
    t.add_argument("--label", help="friendly name for the device")
    t.add_argument("--untrust", action="store_true", help="mark as untrusted instead")
    t.set_defaults(func=cmd_trust)

    n = sub.add_parser("nmap", help="run an nmap port/service scan")
    n.add_argument("target", help="ip, mac, or 'all' for every known device")
    n.set_defaults(func=cmd_nmap)

    li = sub.add_parser("listen", help="run the passive listener live (auto-naming)")
    li.set_defaults(func=cmd_listen)

    cap = sub.add_parser("capture", help="capture traffic; print top talkers live")
    cap.add_argument("--interval", type=int, default=5, help="refresh seconds")
    cap.add_argument("--top", type=int, default=15, help="how many flows to show")
    cap.set_defaults(func=cmd_capture)

    dns = sub.add_parser("dns", help="run the DNS-logging resolver live")
    dns.add_argument("--port", type=int, help="bind port (default 53; use e.g. 15353 to test)")
    dns.set_defaults(func=cmd_dns)

    v = sub.add_parser("serve", help="run monitor loop + web dashboard")
    v.add_argument("--no-monitor", action="store_true", help="dashboard only")
    v.set_defaults(func=cmd_serve)

    return p


def main(argv: Optional[list[str]] = None) -> int:
    config.ensure_dirs()
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
