"""Passive traffic capture (M4).

Captures IP packets and aggregates, per local device:
  * bandwidth (bytes) over time, and
  * flows to each remote endpoint (bytes/packets, resolved to a hostname via
    observed DNS answers).

On a switched LAN a host mostly sees its own traffic + broadcast, so this
primarily profiles the Knox host today. The exact same code captures every
device when placed at a mirror port / on the router or a Pi (see M6). Needs
Npcap + admin, like the other sniffers.
"""

from __future__ import annotations

import ipaddress
import logging
import threading
import time
from typing import Optional

from . import config, net
from .discovery import valid_device_mac
from .store import Store

log = logging.getLogger("knox.traffic")


def _scapy():
    from scapy import all as scapy
    return scapy


def _tls_sni(data: bytes) -> Optional[str]:
    """Extract the SNI hostname from a TLS ClientHello (raw record bytes).

    The SNI is sent in cleartext during the handshake, so this reveals the
    website domain of an HTTPS connection without decrypting anything.
    """
    try:
        if len(data) < 43 or data[0] != 0x16:  # handshake record
            return None
        hs = data[5:]
        if not hs or hs[0] != 0x01:  # ClientHello
            return None
        p = 4  # skip handshake type(1) + length(3)
        p += 2 + 32  # client_version + random
        if p >= len(hs):
            return None
        p += 1 + hs[p]  # session_id
        if p + 2 > len(hs):
            return None
        p += 2 + int.from_bytes(hs[p : p + 2], "big")  # cipher_suites
        if p + 1 > len(hs):
            return None
        p += 1 + hs[p]  # compression_methods
        if p + 2 > len(hs):
            return None
        ext_total = int.from_bytes(hs[p : p + 2], "big")
        p += 2
        end = min(len(hs), p + ext_total)
        while p + 4 <= end:
            etype = int.from_bytes(hs[p : p + 2], "big")
            elen = int.from_bytes(hs[p + 2 : p + 4], "big")
            p += 4
            if etype == 0x0000:  # server_name extension
                sn = hs[p : p + elen]
                if len(sn) >= 5 and sn[2] == 0x00:  # host_name type
                    nlen = int.from_bytes(sn[3:5], "big")
                    name = sn[5 : 5 + nlen]
                    try:
                        return name.decode("ascii")
                    except UnicodeDecodeError:
                        return None
                return None
            p += elen
        return None
    except Exception:
        return None


class TrafficSniffer:
    def __init__(self, store: Optional[Store] = None):
        self.store = store or Store()
        self._nets = [
            ipaddress.ip_network(c, strict=False) for c in net.configured_subnets()
        ]
        self._sniffer = None
        self._flush_stop = threading.Event()
        self._flush_thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        # aggregates, cleared on each flush
        self._flows: dict[tuple, list] = {}   # (mac, rip, proto, dport) -> [bytes, pkts]
        self._bw: dict[str, int] = {}          # mac -> bytes
        self._dns: dict[str, str] = {}         # ip -> hostname (learned)

    # --- lifecycle -----------------------------------------------------------

    def start(self) -> bool:
        try:
            scapy = _scapy()
        except Exception as e:
            log.warning("traffic capture unavailable (scapy/Npcap): %s", e)
            return False
        try:
            self._sniffer = scapy.AsyncSniffer(
                filter=config.CAPTURE_FILTER,
                prn=self._on_packet,
                store=False,
                iface=config.SNIFF_IFACE or None,
            )
            self._sniffer.start()
            self._flush_stop.clear()
            self._flush_thread = threading.Thread(
                target=self._flush_loop, name="knox-traffic-flush", daemon=True
            )
            self._flush_thread.start()
            log.info("traffic capture started (filter=%r)", config.CAPTURE_FILTER)
            return True
        except Exception as e:
            log.warning("could not start traffic capture: %s", e)
            self._sniffer = None
            return False

    def stop(self) -> None:
        self._flush_stop.set()
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception:
                pass
            self._sniffer = None
        self.flush()  # final flush

    # --- capture -------------------------------------------------------------

    def _local_side(self, ip):
        try:
            return any(ip in n for n in self._nets)
        except TypeError:
            return False

    def _on_packet(self, pkt) -> None:
        try:
            scapy = _scapy()
            if not pkt.haslayer(scapy.IP):
                return
            ipl = pkt[scapy.IP]
            src, dst = ipl.src, ipl.dst
            length = len(pkt)

            # Learn DNS names from responses (UDP src port 53).
            if pkt.haslayer(scapy.DNS) and pkt.haslayer(scapy.UDP) and pkt[scapy.UDP].sport == 53:
                self._learn_dns(scapy, pkt)

            src_a = ipaddress.ip_address(src)
            dst_a = ipaddress.ip_address(dst)
            src_local = self._local_side(src_a)
            dst_local = self._local_side(dst_a)
            if not (src_local or dst_local):
                return  # neither side is ours; ignore

            # Determine local (device) vs remote (endpoint) side.
            if src_local and not dst_local:
                local_ip, remote_ip, out = src, dst, True
            elif dst_local and not src_local:
                local_ip, remote_ip, out = dst, src, False
            else:
                # LAN-to-LAN: treat src as the device, dst as the remote.
                local_ip, remote_ip, out = src, dst, True

            remote_a = ipaddress.ip_address(remote_ip)
            if remote_a.is_multicast or remote_ip.endswith(".255"):
                return

            # MAC of the local device from the Ethernet frame.
            mac = None
            if pkt.haslayer(scapy.Ether):
                mac = pkt[scapy.Ether].src if out else pkt[scapy.Ether].dst
            if not valid_device_mac(mac or ""):
                return

            proto, dport = "ip", 0
            if pkt.haslayer(scapy.TCP):
                proto = "tcp"
                tcp = pkt[scapy.TCP]
                dport = tcp.dport if out else tcp.sport
                # Client's TLS ClientHello carries the SNI (the website domain).
                if out and tcp.payload:
                    payload = bytes(tcp.payload)
                    if payload[:1] == b"\x16":  # TLS handshake record
                        sni = _tls_sni(payload)
                        if sni:
                            self._dns[remote_ip] = sni
            elif pkt.haslayer(scapy.UDP):
                proto = "udp"
                dport = pkt[scapy.UDP].dport if out else pkt[scapy.UDP].sport

            mac = mac.upper()
            with self._lock:
                key = (mac, remote_ip, proto, int(dport))
                agg = self._flows.get(key)
                if agg is None:
                    self._flows[key] = [length, 1]
                else:
                    agg[0] += length
                    agg[1] += 1
                self._bw[mac] = self._bw.get(mac, 0) + length
        except Exception:
            log.debug("traffic packet error", exc_info=True)

    def _learn_dns(self, scapy, pkt) -> None:
        try:
            dns = pkt[scapy.DNS]
            an = dns.an
            records = an if isinstance(an, list) else ([an] if an else [])
            for rr in records:
                if getattr(rr, "type", None) == 1:  # A record
                    name = rr.rrname.decode(errors="replace").rstrip(".") if isinstance(rr.rrname, bytes) else str(rr.rrname).rstrip(".")
                    ip = str(rr.rdata)
                    if name and ip:
                        self._dns[ip] = name
        except Exception:
            pass

    # --- flush ---------------------------------------------------------------

    def _flush_loop(self) -> None:
        while not self._flush_stop.is_set():
            waited = 0
            while waited < config.CAPTURE_FLUSH and not self._flush_stop.is_set():
                time.sleep(1)
                waited += 1
            self.flush()

    def flush(self) -> None:
        with self._lock:
            flows = self._flows
            bw = self._bw
            dns = self._dns
            self._flows, self._bw, self._dns = {}, {}, {}
        # Persist learned DNS names first so flows can resolve.
        for ip, host in dns.items():
            self.store.set_dns_name(ip, host)
        for (mac, rip, proto, dport), (nbytes, npkts) in flows.items():
            host = dns.get(rip) or self.store.get_dns_name(rip)
            self.store.add_flow(mac, rip, proto, dport, nbytes, npkts, host)
        for mac, nbytes in bw.items():
            self.store.add_bw_sample(mac, nbytes)


def available() -> bool:
    try:
        _scapy()
        return True
    except Exception:
        return False
