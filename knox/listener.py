"""Passive network listener.

Sniffs broadcast/multicast discovery traffic (ARP, DHCP, mDNS, SSDP, NBNS) with
scapy's AsyncSniffer and turns it into device *hints* + passive sightings. This
is how Knox auto-identifies devices from the names they announce — no active
probing, and it works on a switched LAN because these protocols are all
broadcast/multicast.

Needs Npcap + admin on Windows (same as the ARP sweep).
"""

from __future__ import annotations

import logging
from typing import Callable, Optional

from . import config, net
from .enrich import apply_enrichment
from .store import Store
from .vendors import vendor_for

log = logging.getLogger("knox.listener")

# Observation callback signature: (mac, ip, source, key, value)
Observer = Callable[[str, str, str, str, str], None]


def _scapy():
    from scapy import all as scapy  # lazy, may raise if unavailable
    return scapy


class PassiveListener:
    """Runs an AsyncSniffer and records hints/sightings to the store."""

    def __init__(
        self,
        store: Optional[Store] = None,
        observer: Optional[Observer] = None,
        detect=None,
    ):
        self.store = store or Store()
        self.observer = observer  # optional live callback (used by `knox listen`)
        self.detect = detect  # optional DetectionEngine for ARP/DHCP anomalies
        self._sniffer = None

    # --- lifecycle -----------------------------------------------------------

    def start(self) -> bool:
        """Start sniffing in the background. Returns False if unavailable."""
        try:
            scapy = _scapy()
        except Exception as e:  # scapy/Npcap missing
            log.warning("passive listener unavailable (scapy/Npcap): %s", e)
            return False
        try:
            iface = config.SNIFF_IFACE or None
            self._sniffer = scapy.AsyncSniffer(
                filter=config.SNIFF_FILTER,
                prn=self._handle,
                store=False,
                iface=iface,
            )
            self._sniffer.start()
            log.info("passive listener started (filter=%r)", config.SNIFF_FILTER)
            return True
        except Exception as e:
            log.warning("could not start passive listener: %s", e)
            self._sniffer = None
            return False

    def stop(self) -> None:
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception:
                pass
            self._sniffer = None

    # --- packet dispatch -----------------------------------------------------

    def _handle(self, pkt) -> None:
        try:
            scapy = _scapy()
            if pkt.haslayer(scapy.DHCP):
                self._on_dhcp(scapy, pkt)
            elif pkt.haslayer(scapy.ARP):
                self._on_arp(scapy, pkt)
            elif pkt.haslayer(scapy.UDP):
                sport = pkt[scapy.UDP].sport
                dport = pkt[scapy.UDP].dport
                if 5353 in (sport, dport):
                    self._on_mdns(scapy, pkt)
                elif 1900 in (sport, dport):
                    self._on_ssdp(scapy, pkt)
                elif 137 in (sport, dport):
                    self._on_nbns(scapy, pkt)
        except Exception:
            log.debug("packet handler error", exc_info=True)

    # --- record helpers ------------------------------------------------------

    def _record(self, mac: str, ip: Optional[str], source: str, key: str, value: str) -> None:
        if not mac or not value:
            return
        mac = mac.upper()
        # Ensure the device row exists (ip may be None, e.g. a DHCP request
        # before a lease is granted) — this is a passive sighting too.
        self.store.upsert_device(mac, ip, vendor=vendor_for(mac))
        self.store.add_hint(mac, source, key, value)
        apply_enrichment(self.store, mac)
        if self.observer:
            self.observer(mac, ip or "", source, key, value)

    def _src(self, scapy, pkt):
        """(mac, ip) of the sender, from Ether/IP layers."""
        mac = pkt[scapy.Ether].src if pkt.haslayer(scapy.Ether) else None
        ip = pkt[scapy.IP].src if pkt.haslayer(scapy.IP) else None
        return mac, ip

    # --- protocol handlers ---------------------------------------------------

    def _on_arp(self, scapy, pkt) -> None:
        arp = pkt[scapy.ARP]
        if arp.op in (1, 2) and arp.hwsrc and arp.psrc and arp.psrc != "0.0.0.0":
            # sighting only (no name), via upsert
            self.store.upsert_device(arp.hwsrc.upper(), arp.psrc, vendor=vendor_for(arp.hwsrc))
            if self.detect:
                self.detect.on_arp(arp.hwsrc, arp.psrc)

    def _on_dhcp(self, scapy, pkt) -> None:
        mac, ip = self._src(scapy, pkt)
        # client MAC is most reliable from the BOOTP chaddr / Ether src
        if pkt.haslayer(scapy.BOOTP):
            chaddr = pkt[scapy.BOOTP].chaddr[:6]
            if chaddr and any(chaddr):
                mac = ":".join(f"{b:02X}" for b in chaddr)
        req_ip = None
        hostname = vclass = None
        msg_type = None
        for opt in pkt[scapy.DHCP].options:
            if not isinstance(opt, tuple):
                continue
            name, val = opt[0], opt[1] if len(opt) > 1 else None
            if name == "hostname":
                hostname = val.decode(errors="replace") if isinstance(val, bytes) else str(val)
            elif name == "vendor_class_id":
                vclass = val.decode(errors="replace") if isinstance(val, bytes) else str(val)
            elif name == "requested_addr":
                req_ip = str(val)
            elif name == "message-type":
                msg_type = val
        ip = ip if ip and ip != "0.0.0.0" else req_ip
        if hostname:
            self._record(mac, ip, "dhcp", "hostname", hostname)
        if vclass:
            self._record(mac, ip, "dhcp", "vendor_class", vclass)

        # Offer (2) / ACK (5) come FROM a DHCP server — check it's the gateway.
        if self.detect and msg_type in (2, 5):
            server_mac, server_ip = self._src(scapy, pkt)
            if server_ip:
                self.detect.on_dhcp_server(server_ip, server_mac or "")

    def _on_mdns(self, scapy, pkt) -> None:
        mac, ip = self._src(scapy, pkt)
        if not pkt.haslayer(scapy.DNS):
            return
        dns = pkt[scapy.DNS]
        names: set[str] = set()
        services: set[str] = set()
        for rr in self._iter_records(dns):
            try:
                rrname = getattr(rr, "rrname", None)
                if rrname is None:
                    continue
                rrname = rrname.decode(errors="replace") if isinstance(rrname, bytes) else str(rrname)
                rrname = rrname.rstrip(".")
                if rrname.startswith("_") and "._" in rrname:
                    services.add(".".join(rrname.split(".")[:2]))  # e.g. _googlecast._tcp
                elif rrname.endswith(".local") and not rrname.startswith("_"):
                    names.add(rrname[: -len(".local")])
            except Exception:
                continue
        for svc in services:
            self._record(mac, ip, "mdns", "service", svc)
        for nm in names:
            self._record(mac, ip, "mdns", "name", nm)

    @staticmethod
    def _iter_records(dns):
        """Yield DNS resource records across an/ns/ar, tolerating scapy's
        list-based sections (2.7+) and older payload-chained records."""
        for section in ("an", "ns", "ar"):
            sec = getattr(dns, section, None)
            if not sec:
                continue
            if isinstance(sec, list):
                for rr in sec:
                    yield rr
            else:
                rr, count = sec, 0
                while rr is not None and count < 50:
                    if hasattr(rr, "rrname"):
                        yield rr
                    rr = getattr(rr, "payload", None) or None
                    count += 1

    def _on_ssdp(self, scapy, pkt) -> None:
        mac, ip = self._src(scapy, pkt)
        try:
            payload = bytes(pkt[scapy.UDP].payload).decode(errors="replace")
        except Exception:
            return
        for line in payload.splitlines():
            low = line.lower()
            if low.startswith("server:"):
                self._record(mac, ip, "ssdp", "server", line.split(":", 1)[1].strip())
            elif low.startswith("usn:") and "device:" in low:
                self._record(mac, ip, "ssdp", "usn", line.split(":", 1)[1].strip())

    def _on_nbns(self, scapy, pkt) -> None:
        mac, ip = self._src(scapy, pkt)
        name = None
        try:
            if pkt.haslayer(scapy.NBNSQueryRequest):
                name = pkt[scapy.NBNSQueryRequest].QUESTION_NAME
            elif pkt.haslayer(scapy.NBNSRegistrationRequest):
                name = pkt[scapy.NBNSRegistrationRequest].QUESTION_NAME
        except Exception:
            name = None
        if name:
            if isinstance(name, bytes):
                name = name.decode(errors="replace")
            name = name.strip()
            if name and name != "*":
                self._record(mac, ip, "nbns", "name", name)


def available() -> bool:
    """True if scapy (and thus sniffing) can be imported."""
    try:
        _scapy()
        return True
    except Exception:
        return False
