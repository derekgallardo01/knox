"""Background monitor loop.

Runs discovery on a fixed interval, persists results, raises new-device alerts,
and periodically runs nmap on known hosts. Designed to run in a daemon thread
alongside the Flask dashboard (see :mod:`knox.web.app`).
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Optional

from . import config, net
from .alerts import AlertManager
from .detect import DetectionEngine
from .discovery import discover_all
from .scanner import NmapUnavailable, scan_host
from .store import Store

log = logging.getLogger("knox.monitor")


class Monitor:
    def __init__(self, store: Optional[Store] = None):
        self.store = store or Store()
        self.alerts = AlertManager(self.store)
        self.detect = DetectionEngine(self.store, self.alerts)
        self.subnets = net.configured_subnets()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._listener = None
        self._traffic = None
        self._dns = None
        self._last_nmap = 0.0
        # Track wall-clock via a monotonic counter seeded at start (Date/time
        # helpers in store use real UTC; here we only need relative spacing).
        self._elapsed = 0.0

    # --- lifecycle -----------------------------------------------------------

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="knox-monitor", daemon=True)
        self._thread.start()
        log.info(
            "monitor started on %s (interval=%ss)",
            ", ".join(self.subnets),
            config.SCAN_INTERVAL,
        )
        # Passive listener (auto-naming) runs alongside active scanning.
        if config.PASSIVE:
            from .listener import PassiveListener

            self._listener = PassiveListener(store=self.store, detect=self.detect)
            if not self._listener.start():
                self._listener = None
                log.info("continuing with active scanning only (no passive listener)")

        if config.CAPTURE:
            from .traffic import TrafficSniffer

            self._traffic = TrafficSniffer(store=self.store)
            if not self._traffic.start():
                self._traffic = None

        if config.DNS_SERVER:
            from .dnsserver import DnsServer

            self._dns = DnsServer(store=self.store)
            if not self._dns.start():
                self._dns = None

    def stop(self) -> None:
        self._stop.set()
        if self._listener:
            self._listener.stop()
        if self._traffic:
            self._traffic.stop()
        if self._dns:
            self._dns.stop()
        if self._thread:
            self._thread.join(timeout=5)

    # --- loop ----------------------------------------------------------------

    def _check_wan(self) -> None:
        """Confirm internet reachability; record + alert on up<->down changes."""
        if not config.WAN_CHECK:
            return
        up = net.internet_up()
        prev = self.store.wan_current()
        if prev is None or prev != up:
            self.store.add_wan_event(up)
            if prev is not None:  # don't alert on the very first observation
                if up:
                    self.alerts.raise_alert(
                        "wan_up", "Internet connection restored.", severity="info", dedup=False
                    )
                else:
                    self.alerts.raise_alert(
                        "wan_down", "Internet connection lost.", severity="critical", dedup=False
                    )

    def tick(self) -> int:
        """Run one discovery+alert cycle. Returns the number of devices seen."""
        self._check_wan()
        hosts = discover_all(self.subnets)
        alerted = self.alerts.process(hosts)
        if alerted:
            log.info("new devices this cycle: %s", ", ".join(alerted))

        # Periodic nmap of known hosts, spaced by NMAP_INTERVAL.
        if self._elapsed - self._last_nmap >= config.NMAP_INTERVAL or self._last_nmap == 0:
            self._nmap_known_hosts()
            self._last_nmap = self._elapsed
        return len(hosts)

    def _nmap_known_hosts(self) -> None:
        for dev in self.store.devices():
            if self._stop.is_set() or not dev["ip"]:
                continue
            try:
                old_ports = [dict(p) for p in self.store.ports_for(dev["mac"])]
                ports = scan_host(dev["ip"])
                self.store.replace_ports(dev["mac"], ports)
                self.detect.on_ports(dev["mac"], dev["ip"], old_ports, ports)
            except NmapUnavailable as e:
                log.warning("nmap unavailable, skipping port scans: %s", e)
                return  # no point retrying every host this cycle
            except Exception:
                log.exception("nmap failed for %s", dev["ip"])

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                seen = self.tick()
                log.debug("cycle complete: %d devices", seen)
            except Exception:
                log.exception("monitor cycle failed")
            # Sleep in short slices so stop() is responsive.
            waited = 0.0
            while waited < config.SCAN_INTERVAL and not self._stop.is_set():
                time.sleep(1)
                waited += 1
                self._elapsed += 1
