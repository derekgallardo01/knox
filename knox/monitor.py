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
from .discovery import discover_all
from .scanner import NmapUnavailable, scan_host
from .store import Store

log = logging.getLogger("knox.monitor")


class Monitor:
    def __init__(self, store: Optional[Store] = None):
        self.store = store or Store()
        self.alerts = AlertManager(self.store)
        self.subnets = net.configured_subnets()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
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

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)

    # --- loop ----------------------------------------------------------------

    def tick(self) -> int:
        """Run one discovery+alert cycle. Returns the number of devices seen."""
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
                ports = scan_host(dev["ip"])
                self.store.replace_ports(dev["mac"], ports)
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
