"""Alerting — detect notable events and dispatch notifications.

v1 raises an alert when an *unknown* (untrusted) device appears on the network.
Notifications go to a rotating log file and to the dashboard (via the ``alerts``
table). The :class:`Notifier` interface is intentionally small so phone/email
channels can be added later without touching detection logic.
"""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from typing import Iterable, Protocol

from . import config
from .discovery import Host
from .store import Store


class Notifier(Protocol):
    """Anything that can deliver an alert message."""

    def notify(self, type_: str, message: str, mac: str | None = None) -> None: ...


def _build_logger() -> logging.Logger:
    config.ensure_dirs()
    logger = logging.getLogger("knox.alerts")
    logger.setLevel(logging.INFO)
    # Avoid duplicate handlers if this is called more than once.
    if not any(isinstance(h, RotatingFileHandler) for h in logger.handlers):
        handler = RotatingFileHandler(
            config.LOG_PATH, maxBytes=1_000_000, backupCount=3, encoding="utf-8"
        )
        handler.setFormatter(
            logging.Formatter("%(asctime)s  %(levelname)s  %(message)s")
        )
        logger.addHandler(handler)
    return logger


class LogNotifier:
    """Writes alerts to the rotating Knox log file (and stderr via root)."""

    def __init__(self) -> None:
        self.logger = _build_logger()

    def notify(self, type_: str, message: str, mac: str | None = None) -> None:
        self.logger.warning("[%s] %s", type_, message)


class AlertManager:
    """Runs detection over discovery results and fans out to notifiers."""

    def __init__(self, store: Store, notifiers: Iterable[Notifier] | None = None):
        self.store = store
        self.notifiers = list(notifiers) if notifiers else [LogNotifier()]

    def _emit(self, type_: str, message: str, mac: str | None = None) -> None:
        self.store.add_alert(mac, type_, message)
        for n in self.notifiers:
            try:
                n.notify(type_, message, mac)
            except Exception:  # a broken notifier must not stop the others
                logging.getLogger("knox.alerts").exception("notifier failed")

    def process(self, hosts: Iterable[Host]) -> list[str]:
        """Persist hosts and raise alerts for newly-seen untrusted devices.

        Returns the list of MACs that triggered a ``new_device`` alert.
        """
        alerted: list[str] = []
        for h in hosts:
            existed = self.store.get_device(h.mac) is not None
            is_new = self.store.upsert_device(h.mac, h.ip, h.hostname, h.vendor)
            if is_new and not existed:
                name = h.hostname or h.vendor or "unknown device"
                self._emit(
                    "new_device",
                    f"New device joined: {name} - {h.ip} ({h.mac}, {h.vendor})",
                    h.mac,
                )
                alerted.append(h.mac)
        return alerted
