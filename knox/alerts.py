"""Alerting — detect notable events and dispatch notifications.

v1 raises an alert when an *unknown* (untrusted) device appears on the network.
Notifications go to a rotating log file and to the dashboard (via the ``alerts``
table). The :class:`Notifier` interface is intentionally small so phone/email
channels can be added later without touching detection logic.
"""

from __future__ import annotations

import logging
import urllib.request
from logging.handlers import RotatingFileHandler
from typing import Iterable, Protocol

from . import config
from .discovery import Host
from .store import Store


class Notifier(Protocol):
    """Anything that can deliver an alert message."""

    def notify(
        self, type_: str, message: str, mac: str | None = None, severity: str = "warning"
    ) -> None: ...


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

    def notify(
        self, type_: str, message: str, mac: str | None = None, severity: str = "warning"
    ) -> None:
        level = logging.ERROR if severity == "critical" else logging.WARNING
        self.logger.log(level, "[%s/%s] %s", severity, type_, message)


class NtfyNotifier:
    """Pushes alerts to an ntfy topic (phone notifications, works off-network).

    Enabled by setting ``KNOX_NTFY_TOPIC``. Uses stdlib urllib so there's no
    extra dependency. Header values must be latin-1, so the title is ASCII.
    """

    def __init__(self, topic: str, server: str = "https://ntfy.sh") -> None:
        self.topic = topic
        self.server = server.rstrip("/")

    _PRIORITY = {"critical": "urgent", "warning": "high", "info": "default"}

    def notify(
        self, type_: str, message: str, mac: str | None = None, severity: str = "warning"
    ) -> None:
        title = "Knox: new device" if type_ == "new_device" else f"Knox: {type_}"
        tags = "rotating_light" if severity == "critical" else "warning"
        req = urllib.request.Request(
            f"{self.server}/{self.topic}",
            data=message.encode("utf-8"),
            headers={
                "Title": title,
                "Priority": self._PRIORITY.get(severity, "high"),
                "Tags": tags,
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            resp.read()


def default_notifiers() -> list[Notifier]:
    """Build the notifier list from config: log always, ntfy if configured."""
    notifiers: list[Notifier] = [LogNotifier()]
    if config.NTFY_TOPIC:
        notifiers.append(NtfyNotifier(config.NTFY_TOPIC, config.NTFY_SERVER))
    return notifiers


class AlertManager:
    """Runs detection over discovery results and fans out to notifiers."""

    def __init__(self, store: Store, notifiers: Iterable[Notifier] | None = None):
        self.store = store
        self.notifiers = list(notifiers) if notifiers else default_notifiers()

    def _emit(
        self, type_: str, message: str, mac: str | None = None, severity: str = "warning"
    ) -> None:
        self.store.add_alert(mac, type_, message, severity)
        for n in self.notifiers:
            try:
                n.notify(type_, message, mac, severity)
            except Exception:  # a broken notifier must not stop the others
                logging.getLogger("knox.alerts").exception("notifier failed")

    def raise_alert(
        self,
        type_: str,
        message: str,
        mac: str | None = None,
        severity: str = "warning",
        dedup: bool = True,
    ) -> bool:
        """Emit an alert, skipping it if an identical one already exists.

        Returns True if the alert was emitted, False if de-duplicated away.
        """
        if dedup and self.store.alert_exists(type_, mac, message):
            return False
        self._emit(type_, message, mac, severity)
        return True

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
