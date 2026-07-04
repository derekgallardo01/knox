"""SQLite persistence layer for Knox.

One database file holds the device inventory, presence history (sightings),
nmap port results, and the alert feed. All timestamps are stored as ISO-8601
UTC strings so they sort lexicographically and are human-readable.
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Iterable, Iterator, Optional

from . import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    mac        TEXT PRIMARY KEY,
    ip         TEXT,
    hostname   TEXT,
    vendor     TEXT,
    first_seen TEXT NOT NULL,
    last_seen  TEXT NOT NULL,
    trusted    INTEGER NOT NULL DEFAULT 0,
    label      TEXT
);

CREATE TABLE IF NOT EXISTS sightings (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    mac     TEXT NOT NULL,
    ip      TEXT,
    seen_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sightings_mac ON sightings(mac);

CREATE TABLE IF NOT EXISTS ports (
    mac        TEXT NOT NULL,
    port       INTEGER NOT NULL,
    proto      TEXT NOT NULL,
    service    TEXT,
    version    TEXT,
    scanned_at TEXT NOT NULL,
    PRIMARY KEY (mac, port, proto)
);

CREATE TABLE IF NOT EXISTS alerts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    mac          TEXT,
    type         TEXT NOT NULL,
    message      TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    acknowledged INTEGER NOT NULL DEFAULT 0
);
"""


def now_iso() -> str:
    """Current UTC time as an ISO-8601 string (seconds precision)."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


class Store:
    """Thin wrapper around a SQLite connection with Knox-specific helpers."""

    def __init__(self, path: Optional[str] = None):
        config.ensure_dirs()
        self.path = str(path or config.DB_PATH)
        # check_same_thread=False so the Flask dashboard and monitor thread can
        # share one Store; we serialize writes through short-lived cursors.
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    @contextmanager
    def _write(self) -> Iterator[sqlite3.Cursor]:
        cur = self.conn.cursor()
        try:
            yield cur
            self.conn.commit()
        finally:
            cur.close()

    # --- Devices & sightings -------------------------------------------------

    def upsert_device(
        self,
        mac: str,
        ip: str,
        hostname: Optional[str] = None,
        vendor: Optional[str] = None,
    ) -> bool:
        """Insert or update a device and record a sighting.

        Returns ``True`` if this MAC was never seen before (a new device),
        ``False`` if it already existed.
        """
        mac = mac.upper()
        ts = now_iso()
        row = self.conn.execute(
            "SELECT mac FROM devices WHERE mac = ?", (mac,)
        ).fetchone()
        is_new = row is None
        with self._write() as cur:
            if is_new:
                cur.execute(
                    "INSERT INTO devices (mac, ip, hostname, vendor, first_seen, last_seen) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (mac, ip, hostname, vendor, ts, ts),
                )
            else:
                # Only overwrite hostname/vendor when we have a fresh value.
                cur.execute(
                    "UPDATE devices SET ip = ?, last_seen = ?, "
                    "hostname = COALESCE(?, hostname), "
                    "vendor = COALESCE(?, vendor) WHERE mac = ?",
                    (ip, ts, hostname, vendor, mac),
                )
            cur.execute(
                "INSERT INTO sightings (mac, ip, seen_at) VALUES (?, ?, ?)",
                (mac, ip, ts),
            )
        return is_new

    def set_trusted(self, mac: str, trusted: bool = True) -> None:
        with self._write() as cur:
            cur.execute(
                "UPDATE devices SET trusted = ? WHERE mac = ?",
                (1 if trusted else 0, mac.upper()),
            )

    def set_label(self, mac: str, label: str) -> None:
        with self._write() as cur:
            cur.execute(
                "UPDATE devices SET label = ? WHERE mac = ?", (label, mac.upper())
            )

    def get_device(self, mac: str) -> Optional[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM devices WHERE mac = ?", (mac.upper(),)
        ).fetchone()

    def devices(self) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM devices ORDER BY last_seen DESC"
        ).fetchall()

    # --- Ports ---------------------------------------------------------------

    def replace_ports(self, mac: str, ports: Iterable[dict]) -> None:
        """Replace all stored ports for a host with a fresh scan result."""
        mac = mac.upper()
        ts = now_iso()
        with self._write() as cur:
            cur.execute("DELETE FROM ports WHERE mac = ?", (mac,))
            for p in ports:
                cur.execute(
                    "INSERT OR REPLACE INTO ports "
                    "(mac, port, proto, service, version, scanned_at) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        mac,
                        int(p["port"]),
                        p.get("proto", "tcp"),
                        p.get("service"),
                        p.get("version"),
                        ts,
                    ),
                )

    def ports_for(self, mac: str) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM ports WHERE mac = ? ORDER BY port", (mac.upper(),)
        ).fetchall()

    def port_counts(self) -> dict[str, int]:
        rows = self.conn.execute(
            "SELECT mac, COUNT(*) AS n FROM ports GROUP BY mac"
        ).fetchall()
        return {r["mac"]: r["n"] for r in rows}

    # --- Alerts --------------------------------------------------------------

    def add_alert(self, mac: Optional[str], type_: str, message: str) -> int:
        with self._write() as cur:
            cur.execute(
                "INSERT INTO alerts (mac, type, message, created_at) "
                "VALUES (?, ?, ?, ?)",
                (mac.upper() if mac else None, type_, message, now_iso()),
            )
            return cur.lastrowid

    def alerts(self, limit: int = 100, unacknowledged_only: bool = False) -> list[sqlite3.Row]:
        q = "SELECT * FROM alerts"
        if unacknowledged_only:
            q += " WHERE acknowledged = 0"
        q += " ORDER BY created_at DESC LIMIT ?"
        return self.conn.execute(q, (limit,)).fetchall()

    def acknowledge_alert(self, alert_id: int) -> None:
        with self._write() as cur:
            cur.execute(
                "UPDATE alerts SET acknowledged = 1 WHERE id = ?", (alert_id,)
            )
