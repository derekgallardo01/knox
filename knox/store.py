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

-- Passive-listener evidence used to auto-identify devices. One row per
-- (mac, source, key); latest value + timestamp kept.
CREATE TABLE IF NOT EXISTS hints (
    mac     TEXT NOT NULL,
    source  TEXT NOT NULL,   -- dhcp | mdns | ssdp | nbns
    key     TEXT NOT NULL,   -- hostname | vendor_class | service | server | name
    value   TEXT NOT NULL,
    seen_at TEXT NOT NULL,
    PRIMARY KEY (mac, source, key)
);
CREATE INDEX IF NOT EXISTS idx_hints_mac ON hints(mac);

-- Detection baselines / learned state (e.g. gateway MAC, known DHCP servers).
CREATE TABLE IF NOT EXISTS baseline (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- Internet/WAN reachability transitions (one row per up<->down change).
CREATE TABLE IF NOT EXISTS wan_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    up INTEGER NOT NULL,
    at TEXT NOT NULL
);

-- Per-device traffic flows: bytes/packets to each remote endpoint (M4).
CREATE TABLE IF NOT EXISTS flows (
    mac         TEXT NOT NULL,
    remote_ip   TEXT NOT NULL,
    remote_host TEXT,
    proto       TEXT NOT NULL,
    dport       INTEGER NOT NULL,
    bytes       INTEGER NOT NULL DEFAULT 0,
    packets     INTEGER NOT NULL DEFAULT 0,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    PRIMARY KEY (mac, remote_ip, proto, dport)
);
CREATE INDEX IF NOT EXISTS idx_flows_mac ON flows(mac);

-- Per-device bandwidth time-series (bytes per flush interval) for sparklines.
CREATE TABLE IF NOT EXISTS bw_samples (
    mac   TEXT NOT NULL,
    at    TEXT NOT NULL,
    bytes INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_bw_mac_at ON bw_samples(mac, at);

-- IP -> hostname cache learned from observed DNS answers.
CREATE TABLE IF NOT EXISTS dns_names (
    ip   TEXT PRIMARY KEY,
    host TEXT NOT NULL,
    at   TEXT NOT NULL
);

-- Per-device domain lookups seen by the Knox DNS resolver (aggregated).
CREATE TABLE IF NOT EXISTS dns_hits (
    owner      TEXT NOT NULL,   -- device MAC (preferred) or client IP
    domain     TEXT NOT NULL,
    count      INTEGER NOT NULL DEFAULT 0,
    first_seen TEXT NOT NULL,
    last_seen  TEXT NOT NULL,
    PRIMARY KEY (owner, domain)
);
CREATE INDEX IF NOT EXISTS idx_dns_hits_owner ON dns_hits(owner);
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
        self._migrate()
        self.conn.commit()

    def _migrate(self) -> None:
        """Additive migrations for databases created by an earlier version."""
        acols = {r["name"] for r in self.conn.execute("PRAGMA table_info(alerts)")}
        if "severity" not in acols:
            self.conn.execute(
                "ALTER TABLE alerts ADD COLUMN severity TEXT NOT NULL DEFAULT 'warning'"
            )
        dcols = {r["name"] for r in self.conn.execute("PRAGMA table_info(devices)")}
        for col in ("owner", "notes", "os"):
            if col not in dcols:
                self.conn.execute(f"ALTER TABLE devices ADD COLUMN {col} TEXT")
        if "blocked" not in dcols:
            self.conn.execute(
                "ALTER TABLE devices ADD COLUMN blocked INTEGER NOT NULL DEFAULT 0"
            )

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
        from .discovery import valid_device_mac

        if not valid_device_mac(mac):
            return False  # never record null/broadcast/multicast pseudo-devices
        mac = mac.upper()
        ts = now_iso()
        # Don't let a later scan downgrade a known vendor to Unknown/Private —
        # pass None so COALESCE keeps whatever we already resolved (or a manual
        # override). New devices still record whatever we have.
        if vendor in (None, "", "Unknown", "Private"):
            vendor = None
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
                # COALESCE so a passive packet with no IP/hostname/vendor never
                # wipes a value we already have (only fresh values overwrite).
                cur.execute(
                    "UPDATE devices SET ip = COALESCE(?, ip), last_seen = ?, "
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

    def trust_all(self) -> int:
        """Mark every known device as trusted (baseline the current network)."""
        with self._write() as cur:
            cur.execute("UPDATE devices SET trusted = 1 WHERE trusted = 0")
            return cur.rowcount

    def set_label(self, mac: str, label: str) -> None:
        with self._write() as cur:
            cur.execute(
                "UPDATE devices SET label = ? WHERE mac = ?", (label, mac.upper())
            )

    def _set_field(self, mac: str, field: str, value) -> None:
        with self._write() as cur:
            cur.execute(f"UPDATE devices SET {field} = ? WHERE mac = ?", (value, mac.upper()))

    def set_owner(self, mac: str, owner: str) -> None:
        self._set_field(mac, "owner", (owner or "").strip() or None)

    def set_notes(self, mac: str, notes: str) -> None:
        self._set_field(mac, "notes", notes or None)

    def set_os(self, mac: str, os_name: str) -> None:
        self._set_field(mac, "os", os_name or None)

    def set_blocked(self, mac: str, blocked: bool = True) -> None:
        self._set_field(mac, "blocked", 1 if blocked else 0)

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

    def add_alert(
        self,
        mac: Optional[str],
        type_: str,
        message: str,
        severity: str = "warning",
    ) -> int:
        with self._write() as cur:
            cur.execute(
                "INSERT INTO alerts (mac, type, message, created_at, severity) "
                "VALUES (?, ?, ?, ?, ?)",
                (mac.upper() if mac else None, type_, message, now_iso(), severity),
            )
            return cur.lastrowid

    def alert_exists(self, type_: str, mac: Optional[str], message: str) -> bool:
        """True if an identical alert already exists (for de-duplication)."""
        return (
            self.conn.execute(
                "SELECT 1 FROM alerts WHERE type = ? AND ifnull(mac,'') = ? "
                "AND message = ? LIMIT 1",
                (type_, mac.upper() if mac else "", message),
            ).fetchone()
            is not None
        )

    def alerts(
        self,
        limit: int = 100,
        unacknowledged_only: bool = False,
        severity: Optional[str] = None,
        type_: Optional[str] = None,
        search: Optional[str] = None,
        offset: int = 0,
    ) -> list[sqlite3.Row]:
        clauses, params = [], []
        if unacknowledged_only:
            clauses.append("acknowledged = 0")
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        if type_:
            clauses.append("type = ?")
            params.append(type_)
        if search:
            clauses.append("(message LIKE ? OR ifnull(mac,'') LIKE ?)")
            params += [f"%{search}%", f"%{search}%"]
        q = "SELECT * FROM alerts"
        if clauses:
            q += " WHERE " + " AND ".join(clauses)
        q += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params += [limit, offset]
        return self.conn.execute(q, params).fetchall()

    def alert_types(self) -> list[str]:
        rows = self.conn.execute(
            "SELECT DISTINCT type FROM alerts ORDER BY type"
        ).fetchall()
        return [r["type"] for r in rows]

    def acknowledge_alert(self, alert_id: int) -> None:
        with self._write() as cur:
            cur.execute(
                "UPDATE alerts SET acknowledged = 1 WHERE id = ?", (alert_id,)
            )

    def acknowledge_all(self) -> int:
        """Dismiss every outstanding alert."""
        with self._write() as cur:
            cur.execute("UPDATE alerts SET acknowledged = 1 WHERE acknowledged = 0")
            return cur.rowcount

    # --- Hints (passive-listener evidence) ----------------------------------

    def add_hint(self, mac: str, source: str, key: str, value: str) -> bool:
        """Record/refresh a passive identification hint.

        Returns True if this is a new (mac, source, key) or the value changed.
        """
        if not value:
            return False
        mac = mac.upper()
        value = value.strip()
        existing = self.conn.execute(
            "SELECT value FROM hints WHERE mac = ? AND source = ? AND key = ?",
            (mac, source, key),
        ).fetchone()
        changed = existing is None or existing["value"] != value
        with self._write() as cur:
            cur.execute(
                "INSERT INTO hints (mac, source, key, value, seen_at) "
                "VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(mac, source, key) DO UPDATE SET value = excluded.value, "
                "seen_at = excluded.seen_at",
                (mac, source, key, value, now_iso()),
            )
        return changed

    def hints_for(self, mac: str) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM hints WHERE mac = ? ORDER BY source, key", (mac.upper(),)
        ).fetchall()

    # --- Detection baselines -------------------------------------------------

    def get_baseline(self, key: str) -> Optional[str]:
        row = self.conn.execute(
            "SELECT value FROM baseline WHERE key = ?", (key,)
        ).fetchone()
        return row["value"] if row else None

    def set_baseline(self, key: str, value: str) -> None:
        with self._write() as cur:
            cur.execute(
                "INSERT INTO baseline (key, value, updated_at) VALUES (?, ?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value, "
                "updated_at = excluded.updated_at",
                (key, value, now_iso()),
            )

    # --- Sighting history ----------------------------------------------------

    def sightings_since(self, mac: str, since_iso: str) -> list[str]:
        """Timestamps (ISO) this MAC was seen at or after ``since_iso``."""
        rows = self.conn.execute(
            "SELECT seen_at FROM sightings WHERE mac = ? AND seen_at >= ? "
            "ORDER BY seen_at",
            (mac.upper(), since_iso),
        ).fetchall()
        return [r["seen_at"] for r in rows]

    # --- WAN / internet uptime ----------------------------------------------

    def wan_current(self) -> Optional[bool]:
        row = self.conn.execute(
            "SELECT up FROM wan_events ORDER BY id DESC LIMIT 1"
        ).fetchone()
        return None if row is None else bool(row["up"])

    def add_wan_event(self, up: bool) -> None:
        with self._write() as cur:
            cur.execute(
                "INSERT INTO wan_events (up, at) VALUES (?, ?)", (1 if up else 0, now_iso())
            )

    def wan_events_since(self, since_iso: str) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT up, at FROM wan_events WHERE at >= ? ORDER BY at", (since_iso,)
        ).fetchall()

    # --- Traffic (flows / bandwidth / DNS names) ----------------------------

    def add_flow(
        self,
        mac: str,
        remote_ip: str,
        proto: str,
        dport: int,
        nbytes: int,
        npackets: int,
        remote_host: Optional[str] = None,
    ) -> None:
        """Accumulate bytes/packets for a (device, remote, proto, port) flow."""
        mac = mac.upper()
        ts = now_iso()
        with self._write() as cur:
            cur.execute(
                "INSERT INTO flows (mac, remote_ip, remote_host, proto, dport, "
                "bytes, packets, first_seen, last_seen) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(mac, remote_ip, proto, dport) DO UPDATE SET "
                "bytes = bytes + excluded.bytes, packets = packets + excluded.packets, "
                "remote_host = COALESCE(excluded.remote_host, remote_host), "
                "last_seen = excluded.last_seen",
                (mac, remote_ip, remote_host, proto, dport, nbytes, npackets, ts, ts),
            )

    def top_flows(self, mac: str, limit: int = 20) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM flows WHERE mac = ? ORDER BY bytes DESC LIMIT ?",
            (mac.upper(), limit),
        ).fetchall()

    def device_bytes(self, mac: str) -> int:
        row = self.conn.execute(
            "SELECT COALESCE(SUM(bytes),0) AS b FROM flows WHERE mac = ?", (mac.upper(),)
        ).fetchone()
        return row["b"] if row else 0

    def add_bw_sample(self, mac: str, nbytes: int) -> None:
        with self._write() as cur:
            cur.execute(
                "INSERT INTO bw_samples (mac, at, bytes) VALUES (?, ?, ?)",
                (mac.upper(), now_iso(), nbytes),
            )

    def bw_series(self, mac: str, since_iso: str) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT at, bytes FROM bw_samples WHERE mac = ? AND at >= ? ORDER BY at",
            (mac.upper(), since_iso),
        ).fetchall()

    def set_dns_name(self, ip: str, host: str) -> None:
        with self._write() as cur:
            cur.execute(
                "INSERT INTO dns_names (ip, host, at) VALUES (?, ?, ?) "
                "ON CONFLICT(ip) DO UPDATE SET host = excluded.host, at = excluded.at",
                (ip, host, now_iso()),
            )

    def get_dns_name(self, ip: str) -> Optional[str]:
        row = self.conn.execute(
            "SELECT host FROM dns_names WHERE ip = ?", (ip,)
        ).fetchone()
        return row["host"] if row else None

    def device_by_ip(self, ip: str) -> Optional[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM devices WHERE ip = ? ORDER BY last_seen DESC LIMIT 1", (ip,)
        ).fetchone()

    def log_dns_query(self, client_ip: str, domain: str) -> str:
        """Record a domain lookup by a device (resolved from client IP to MAC).

        Returns the owner key used (MAC if known, else the client IP).
        """
        dev = self.device_by_ip(client_ip)
        owner = dev["mac"] if dev else client_ip
        ts = now_iso()
        with self._write() as cur:
            cur.execute(
                "INSERT INTO dns_hits (owner, domain, count, first_seen, last_seen) "
                "VALUES (?, ?, 1, ?, ?) "
                "ON CONFLICT(owner, domain) DO UPDATE SET count = count + 1, "
                "last_seen = excluded.last_seen",
                (owner, domain, ts, ts),
            )
        return owner

    def top_domains(self, owner: str, limit: int = 50) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM dns_hits WHERE owner = ? ORDER BY count DESC, last_seen DESC LIMIT ?",
            (owner.upper() if ":" in owner else owner, limit),
        ).fetchall()

    def unacknowledged_count(self) -> int:
        row = self.conn.execute(
            "SELECT COUNT(*) AS n FROM alerts WHERE acknowledged = 0"
        ).fetchone()
        return row["n"] if row else 0
