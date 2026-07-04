"""Flask dashboard + JSON API for Knox.

Serves a single auto-refreshing page plus a small JSON API the page polls.
Optionally starts the background :class:`knox.monitor.Monitor` so one
``python -m knox serve`` process does discovery, alerting, scanning, and the UI.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone

from flask import (
    Flask,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from .. import config, net
from ..enrich import group_key
from ..store import Store

app = Flask(__name__)
# Session signing key: explicit > derived-from-password (stable across restarts)
# > random (fine, just logs users out on restart).
if config.SECRET_KEY:
    app.secret_key = config.SECRET_KEY
elif config.PASSWORD:
    app.secret_key = hashlib.sha256(("knox:" + config.PASSWORD).encode()).hexdigest()
else:
    app.secret_key = secrets.token_hex(16)

_store: Store | None = None
_monitor = None  # set in run_server when monitoring is enabled


# --- Auth ------------------------------------------------------------------

def _auth_required() -> bool:
    return bool(config.PASSWORD)


@app.before_request
def _gate():
    if not _auth_required():
        return None
    # Allow the login page and static assets through unauthenticated.
    if request.endpoint in ("login", "static") or request.path.startswith("/static/"):
        return None
    if session.get("authed"):
        return None
    if request.path.startswith("/api/"):
        return jsonify({"error": "unauthorized"}), 401
    return redirect(url_for("login", next=request.path))


@app.route("/login", methods=["GET", "POST"])
def login():
    if not _auth_required() or session.get("authed"):
        return redirect(url_for("index"))
    error = None
    if request.method == "POST":
        given = request.form.get("password", "")
        if hmac.compare_digest(given, config.PASSWORD):
            session["authed"] = True
            session.permanent = True
            return redirect(request.args.get("next") or url_for("index"))
        error = "Incorrect password."
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


def get_store() -> Store:
    global _store
    if _store is None:
        _store = Store()
    return _store


def _age_seconds(iso: str) -> float:
    try:
        seen = datetime.fromisoformat(iso)
    except ValueError:
        return 1e9
    if seen.tzinfo is None:
        seen = seen.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - seen).total_seconds()


def _row_get(row, key):
    return row[key] if key in row.keys() else None


def _device_dict(row, port_counts: dict) -> dict:
    online = _age_seconds(row["last_seen"]) <= config.OFFLINE_AFTER
    owner = _row_get(row, "owner")
    return {
        "mac": row["mac"],
        "ip": row["ip"],
        "hostname": row["hostname"],
        "vendor": row["vendor"],
        "label": row["label"],
        "owner": owner,
        "notes": _row_get(row, "notes"),
        "os": _row_get(row, "os"),
        "blocked": bool(_row_get(row, "blocked")),
        "trusted": bool(row["trusted"]),
        "first_seen": row["first_seen"],
        "last_seen": row["last_seen"],
        "online": online,
        "ports": port_counts.get(row["mac"], 0),
        "group": group_key(row["label"], row["hostname"], owner, row["mac"]),
    }


def _wan_summary(store) -> dict:
    """Current internet status + uptime % over the last 24h from wan_events.

    wan_events records only transitions, so we integrate the up-time between
    them. The period before the first recorded event is assumed to be in that
    first event's state (best effort for a freshly-started monitor).
    """
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(hours=24)
    current = store.wan_current()
    events = store.wan_events_since(window_start.replace(microsecond=0).isoformat())

    if events:
        state = bool(events[0]["up"])
    else:
        state = bool(current) if current is not None else True

    up_seconds = 0.0
    cursor = window_start
    for e in events:
        t = datetime.fromisoformat(e["at"])
        if t.tzinfo is None:
            t = t.replace(tzinfo=timezone.utc)
        t = max(t, window_start)
        if state:
            up_seconds += (t - cursor).total_seconds()
        cursor = t
        state = bool(e["up"])
    if state:
        up_seconds += (now - cursor).total_seconds()

    total = (now - window_start).total_seconds()
    pct = round(100.0 * up_seconds / total, 2) if total else 100.0
    return {"up": current, "uptime_24h": max(0.0, min(100.0, pct))}


@app.route("/")
def index():
    return render_template(
        "dashboard.html",
        subnet=", ".join(net.configured_subnets()),
        auth=_auth_required(),
    )


@app.route("/device/<mac>")
def device_page(mac: str):
    store = get_store()
    dev = store.get_device(mac)
    if not dev:
        return "Device not found", 404
    return render_template("device.html", mac=mac.upper())


@app.route("/api/device/<mac>/timeline")
def api_timeline(mac: str):
    """Presence buckets over a window: each bucket online if any sighting fell in it."""
    store = get_store()
    if not store.get_device(mac):
        return jsonify({"error": "not found"}), 404
    hours = max(1, min(168, request.args.get("hours", 24, type=int)))
    buckets = 96  # fixed resolution across the window
    now = datetime.now(timezone.utc)
    start = now - timedelta(hours=hours)
    span = (now - start).total_seconds()
    width = span / buckets
    seen = [False] * buckets
    for ts in store.sightings_since(mac, start.replace(microsecond=0).isoformat()):
        t = datetime.fromisoformat(ts)
        if t.tzinfo is None:
            t = t.replace(tzinfo=timezone.utc)
        idx = int((t - start).total_seconds() / width)
        if 0 <= idx < buckets:
            seen[idx] = True
    online = sum(seen)
    return jsonify(
        {
            "hours": hours,
            "buckets": seen,
            "uptime_pct": round(100.0 * online / buckets, 1),
            "start": start.replace(microsecond=0).isoformat(),
        }
    )


@app.route("/api/devices")
def api_devices():
    store = get_store()
    counts = store.port_counts()
    devices = [_device_dict(d, counts) for d in store.devices()]
    return jsonify(
        {
            "devices": devices,
            "online": sum(1 for d in devices if d["online"]),
            "total": len(devices),
            "untrusted": sum(1 for d in devices if not d["trusted"]),
            "open_ports": sum(d["ports"] for d in devices),
            "gateways": [net.gateway_ip(s) for s in net.configured_subnets()],
            "unacked_alerts": store.unacknowledged_count(),
            "wan": _wan_summary(store),
        }
    )


@app.route("/api/device/<mac>")
def api_device(mac: str):
    store = get_store()
    dev = store.get_device(mac)
    if not dev:
        return jsonify({"error": "not found"}), 404
    counts = store.port_counts()
    data = _device_dict(dev, counts)
    data["port_list"] = [
        {
            "port": p["port"],
            "proto": p["proto"],
            "service": p["service"],
            "version": p["version"],
        }
        for p in store.ports_for(mac)
    ]
    data["hints"] = [
        {"source": h["source"], "key": h["key"], "value": h["value"], "seen_at": h["seen_at"]}
        for h in store.hints_for(mac)
    ]
    return jsonify(data)


@app.route("/api/device/<mac>/traffic")
def api_traffic(mac: str):
    store = get_store()
    if not store.get_device(mac):
        return jsonify({"error": "not found"}), 404
    flows = [
        {
            "remote_ip": r["remote_ip"],
            "remote_host": r["remote_host"],
            "proto": r["proto"],
            "dport": r["dport"],
            "bytes": r["bytes"],
            "packets": r["packets"],
        }
        for r in store.top_flows(mac, 25)
    ]
    since = (datetime.now(timezone.utc) - timedelta(hours=6)).replace(microsecond=0).isoformat()
    series = [{"at": r["at"], "bytes": r["bytes"]} for r in store.bw_series(mac, since)]
    return jsonify(
        {
            "flows": flows,
            "series": series,
            "total_bytes": store.device_bytes(mac),
            "capture_on": config.CAPTURE,
        }
    )


@app.route("/api/device/<mac>/domains")
def api_domains(mac: str):
    store = get_store()
    if not store.get_device(mac):
        return jsonify({"error": "not found"}), 404
    rows = store.top_domains(mac.upper(), 50)
    return jsonify(
        {
            "domains": [
                {"domain": r["domain"], "count": r["count"], "last_seen": r["last_seen"]}
                for r in rows
            ],
            "dns_on": config.DNS_SERVER,
        }
    )


@app.route("/alerts")
def alerts_page():
    return render_template("alerts.html", auth=_auth_required())


@app.route("/api/alerts")
def api_alerts():
    store = get_store()
    rows = store.alerts(
        limit=request.args.get("limit", 100, type=int),
        offset=request.args.get("offset", 0, type=int),
        severity=request.args.get("severity") or None,
        type_=request.args.get("type") or None,
        search=request.args.get("search") or None,
        unacknowledged_only=request.args.get("unacked") == "1",
    )
    return jsonify(
        {
            "alerts": [
                {
                    "id": r["id"],
                    "mac": r["mac"],
                    "type": r["type"],
                    "message": r["message"],
                    "created_at": r["created_at"],
                    "acknowledged": bool(r["acknowledged"]),
                    "severity": (r["severity"] if "severity" in r.keys() else "warning"),
                }
                for r in rows
            ],
            "types": store.alert_types(),
        }
    )


@app.route("/api/device/<mac>/trust", methods=["POST"])
def api_trust(mac: str):
    store = get_store()
    if not store.get_device(mac):
        return jsonify({"error": "not found"}), 404
    trusted = request.json.get("trusted", True) if request.is_json else True
    store.set_trusted(mac, bool(trusted))
    return jsonify({"ok": True, "mac": mac.upper(), "trusted": bool(trusted)})


@app.route("/api/device/<mac>/label", methods=["POST"])
def api_label(mac: str):
    store = get_store()
    if not store.get_device(mac):
        return jsonify({"error": "not found"}), 404
    label = (request.json.get("label") if request.is_json else "") or ""
    store.set_label(mac, label.strip())
    return jsonify({"ok": True, "mac": mac.upper(), "label": label.strip()})


@app.route("/api/device/<mac>/owner", methods=["POST"])
def api_owner(mac: str):
    store = get_store()
    if not store.get_device(mac):
        return jsonify({"error": "not found"}), 404
    owner = (request.json.get("owner") if request.is_json else "") or ""
    store.set_owner(mac, owner)
    return jsonify({"ok": True, "mac": mac.upper(), "owner": owner.strip()})


@app.route("/api/device/<mac>/notes", methods=["POST"])
def api_notes(mac: str):
    store = get_store()
    if not store.get_device(mac):
        return jsonify({"error": "not found"}), 404
    notes = (request.json.get("notes") if request.is_json else "") or ""
    store.set_notes(mac, notes)
    return jsonify({"ok": True, "mac": mac.upper()})


@app.route("/api/devices/trust-all", methods=["POST"])
def api_trust_all():
    n = get_store().trust_all()
    return jsonify({"ok": True, "trusted": n})


@app.route("/api/devices/trust", methods=["POST"])
def api_bulk_trust():
    store = get_store()
    body = request.json if request.is_json else {}
    macs = body.get("macs", [])
    trusted = bool(body.get("trusted", True))
    n = 0
    for mac in macs:
        if store.get_device(mac):
            store.set_trusted(mac, trusted)
            n += 1
    return jsonify({"ok": True, "count": n, "trusted": trusted})


@app.route("/api/alerts/<int:alert_id>/ack", methods=["POST"])
def api_ack(alert_id: int):
    get_store().acknowledge_alert(alert_id)
    return jsonify({"ok": True})


@app.route("/api/alerts/ack-all", methods=["POST"])
def api_ack_all():
    n = get_store().acknowledge_all()
    return jsonify({"ok": True, "dismissed": n})


def run_server(start_monitor: bool = True) -> None:
    global _store, _monitor
    _store = Store()
    if start_monitor:
        from ..monitor import Monitor

        _monitor = Monitor(store=_store)
        _monitor.start()
    print(
        f"Knox dashboard: http://{config.WEB_HOST}:{config.WEB_PORT}  "
        f"(monitor {'on' if start_monitor else 'off'})"
    )
    # use_reloader=False so the monitor thread isn't started twice.
    app.run(host=config.WEB_HOST, port=config.WEB_PORT, use_reloader=False)
