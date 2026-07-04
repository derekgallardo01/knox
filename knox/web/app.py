"""Flask dashboard + JSON API for Knox.

Serves a single auto-refreshing page plus a small JSON API the page polls.
Optionally starts the background :class:`knox.monitor.Monitor` so one
``python -m knox serve`` process does discovery, alerting, scanning, and the UI.
"""

from __future__ import annotations

from datetime import datetime, timezone

from flask import Flask, jsonify, render_template, request

from .. import config, net
from ..store import Store

app = Flask(__name__)
_store: Store | None = None
_monitor = None  # set in run_server when monitoring is enabled


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


def _device_dict(row, port_counts: dict) -> dict:
    online = _age_seconds(row["last_seen"]) <= config.OFFLINE_AFTER
    return {
        "mac": row["mac"],
        "ip": row["ip"],
        "hostname": row["hostname"],
        "vendor": row["vendor"],
        "label": row["label"],
        "trusted": bool(row["trusted"]),
        "first_seen": row["first_seen"],
        "last_seen": row["last_seen"],
        "online": online,
        "ports": port_counts.get(row["mac"], 0),
    }


@app.route("/")
def index():
    return render_template("dashboard.html", subnet=net.detect_subnet())


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
            "gateway": net.gateway_ip(),
            "unacked_alerts": store.unacknowledged_count(),
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
    return jsonify(data)


@app.route("/api/alerts")
def api_alerts():
    store = get_store()
    rows = store.alerts(limit=100)
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
                }
                for r in rows
            ]
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


@app.route("/api/devices/trust-all", methods=["POST"])
def api_trust_all():
    n = get_store().trust_all()
    return jsonify({"ok": True, "trusted": n})


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
