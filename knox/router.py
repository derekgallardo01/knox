"""Reyee/Ruijie router integration — per-device bandwidth via the local API.

Reverse-engineered from the router's LuCI eweb (ReyeeOS). Flow:
  1. login: AES-encrypt the password (gibberish-aes / OpenSSL AES-256-CBC with
     the firmware key), POST /cgi-bin/luci/api/auth -> session id (sid).
  2. signed RPC: POST /cgi-bin/luci/api/cmd?auth=<sid> a `cmdArr` batch running
     `devSta.get {module: sta_list}`, with two signature headers:
       Content-Accept  = md5(SALT + byteLength(json))
       Contents-Accept = md5(SALT + json)
  3. response: a client list with per-device cumulative `up`/`down` byte
     counters, hostname, IP, SSID, band, rssi.

The RouterPoller polls sta_list on an interval, diffs the byte counters to get
each device's live up/down rate, feeds them into bw_samples (for the existing
bandwidth charts / top-talkers) and a rates table (for the live column), and
enriches the device inventory (MAC -> IP/hostname) from the router's view.

Enabled only when KNOX_ROUTER_PASSWORD is set. Requires `requests` + `pycryptodome`.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import threading
import time
from typing import Optional

from . import config
from .store import Store

log = logging.getLogger("knox.router")

_LOGIN_KEY = "RjYkhwzx$2018!"   # firmware AES passphrase for the login password
_SIGN_SALT = "Web@Rj$2020!"     # request-signing salt


def _md5(s: str) -> str:
    return hashlib.md5(s.encode("utf-8")).hexdigest()


def _evp(passphrase: bytes, salt: bytes, klen: int = 32, ilen: int = 16):
    d = b""
    prev = b""
    while len(d) < klen + ilen:
        prev = hashlib.md5(prev + passphrase + salt).digest()
        d += prev
    return d[:klen], d[klen : klen + ilen]


def _aes_enc(text: str, passphrase: str) -> str:
    """OpenSSL-compatible AES-256-CBC (gibberish-aes) -> base64 'Salted__' blob."""
    from Crypto.Cipher import AES  # pycryptodome

    salt = os.urandom(8)
    key, iv = _evp(passphrase.encode(), salt)
    data = text.encode()
    pad = 16 - len(data) % 16
    data += bytes([pad]) * pad
    ct = AES.new(key, AES.MODE_CBC, iv).encrypt(data)
    return base64.b64encode(b"Salted__" + salt + ct).decode()


def _byte_len(s: str) -> int:
    """Replicates the eweb signature length: 1 per char <=0xFF, 3 per BMP char,
    4 per astral char."""
    t = 0
    for ch in s:
        cp = ord(ch)
        t += 1 if cp <= 0xFF else (3 if cp <= 0xFFFF else 4)
    return t


class ReyeeRouter:
    def __init__(self, url: str, user: str, password: str):
        import requests

        self.base = (url or "").rstrip("/")
        self.user = user or "admin"
        self.password = password
        self.sid: Optional[str] = None
        self.session = requests.Session()
        self.session.verify = False
        try:  # silence the self-signed-cert warning
            import urllib3

            urllib3.disable_warnings()
        except Exception:
            pass

    def login(self) -> bool:
        body = {
            "method": "login",
            "params": {
                "password": _aes_enc(self.password, _LOGIN_KEY).replace("\n", ""),
                "username": self.user,
                "time": str(int(time.time())),
                "encry": True,
                "limit": False,
            },
        }
        try:
            r = self.session.post(
                self.base + "/cgi-bin/luci/api/auth", json=body, timeout=8
            ).json()
        except Exception as e:
            log.warning("router login request failed: %s", e)
            return False
        if r.get("code") == 0 and r.get("data", {}).get("sid"):
            self.sid = r["data"]["sid"]
            return True
        log.warning("router login rejected (code=%s)", r.get("code"))
        return False

    def _signed_post(self, url_mod: str, data: dict):
        body = json.dumps(data, separators=(",", ":"), ensure_ascii=False)
        headers = {
            "Content-Type": "application/json",
            "Content-Accept": _md5(_SIGN_SALT + str(_byte_len(body))),
            "Contents-Accept": _md5(_SIGN_SALT + body),
        }
        url = f"{self.base}/cgi-bin/luci/api/{url_mod}?auth={self.sid}"
        return self.session.post(url, data=body.encode("utf-8"), headers=headers, timeout=12).json()

    def sta_list(self) -> list[dict]:
        """Return the connected-client list (with up/down byte counters)."""
        if not self.sid and not self.login():
            return []
        cmd = {"method": "devSta.get", "params": {"module": "sta_list"}}
        payload = {"method": "cmdArr", "params": {"device": "pc", "params": [cmd]}}
        try:
            j = self._signed_post("cmd", payload)
            if j.get("code") != 0:  # session likely expired — re-login once
                if self.login():
                    j = self._signed_post("cmd", payload)
        except Exception as e:
            log.debug("sta_list failed: %s", e)
            return []
        if not j or j.get("code") != 0:
            return []
        clients: list[dict] = []
        for block in j.get("data", []) or []:
            for c in (block.get("list") or []):
                clients.append(c)
        return clients


class RouterPoller:
    """Polls the router's client list and derives per-device bandwidth."""

    def __init__(self, store: Optional[Store] = None):
        self.store = store or Store()
        self.router = ReyeeRouter(config.ROUTER_URL, config.ROUTER_USER, config.ROUTER_PASSWORD)
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._prev: dict[str, tuple[int, int, float]] = {}  # mac -> (up, down, monotonic)

    def start(self) -> bool:
        if not config.ROUTER_PASSWORD:
            return False
        if not self.router.login():
            log.info("router poller disabled (login failed)")
            return False
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="knox-router", daemon=True)
        self._thread.start()
        log.info("router poller started (%s, every %ss)", config.ROUTER_URL, config.ROUTER_POLL)
        return True

    def stop(self) -> None:
        self._stop.set()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self._poll()
            except Exception:
                log.exception("router poll failed")
            waited = 0
            while waited < config.ROUTER_POLL and not self._stop.is_set():
                time.sleep(1)
                waited += 1

    def _poll(self) -> None:
        now = time.monotonic()
        for c in self.router.sta_list():
            try:
                self._process_client(c, now)
            except Exception:
                log.debug("router client update failed", exc_info=True)

    def _process_client(self, c: dict, now: float) -> None:
        mac = (c.get("mac") or "").upper()
        if not mac:
            return
        try:
            up = int(c.get("up") or 0)
            down = int(c.get("down") or 0)
        except (TypeError, ValueError):
            return
        ip = c.get("userIp") or None
        host = c.get("hostName") or None
        # Enrich inventory from the router's view (also a presence sighting).
        self.store.upsert_device(mac, ip, host, None)

        prev = self._prev.get(mac)
        self._prev[mac] = (up, down, now)
        if prev:
            dt = now - prev[2]
            if dt <= 0:
                return
            d_up = up - prev[0]
            d_down = down - prev[1]
            if d_up < 0:  # counter reset (device reconnected)
                d_up = up
            if d_down < 0:
                d_down = down
            self.store.add_bw_sample(mac, d_up + d_down)
            self.store.set_rate(mac, int(d_down / dt), int(d_up / dt))


def available() -> bool:
    """True if router polling is configured and deps are importable."""
    if not config.ROUTER_PASSWORD:
        return False
    try:
        import requests  # noqa: F401
        from Crypto.Cipher import AES  # noqa: F401

        return True
    except Exception:
        return False
