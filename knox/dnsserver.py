"""Knox DNS-logging resolver (Pi-hole-lite).

A forwarding UDP DNS server: it parses the queried domain (for per-device
logging), forwards the raw query to an upstream resolver, and relays the raw
answer back. Point your router's DHCP DNS at this host and every device's
lookups are logged per-device — no port mirroring needed.

Binding port 53 requires admin on Windows. For testing, set KNOX_DNS_PORT to a
high port and query it directly.
"""

from __future__ import annotations

import logging
import socket
import socketserver
import threading
from typing import Callable, Optional

from . import config
from .store import Store

log = logging.getLogger("knox.dns")

# Query-type numbers we bother logging (address-ish lookups = real websites).
_LOG_QTYPES = {1, 28, 65}  # A, AAAA, HTTPS


def parse_question(data: bytes):
    """Return (qname, qtype) from a DNS query packet, or (None, None)."""
    try:
        if len(data) < 12:
            return None, None
        qdcount = int.from_bytes(data[4:6], "big")
        if qdcount < 1:
            return None, None
        p = 12
        labels = []
        while True:
            if p >= len(data):
                return None, None
            length = data[p]
            p += 1
            if length == 0:
                break
            if length & 0xC0:  # compression pointer — not expected in a question
                return None, None
            labels.append(data[p : p + length].decode("ascii", errors="replace"))
            p += length
        qtype = int.from_bytes(data[p : p + 2], "big") if p + 2 <= len(data) else 0
        return ".".join(labels), qtype
    except Exception:
        return None, None


class _Handler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        client_ip = self.client_address[0]
        srv: "DnsServer" = self.server.knox

        qname, qtype = parse_question(data)
        if qname and qtype in _LOG_QTYPES and not qname.endswith(".arpa"):
            try:
                owner = srv.store.log_dns_query(client_ip, qname.lower())
                if srv.observer:
                    srv.observer(client_ip, owner, qname.lower())
            except Exception:
                log.debug("dns log failed", exc_info=True)

        # Forward the raw query upstream and relay the raw answer back.
        try:
            up = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            up.settimeout(4)
            up.sendto(data, (config.DNS_UPSTREAM, 53))
            resp, _ = up.recvfrom(4096)
            up.close()
            sock.sendto(resp, self.client_address)
        except Exception:
            log.debug("dns forward failed for %s", qname, exc_info=True)


class _UDPServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True


class DnsServer:
    """Threaded forwarding DNS server that logs per-device domain lookups."""

    def __init__(self, store: Optional[Store] = None, observer: Optional[Callable] = None):
        self.store = store or Store()
        self.observer = observer
        self._server: Optional[_UDPServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self) -> bool:
        try:
            self._server = _UDPServer((config.DNS_BIND, config.DNS_PORT), _Handler)
            self._server.knox = self  # share state with handlers
            self._thread = threading.Thread(
                target=self._server.serve_forever, name="knox-dns", daemon=True
            )
            self._thread.start()
            log.info(
                "DNS resolver on %s:%s -> upstream %s",
                config.DNS_BIND, config.DNS_PORT, config.DNS_UPSTREAM,
            )
            return True
        except PermissionError:
            log.warning("DNS resolver needs admin to bind port %s", config.DNS_PORT)
            return False
        except OSError as e:
            log.warning("could not bind DNS resolver on %s:%s: %s",
                        config.DNS_BIND, config.DNS_PORT, e)
            return False

    def stop(self) -> None:
        if self._server is not None:
            try:
                self._server.shutdown()
                self._server.server_close()
            except Exception:
                pass
            self._server = None
