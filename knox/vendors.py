"""MAC address -> hardware vendor resolution.

Uses the offline ``mac-vendor-lookup`` OUI database when available so lookups
work without network access. Degrades gracefully to ``"Unknown"`` if the
library isn't installed.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Optional

try:
    from mac_vendor_lookup import MacLookup, VendorNotFoundError

    _lookup: Optional["MacLookup"] = MacLookup()
except Exception:  # pragma: no cover - optional dependency / missing DB
    _lookup = None

    class VendorNotFoundError(Exception):
        pass


@lru_cache(maxsize=4096)
def vendor_for(mac: str) -> str:
    """Return the vendor name for a MAC address, or ``"Unknown"``."""
    if not mac or _lookup is None:
        return "Unknown"
    try:
        return _lookup.lookup(mac)
    except (VendorNotFoundError, KeyError, Exception):
        return "Unknown"


# Hostname keyword -> maker. Used when the MAC is randomized/private so the OUI
# gives no vendor. Order matters: more specific keys first.
_HOSTNAME_VENDORS: list[tuple[tuple[str, ...], str]] = [
    (("iphone", "ipad", "macbook", "apple", "-imac"), "Apple (inferred)"),
    (("pixel", "chromecast", "google-home", "nest"), "Google (inferred)"),
    (("galaxy", "tab-s", "samsung", "-a13", "-a23", "-a53",
      "-s21", "-s22", "-s23", "-s24", "-s25", "-s26"), "Samsung (inferred)"),
    (("oneplus",), "OnePlus (inferred)"),
    (("xbox",), "Microsoft (inferred)"),
    (("roku", "tcl"), "TCL/Roku (inferred)"),
    (("amazon", "echo", "alexa", "blink", "firetv", "fire-"), "Amazon (inferred)"),
    (("reolink",), "Reolink (inferred)"),
    (("kasa", "tp-link", "tplink", "tapo"), "TP-Link (inferred)"),
    (("wyze",), "Wyze (inferred)"),
]

_UNKNOWN = ("", "Unknown", "Private")


def infer_vendor(mac: str, hostname: Optional[str] = None) -> str:
    """Vendor from OUI, falling back to hostname keywords for randomized MACs."""
    v = vendor_for(mac)
    if v not in _UNKNOWN:
        return v
    if hostname:
        h = hostname.lower()
        for keys, name in _HOSTNAME_VENDORS:
            if any(k in h for k in keys):
                return name
    return v
