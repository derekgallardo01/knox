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
