"""Turn passive hints (DHCP/mDNS/SSDP/NBNS) into a device's maker, name, role.

Priority for the maker/vendor: real MAC OUI > DHCP vendor-class > mDNS/SSDP
service > hostname keyword. Names come from DHCP hostname or the mDNS instance
name. This never touches a user-set ``label`` — only the derived
``hostname``/``vendor`` fields.
"""

from __future__ import annotations

import re
from typing import Iterable, Optional

from .vendors import infer_vendor, vendor_for


def group_key(
    label: Optional[str] = None,
    hostname: Optional[str] = None,
    owner: Optional[str] = None,
    mac: Optional[str] = None,
) -> str:
    """A key that collapses the same physical device's multiple (randomized)
    MACs into one logical device.

    Priority: explicit ``owner`` > normalized name (label/hostname, alnum-only,
    ``.lan`` stripped) > the MAC itself (its own group). Normalizing to
    alnum-only lets a label ("Nacha's Galaxy S26 Ultra") and its reverse-DNS
    hostname ("Nacha-s-Galaxy-S26-Ultra.lan") land in the same group.
    """
    if owner and owner.strip():
        return "owner:" + owner.strip().lower()
    # Only merge by name for RANDOMIZED (locally-administered) MACs — those are
    # a phone cycling its MAC. Global/real-OUI MACs are distinct physical
    # devices and must never merge just because they share a manual label.
    randomized = False
    if mac:
        try:
            randomized = bool(int(mac[:2], 16) & 0x02)
        except ValueError:
            randomized = False
    if randomized:
        base = (label or hostname or "").lower()
        if base.endswith(".lan"):
            base = base[: -len(".lan")]
        norm = re.sub(r"[^a-z0-9]", "", base)
        if norm:
            return norm
    return (mac or "").upper()

# mDNS service type -> (maker or None, human role)
_MDNS_SERVICES: dict[str, tuple[Optional[str], str]] = {
    "_googlecast._tcp": ("Google", "Chromecast / Google TV"),
    "_googlezone._tcp": ("Google", "Google device"),
    "_airplay._tcp": ("Apple", "AirPlay device"),
    "_raop._tcp": ("Apple", "AirPlay audio"),
    "_companion-link._tcp": ("Apple", "Apple device"),
    "_hap._tcp": (None, "HomeKit accessory"),
    "_amzn-alexa._tcp": ("Amazon", "Alexa device"),
    "_amzn-wplay._tcp": ("Amazon", "Amazon device"),
    "_spotify-connect._tcp": (None, "Spotify Connect"),
    "_printer._tcp": (None, "Printer"),
    "_ipp._tcp": (None, "Printer"),
    "_pdl-datastream._tcp": (None, "Printer"),
    "_axis-video._tcp": ("Axis", "Camera"),
    "_reolink._tcp": ("Reolink", "Camera"),
    "_roku._tcp": ("Roku", "Streaming TV"),
    "_rsp._tcp": ("Roku", "Streaming TV"),
    "_sonos._tcp": ("Sonos", "Speaker"),
    "_nvstream._tcp": ("NVIDIA", "GameStream host"),
    "_smb._tcp": (None, "File server"),
    "_ssh._tcp": (None, "SSH host"),
}

# DHCP vendor-class substring (lowercased) -> maker / OS
_DHCP_VENDOR_CLASS: list[tuple[str, str]] = [
    ("android-dhcp", "Android"),
    ("msft ", "Windows"),
    ("dhcpcd", "Linux/IoT"),
    ("udhcp", "Linux/IoT"),
    ("ubnt", "Ubiquiti"),
    ("amazon", "Amazon"),
    ("google", "Google"),
    ("ring", "Ring"),
    ("reolink", "Reolink"),
    ("espressif", "Espressif (ESP IoT)"),
    ("tuya", "Tuya (smart home)"),
    ("roku", "Roku"),
]

# SSDP SERVER header substring (lowercased) -> maker
_SSDP_SERVER: list[tuple[str, str]] = [
    ("roku", "Roku"),
    ("ring", "Ring"),
    ("reolink", "Reolink"),
    ("samsung", "Samsung"),
    ("lg ", "LG"),
    ("sonos", "Sonos"),
    ("xbox", "Microsoft"),
]

_UNKNOWN = ("", "Unknown", "Private", None)


def _hint_map(hints: Iterable) -> dict[tuple[str, str], str]:
    """Index hint rows/tuples as {(source, key): value}. mDNS services collapse
    to key 'service' but there can be several — keep them under distinct keys."""
    out: dict[tuple[str, str], str] = {}
    for h in hints:
        source, key, value = h["source"], h["key"], h["value"]
        out[(source, key)] = value
    return out


def derive(mac: str, hostname: Optional[str], hints: Iterable) -> dict:
    """Return the best {vendor, hostname, role, sources} for a device."""
    hm = _hint_map(hints)
    sources: list[str] = []

    # --- vendor ---
    vendor = vendor_for(mac)
    if vendor in _UNKNOWN:
        vendor = None
        vc = hm.get(("dhcp", "vendor_class"), "").lower()
        for needle, maker in _DHCP_VENDOR_CLASS:
            if needle in vc:
                vendor = f"{maker} (DHCP)"
                sources.append("DHCP vendor-class")
                break
        if not vendor:
            svc = hm.get(("mdns", "service"), "")
            info = _MDNS_SERVICES.get(svc)
            if info and info[0]:
                vendor = f"{info[0]} (mDNS)"
                sources.append("mDNS")
        if not vendor:
            server = hm.get(("ssdp", "server"), "").lower()
            for needle, maker in _SSDP_SERVER:
                if needle in server:
                    vendor = f"{maker} (SSDP)"
                    sources.append("SSDP")
                    break
        if not vendor:
            # fall back to hostname keyword inference (may return Unknown)
            vendor = infer_vendor(mac, hostname)

    # --- role ---
    role = None
    svc = hm.get(("mdns", "service"), "")
    if svc in _MDNS_SERVICES:
        role = _MDNS_SERVICES[svc][1]

    # --- name ---
    name = (
        hm.get(("dhcp", "hostname"))
        or hm.get(("mdns", "name"))
        or hm.get(("nbns", "name"))
    )
    if name:
        sources.append("DHCP hostname" if ("dhcp", "hostname") in hm else "advertised name")

    return {"vendor": vendor, "hostname": name, "role": role, "sources": sources}


def apply_enrichment(store, mac: str) -> bool:
    """Recompute a device's name/vendor from its stored hints; update if better.

    Never overwrites a user ``label``. Returns True if the device row changed.
    """
    dev = store.get_device(mac)
    if not dev:
        return False
    d = derive(mac, dev["hostname"], store.hints_for(mac))
    new_hostname = dev["hostname"] or d["hostname"]
    new_vendor = dev["vendor"] if dev["vendor"] not in _UNKNOWN else d["vendor"]
    if new_hostname == dev["hostname"] and new_vendor == dev["vendor"]:
        return False
    with store._write() as cur:
        cur.execute(
            "UPDATE devices SET hostname = COALESCE(?, hostname), "
            "vendor = COALESCE(?, vendor) WHERE mac = ?",
            (new_hostname, new_vendor, mac.upper()),
        )
    return True
