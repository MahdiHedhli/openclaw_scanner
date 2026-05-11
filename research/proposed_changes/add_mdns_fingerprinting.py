"""
Proposed changes: Enhanced mDNS/DNS-SD Service Discovery Fingerprinting
========================================================================
Date: 2026-03-24  (Research Run 5, Topic #9)

Extends the scanner's mDNS metadata extraction from Shodan banners to
capture the full set of fingerprinting signals available in DNS-SD
service advertisements.  Also adds mDNS-based condition types to the
rules engine and example fingerprint rules.

Current state
-------------
The existing _extract_gateway_port() in sources.py only reads:
  - Service names (to extract numeric port prefixes)
  - The "gatewayPort=" TXT record value

This proposal extracts the full mDNS fingerprint surface:
  - Service instance names
  - Service type portfolio
  - All TXT record key-value pairs
  - Hostname patterns
  - Advertised ports

Files affected
--------------
* openclaw_scanner/models.py    — new MdnsFingerprint model
* openclaw_scanner/sources.py   — enhanced mDNS extraction
* openclaw_scanner/inference.py  — new condition types
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set


# ---------------------------------------------------------------------------
# 1.  Model: MdnsFingerprint
# ---------------------------------------------------------------------------

@dataclass
class MdnsFingerprint:
    """Structured representation of mDNS/DNS-SD metadata extracted from
    a Shodan banner's ``mdns`` field.
    """
    # Service types advertised, e.g. {"_openclaw-gw._tcp", "_http._tcp"}
    service_types: Set[str] = field(default_factory=set)

    # Full service instance names, e.g.
    # ["OpenClaw Gateway._openclaw-gw._tcp.local"]
    instance_names: List[str] = field(default_factory=list)

    # Hostname from SRV or mDNS A record, e.g. "openclaw-gw-abc123.local"
    hostname: Optional[str] = None

    # All TXT record key-value pairs aggregated across services,
    # e.g. {"version": "2026.2.14", "gatewayPort": "18789", "model": "openclaw-gw"}
    txt_records: Dict[str, str] = field(default_factory=dict)

    # Ports advertised across all services
    advertised_ports: Set[int] = field(default_factory=set)

    # Version string extracted from TXT records (if present)
    version: Optional[str] = None

    # Product markers found in instance names or TXT values
    product_markers: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# 2.  Extraction function — replaces/extends _extract_gateway_port()
# ---------------------------------------------------------------------------

# Known product markers to search for in mDNS data
MDNS_PRODUCT_MARKERS = [
    "openclaw",
    "clawdbot",
    "moltbot",
    "claw gateway",
    "openclaw-gw",
    "clawdbot-gw",
]

# Regex for service type extraction from Shodan mDNS service keys
# Example key: "18789/OpenClaw Gateway._openclaw-gw._tcp.local"
SERVICE_KEY_RE = re.compile(
    r"^(?:(\d+)/)?(.+)\.(_([\w-]+)\._(?:tcp|udp)\.local)$"
)

# Version pattern in TXT records
VERSION_RE = re.compile(r"^20\d{2}\.\d+\.\d+(?:-[A-Za-z0-9]+)?$")


def extract_mdns_fingerprint(item: dict) -> Optional[MdnsFingerprint]:
    """Extract a full mDNS fingerprint from a Shodan banner dict.

    Parameters
    ----------
    item : dict
        A single Shodan banner object (from JSON export or API).

    Returns
    -------
    MdnsFingerprint or None
        None if the banner has no mDNS data.
    """
    mdns = item.get("mdns") or {}
    services = mdns.get("services") or {}

    if not services:
        return None

    fp = MdnsFingerprint()

    for service_key, service_data in services.items():
        _parse_service_key(service_key, fp)
        _parse_txt_records(service_data, fp)

    # Extract hostname from the mDNS top-level fields if available
    hostname = mdns.get("hostname")
    if hostname:
        fp.hostname = str(hostname).rstrip(".")

    # Try to extract version from TXT records
    for key in ("version", "fw_version", "firmware_version", "sw_version"):
        value = fp.txt_records.get(key)
        if value and VERSION_RE.match(value):
            fp.version = value
            break

    # Detect product markers in instance names and TXT values
    _detect_product_markers(fp)

    return fp


def _parse_service_key(service_key: str, fp: MdnsFingerprint) -> None:
    """Parse a Shodan mDNS service key like
    '18789/OpenClaw Gateway._openclaw-gw._tcp.local' into its components.
    """
    match = SERVICE_KEY_RE.match(service_key)
    if match:
        port_str, instance_name, service_type, _short_type = match.groups()
        if port_str and port_str.isdigit():
            fp.advertised_ports.add(int(port_str))
        fp.instance_names.append(instance_name)
        fp.service_types.add(service_type)
    else:
        # Fallback: try to extract port from simple numeric prefix
        prefix = service_key.split("/", 1)[0]
        if prefix.isdigit():
            fp.advertised_ports.add(int(prefix))
        fp.instance_names.append(service_key)


def _parse_txt_records(service_data: dict, fp: MdnsFingerprint) -> None:
    """Parse TXT record data entries from a Shodan mDNS service."""
    data_entries = service_data.get("data", [])
    for entry in data_entries:
        if not isinstance(entry, str):
            continue
        if "=" in entry:
            key, _, value = entry.partition("=")
            key = key.strip().lower()
            value = value.strip()
            fp.txt_records[key] = value

            # Extract port from gatewayPort
            if key == "gatewayport" and value.isdigit():
                fp.advertised_ports.add(int(value))
        else:
            # Boolean flag (key with no value per RFC 6763 §6.4)
            fp.txt_records[entry.strip().lower()] = ""


def _detect_product_markers(fp: MdnsFingerprint) -> None:
    """Search instance names, TXT values, and service types for known
    product markers.
    """
    search_corpus = " ".join(
        fp.instance_names
        + list(fp.txt_records.values())
        + list(fp.service_types)
    ).lower()

    for marker in MDNS_PRODUCT_MARKERS:
        if marker in search_corpus:
            fp.product_markers.append(marker)


# ---------------------------------------------------------------------------
# 3.  Integration into sources.py — enhanced _extract_gateway_port()
# ---------------------------------------------------------------------------

# The existing function should be refactored to use extract_mdns_fingerprint():
#
# def _extract_gateway_port(item: dict) -> Optional[int]:
#     fp = extract_mdns_fingerprint(item)
#     if fp is None:
#         return None
#     # Return the first advertised port (preferring 18789 if present)
#     if 18789 in fp.advertised_ports:
#         return 18789
#     return next(iter(fp.advertised_ports), None)
#
# The MdnsFingerprint should also be stored on the ScanResult for use
# in fingerprint rule evaluation.


# ---------------------------------------------------------------------------
# 4.  New condition types for inference.py
# ---------------------------------------------------------------------------

def _mdns_service_type(condition: dict, mdns_fp: Optional[MdnsFingerprint]) -> bool:
    """True if the device advertises the specified mDNS service type.

    Rule format:
        {"type": "mdns_service_type", "value": "_openclaw-gw._tcp.local"}
    """
    if mdns_fp is None:
        return False
    target = condition["value"].lower()
    return any(target in st.lower() for st in mdns_fp.service_types)


def _mdns_instance_name_contains(condition: dict, mdns_fp: Optional[MdnsFingerprint]) -> bool:
    """True if any service instance name contains the specified substring.

    Rule format:
        {"type": "mdns_instance_name_contains", "value": "OpenClaw"}
    """
    if mdns_fp is None:
        return False
    needle = condition["value"].lower()
    return any(needle in name.lower() for name in mdns_fp.instance_names)


def _mdns_txt_key_value(condition: dict, mdns_fp: Optional[MdnsFingerprint]) -> bool:
    """True if the TXT records contain the specified key with a value
    matching the pattern.

    Rule format (exact match):
        {"type": "mdns_txt_key_value", "key": "model", "value": "openclaw-gw"}

    Rule format (key exists, any value):
        {"type": "mdns_txt_key_value", "key": "version"}
    """
    if mdns_fp is None:
        return False
    key = condition["key"].lower()
    expected_value = condition.get("value")
    actual = mdns_fp.txt_records.get(key)
    if actual is None:
        return False
    if expected_value is None:
        return True  # key exists, any value accepted
    return expected_value.lower() == actual.lower()


def _mdns_hostname_pattern(condition: dict, mdns_fp: Optional[MdnsFingerprint]) -> bool:
    """True if the mDNS hostname matches the regex pattern.

    Rule format:
        {"type": "mdns_hostname_pattern", "value": "^(openclaw|clawdbot|moltbot)-.*\\.local$"}
    """
    if mdns_fp is None or mdns_fp.hostname is None:
        return False
    pattern = re.compile(condition["value"], re.IGNORECASE)
    return bool(pattern.search(mdns_fp.hostname))


def _mdns_has_version(condition: dict, mdns_fp: Optional[MdnsFingerprint]) -> bool:
    """True if a version string was extracted from mDNS TXT records.

    Rule format:
        {"type": "mdns_has_version"}
    """
    if mdns_fp is None:
        return False
    return mdns_fp.version is not None


def _mdns_port_advertised(condition: dict, mdns_fp: Optional[MdnsFingerprint]) -> bool:
    """True if the specified port is advertised in mDNS SRV records.

    Rule format:
        {"type": "mdns_port_advertised", "value": 18789}
    """
    if mdns_fp is None:
        return False
    return int(condition["value"]) in mdns_fp.advertised_ports


# ---------------------------------------------------------------------------
# 5.  Example fingerprint rules using mDNS conditions
# ---------------------------------------------------------------------------

EXAMPLE_MDNS_RULES = [
    {
        "id": "openclaw-mdns-service-type",
        "family": "openclaw_mdns_confirmed",
        "label": "OpenClaw gateway confirmed via _openclaw-gw._tcp mDNS service type",
        "confidence": 0.97,
        "notes": (
            "The device advertises the custom _openclaw-gw._tcp service type, "
            "which is a definitive product identifier. This service type is "
            "registered exclusively by OpenClaw gateway firmware."
        ),
        "all": [
            {
                "type": "mdns_service_type",
                "value": "_openclaw-gw._tcp.local"
            }
        ]
    },
    {
        "id": "clawdbot-mdns-service-type",
        "family": "clawdbot_mdns_confirmed",
        "label": "Clawdbot gateway confirmed via _clawdbot-gw._tcp mDNS service type",
        "confidence": 0.97,
        "notes": (
            "The device advertises the custom _clawdbot-gw._tcp service type."
        ),
        "all": [
            {
                "type": "mdns_service_type",
                "value": "_clawdbot-gw._tcp.local"
            }
        ]
    },
    {
        "id": "openclaw-mdns-instance-name",
        "family": "openclaw_mdns_instance",
        "label": "OpenClaw gateway identified via mDNS instance name",
        "confidence": 0.92,
        "notes": (
            "The mDNS service instance name contains 'OpenClaw', indicating "
            "the device identifies itself as an OpenClaw gateway."
        ),
        "all": [
            {
                "type": "mdns_instance_name_contains",
                "value": "OpenClaw"
            }
        ]
    },
    {
        "id": "openclaw-mdns-hostname-pattern",
        "family": "openclaw_mdns_hostname",
        "label": "OpenClaw gateway identified via mDNS hostname pattern",
        "confidence": 0.85,
        "notes": (
            "The mDNS hostname matches the openclaw-gw-* naming convention "
            "used by default OpenClaw installations."
        ),
        "all": [
            {
                "type": "mdns_hostname_pattern",
                "value": "^openclaw-gw-"
            },
            {
                "type": "mdns_port_advertised",
                "value": 18789
            }
        ]
    },
    {
        "id": "openclaw-mdns-txt-version",
        "family": "openclaw_mdns_versioned",
        "label": "OpenClaw gateway with version exposed in mDNS TXT records",
        "confidence": 0.95,
        "notes": (
            "The device advertises an OpenClaw service type AND exposes a "
            "version string in its TXT records. This provides both product "
            "identification and exact version information for CVE correlation."
        ),
        "all": [
            {
                "type": "mdns_service_type",
                "value": "_openclaw-gw._tcp.local"
            },
            {
                "type": "mdns_has_version"
            }
        ]
    },
    {
        "id": "openclaw-mdns-model-txt",
        "family": "openclaw_mdns_model",
        "label": "OpenClaw gateway identified via model TXT record",
        "confidence": 0.93,
        "notes": (
            "The mDNS TXT record contains model=openclaw-gw, a strong "
            "product identifier."
        ),
        "all": [
            {
                "type": "mdns_txt_key_value",
                "key": "model",
                "value": "openclaw-gw"
            }
        ]
    },
]


# ---------------------------------------------------------------------------
# 6.  Version extraction integration
# ---------------------------------------------------------------------------

# When an MdnsFingerprint has a .version field, it should be added to the
# version inference pipeline in inference.py as a high-confidence source:
#
# if mdns_fp and mdns_fp.version:
#     matches.append(VersionMatch(
#         version=mdns_fp.version,
#         confidence=0.98,
#         source="mdns_txt_record",
#         notes="Version extracted from mDNS TXT record 'version' key.",
#         exact=True,
#     ))
#
# This is extremely high confidence because the device is self-reporting
# its version in a structured field.


# ---------------------------------------------------------------------------
# 7.  Active mDNS probing (future enhancement)
# ---------------------------------------------------------------------------

# For local network scanning, the scanner could send mDNS queries for
# known OpenClaw service types.  This requires the `zeroconf` library:
#
# pip install zeroconf
#
# Example query:
#
#   from zeroconf import Zeroconf, ServiceBrowser
#
#   class OpenClawListener:
#       def add_service(self, zc, type_, name):
#           info = zc.get_service_info(type_, name)
#           if info:
#               # Extract host, port, TXT records
#               pass
#
#   zc = Zeroconf()
#   browser = ServiceBrowser(zc, "_openclaw-gw._tcp.local.", OpenClawListener())
#   time.sleep(5)  # wait for responses
#   zc.close()
#
# This would be gated behind a --local-scan or --mdns-probe flag and
# would only work on the local network segment (multicast is not routable).
