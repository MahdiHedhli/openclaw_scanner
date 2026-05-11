"""
Proposed enhancement: Improved Shodan banner field extraction

This module shows how to extend the scanner's Shodan import to extract
additional banner properties for richer offline detection and pivot-based
discovery.

Date: 2026-03-23
Topic: #8 Banner grabbing improvements
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# New model: Extended Shodan banner metadata
# ---------------------------------------------------------------------------

@dataclass
class ShodanBannerMeta:
    """
    Extended metadata extracted from a Shodan banner beyond what the scanner
    currently captures.  These fields enable pivot-based discovery (finding
    more instances from one confirmed hit) and richer offline fingerprinting.
    """

    # --- Core identifiers ---
    ip_str: str = ""
    port: int = 0
    transport: str = "tcp"

    # --- Shodan product detection ---
    product: Optional[str] = None          # Shodan's own product label
    version: Optional[str] = None          # Shodan-detected version string
    cpe: List[str] = field(default_factory=list)  # CPE identifiers
    os: Optional[str] = None               # Detected operating system

    # --- Hash-based pivots ---
    banner_hash: Optional[int] = None      # hash of raw banner data
    html_hash: Optional[int] = None        # http.html_hash
    headers_hash: Optional[int] = None     # http.headers_hash
    favicon_hash: Optional[int] = None     # http.favicon.hash
    robots_hash: Optional[int] = None      # http.robots_hash

    # --- HTTP properties ---
    http_title: Optional[str] = None       # http.title
    http_server: Optional[str] = None      # http.server (Server header)
    http_status: Optional[int] = None      # http.status
    http_components: Dict[str, Any] = field(default_factory=dict)  # detected web tech
    http_waf: Optional[str] = None         # detected WAF

    # --- SSL/TLS properties ---
    ssl_cert_subject_cn: Optional[str] = None
    ssl_cert_issuer_o: Optional[str] = None
    ssl_cert_fingerprint: Optional[str] = None
    ssl_cert_serial: Optional[str] = None
    ssl_cert_pubkey_bits: Optional[int] = None
    ssl_cert_pubkey_type: Optional[str] = None
    ssl_cert_expired: Optional[bool] = None
    ssl_versions: List[str] = field(default_factory=list)
    ssl_cipher: Optional[str] = None
    ssl_jarm: Optional[str] = None

    # --- Shodan vulnerability detection ---
    vulns: List[str] = field(default_factory=list)  # CVE IDs flagged by Shodan

    # --- Network context ---
    org: Optional[str] = None
    asn: Optional[str] = None
    hostnames: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)

    # --- Internal Shodan metadata ---
    shodan_module: Optional[str] = None    # _shodan.module


def extract_banner_meta(banner: Dict[str, Any]) -> ShodanBannerMeta:
    """
    Extract extended metadata from a raw Shodan banner dict.

    Usage:
        import json
        with open("shodan_export.json") as f:
            for line in f:
                banner = json.loads(line)
                meta = extract_banner_meta(banner)
    """
    http = banner.get("http", {}) or {}
    ssl_data = banner.get("ssl", {}) or {}
    ssl_cert = ssl_data.get("cert", {}) or {}
    ssl_subject = ssl_cert.get("subject", {}) or {}
    ssl_issuer = ssl_cert.get("issuer", {}) or {}
    ssl_pubkey = ssl_cert.get("pubkey", {}) or {}
    shodan_meta = banner.get("_shodan", {}) or {}
    favicon = http.get("favicon", {}) or {}

    return ShodanBannerMeta(
        # Core identifiers
        ip_str=banner.get("ip_str", ""),
        port=banner.get("port", 0),
        transport=banner.get("transport", "tcp"),

        # Shodan product detection
        product=banner.get("product"),
        version=banner.get("version"),
        cpe=banner.get("cpe", []) or [],
        os=banner.get("os"),

        # Hash-based pivots
        banner_hash=banner.get("hash"),
        html_hash=http.get("html_hash"),
        headers_hash=http.get("headers_hash"),
        favicon_hash=favicon.get("hash"),
        robots_hash=http.get("robots_hash"),

        # HTTP properties
        http_title=http.get("title"),
        http_server=http.get("server"),
        http_status=http.get("status"),
        http_components=http.get("components", {}) or {},
        http_waf=http.get("waf"),

        # SSL/TLS properties
        ssl_cert_subject_cn=ssl_subject.get("CN"),
        ssl_cert_issuer_o=ssl_issuer.get("O"),
        ssl_cert_fingerprint=ssl_cert.get("fingerprint", {}).get("sha256"),
        ssl_cert_serial=str(ssl_cert.get("serial")) if ssl_cert.get("serial") else None,
        ssl_cert_pubkey_bits=ssl_pubkey.get("bits"),
        ssl_cert_pubkey_type=ssl_pubkey.get("type"),
        ssl_cert_expired=ssl_cert.get("expired"),
        ssl_versions=ssl_data.get("versions", []) or [],
        ssl_cipher=ssl_data.get("cipher", {}).get("name") if isinstance(ssl_data.get("cipher"), dict) else None,
        ssl_jarm=ssl_data.get("jarm"),

        # Shodan vulnerability detection
        vulns=list(banner.get("vulns", {}).keys()) if isinstance(banner.get("vulns"), dict) else banner.get("vulns", []) or [],

        # Network context
        org=banner.get("org"),
        asn=banner.get("asn"),
        hostnames=banner.get("hostnames", []) or [],
        domains=banner.get("domains", []) or [],

        # Internal Shodan metadata
        shodan_module=shodan_meta.get("module"),
    )


# ---------------------------------------------------------------------------
# Pivot query generator
# ---------------------------------------------------------------------------

def generate_pivot_queries(meta: ShodanBannerMeta) -> List[str]:
    """
    Given a confirmed OpenClaw banner, generate Shodan search queries
    that can find additional instances of the same deployment.

    Returns a list of Shodan query strings ordered by expected specificity
    (most specific first).
    """
    queries = []

    # Hash-based pivots (most specific — identical content)
    if meta.html_hash and meta.html_hash != 0:
        queries.append(f"http.html_hash:{meta.html_hash}")
    if meta.banner_hash and meta.banner_hash != 0:
        queries.append(f"hash:{meta.banner_hash}")
    if meta.headers_hash and meta.headers_hash != 0:
        queries.append(f"http.headers_hash:{meta.headers_hash}")
    if meta.favicon_hash and meta.favicon_hash != 0:
        queries.append(f"http.favicon.hash:{meta.favicon_hash}")

    # JARM pivot (same TLS stack)
    if meta.ssl_jarm and meta.ssl_jarm != "00000000000000000000000000000000000000000000000000000000000000":
        queries.append(f'ssl.jarm:"{meta.ssl_jarm}"')

    # Certificate pivot
    if meta.ssl_cert_fingerprint:
        queries.append(f'ssl.cert.fingerprint:"{meta.ssl_cert_fingerprint}"')

    # Title-based (broader)
    if meta.http_title:
        for known_title in ["OpenClaw Control", "Clawdbot Control", "Moltbot Control"]:
            if known_title.lower() in meta.http_title.lower():
                queries.append(f'http.title:"{known_title}" port:{meta.port}')
                break

    return queries


# ---------------------------------------------------------------------------
# Platform detection from Shodan OS field
# ---------------------------------------------------------------------------

def detect_platform(meta: ShodanBannerMeta) -> Optional[str]:
    """
    Map Shodan's `os` field to a platform identifier for platform-aware
    CVE correlation.

    Returns: "windows", "macos", "linux", or None if unknown.
    """
    if not meta.os:
        return None

    os_lower = meta.os.lower()
    if "windows" in os_lower:
        return "windows"
    if "mac" in os_lower or "darwin" in os_lower:
        return "macos"
    if "linux" in os_lower or "ubuntu" in os_lower or "debian" in os_lower:
        return "linux"
    return None


# ---------------------------------------------------------------------------
# Cross-reference Shodan vulns with internal CVE database
# ---------------------------------------------------------------------------

def cross_reference_vulns(
    shodan_vulns: List[str],
    rules_vulns: List[dict],
) -> dict:
    """
    Compare Shodan-reported CVEs with the scanner's internal CVE database.

    Returns:
        {
            "confirmed": [...],     # In both Shodan and our DB
            "shodan_only": [...],   # Shodan reports but not in our DB (potential new CVEs)
            "scanner_only": [...],  # In our DB but Shodan doesn't flag
        }
    """
    shodan_set = set(shodan_vulns)
    scanner_set = {v["id"] for v in rules_vulns}

    return {
        "confirmed": sorted(shodan_set & scanner_set),
        "shodan_only": sorted(shodan_set - scanner_set),
        "scanner_only": sorted(scanner_set - shodan_set),
    }
