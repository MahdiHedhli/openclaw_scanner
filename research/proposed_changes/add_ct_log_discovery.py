"""
Proposed addition: Certificate Transparency log monitoring for passive OpenClaw discovery.

Research date: 2026-03-27
Topic: Cross-cutting X4

This module provides three CT-based discovery mechanisms:
1. crt.sh JSON API queries for batch subdomain discovery
2. CertStream real-time WebSocket monitoring for new certificate detection
3. crt.sh Atom/RSS feed polling for lightweight continuous monitoring

Dependencies:
- stdlib only for crt.sh API queries (urllib)
- Optional: certstream (pip install certstream) for real-time monitoring
- Optional: feedparser (pip install feedparser) for RSS feed polling

Integration: This is a target discovery module — it produces candidate
hostnames/IPs for the existing probe engine, not a fingerprinting layer.
"""

import json
import re
import socket
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class CTCertificateRecord:
    """A single certificate record from CT logs."""
    id: Optional[int] = None
    issuer_ca_id: Optional[int] = None
    issuer_name: Optional[str] = None
    common_name: Optional[str] = None
    name_value: Optional[str] = None  # SAN entries, newline-separated
    not_before: Optional[str] = None
    not_after: Optional[str] = None
    serial_number: Optional[str] = None
    entry_timestamp: Optional[str] = None


@dataclass
class CTDiscoveryResult:
    """Aggregated results from a CT log discovery sweep."""
    query: str
    source: str  # "crt.sh", "certstream", "rss"
    timestamp: str
    certificates: List[CTCertificateRecord] = field(default_factory=list)
    unique_domains: Set[str] = field(default_factory=set)
    resolved_ips: Dict[str, List[str]] = field(default_factory=dict)  # domain -> [IPs]
    errors: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Default keyword patterns for OpenClaw detection
# ---------------------------------------------------------------------------

DEFAULT_CT_KEYWORDS = [
    "openclaw",
    "clawdbot",
    "moltbot",
    "claw-gw",
    "openclaw-gw",
    "moltbot-gw",
    "clawdbot-gw",
]

# Pattern to extract individual domain names from SAN name_value fields
DOMAIN_SPLIT_RE = re.compile(r"[\s\n]+")

# Filter out wildcard-only entries and non-FQDN entries
VALID_DOMAIN_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$")


# ---------------------------------------------------------------------------
# 1. crt.sh JSON API discovery
# ---------------------------------------------------------------------------

CRT_SH_API = "https://crt.sh/"
CRT_SH_TIMEOUT = 30  # seconds


def query_crtsh(
    keyword: str,
    timeout: float = CRT_SH_TIMEOUT,
    deduplicate: bool = True,
    exclude_expired: bool = True,
) -> CTDiscoveryResult:
    """
    Query crt.sh JSON API for certificates matching a keyword.

    Args:
        keyword: Search term (e.g., "openclaw"). Will be wrapped in %keyword%.
        timeout: HTTP request timeout in seconds.
        deduplicate: If True, request deduplicated results from crt.sh.
        exclude_expired: If True, request only currently valid certificates.

    Returns:
        CTDiscoveryResult with discovered certificates and extracted domains.
    """
    result = CTDiscoveryResult(
        query=keyword,
        source="crt.sh",
        timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    )

    # Build query URL
    params = f"q=%25{quote(keyword)}%25&output=json"
    if deduplicate:
        params += "&deduplicate=Y"
    if exclude_expired:
        params += "&exclude=expired"
    url = f"{CRT_SH_API}?{params}"

    try:
        req = Request(url, headers={"User-Agent": "OpenClawScanner/CT-Discovery"})
        with urlopen(req, timeout=timeout) as response:
            raw = response.read()
            data = json.loads(raw)
    except (HTTPError, URLError, json.JSONDecodeError, Exception) as exc:
        result.errors.append(f"crt.sh query failed for '{keyword}': {exc}")
        return result

    if not isinstance(data, list):
        result.errors.append(f"Unexpected crt.sh response type: {type(data)}")
        return result

    for entry in data:
        cert = CTCertificateRecord(
            id=entry.get("id"),
            issuer_ca_id=entry.get("issuer_ca_id"),
            issuer_name=entry.get("issuer_name"),
            common_name=entry.get("common_name"),
            name_value=entry.get("name_value"),
            not_before=entry.get("not_before"),
            not_after=entry.get("not_after"),
            serial_number=entry.get("serial_number"),
            entry_timestamp=entry.get("entry_timestamp"),
        )
        result.certificates.append(cert)

        # Extract domains from name_value (SAN entries)
        if cert.name_value:
            for name in DOMAIN_SPLIT_RE.split(cert.name_value):
                name = name.strip().lstrip("*.")
                if name and VALID_DOMAIN_RE.match(name):
                    result.unique_domains.add(name.lower())

        # Extract domain from common_name
        if cert.common_name:
            cn = cert.common_name.strip().lstrip("*.")
            if cn and VALID_DOMAIN_RE.match(cn):
                result.unique_domains.add(cn.lower())

    return result


def discover_via_crtsh(
    keywords: Optional[List[str]] = None,
    timeout: float = CRT_SH_TIMEOUT,
    delay_between_queries: float = 2.0,
    resolve_dns: bool = False,
) -> CTDiscoveryResult:
    """
    Run CT discovery across multiple keywords via crt.sh.

    Args:
        keywords: List of search terms. Defaults to DEFAULT_CT_KEYWORDS.
        timeout: HTTP timeout per query.
        delay_between_queries: Seconds to wait between queries (rate limiting).
        resolve_dns: If True, resolve discovered domains to IP addresses.

    Returns:
        Merged CTDiscoveryResult with all findings.
    """
    if keywords is None:
        keywords = DEFAULT_CT_KEYWORDS

    merged = CTDiscoveryResult(
        query=", ".join(keywords),
        source="crt.sh",
        timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    )

    for i, keyword in enumerate(keywords):
        if i > 0:
            time.sleep(delay_between_queries)

        result = query_crtsh(keyword, timeout=timeout)
        merged.certificates.extend(result.certificates)
        merged.unique_domains.update(result.unique_domains)
        merged.errors.extend(result.errors)

    if resolve_dns:
        merged.resolved_ips = _resolve_domains(merged.unique_domains)

    return merged


# ---------------------------------------------------------------------------
# 2. CertStream real-time monitoring
# ---------------------------------------------------------------------------

def start_certstream_monitor(
    callback: Callable[[str, CTCertificateRecord], None],
    keywords: Optional[List[str]] = None,
    certstream_url: str = "wss://certstream.calidog.io/",
) -> None:
    """
    Start a CertStream WebSocket monitor that filters for OpenClaw-related certificates.

    Requires: pip install certstream

    Args:
        callback: Function called with (matched_keyword, cert_record) for each match.
        keywords: Keywords to filter on. Defaults to DEFAULT_CT_KEYWORDS.
        certstream_url: CertStream WebSocket URL.

    Raises:
        ImportError if certstream library is not installed.
    """
    try:
        import certstream  # type: ignore
    except ImportError:
        raise ImportError(
            "CertStream monitoring requires the 'certstream' package. "
            "Install with: pip install certstream"
        )

    if keywords is None:
        keywords = DEFAULT_CT_KEYWORDS

    keyword_patterns = [kw.lower() for kw in keywords]

    def _on_message(message: Dict[str, Any], context: Any) -> None:
        if message.get("message_type") != "certificate_update":
            return

        data = message.get("data", {})
        leaf = data.get("leaf_cert", {})
        all_domains = leaf.get("all_domains", [])
        subject = leaf.get("subject", {})

        # Check all domains (SANs + CN) against keywords
        searchable = " ".join(str(d).lower() for d in all_domains)
        if subject.get("CN"):
            searchable += " " + str(subject["CN"]).lower()

        for keyword in keyword_patterns:
            if keyword in searchable:
                cert = CTCertificateRecord(
                    common_name=subject.get("CN"),
                    name_value="\n".join(str(d) for d in all_domains),
                    issuer_name=str(leaf.get("issuer", {}).get("O", "")),
                    not_before=leaf.get("not_before"),
                    not_after=leaf.get("not_after"),
                    serial_number=leaf.get("serial_number"),
                )
                callback(keyword, cert)
                break  # Only fire once per certificate

    certstream.listen_for_events(_on_message, url=certstream_url)


# ---------------------------------------------------------------------------
# 3. crt.sh Atom/RSS feed polling
# ---------------------------------------------------------------------------

CRT_SH_ATOM_URL = "https://crt.sh/atom"


def build_crtsh_feed_url(keyword: str) -> str:
    """Build a crt.sh Atom feed URL for continuous monitoring."""
    return f"{CRT_SH_ATOM_URL}?q=%25{quote(keyword)}%25"


def poll_crtsh_feeds(
    keywords: Optional[List[str]] = None,
) -> Dict[str, str]:
    """
    Return a dict of keyword -> Atom feed URL for RSS reader integration.

    These URLs can be added to any RSS reader or polled with feedparser
    for lightweight continuous monitoring without WebSocket dependencies.
    """
    if keywords is None:
        keywords = DEFAULT_CT_KEYWORDS

    return {kw: build_crtsh_feed_url(kw) for kw in keywords}


# ---------------------------------------------------------------------------
# DNS resolution helper
# ---------------------------------------------------------------------------

def _resolve_domains(
    domains: Set[str],
    timeout: float = 5.0,
) -> Dict[str, List[str]]:
    """Resolve a set of domains to IP addresses."""
    resolved: Dict[str, List[str]] = {}
    original_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)

    try:
        for domain in sorted(domains):
            try:
                ips = [info[4][0] for info in socket.getaddrinfo(domain, None)]
                resolved[domain] = sorted(set(ips))
            except (socket.gaierror, socket.timeout, OSError):
                resolved[domain] = []
    finally:
        socket.setdefaulttimeout(original_timeout)

    return resolved


# ---------------------------------------------------------------------------
# CLI integration sketch
# ---------------------------------------------------------------------------

PROPOSED_CLI_FLAGS = """
Proposed CLI flags for CT log discovery:

  --ct-discover           Run a crt.sh batch discovery sweep and output candidate targets.
                          Queries crt.sh for certificates matching OpenClaw keywords.

  --ct-keywords LIST      Comma-separated keywords for CT search (default: openclaw,clawdbot,moltbot,...)

  --ct-resolve            Resolve discovered domains to IP addresses for active scanning.

  --certstream            Start real-time CertStream monitoring mode (requires 'certstream' package).
                          Streams newly issued certificates matching OpenClaw keywords.

  --ct-feeds              Output Atom/RSS feed URLs for continuous monitoring in external RSS readers.

Example workflow:
  # Discover targets via CT logs, resolve to IPs, then scan
  openclaw-scanner --ct-discover --ct-resolve --output ct_targets.json
  openclaw-scanner --targets ct_targets.json --probe

  # Real-time monitoring (long-running)
  openclaw-scanner --certstream --output new_deployments.jsonl
"""


# ---------------------------------------------------------------------------
# Self-signed certificate detection signal
# ---------------------------------------------------------------------------

def is_likely_default_openclaw_cert(cert_info: Dict[str, Any]) -> bool:
    """
    Heuristic to detect OpenClaw's auto-generated self-signed certificates.

    OpenClaw generates self-signed certs by default. Key signals:
    - Self-signed (issuer == subject)
    - Short validity period (often 365 days or less)
    - Generic subject fields (no organization, common name may be hostname or IP)

    This complements Topic #2 (TLS certificate fingerprinting) by identifying
    default/unconfigured deployments that are MORE likely to be vulnerable.
    """
    subject = cert_info.get("subject", {})
    issuer = cert_info.get("issuer", {})

    # Self-signed check
    if subject == issuer:
        return True

    # Common auto-generated patterns
    cn = str(subject.get("CN", "")).lower()
    if cn in ("localhost", "127.0.0.1", "0.0.0.0"):
        return True
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", cn):
        return True  # IP address as CN = likely auto-generated

    return False
