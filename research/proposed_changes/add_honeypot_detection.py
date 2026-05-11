"""
Proposed addition: Honeypot/Decoy Detection Module
Research topic: Cross-Cutting X6
Date: 2026-03-27

This module provides honeypot and decoy detection capabilities to reduce
false positives in scan results. It combines multiple detection signals:
Shodan Honeyscore, service multiplicity, response timing uniformity,
banner consistency, TCP stack verification, and historical stability.

Integration points:
- After probe.py collects HTTP responses
- After inference.py computes product confidence
- Honeypot assessment can cap or discount product confidence

Dependencies:
- None required (uses stdlib + existing Shodan API client)
- Optional: Shodan API key (for honeyscore + history lookups)
"""

from dataclasses import dataclass, field
from typing import Optional
import statistics
import math


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

@dataclass
class HoneypotAssessment:
    """Assessment of whether a scan target is likely a honeypot."""

    # Shodan-derived signals
    honeyscore: Optional[float] = None  # 0.0-1.0 from Shodan API
    service_count: int = 0              # Total open ports/services on host
    service_protocols: list[str] = field(default_factory=list)

    # Service diversity analysis
    service_diversity_suspicious: bool = False  # Too many diverse protocols

    # Timing analysis
    timing_cv: Optional[float] = None   # Coefficient of variation of TTFB
    timing_uniform: bool = False        # CV < threshold = suspicious

    # Banner consistency
    banner_consistency_issues: list[str] = field(default_factory=list)

    # TCP stack analysis
    tcp_stack_mismatch: bool = False    # TCP fingerprint vs claimed OS

    # Historical analysis (Shodan history)
    banner_age_days: Optional[int] = None  # Days since banner last changed
    static_deployment: bool = False        # Unchanged >180 days

    # Known honeypot software detection
    known_honeypot_signature: Optional[str] = None

    # Network context
    cloud_datacenter: bool = False
    datacenter_provider: Optional[str] = None

    # Overall assessment
    overall_honeypot_probability: float = 0.0
    assessment_notes: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Detection: Shodan Honeyscore
# ---------------------------------------------------------------------------

def query_honeyscore(ip: str, shodan_api) -> Optional[float]:
    """
    Query Shodan's Honeyscore API for a target IP.

    Args:
        ip: Target IP address
        shodan_api: Initialized Shodan API client

    Returns:
        Honeyscore float (0.0-1.0) or None if unavailable.
    """
    # Shodan API: GET https://api.shodan.io/labs/honeyscore/{ip}?key={API_KEY}
    # Returns: float score or "NA"
    try:
        # shodan_api.labs.honeyscore(ip) if using the shodan Python library
        # Fallback: direct HTTP request to the API
        import urllib.request
        import json

        api_key = getattr(shodan_api, 'api_key', None)
        if not api_key:
            return None

        url = f"https://api.shodan.io/labs/honeyscore/{ip}?key={api_key}"
        req = urllib.request.Request(url, headers={"User-Agent": "OpenClawScanner/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = resp.read().decode("utf-8").strip()
            if result == "NA":
                return None
            return float(result)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Detection: Service Multiplicity
# ---------------------------------------------------------------------------

# Protocols expected for a legitimate OpenClaw gateway
EXPECTED_OPENCLAW_PROTOCOLS = {"http", "https", "ssh"}

# Protocols that are suspicious on an OpenClaw host
SUSPICIOUS_PROTOCOLS = {
    "telnet", "ftp", "smtp", "pop3", "imap", "sip", "mqtt",
    "modbus", "s7comm", "bacnet", "dnp3", "enip",  # ICS protocols
    "mysql", "postgres", "redis", "mongodb",         # Database protocols
    "smb", "nfs", "ldap",                            # File/directory protocols
    "vnc", "rdp",                                     # Remote desktop
}


def assess_service_multiplicity(
    open_ports: list[dict],
    max_expected_services: int = 5,
    suspicious_threshold: int = 10,
) -> tuple[int, bool, list[str]]:
    """
    Assess whether a host's service profile is consistent with a real
    OpenClaw gateway or suggests a honeypot.

    Args:
        open_ports: List of dicts with 'port', 'transport', 'product' keys
                    (from Shodan host lookup)
        max_expected_services: Max services expected for real gateway
        suspicious_threshold: Service count that triggers honeypot flag

    Returns:
        Tuple of (service_count, is_suspicious, protocol_list)
    """
    service_count = len(open_ports)
    protocols = []
    suspicious_protocols_found = []

    for svc in open_ports:
        product = (svc.get("product") or "").lower()
        port = svc.get("port", 0)
        transport = svc.get("transport", "tcp")

        # Infer protocol from port/product
        proto = product or f"port-{port}/{transport}"
        protocols.append(proto)

        for sp in SUSPICIOUS_PROTOCOLS:
            if sp in product or sp in proto:
                suspicious_protocols_found.append(f"{sp} (port {port})")

    is_suspicious = (
        service_count >= suspicious_threshold
        or len(suspicious_protocols_found) >= 3
    )

    return service_count, is_suspicious, protocols


# ---------------------------------------------------------------------------
# Detection: Response Timing Uniformity
# ---------------------------------------------------------------------------

def assess_timing_uniformity(
    response_times_ms: list[float],
    cv_threshold: float = 0.10,
    min_samples: int = 5,
) -> tuple[Optional[float], bool]:
    """
    Assess whether response times across different probe paths are
    suspiciously uniform (indicating a honeypot serving from a lookup table).

    Real servers show varied response times because different endpoints
    involve different backend processing. Honeypots often serve all
    responses from the same static handler with near-identical latency.

    Args:
        response_times_ms: List of TTFB measurements (one per probe path)
        cv_threshold: Coefficient of variation below which timing is "uniform"
        min_samples: Minimum number of samples needed for analysis

    Returns:
        Tuple of (coefficient_of_variation, is_uniform)
    """
    # Filter out None/zero values
    valid_times = [t for t in response_times_ms if t and t > 0]

    if len(valid_times) < min_samples:
        return None, False

    mean_time = statistics.mean(valid_times)
    if mean_time <= 0:
        return None, False

    stdev_time = statistics.stdev(valid_times)
    cv = stdev_time / mean_time

    return cv, cv < cv_threshold


# ---------------------------------------------------------------------------
# Detection: Banner Consistency
# ---------------------------------------------------------------------------

# Known OS-to-TTL mappings
OS_TTL_DEFAULTS = {
    "linux": 64,
    "windows": 128,
    "macos": 64,
    "freebsd": 64,
    "solaris": 255,
}

# Known server-to-runtime mappings
SERVER_RUNTIME_MAP = {
    "nginx": "nginx",
    "apache": "apache",
    "express": "node",
    "koa": "node",
    "go": "go",
    "caddy": "go",
}


def check_banner_consistency(
    http_server_header: Optional[str],
    http2_runtime: Optional[str],
    tls_cert_subject: Optional[str],
    claimed_os: Optional[str],
    tcp_ttl: Optional[int],
    jarm_hash: Optional[str],
    known_proxy_jarm_hashes: set[str] = frozenset(),
) -> list[str]:
    """
    Cross-reference signals from multiple fingerprint layers to detect
    inconsistencies that suggest a honeypot or misconfigured emulation.

    Args:
        http_server_header: HTTP Server header value (e.g., "nginx/1.24.0")
        http2_runtime: Detected HTTP/2 runtime (e.g., "go", "node")
        tls_cert_subject: TLS certificate subject CN/O
        claimed_os: OS claimed by Shodan or inferred from banners
        tcp_ttl: Observed TCP TTL value
        jarm_hash: JARM TLS fingerprint
        known_proxy_jarm_hashes: Set of JARM hashes known to be CDN/proxies

    Returns:
        List of inconsistency descriptions (empty = consistent)
    """
    issues = []

    # Check HTTP/2 runtime vs Server header
    if http_server_header and http2_runtime:
        server_lower = http_server_header.lower()
        for server_key, runtime in SERVER_RUNTIME_MAP.items():
            if server_key in server_lower and runtime != http2_runtime:
                issues.append(
                    f"Server header suggests {runtime} but HTTP/2 SETTINGS "
                    f"indicate {http2_runtime}"
                )

    # Check TTL vs claimed OS
    if tcp_ttl and claimed_os:
        os_lower = claimed_os.lower()
        for os_name, expected_ttl in OS_TTL_DEFAULTS.items():
            if os_name in os_lower:
                # Allow ±1 for network hop adjustment
                if abs(tcp_ttl - expected_ttl) > 1:
                    issues.append(
                        f"TCP TTL {tcp_ttl} inconsistent with claimed OS "
                        f"{claimed_os} (expected ~{expected_ttl})"
                    )
                break

    # Check for honeyd-specific TTL (63 = Linux default minus 1 hop)
    if tcp_ttl == 63 and claimed_os and "windows" in claimed_os.lower():
        issues.append(
            "TTL=63 on claimed Windows host suggests honeyd Linux emulation"
        )

    # Check JARM hash against known proxy hashes
    if jarm_hash and jarm_hash in known_proxy_jarm_hashes:
        # Not necessarily a honeypot, but worth noting
        issues.append(
            f"JARM hash matches known CDN/proxy — may not reflect origin server"
        )

    return issues


# ---------------------------------------------------------------------------
# Detection: Historical Stability (Shodan History)
# ---------------------------------------------------------------------------

def assess_banner_stability(
    shodan_history: list[dict],
    stale_threshold_days: int = 180,
) -> tuple[Optional[int], bool]:
    """
    Assess whether a host's Shodan banners have changed over time.
    Static, never-changing banners may indicate a honeypot or abandoned host.

    Args:
        shodan_history: List of Shodan historical banner snapshots
                       (from shodan.host(ip, history=True))
        stale_threshold_days: Days of unchanged banners to flag as stale

    Returns:
        Tuple of (days_since_last_change, is_static)
    """
    if not shodan_history or len(shodan_history) < 2:
        return None, False

    from datetime import datetime

    # Sort by timestamp
    sorted_history = sorted(
        shodan_history,
        key=lambda h: h.get("timestamp", ""),
        reverse=True,
    )

    # Compare most recent banners for changes
    latest = sorted_history[0]
    latest_hash = latest.get("hash", 0)
    latest_ts = latest.get("timestamp", "")

    last_change_ts = latest_ts
    for entry in sorted_history[1:]:
        entry_hash = entry.get("hash", 0)
        if entry_hash != latest_hash:
            last_change_ts = entry.get("timestamp", latest_ts)
            break

    # Calculate days since last change
    try:
        last_change_dt = datetime.fromisoformat(
            last_change_ts.replace("Z", "+00:00")
        )
        now = datetime.now(last_change_dt.tzinfo)
        days_since_change = (now - last_change_dt).days
    except (ValueError, TypeError):
        return None, False

    is_static = days_since_change >= stale_threshold_days
    return days_since_change, is_static


# ---------------------------------------------------------------------------
# Detection: Known Honeypot Signatures
# ---------------------------------------------------------------------------

KNOWN_HONEYPOT_SIGNATURES = {
    # SSH honeypots
    "cowrie": {
        "type": "ssh_banner",
        "patterns": [
            "SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2",  # Cowrie default
            "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13",
        ],
    },
    # HTTP honeypots
    "glastopf": {
        "type": "http_header",
        "patterns": ["Glastopf"],
    },
    "dionaea": {
        "type": "service_emulation",
        "tell": "SMB + HTTP + FTP + MySQL on single host with generic banners",
    },
    # ICS honeypots (unlikely for OpenClaw, but worth checking)
    "conpot": {
        "type": "service_emulation",
        "tell": "Modbus + S7comm + HTTP on single host",
    },
}


def check_known_honeypot_signatures(
    ssh_banner: Optional[str] = None,
    http_headers: Optional[dict] = None,
    service_products: Optional[list[str]] = None,
) -> Optional[str]:
    """
    Check for known honeypot software signatures.

    Returns:
        Name of detected honeypot software, or None.
    """
    # Check SSH banner
    if ssh_banner:
        for sig_name, sig in KNOWN_HONEYPOT_SIGNATURES.items():
            if sig.get("type") == "ssh_banner":
                for pattern in sig.get("patterns", []):
                    if pattern in ssh_banner:
                        return sig_name

    # Check HTTP headers
    if http_headers:
        server = http_headers.get("server", "")
        for sig_name, sig in KNOWN_HONEYPOT_SIGNATURES.items():
            if sig.get("type") == "http_header":
                for pattern in sig.get("patterns", []):
                    if pattern.lower() in server.lower():
                        return sig_name

    return None


# ---------------------------------------------------------------------------
# Combined Assessment
# ---------------------------------------------------------------------------

# Weight each signal contributes to the overall honeypot probability
SIGNAL_WEIGHTS = {
    "honeyscore": 0.35,           # Shodan's algorithm (strongest single signal)
    "service_diversity": 0.20,    # Too many diverse services
    "timing_uniformity": 0.15,    # Suspiciously uniform response times
    "banner_consistency": 0.15,   # Cross-layer contradictions
    "tcp_mismatch": 0.10,         # TCP stack vs claimed OS
    "static_deployment": 0.05,    # Unchanged banners over time
}


def compute_honeypot_probability(assessment: HoneypotAssessment) -> float:
    """
    Combine all honeypot detection signals into a single probability score.

    Uses a weighted evidence combination approach (simplified Dempster-Shafer
    inspired, consistent with the composite scoring framework from Topic X1).

    Returns:
        float between 0.0 (definitely not a honeypot) and 1.0 (definitely a honeypot)
    """
    evidence_scores = {}

    # Shodan honeyscore (direct pass-through)
    if assessment.honeyscore is not None:
        evidence_scores["honeyscore"] = assessment.honeyscore

    # Service diversity
    if assessment.service_diversity_suspicious:
        # Scale based on how many excess services
        excess = max(0, assessment.service_count - 5)
        evidence_scores["service_diversity"] = min(1.0, excess / 15.0)
    elif assessment.service_count > 0:
        evidence_scores["service_diversity"] = 0.0

    # Timing uniformity
    if assessment.timing_cv is not None:
        if assessment.timing_uniform:
            # Lower CV = more suspicious
            evidence_scores["timing_uniformity"] = max(0.0, 1.0 - assessment.timing_cv * 10)
        else:
            evidence_scores["timing_uniformity"] = 0.0

    # Banner consistency
    if assessment.banner_consistency_issues:
        n_issues = len(assessment.banner_consistency_issues)
        evidence_scores["banner_consistency"] = min(1.0, n_issues * 0.3)

    # TCP mismatch
    if assessment.tcp_stack_mismatch:
        evidence_scores["tcp_mismatch"] = 0.8

    # Static deployment
    if assessment.banner_age_days is not None:
        if assessment.static_deployment:
            evidence_scores["static_deployment"] = 0.6
        else:
            evidence_scores["static_deployment"] = 0.0

    # Known honeypot signature (override — if matched, high probability)
    if assessment.known_honeypot_signature:
        return 0.95  # Near-certain honeypot

    if not evidence_scores:
        return 0.0

    # Weighted combination using DS-inspired formula:
    # combined = 1 - product(1 - weight_i * evidence_i)
    product_term = 1.0
    for signal_name, score in evidence_scores.items():
        weight = SIGNAL_WEIGHTS.get(signal_name, 0.1)
        product_term *= (1.0 - weight * score)

    combined = 1.0 - product_term
    return round(min(1.0, max(0.0, combined)), 3)


def assess_honeypot(
    ip: str,
    probe_results: dict,
    shodan_data: Optional[dict] = None,
    shodan_api=None,
    timing_data: Optional[list[float]] = None,
    tcp_fingerprint: Optional[dict] = None,
) -> HoneypotAssessment:
    """
    Perform a comprehensive honeypot assessment for a scan target.

    This is the main entry point. Call after HTTP probing is complete.

    Args:
        ip: Target IP address
        probe_results: Dict of path -> ProbeObservation from probe.py
        shodan_data: Shodan host data (if available from import or API)
        shodan_api: Shodan API client (for honeyscore + history lookups)
        timing_data: List of response times in ms from probing
        tcp_fingerprint: TCP fingerprint data from JA4TScan (if available)

    Returns:
        HoneypotAssessment with all signals and overall probability
    """
    assessment = HoneypotAssessment()

    # 1. Shodan Honeyscore
    if shodan_api:
        assessment.honeyscore = query_honeyscore(ip, shodan_api)
        if assessment.honeyscore and assessment.honeyscore >= 0.5:
            assessment.assessment_notes.append(
                f"Shodan Honeyscore: {assessment.honeyscore} (probable honeypot)"
            )

    # 2. Service multiplicity (from Shodan data)
    if shodan_data and "ports" in shodan_data:
        ports_data = shodan_data.get("data", [])
        count, suspicious, protocols = assess_service_multiplicity(ports_data)
        assessment.service_count = count
        assessment.service_diversity_suspicious = suspicious
        assessment.service_protocols = protocols
        if suspicious:
            assessment.assessment_notes.append(
                f"Host exposes {count} services — excessive for OpenClaw gateway"
            )

    # 3. Timing uniformity
    if timing_data:
        cv, uniform = assess_timing_uniformity(timing_data)
        assessment.timing_cv = cv
        assessment.timing_uniform = uniform
        if uniform:
            assessment.assessment_notes.append(
                f"Response time CV={cv:.3f} — suspiciously uniform across endpoints"
            )

    # 4. Banner consistency
    http_server = None
    http2_runtime = None
    claimed_os = shodan_data.get("os") if shodan_data else None

    # Extract Server header from probe results
    for path, obs in probe_results.items():
        headers = getattr(obs, "headers", {}) or {}
        if "server" in headers:
            http_server = headers["server"]
            break

    issues = check_banner_consistency(
        http_server_header=http_server,
        http2_runtime=http2_runtime,
        tls_cert_subject=None,
        claimed_os=claimed_os,
        tcp_ttl=tcp_fingerprint.get("ttl") if tcp_fingerprint else None,
        jarm_hash=None,
    )
    assessment.banner_consistency_issues = issues
    for issue in issues:
        assessment.assessment_notes.append(f"Inconsistency: {issue}")

    # 5. TCP stack mismatch
    if tcp_fingerprint and claimed_os:
        inferred_os = tcp_fingerprint.get("inferred_os", "")
        if inferred_os and claimed_os:
            if inferred_os.lower() not in claimed_os.lower():
                assessment.tcp_stack_mismatch = True
                assessment.assessment_notes.append(
                    f"TCP stack suggests {inferred_os} but claimed OS is {claimed_os}"
                )

    # 6. Historical stability (from Shodan history)
    if shodan_data and shodan_api:
        try:
            history = shodan_api.host(ip, history=True)
            history_data = history.get("data", [])
            days, static = assess_banner_stability(history_data)
            assessment.banner_age_days = days
            assessment.static_deployment = static
            if static:
                assessment.assessment_notes.append(
                    f"Banner unchanged for {days} days — possible honeypot or abandoned"
                )
        except Exception:
            pass

    # 7. Known honeypot signatures
    ssh_banner = None
    if shodan_data:
        for svc in shodan_data.get("data", []):
            if svc.get("port") == 22:
                ssh_banner = svc.get("data", "").split("\n")[0]
                break

    sig = check_known_honeypot_signatures(
        ssh_banner=ssh_banner,
        http_headers={"server": http_server} if http_server else None,
    )
    assessment.known_honeypot_signature = sig
    if sig:
        assessment.assessment_notes.append(
            f"Known honeypot signature detected: {sig}"
        )

    # 8. Compute overall probability
    assessment.overall_honeypot_probability = compute_honeypot_probability(assessment)

    return assessment


# ---------------------------------------------------------------------------
# New condition types for the rules engine
# ---------------------------------------------------------------------------

NEW_CONDITION_TYPES = {
    "honeyscore_gte": {
        "description": "Shodan honeyscore >= threshold value",
        "example": {"type": "honeyscore_gte", "value": 0.5},
    },
    "service_count_gte": {
        "description": "Total services on host >= threshold",
        "example": {"type": "service_count_gte", "value": 10},
    },
    "timing_cv_lt": {
        "description": "Response time coefficient of variation < threshold (low = suspicious uniformity)",
        "example": {"type": "timing_cv_lt", "value": 0.1},
    },
    "banner_age_gte": {
        "description": "Days since Shodan banner last changed >= threshold",
        "example": {"type": "banner_age_gte", "value": 180},
    },
    "tcp_os_mismatch": {
        "description": "TCP stack fingerprint contradicts claimed OS",
        "example": {"type": "tcp_os_mismatch", "value": True},
    },
    "is_honeypot": {
        "description": "Overall honeypot probability >= threshold",
        "example": {"type": "is_honeypot", "value": 0.5},
    },
}


# ---------------------------------------------------------------------------
# Example fingerprint rules (for openclaw_rules.json)
# ---------------------------------------------------------------------------

EXAMPLE_HONEYPOT_RULES = [
    {
        "id": "probable-honeypot-shodan-flagged",
        "family": "honeypot_detection",
        "label": "Shodan identifies host as probable honeypot",
        "confidence": 0.85,
        "notes": "Shodan's proprietary honeyscore algorithm flags this IP. "
                 "Most effective against standard/default honeypot configs.",
        "all": [
            {"type": "honeyscore_gte", "value": 0.5},
        ],
    },
    {
        "id": "probable-honeypot-service-overload",
        "family": "honeypot_detection",
        "label": "Probable honeypot: excessive service diversity on single host",
        "confidence": 0.70,
        "notes": "Real OpenClaw gateways typically expose 1-3 ports (18789, 22, 443). "
                 "Hosts with 10+ diverse services are likely honeypots.",
        "all": [
            {"type": "service_count_gte", "value": 10},
            {"type": "path_status", "path": "/", "statuses": [200]},
            {"type": "title_contains", "path": "/", "value": "Control"},
        ],
    },
    {
        "id": "probable-honeypot-uniform-timing",
        "family": "honeypot_detection",
        "label": "Probable honeypot: suspiciously uniform response times",
        "confidence": 0.55,
        "notes": "Real servers show varied TTFB across endpoints due to different "
                 "backend processing. CV < 0.1 suggests static response serving.",
        "all": [
            {"type": "timing_cv_lt", "value": 0.1},
            {"type": "title_contains", "path": "/", "value": "Control"},
        ],
    },
    {
        "id": "probable-honeypot-stale-banner",
        "family": "honeypot_detection",
        "label": "Probable honeypot or abandoned: banner unchanged for 6+ months",
        "confidence": 0.45,
        "notes": "Long-static banners suggest either a honeypot frozen at a specific "
                 "version or an abandoned deployment. Either way, worth flagging.",
        "all": [
            {"type": "banner_age_gte", "value": 180},
            {"type": "title_contains", "path": "/", "value": "Control"},
        ],
    },
]


# ---------------------------------------------------------------------------
# CLI flag proposals
# ---------------------------------------------------------------------------

CLI_FLAGS = {
    "--honeypot-check": {
        "description": "Enable honeypot detection analysis",
        "default": False,
        "type": "bool",
    },
    "--exclude-honeypots": {
        "description": "Exclude targets flagged as probable honeypots from results",
        "default": False,
        "type": "bool",
    },
    "--honeypot-threshold": {
        "description": "Minimum honeypot probability to flag/exclude (0.0-1.0)",
        "default": 0.5,
        "type": "float",
    },
}
