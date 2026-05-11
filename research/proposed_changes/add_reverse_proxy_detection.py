"""
Proposed addition: Reverse proxy detection module for OpenClaw Scanner.

This module analyzes existing probe response headers to detect whether the target
is behind a known reverse proxy or CDN. It requires NO additional network requests —
it operates entirely on data already collected by the probe engine.

When a proxy is detected, the scanner should adjust fingerprint confidence:
- Reduce confidence for proxy-influenced signals (Server header, TLS cert, JARM)
- Increase reliance on pass-through signals (page title, JS files, JSON keys, favicon)
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Proxy type enumeration
# ---------------------------------------------------------------------------

class ProxyType(str, Enum):
    CLOUDFLARE = "cloudflare"
    AWS_CLOUDFRONT = "aws_cloudfront"
    AWS_ALB = "aws_alb"
    NGINX = "nginx"
    HAPROXY = "haproxy"
    TRAEFIK = "traefik"
    AKAMAI = "akamai"
    FASTLY = "fastly"
    GENERIC = "generic"
    NONE = "none"


# ---------------------------------------------------------------------------
# Detection result model
# ---------------------------------------------------------------------------

@dataclass
class ProxyDetectionResult:
    detected: bool = False
    proxy_type: ProxyType = ProxyType.NONE
    confidence: float = 0.0
    indicators: List[str] = field(default_factory=list)
    notes: str = ""


# ---------------------------------------------------------------------------
# Known proxy header signatures
# ---------------------------------------------------------------------------

# Each entry: (header_name_lower, value_substring_or_None, proxy_type, confidence_boost)
# value_substring_or_None: if None, presence of the header alone is sufficient
PROXY_HEADER_SIGNATURES: List[Tuple[str, Optional[str], ProxyType, float]] = [
    # Cloudflare
    ("cf-ray", None, ProxyType.CLOUDFLARE, 0.95),
    ("cf-cache-status", None, ProxyType.CLOUDFLARE, 0.90),
    ("cf-connecting-ip", None, ProxyType.CLOUDFLARE, 0.85),
    ("server", "cloudflare", ProxyType.CLOUDFLARE, 0.90),

    # AWS CloudFront
    ("x-amz-cf-id", None, ProxyType.AWS_CLOUDFRONT, 0.95),
    ("x-amz-cf-pop", None, ProxyType.AWS_CLOUDFRONT, 0.90),
    ("x-cache", "cloudfront", ProxyType.AWS_CLOUDFRONT, 0.85),

    # AWS ALB/ELB
    ("x-amzn-trace-id", None, ProxyType.AWS_ALB, 0.80),

    # nginx (as reverse proxy, not origin)
    ("server", "nginx", ProxyType.NGINX, 0.50),  # lower confidence: could be the origin itself
    ("x-nginx-request-id", None, ProxyType.NGINX, 0.75),

    # Traefik
    ("x-traefik-router", None, ProxyType.TRAEFIK, 0.85),

    # Akamai
    ("x-akamai-transformed", None, ProxyType.AKAMAI, 0.90),
    ("server", "akamaighost", ProxyType.AKAMAI, 0.90),
    ("server", "akamai", ProxyType.AKAMAI, 0.85),

    # Fastly
    ("x-served-by", None, ProxyType.FASTLY, 0.70),
    ("x-fastly-request-id", None, ProxyType.FASTLY, 0.90),
    ("server", "fastly", ProxyType.FASTLY, 0.85),

    # Generic proxy indicators (lower confidence, just indicate *some* proxy)
    ("via", None, ProxyType.GENERIC, 0.60),
    ("x-forwarded-for", None, ProxyType.GENERIC, 0.40),
    ("x-forwarded-proto", None, ProxyType.GENERIC, 0.35),
    ("x-real-ip", None, ProxyType.GENERIC, 0.35),
    ("forwarded", None, ProxyType.GENERIC, 0.40),
]


# Known CDN JARM hashes (examples — populate from lab data)
KNOWN_CDN_JARM_HASHES: Dict[str, ProxyType] = {
    # Cloudflare JARM signatures (multiple variants exist)
    # These are placeholder values — real hashes should be derived from lab testing
    # "27d27d27d0000001dc41d43d00041d...": ProxyType.CLOUDFLARE,
    # "27d3ed3ed0003ed00042d43d00041d...": ProxyType.CLOUDFLARE,
}


# ---------------------------------------------------------------------------
# Detection function
# ---------------------------------------------------------------------------

def detect_proxy(
    observations: Dict[str, "ProbeObservation"],  # type: ignore[name-defined]
    jarm_hash: Optional[str] = None,
) -> ProxyDetectionResult:
    """
    Analyze probe observations to detect reverse proxy presence.

    This function examines all response headers across all probed paths.
    It does NOT make additional network requests.

    Args:
        observations: Dict of path -> ProbeObservation from the probe engine.
        jarm_hash: Optional JARM hash if --jarm was used.

    Returns:
        ProxyDetectionResult with detection outcome and indicators.
    """
    indicators: List[str] = []
    proxy_scores: Dict[ProxyType, float] = {}

    # Check all response headers across all probe paths
    for path, obs in observations.items():
        for header_name, value_substring, proxy_type, confidence in PROXY_HEADER_SIGNATURES:
            header_value = obs.headers.get(header_name, "")
            if not header_value:
                continue

            if value_substring is None or value_substring.lower() in header_value.lower():
                indicator = f"{path}: {header_name}={header_value[:80]}"
                if indicator not in indicators:
                    indicators.append(indicator)

                current = proxy_scores.get(proxy_type, 0.0)
                proxy_scores[proxy_type] = max(current, confidence)

    # Check JARM against known CDN signatures
    if jarm_hash and jarm_hash in KNOWN_CDN_JARM_HASHES:
        proxy_type = KNOWN_CDN_JARM_HASHES[jarm_hash]
        indicators.append(f"JARM hash matches known {proxy_type.value} signature")
        current = proxy_scores.get(proxy_type, 0.0)
        proxy_scores[proxy_type] = max(current, 0.92)

    # Check for TLS/HTTP layer mismatch (Server header says one thing, content says another)
    # This is a heuristic: if Server says "cloudflare" but title says "OpenClaw Control",
    # that's a strong proxy indicator
    server_values = set()
    title_values = set()
    for obs in observations.values():
        if "server" in obs.headers:
            server_values.add(obs.headers["server"].lower())
        if obs.title:
            title_values.add(obs.title.lower())

    product_keywords = {"openclaw", "clawdbot", "moltbot", "claw gateway"}
    proxy_server_names = {"cloudflare", "nginx", "akamai", "fastly", "haproxy"}

    has_product_title = any(
        kw in title for title in title_values for kw in product_keywords
    )
    has_proxy_server = any(
        ps in sv for sv in server_values for ps in proxy_server_names
    )

    if has_product_title and has_proxy_server:
        indicators.append("Server header indicates proxy but content shows OpenClaw product")
        # Boost the detected proxy type or add generic
        for sv in server_values:
            for ps in proxy_server_names:
                if ps in sv:
                    for _, _, pt, _ in PROXY_HEADER_SIGNATURES:
                        if pt.value == ps:
                            current = proxy_scores.get(pt, 0.0)
                            proxy_scores[pt] = max(current, 0.75)
                            break

    if not proxy_scores:
        return ProxyDetectionResult(detected=False, proxy_type=ProxyType.NONE)

    # Pick the highest-confidence proxy type (prefer specific over generic)
    best_type = ProxyType.NONE
    best_score = 0.0
    for pt, score in proxy_scores.items():
        if pt == ProxyType.GENERIC and score <= best_score:
            continue  # prefer specific types over generic
        if score > best_score or (score == best_score and pt != ProxyType.GENERIC):
            best_type = pt
            best_score = score

    notes_parts = []
    if best_type != ProxyType.NONE:
        notes_parts.append(
            f"Detected {best_type.value} reverse proxy with {best_score:.0%} confidence."
        )
        notes_parts.append(
            "TLS-layer signals (JARM, cert) may reflect the proxy rather than the origin."
        )
        notes_parts.append(
            "Content-layer signals (title, JS files, JSON keys, favicon) remain reliable."
        )

    return ProxyDetectionResult(
        detected=True,
        proxy_type=best_type,
        confidence=best_score,
        indicators=indicators,
        notes=" ".join(notes_parts),
    )


# ---------------------------------------------------------------------------
# Confidence adjustment utility
# ---------------------------------------------------------------------------

# Signals that are typically altered by reverse proxies
PROXY_AFFECTED_SIGNALS = {
    "server_header",
    "tls_cert",
    "jarm_hash",
    "header_order",      # proxy may reorder headers
}

# Signals that typically pass through reverse proxies unchanged
PROXY_PASSTHROUGH_SIGNALS = {
    "page_title",
    "js_files",
    "json_keys",
    "body_markers",
    "body_hash",
    "favicon_hash",
    "error_text",
    "version_hints",
}


def adjust_confidence_for_proxy(
    base_confidence: float,
    signal_type: str,
    proxy_result: ProxyDetectionResult,
) -> float:
    """
    Adjust a fingerprint confidence score based on proxy detection.

    For proxy-affected signals, reduce confidence proportionally.
    For pass-through signals, no adjustment needed.
    """
    if not proxy_result.detected:
        return base_confidence

    if signal_type in PROXY_AFFECTED_SIGNALS:
        # Reduce confidence based on how confident we are about the proxy
        reduction = proxy_result.confidence * 0.5  # up to 50% reduction
        return max(0.1, base_confidence - reduction)

    # Pass-through signals are unaffected
    return base_confidence
