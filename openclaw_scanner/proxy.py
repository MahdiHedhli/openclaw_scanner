from typing import Dict, Iterable, List, Optional, Tuple

from .models import ProbeObservation, ProxyDetection

GENERIC_PROXY = "generic"

PROXY_HEADER_SIGNATURES: List[Tuple[str, Optional[str], str, float]] = [
    ("cf-ray", None, "cloudflare", 0.95),
    ("cf-cache-status", None, "cloudflare", 0.90),
    ("cf-connecting-ip", None, "cloudflare", 0.85),
    ("server", "cloudflare", "cloudflare", 0.90),
    ("x-amz-cf-id", None, "aws_cloudfront", 0.95),
    ("x-amz-cf-pop", None, "aws_cloudfront", 0.90),
    ("x-cache", "cloudfront", "aws_cloudfront", 0.85),
    ("x-amzn-trace-id", None, "aws_alb", 0.80),
    ("server", "nginx", "nginx", 0.50),
    ("x-nginx-request-id", None, "nginx", 0.75),
    ("x-traefik-router", None, "traefik", 0.85),
    ("x-akamai-transformed", None, "akamai", 0.90),
    ("server", "akamai", "akamai", 0.85),
    ("server", "akamaighost", "akamai", 0.90),
    ("x-fastly-request-id", None, "fastly", 0.90),
    ("x-served-by", None, "fastly", 0.70),
    ("server", "fastly", "fastly", 0.85),
    ("via", None, GENERIC_PROXY, 0.60),
    ("x-forwarded-for", None, GENERIC_PROXY, 0.40),
    ("x-forwarded-proto", None, GENERIC_PROXY, 0.35),
    ("x-real-ip", None, GENERIC_PROXY, 0.35),
    ("forwarded", None, GENERIC_PROXY, 0.40),
]

PRODUCT_TITLES = ("openclaw", "clawdbot", "moltbot", "claw gateway")
PROXY_SERVER_HINTS = ("cloudflare", "nginx", "akamai", "fastly", "haproxy", "traefik")


def detect_proxy(
    observations: Dict[str, ProbeObservation],
    passive_waf: Optional[str] = None,
) -> ProxyDetection:
    indicators: List[str] = []
    scores: Dict[str, float] = {}

    for key, observation in observations.items():
        for header_name, value_substring, proxy_type, confidence in PROXY_HEADER_SIGNATURES:
            header_value = observation.headers.get(header_name, "")
            if not header_value:
                continue
            if value_substring is not None and value_substring.lower() not in header_value.lower():
                continue

            indicator = f"{key}: {header_name}={header_value[:80]}"
            if indicator not in indicators:
                indicators.append(indicator)
            scores[proxy_type] = max(scores.get(proxy_type, 0.0), confidence)

    if passive_waf:
        normalized = _normalize_waf_name(passive_waf)
        indicators.append(f"passive_waf={passive_waf}")
        if normalized:
            scores[normalized] = max(scores.get(normalized, 0.0), 0.90)
        else:
            scores[GENERIC_PROXY] = max(scores.get(GENERIC_PROXY, 0.0), 0.75)

    if _has_proxy_content_mismatch(observations):
        indicators.append("proxy-content mismatch: proxy-like server header with OpenClaw-family UI title")
        best_specific = _best_specific_proxy(scores)
        if best_specific:
            scores[best_specific] = max(scores.get(best_specific, 0.0), 0.75)
        else:
            scores[GENERIC_PROXY] = max(scores.get(GENERIC_PROXY, 0.0), 0.70)

    if not scores:
        return ProxyDetection(detected=False, proxy_type=None, confidence=0.0, indicators=[])

    proxy_type, confidence = _pick_best_proxy(scores)
    notes = (
        f"Detected {proxy_type} reverse-proxy signals. "
        "Content-layer artifacts remain more trustworthy than proxy-influenced transport or server-header signals."
    )
    return ProxyDetection(
        detected=True,
        proxy_type=proxy_type,
        confidence=round(confidence, 2),
        indicators=indicators,
        notes=notes,
    )


def _normalize_waf_name(value: str) -> Optional[str]:
    lowered = value.strip().lower()
    if not lowered:
        return None
    if "cloudflare" in lowered:
        return "cloudflare"
    if "cloudfront" in lowered:
        return "aws_cloudfront"
    if "akamai" in lowered:
        return "akamai"
    if "fastly" in lowered:
        return "fastly"
    if "traefik" in lowered:
        return "traefik"
    if "nginx" in lowered:
        return "nginx"
    return None


def _has_proxy_content_mismatch(observations: Dict[str, ProbeObservation]) -> bool:
    server_values = {
        value.lower()
        for observation in observations.values()
        for key, value in observation.headers.items()
        if key == "server" and value
    }
    titles = [
        observation.title.lower()
        for observation in observations.values()
        if observation.title
    ]

    if not server_values or not titles:
        return False

    has_product_title = any(
        marker in title
        for title in titles
        for marker in PRODUCT_TITLES
    )
    has_proxy_server = any(
        hint in server_value
        for server_value in server_values
        for hint in PROXY_SERVER_HINTS
    )
    return has_product_title and has_proxy_server


def _best_specific_proxy(scores: Dict[str, float]) -> Optional[str]:
    specific = [
        (proxy_type, score)
        for proxy_type, score in scores.items()
        if proxy_type != GENERIC_PROXY
    ]
    if not specific:
        return None
    return max(specific, key=lambda item: item[1])[0]


def _pick_best_proxy(scores: Dict[str, float]) -> Tuple[str, float]:
    ranked: Iterable[Tuple[str, float]] = sorted(
        scores.items(),
        key=lambda item: (item[0] != GENERIC_PROXY, item[1]),
        reverse=True,
    )
    best_type, best_score = next(iter(ranked))
    return best_type, best_score
