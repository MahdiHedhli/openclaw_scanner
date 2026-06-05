from dataclasses import asdict, dataclass
from typing import Any, Dict, Iterable, List, Optional

from .passive_noise import assess_passive_noise


DEFAULT_DISCOVERY_PROBE_PORTS = (18789, 8080, 8443, 9000, 3000, 5000)

KNOWN_CONTROL_TITLES = (
    "OpenClaw Control",
    "Clawdbot Control",
    "Moltbot Control",
)

NAME_INDICATORS = (
    "openclaw",
    "clawbot",
    "clawdbot",
    "moltbot",
)

SENSITIVE_HEADER_NAMES = {
    "authorization",
    "cookie",
    "proxy-authorization",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-access-token",
    "x-csrf-token",
    "x-forwarded-authorization",
    "x-session-token",
    "x-xsrf-token",
}

SENSITIVE_HEADER_FRAGMENTS = (
    "api-key",
    "auth-token",
    "authorization",
    "access-token",
    "session-token",
)


@dataclass(frozen=True)
class DiscoveryQuery:
    id: str
    engine: str
    query: str
    source: str
    confidence: float
    notes: str

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["description"] = self.notes
        data["confidence_weight"] = self.confidence
        data["source_engine"] = self.engine
        return data


BASE_SHODAN_QUERIES = (
    DiscoveryQuery(
        id="shodan-title-openclaw-control",
        engine="shodan",
        query='http.title:"OpenClaw Control"',
        source="http_title",
        confidence=0.82,
        notes="Exact control UI title observed in lab and field captures.",
    ),
    DiscoveryQuery(
        id="shodan-title-clawdbot-control",
        engine="shodan",
        query='http.title:"Clawdbot Control"',
        source="http_title",
        confidence=0.78,
        notes="Clawdbot-branded control UI title; family signal only.",
    ),
    DiscoveryQuery(
        id="shodan-title-moltbot-control",
        engine="shodan",
        query='http.title:"Moltbot Control"',
        source="http_title",
        confidence=0.78,
        notes="Moltbot-branded control UI title; family signal only.",
    ),
    DiscoveryQuery(
        id="shodan-mdns-openclaw-gateway",
        engine="shodan",
        query='product:"mDNS" "_openclaw-gw._tcp.local"',
        source="mdns_service",
        confidence=0.62,
        notes="Passive mDNS gateway service advertisement.",
    ),
    DiscoveryQuery(
        id="shodan-mdns-clawdbot-gateway",
        engine="shodan",
        query='product:"mDNS" "_clawdbot-gw._tcp.local"',
        source="mdns_service",
        confidence=0.60,
        notes="Passive Clawdbot gateway service advertisement.",
    ),
    DiscoveryQuery(
        id="shodan-mdns-moltbot",
        engine="shodan",
        query='product:"mDNS" "_moltbot"',
        source="mdns_service",
        confidence=0.55,
        notes="Passive Moltbot mDNS advertisement.",
    ),
)


def discovery_queries(
    rules: Optional[Dict[str, Any]] = None,
    engine: str = "shodan",
) -> List[DiscoveryQuery]:
    normalized_engine = engine.lower().strip()
    queries: List[DiscoveryQuery] = []
    if normalized_engine == "shodan":
        queries.extend(BASE_SHODAN_QUERIES)
        queries.extend(_favicon_queries_from_rules(rules or {}))
    return queries


def render_discovery_queries(
    queries: Iterable[DiscoveryQuery],
    output_format: str,
) -> str:
    rows = [query.to_dict() for query in queries]
    if output_format in {"json", "ndjson"}:
        import json

        if output_format == "ndjson":
            return "\n".join(json.dumps(row, sort_keys=True) for row in rows)
        return json.dumps(rows, indent=2, sort_keys=True)

    lines = []
    for query in queries:
        lines.append(
            f"{query.id}\n"
            f"  engine: {query.engine}\n"
            f"  query: {query.query}\n"
            f"  source: {query.source}\n"
            f"  confidence: {query.confidence:.2f}\n"
            f"  notes: {query.notes}"
        )
    return "\n\n".join(lines) + ("\n" if lines else "")


def select_discovery_queries(
    query_ids: Iterable[str],
    queries: Iterable[DiscoveryQuery],
) -> List[DiscoveryQuery]:
    by_id = {query.id: query for query in queries}
    selected = []
    missing = []
    for query_id in query_ids:
        if query_id == "all":
            return list(queries)
        query = by_id.get(query_id)
        if query is None:
            missing.append(query_id)
        else:
            selected.append(query)
    if missing:
        known = ", ".join(sorted(by_id))
        raise ValueError(f"unknown discovery query id(s): {', '.join(missing)}; known: {known}")
    return selected


def score_passive_record(record: Dict[str, Any]) -> Dict[str, Any]:
    """Return conservative discovery confidence metadata for a passive record."""
    sources = []
    confidence = 0.0
    http = record.get("http") or {}
    ssl_data = record.get("ssl") or {}
    mdns = record.get("mdns") or {}

    title = _optional_lower(http.get("title") or record.get("title"))
    for known_title in KNOWN_CONTROL_TITLES:
        if title and known_title.lower() in title:
            sources.append(f"http_title:{known_title}")
            confidence = max(confidence, 0.82)
            break

    body_text = "\n".join(
        str(value)
        for value in (
            record.get("data"),
            http.get("html"),
            http.get("body"),
            record.get("product"),
        )
        if value
    ).lower()
    body_markers = sorted(marker for marker in NAME_INDICATORS if marker in body_text)
    if body_markers:
        sources.append("http_body_marker:" + ",".join(body_markers))
        confidence = max(confidence, 0.60)

    favicon_hash = _extract_favicon_hash(http)
    if favicon_hash is not None:
        sources.append(f"favicon_hash:{favicon_hash}")
        confidence = max(confidence, 0.72)

    if _extract_ssl_jarm(ssl_data):
        sources.append("passive_tls_jarm")
        confidence = max(confidence, 0.45)

    tls_names = " ".join(_extract_tls_names(ssl_data)).lower()
    tls_markers = sorted(marker for marker in NAME_INDICATORS if marker in tls_names)
    if tls_markers:
        sources.append("passive_tls_name:" + ",".join(tls_markers))
        confidence = max(confidence, 0.58)

    mdns_text = str(mdns).lower()
    mdns_markers = sorted(marker for marker in NAME_INDICATORS if marker in mdns_text)
    if "_openclaw-gw._tcp.local" in mdns_text or "_clawdbot-gw._tcp.local" in mdns_text:
        mdns_markers.append("gateway")
    if mdns_markers:
        sources.append("mdns:" + ",".join(sorted(set(mdns_markers))))
        confidence = max(confidence, 0.62)

    noise = assess_passive_noise(record)
    if noise.get("passive_noise_downgraded"):
        confidence = min(
            confidence,
            float(noise.get("passive_noise_confidence_cap", confidence)),
        )

    return {
        "discovery_confidence": round(confidence, 2),
        "discovery_sources": sorted(set(sources)),
        **{
            key: value
            for key, value in noise.items()
            if value not in (None, [], {}, "")
        },
    }


def safe_headers(headers: Any) -> Dict[str, str]:
    if not isinstance(headers, dict):
        return {}
    result = {}
    for key, value in headers.items():
        normalized_key = str(key).lower()
        if is_sensitive_header_name(normalized_key):
            continue
        result[normalized_key] = str(value)
    return result


def is_sensitive_header_name(value: Any) -> bool:
    normalized = str(value or "").strip().lower().replace("_", "-")
    if normalized in SENSITIVE_HEADER_NAMES:
        return True
    return any(fragment in normalized for fragment in SENSITIVE_HEADER_FRAGMENTS)


def _favicon_queries_from_rules(rules: Dict[str, Any]) -> List[DiscoveryQuery]:
    hashes = sorted(
        {
            int(condition["value"])
            for condition in _iter_rule_conditions(rules)
            if condition.get("type") == "favicon_hash"
            and _is_intlike(condition.get("value"))
        }
    )
    return [
        DiscoveryQuery(
            id=f"shodan-favicon-{value}",
            engine="shodan",
            query=f"http.favicon.hash:{value}",
            source="favicon_hash",
            confidence=0.72,
            notes="Favicon hash query generated from the active ruleset; family signal only.",
        )
        for value in hashes
    ]


def _iter_rule_conditions(rules: Dict[str, Any]) -> Iterable[Dict[str, Any]]:
    for section in ("fingerprint_rules", "version_rules"):
        for rule in rules.get(section, []) or []:
            for branch in ("all", "any"):
                for condition in rule.get(branch, []) or []:
                    if isinstance(condition, dict):
                        yield condition


def _extract_favicon_hash(http: Dict[str, Any]) -> Optional[int]:
    favicon = http.get("favicon")
    candidates = [http.get("favicon_hash")]
    if isinstance(favicon, dict):
        candidates.extend(
            [
                favicon.get("hash"),
                favicon.get("mmh3"),
                favicon.get("murmurhash3"),
            ]
        )
    else:
        candidates.append(favicon)

    for value in candidates:
        if _is_intlike(value):
            return int(value)
    return None


def _extract_ssl_jarm(ssl_data: Dict[str, Any]) -> Optional[str]:
    value = ssl_data.get("jarm") if isinstance(ssl_data, dict) else None
    if value in (None, ""):
        return None
    return str(value)


def _extract_tls_names(ssl_data: Dict[str, Any]) -> List[str]:
    if not isinstance(ssl_data, dict):
        return []
    cert = ssl_data.get("cert") or {}
    subject = cert.get("subject") or {}
    names = []
    for key in ("CN", "common_name", "commonName"):
        value = subject.get(key)
        if value:
            names.append(str(value))
    san = cert.get("san") or cert.get("names") or cert.get("dns_names") or []
    if isinstance(san, dict):
        san = san.get("dns") or san.get("names") or []
    if isinstance(san, str):
        names.append(san)
    elif isinstance(san, list):
        names.extend(str(value) for value in san if value)
    return names


def _is_intlike(value: Any) -> bool:
    if value in (None, ""):
        return False
    try:
        int(value)
    except (TypeError, ValueError):
        return False
    return True


def _optional_lower(value: Any) -> Optional[str]:
    if value in (None, ""):
        return None
    return str(value).lower()
