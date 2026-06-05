from typing import Any, Dict, Iterable, List


OPENCLAW_TOKENS = (
    "openclaw",
    "clawdbot",
    "moltbot",
    "claw gateway",
    "_openclaw-gw._tcp.local",
    "_clawdbot-gw._tcp.local",
)

PRODUCT_SIGNATURES = (
    (
        "ivanti_epmm",
        ("ivanti epmm", "endpoint manager mobile", "mobileiron"),
        0.25,
        "passive product metadata identifies Ivanti EPMM",
    ),
    (
        "sophos_ssl_vpn",
        ("sophos ssl vpn", "sophos user portal", "sophos firewall"),
        0.25,
        "passive product metadata identifies Sophos SSL VPN",
    ),
    (
        "dlink_webcam",
        ("d-link webcam", "dlink webcam", "d-link internet camera", "dcs-"),
        0.25,
        "passive product metadata identifies D-Link webcam",
    ),
    (
        "ncat_proxy",
        ("ncat http proxy", "ncat proxy", "nmap ncat"),
        0.25,
        "passive product metadata identifies Ncat proxy",
    ),
)

SERVER_SIGNATURES = (
    (
        "microsoft_iis",
        ("microsoft-iis", "microsoft iis", "iis httpd"),
        0.45,
        "generic Microsoft IIS banner without OpenClaw evidence",
    ),
    (
        "apache_default",
        (
            "apache httpd",
            "apache/2",
            "apache2 ubuntu default page",
            "it works!",
        ),
        0.45,
        "generic Apache/default-site banner without OpenClaw evidence",
    ),
)


def assess_passive_noise(record: Dict[str, Any]) -> Dict[str, Any]:
    """Return conservative passive false-positive annotations for known products.

    The result is metadata only. It should rank or explain passive candidates,
    not suppress active validation when other strong OpenClaw evidence exists.
    """
    haystacks = _record_haystacks(record)
    joined = "\n".join(haystacks)
    has_openclaw_evidence = any(token in joined for token in OPENCLAW_TOKENS)

    matched_products: List[str] = []
    reasons: List[str] = []
    cap = 1.0

    for product_id, needles, candidate_cap, reason in PRODUCT_SIGNATURES:
        if any(needle in joined for needle in needles):
            matched_products.append(product_id)
            reasons.append(reason)
            cap = min(cap, candidate_cap)

    if not has_openclaw_evidence:
        for product_id, needles, candidate_cap, reason in SERVER_SIGNATURES:
            if any(needle in joined for needle in needles):
                matched_products.append(product_id)
                reasons.append(reason)
                cap = min(cap, candidate_cap)

    if not matched_products:
        return {
            "passive_noise_downgraded": False,
            "passive_noise_reasons": [],
            "passive_noise_matched_products": [],
        }

    if has_openclaw_evidence:
        reasons.append(
            "OpenClaw-like passive evidence also present; active validation remains allowed"
        )

    return {
        "passive_noise_downgraded": True,
        "passive_noise_confidence_cap": cap,
        "passive_noise_reasons": sorted(set(reasons)),
        "passive_noise_matched_products": sorted(set(matched_products)),
    }


def _record_haystacks(record: Dict[str, Any]) -> List[str]:
    values: List[str] = []
    for key in ("product", "version", "os", "data", "title"):
        values.extend(_string_values(record.get(key)))

    http = record.get("http") or {}
    if isinstance(http, dict):
        for key in ("title", "server", "html", "body"):
            values.extend(_string_values(http.get(key)))
        components = http.get("components") or {}
        if isinstance(components, dict):
            for name, metadata in components.items():
                values.extend(_string_values(name))
                values.extend(_string_values(metadata))
        headers = http.get("headers") or {}
        if isinstance(headers, dict):
            for key, value in headers.items():
                values.extend(_string_values(key))
                values.extend(_string_values(value))

    ssl_data = record.get("ssl") or {}
    values.extend(_string_values(ssl_data))

    mdns = record.get("mdns") or {}
    values.extend(_string_values(mdns))

    return [value.lower() for value in values if value]


def _string_values(value: Any) -> Iterable[str]:
    if value in (None, ""):
        return []
    if isinstance(value, dict):
        items: List[str] = []
        for key, child in value.items():
            items.extend(_string_values(key))
            items.extend(_string_values(child))
        return items
    if isinstance(value, (list, tuple, set)):
        items = []
        for child in value:
            items.extend(_string_values(child))
        return items
    return [str(value)]
