import ipaddress
import json
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, urlunparse

from .probe import ProbeConfig


AUTHORIZATION_ACK_TEXT = (
    "I confirm that I own this system or am explicitly authorized to assess it."
)

CHECKER_USER_AGENT = "openclaw-scanner-exposure-checker/0.1"
CHECKER_MAX_REDIRECTS = 2
CHECKER_MAX_RESPONSE_BYTES = 32768
CHECKER_TIMEOUT_SECONDS = 4.0

BLOCKED_HOST_SUFFIXES = (
    ".local",
    ".localhost",
    ".internal",
    ".lan",
    ".home.arpa",
)

METADATA_IPS = {
    ipaddress.ip_address("169.254.169.254"),
}

SHARED_ADDRESS_BLOCKS = (
    ipaddress.ip_network("100.64.0.0/10"),
)

CHECKER_PROBES = (
    ProbeConfig(path="/", method="GET"),
    ProbeConfig(path="/login", method="GET"),
    ProbeConfig(path="/api/version", method="GET"),
    ProbeConfig(path="/api/status", method="GET"),
    ProbeConfig(path="/api/health", method="GET"),
    ProbeConfig(path="/v1/models", method="GET"),
    ProbeConfig(path="/favicon.ico", method="GET"),
    ProbeConfig(path="/manifest.json", method="GET"),
)


class CheckerValidationError(ValueError):
    pass


@dataclass
class RateLimitBucket:
    events: Dict[Tuple[str, str], List[float]] = field(default_factory=dict)


def normalize_checker_target(value: str) -> str:
    if not value or not str(value).strip():
        raise CheckerValidationError("target is required")

    raw = str(value).strip()
    parsed = urlparse(raw if "://" in raw else f"https://{raw}")
    if parsed.scheme not in {"http", "https"}:
        raise CheckerValidationError("target scheme must be http or https")
    if parsed.username or parsed.password:
        raise CheckerValidationError("target must not include credentials")
    if not parsed.hostname:
        raise CheckerValidationError("target hostname is required")

    _validate_public_hostname(parsed.hostname)

    netloc = parsed.hostname
    if ":" in netloc and not netloc.startswith("["):
        netloc = f"[{netloc}]"
    if parsed.port:
        netloc = f"{netloc}:{parsed.port}"

    path = parsed.path or "/"
    return urlunparse((parsed.scheme, netloc, path, "", "", ""))


def validate_checker_request(payload: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        raise CheckerValidationError("request body must be a JSON object")
    if payload.get("authorization_acknowledged") is not True:
        raise CheckerValidationError("authorization acknowledgement is required")
    if not str(payload.get("captcha_token") or "").strip():
        raise CheckerValidationError("CAPTCHA token is required")

    normalized_target = normalize_checker_target(str(payload.get("target") or ""))
    return {
        "target": normalized_target,
        "authorization_acknowledged": True,
        "captcha_required": True,
    }


def checker_probe_configs() -> List[ProbeConfig]:
    return list(CHECKER_PROBES)


def check_rate_limit(
    bucket: RateLimitBucket,
    client_key: str,
    target_key: str,
    limit: int = 5,
    window_seconds: int = 3600,
    now: Optional[float] = None,
) -> Dict[str, Any]:
    current = time.time() if now is None else float(now)
    key = (str(client_key), str(target_key))
    cutoff = current - window_seconds
    recent = [event for event in bucket.events.get(key, []) if event > cutoff]
    allowed = len(recent) < limit
    if allowed:
        recent.append(current)
    bucket.events[key] = recent
    reset_at = min(recent) + window_seconds if recent else current + window_seconds
    return {
        "allowed": allowed,
        "remaining": max(limit - len(recent), 0),
        "reset_after_seconds": max(int(reset_at - current), 0),
    }


def checker_api_contract() -> Dict[str, Any]:
    return {
        "request": {
            "method": "POST",
            "content_type": "application/json",
            "body": {
                "target": "https://gateway.example.com:18789",
                "authorization_acknowledged": True,
                "authorization_text": AUTHORIZATION_ACK_TEXT,
                "captcha_token": "provider-token",
            },
        },
        "response": {
            "reachable": True,
            "possible_openclaw": True,
            "family_match": True,
            "exact_version": "2026.5.28",
            "risk_context": "known version identified",
            "evidence_summary": [
                "status_distribution_signature=200:5;401:1",
                "exact_version=2026.5.28; source=lab_rule_id",
            ],
        },
        "limits": {
            "methods": ["GET"],
            "post_probes": False,
            "authentication_attempts": False,
            "debugger_socket_connections": False,
            "vnc_interaction": False,
            "max_redirects": CHECKER_MAX_REDIRECTS,
            "timeout_seconds": CHECKER_TIMEOUT_SECONDS,
            "max_response_bytes": CHECKER_MAX_RESPONSE_BYTES,
        },
    }


def checker_api_contract_json() -> str:
    return json.dumps(checker_api_contract(), indent=2, sort_keys=True)


def validate_public_ip_address(value: str) -> None:
    try:
        ip = ipaddress.ip_address(str(value).strip("[]"))
    except ValueError as exc:
        raise CheckerValidationError("invalid IP address") from exc

    if ip in METADATA_IPS:
        raise CheckerValidationError("cloud metadata IP targets are blocked")
    if any(ip in network for network in SHARED_ADDRESS_BLOCKS):
        raise CheckerValidationError("shared/private address ranges are blocked")
    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_unspecified
        or ip.is_reserved
    ):
        raise CheckerValidationError("non-public IP targets are blocked")


def _validate_public_hostname(hostname: str) -> None:
    normalized = hostname.strip().rstrip(".").lower()
    if normalized in {"localhost", "localhost.localdomain"}:
        raise CheckerValidationError("localhost targets are blocked")
    if normalized.endswith(BLOCKED_HOST_SUFFIXES):
        raise CheckerValidationError("internal hostname suffix is blocked")
    if "." not in normalized and not _looks_like_ip(normalized):
        raise CheckerValidationError("single-label internal hostnames are blocked")

    try:
        ipaddress.ip_address(normalized.strip("[]"))
    except ValueError:
        return

    validate_public_ip_address(normalized)


def _looks_like_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip("[]"))
    except ValueError:
        return False
    return True
