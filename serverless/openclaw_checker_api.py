"""Reference serverless backend for the static OpenClaw exposure checker.

This module is intentionally conservative and dependency-free. It is a skeleton
for Vercel/Cloudflare-Python-style deployments, not GitHub Pages code. A
production deployment should replace the in-memory rate limiter with durable
storage and wire verify_captcha() to Turnstile, hCaptcha, or an equivalent
provider.
"""

from typing import Any, Dict
from urllib.parse import urlparse
import socket

from openclaw_scanner.checker import (
    CHECKER_MAX_RESPONSE_BYTES,
    CHECKER_TIMEOUT_SECONDS,
    CHECKER_USER_AGENT,
    CheckerValidationError,
    RateLimitBucket,
    check_rate_limit,
    checker_probe_configs,
    normalize_checker_target,
    validate_checker_request,
    validate_public_ip_address,
)
from openclaw_scanner.cli import _apply_inferences
from openclaw_scanner.inference import load_rules
from openclaw_scanner.models import ScanResult
from openclaw_scanner.probe import probe_candidate


RATE_LIMIT_BUCKET = RateLimitBucket()


def handle_checker_payload(payload: Dict[str, Any], client_ip: str) -> Dict[str, Any]:
    validated = validate_checker_request(payload)
    target = normalize_checker_target(validated["target"])
    enforce_resolved_public_addresses(target)

    if not verify_captcha(str(payload.get("captcha_token") or "")):
        return {"status": 403, "body": {"error": "CAPTCHA verification failed"}}

    rate = check_rate_limit(
        RATE_LIMIT_BUCKET,
        client_key=client_ip,
        target_key=target,
        limit=5,
        window_seconds=3600,
    )
    if not rate["allowed"]:
        return {
            "status": 429,
            "body": {
                "error": "rate limit exceeded",
                "reset_after_seconds": rate["reset_after_seconds"],
            },
        }

    try:
        body = run_low_impact_check(target)
    except CheckerValidationError as exc:
        return {"status": 400, "body": {"error": str(exc)}}
    return {"status": 200, "body": body}


def verify_captcha(token: str) -> bool:
    """Placeholder only. Replace before deploying publicly."""
    return bool(token.strip())


def enforce_resolved_public_addresses(target: str) -> None:
    parsed = urlparse(target)
    if not parsed.hostname:
        raise CheckerValidationError("target hostname is required")
    for family, _, _, _, sockaddr in socket.getaddrinfo(parsed.hostname, parsed.port or 443):
        if family not in (socket.AF_INET, socket.AF_INET6):
            continue
        validate_public_ip_address(str(sockaddr[0]))


def run_low_impact_check(target: str) -> Dict[str, Any]:
    observations, errors = probe_candidate(
        base_url=target,
        probes=checker_probe_configs(),
        timeout=CHECKER_TIMEOUT_SECONDS,
        verify_tls=True,
        user_agent=CHECKER_USER_AGENT,
        max_bytes=CHECKER_MAX_RESPONSE_BYTES,
    )
    result = _apply_inferences(
        ScanResult(
            input_target="user-authorized-target",
            source="exposure_checker",
            probed_base=target,
            observations=observations,
            errors=errors,
        ),
        load_rules(None),
    )
    top_family = result.fingerprint_matches[0] if result.fingerprint_matches else None
    top_version = result.matched_versions[0] if result.matched_versions else None
    correlation_grade_version = (
        top_version
        if top_version is not None and top_version.exact and top_version.correlate
        else None
    )
    vulnerabilities = result.vulnerability_matches if correlation_grade_version else []

    return {
        "reachable": any(
            observation.status is not None for observation in observations.values()
        ),
        "candidate": result.product_confidence > 0,
        "family_fingerprint": {
            "found": top_family is not None,
            "confidence": round(top_family.confidence, 2) if top_family else 0.0,
            "label": top_family.label or top_family.family if top_family else None,
        },
        "exact_version": {
            "found": correlation_grade_version is not None,
            "version": correlation_grade_version.version
            if correlation_grade_version
            else None,
            "source": correlation_grade_version.source
            if correlation_grade_version
            else None,
        },
        "vulnerability_correlation": {
            "found": bool(vulnerabilities),
            "count": len(vulnerabilities),
            "details_available": bool(vulnerabilities),
            "requires_correlation_grade_exact_version": True,
        },
    }
