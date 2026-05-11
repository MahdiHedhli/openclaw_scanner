"""
Proposed addition: WebSocket endpoint probing for OpenClaw Scanner.

This module adds WebSocket upgrade handshake probes to the scanner's
existing HTTP probing infrastructure. It does NOT establish full WebSocket
connections — it only analyzes the HTTP upgrade handshake response.

The approach leverages the existing ProbeConfig and _fetch() function by
adding WebSocket-specific headers to standard HTTP GET requests.
"""

import base64
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional

# Assuming these are imported from the existing codebase:
# from .probe import ProbeConfig
# from .models import ProbeObservation


# ---------------------------------------------------------------------------
# WebSocket probe configuration
# ---------------------------------------------------------------------------

# Common WebSocket endpoint paths to probe on OpenClaw gateways.
# Derived from: CVE descriptions mentioning gateway_ws surface,
# common IoT gateway conventions, and typical SPA patterns.
WS_CANDIDATE_PATHS = [
    "/ws",
    "/wss",
    "/socket",
    "/api/ws",
    "/api/websocket",
    "/gateway",
    "/gateway/ws",
    "/control/ws",
    "/agent/ws",
    "/events",
    "/stream",
    "/realtime",
    "/v1/ws",
    "/socket.io/",
]


def build_ws_upgrade_headers(host: str) -> Dict[str, str]:
    """
    Build the HTTP headers needed for a WebSocket upgrade handshake.

    These headers are added to a standard GET request. The server's response
    (101, 400, 403, 404, etc.) and response headers contain fingerprinting signals.
    """
    # Generate a random 16-byte key, base64-encoded, per RFC 6455
    ws_key = base64.b64encode(os.urandom(16)).decode("ascii")

    return {
        "Upgrade": "websocket",
        "Connection": "Upgrade",
        "Sec-WebSocket-Key": ws_key,
        "Sec-WebSocket-Version": "13",
        "Origin": f"https://{host}",
    }


def build_ws_probe_configs(host: str, extra_paths: Optional[List[str]] = None):
    """
    Build ProbeConfig objects for WebSocket endpoint discovery.

    Each config is a standard GET request with WebSocket upgrade headers.
    The existing _fetch() function handles these identically to regular probes.

    Usage:
        ws_probes = build_ws_probe_configs("target.example.com")
        for probe in ws_probes:
            # Use existing probe_candidate() infrastructure
            pass
    """
    # Import here to avoid circular dependency in proposed code
    # from .probe import ProbeConfig

    paths = list(WS_CANDIDATE_PATHS)
    if extra_paths:
        paths.extend(extra_paths)

    ws_headers = build_ws_upgrade_headers(host)
    configs = []

    for path in paths:
        # ProbeConfig(path=path, method="GET", headers=ws_headers)
        configs.append({
            "path": path,
            "method": "GET",
            "headers": dict(ws_headers),  # copy to avoid shared mutation
        })

    return configs


# ---------------------------------------------------------------------------
# WebSocket handshake result model
# ---------------------------------------------------------------------------

@dataclass
class WsHandshakeResult:
    """Result of a WebSocket upgrade handshake probe."""
    path: str
    ws_supported: bool = False           # True if server responded with 101
    status: Optional[int] = None         # HTTP status code
    sec_websocket_accept: Optional[str] = None
    sec_websocket_protocol: Optional[str] = None   # Negotiated subprotocol
    sec_websocket_extensions: Optional[str] = None  # Negotiated extensions
    error_body: Optional[str] = None     # Error response body (for non-101 responses)
    error_json_keys: List[str] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)


def analyze_ws_handshake(path: str, observation) -> WsHandshakeResult:
    """
    Analyze a ProbeObservation from a WebSocket upgrade probe.

    This extracts WebSocket-specific signals from the HTTP response
    to a WebSocket upgrade request.

    Args:
        path: The probed path.
        observation: A ProbeObservation from _fetch() with WS upgrade headers.

    Returns:
        WsHandshakeResult with extracted WebSocket signals.
    """
    result = WsHandshakeResult(
        path=path,
        status=observation.status,
        headers=dict(observation.headers),
    )

    if observation.status == 101:
        result.ws_supported = True
        result.sec_websocket_accept = observation.headers.get("sec-websocket-accept")
        result.sec_websocket_protocol = observation.headers.get("sec-websocket-protocol")
        result.sec_websocket_extensions = observation.headers.get("sec-websocket-extensions")
    else:
        # Non-101 response — extract error information for fingerprinting
        result.error_body = observation.error_text
        result.error_json_keys = list(observation.json_keys) if observation.json_keys else []

    return result


# ---------------------------------------------------------------------------
# WebSocket fingerprinting rules (examples for openclaw_rules.json)
# ---------------------------------------------------------------------------

# These would be added to the fingerprint_rules array in openclaw_rules.json.
# They match on WebSocket handshake responses to identify OpenClaw gateways.

EXAMPLE_WS_FINGERPRINT_RULES = [
    {
        "id": "openclaw-ws-endpoint-detected",
        "family": "openclaw_ws_gateway",
        "label": "OpenClaw gateway with active WebSocket endpoint",
        "confidence": 0.88,
        "notes": "WebSocket upgrade succeeds on /ws or /gateway/ws, indicating an active OpenClaw gateway WebSocket interface.",
        "any": [
            {
                "type": "ws_upgrade_supported",
                "path": "/ws",
                "value": True,
            },
            {
                "type": "ws_upgrade_supported",
                "path": "/gateway/ws",
                "value": True,
            },
            {
                "type": "ws_upgrade_supported",
                "path": "/api/ws",
                "value": True,
            },
        ],
    },
    {
        "id": "openclaw-ws-auth-error-pattern",
        "family": "openclaw_ws_auth_required",
        "label": "OpenClaw gateway WebSocket requiring auth token",
        "confidence": 0.82,
        "notes": "WebSocket upgrade returns 401/403 with JSON error containing auth-related keys, consistent with OpenClaw's token-based WS authentication.",
        "all": [
            {
                "type": "ws_upgrade_status",
                "path": "/ws",
                "statuses": [401, 403],
            },
            {
                "type": "ws_error_json_key",
                "path": "/ws",
                "value": "error",
            },
        ],
    },
]


# ---------------------------------------------------------------------------
# New condition types for the rules engine
# ---------------------------------------------------------------------------

# These would be added to the _condition_matches() function in inference.py:

PROPOSED_NEW_CONDITION_TYPES = """
# Add to _condition_matches() in inference.py:

if condition_type == "ws_upgrade_supported":
    # Check if a WebSocket upgrade probe returned 101
    expected = bool(condition.get("value", True))
    return any(obs.status == 101 for obs in candidate_observations) == expected

if condition_type == "ws_upgrade_status":
    # Check WebSocket upgrade response status code
    statuses = {int(v) for v in condition.get("statuses", [])}
    return any(obs.status in statuses for obs in candidate_observations)

if condition_type == "ws_subprotocol_contains":
    # Check negotiated Sec-WebSocket-Protocol
    needle = condition["value"].lower()
    return any(
        needle in obs.headers.get("sec-websocket-protocol", "").lower()
        for obs in candidate_observations
    )

if condition_type == "ws_extension_contains":
    # Check negotiated Sec-WebSocket-Extensions
    needle = condition["value"].lower()
    return any(
        needle in obs.headers.get("sec-websocket-extensions", "").lower()
        for obs in candidate_observations
    )

if condition_type == "ws_error_json_key":
    # Check for specific keys in WebSocket upgrade error JSON response
    key_name = condition["value"]
    return any(key_name in obs.json_keys for obs in candidate_observations)
"""


# ---------------------------------------------------------------------------
# JS source analysis for WebSocket URL discovery
# ---------------------------------------------------------------------------

import re

WS_URL_PATTERNS = [
    # Match WebSocket constructor calls: new WebSocket("ws://..." or "wss://...")
    re.compile(r"""new\s+WebSocket\s*\(\s*['"](wss?://[^'"]+)['"]""", re.IGNORECASE),
    # Match template literal WS URLs: `wss://${host}/ws`
    re.compile(r"""[`'"](wss?://[^`'"]*(?:\$\{[^}]+\})?[^`'"]*)['"`]"""),
    # Match path-only references that are likely WS endpoints
    re.compile(r"""(?:ws_?(?:url|path|endpoint)|websocket_?(?:url|path))\s*[:=]\s*['"]([^'"]+)['"]""", re.IGNORECASE),
]


def extract_ws_paths_from_js(js_content: str) -> List[str]:
    """
    Extract WebSocket endpoint paths from JavaScript source code.

    The scanner already fetches JS files referenced in HTML pages.
    This function analyzes those files for WebSocket URL patterns
    to discover additional probe targets.

    Returns:
        List of path strings (e.g., ["/ws", "/gateway/ws"]).
    """
    paths = set()

    for pattern in WS_URL_PATTERNS:
        for match in pattern.finditer(js_content):
            url_or_path = match.group(1)
            # Extract just the path component
            if url_or_path.startswith(("ws://", "wss://")):
                # Parse out the path from a full URL
                # Simple extraction: everything after the third /
                parts = url_or_path.split("/", 3)
                if len(parts) >= 4:
                    path = "/" + parts[3]
                    # Strip template literal placeholders
                    path = re.sub(r"\$\{[^}]+\}", "", path)
                    if path and path != "/":
                        paths.add(path)
            elif url_or_path.startswith("/"):
                paths.add(url_or_path)

    return sorted(paths)
