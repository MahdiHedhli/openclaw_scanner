"""
Proposed Change: HTTP/2 Protocol-Level Fingerprinting
=====================================================
Date: 2026-03-24
Research topic: #3 HTTP/2 and protocol-level fingerprinting

This file contains proposed additions to support HTTP/2 server
fingerprinting via SETTINGS frame analysis and ALPN negotiation.

The scanner can identify the server's HTTP/2 implementation (Go, Node.js,
nginx, etc.) by examining the SETTINGS parameters sent in the server's
connection preface. This provides a transport-layer signal independent
of HTTP content, useful when HTTP-level fingerprinting is obscured.

IMPORTANT: This requires an optional dependency (httpx + h2) and should
be gated behind an --h2 / --http2-fingerprint CLI flag.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


# ── Data model for HTTP/2 fingerprint ────────────────────────────────

@dataclass
class Http2ServerFingerprint:
    """Captures the HTTP/2 connection-level parameters from the server."""

    # Raw SETTINGS frame values from server connection preface.
    # Keys are setting IDs (1-6), values are integers.
    settings: Dict[int, int] = field(default_factory=dict)

    # ALPN protocol negotiated during TLS handshake (e.g., "h2")
    alpn_protocol: Optional[str] = None

    # Whether the server supports HTTP/2 at all
    h2_supported: bool = False

    # Formatted fingerprint string: "1=4096;2=0;3=250;4=1048576;5=16384"
    settings_fingerprint: str = ""

    # Inferred server runtime based on known defaults
    inferred_runtime: Optional[str] = None

    # Confidence of the runtime inference (0.0 - 1.0)
    runtime_confidence: float = 0.0

    # Error message if HTTP/2 probing failed
    error: Optional[str] = None


# ── HTTP/2 SETTINGS parameter IDs (RFC 7540 Section 6.5.2) ──────────

SETTINGS_HEADER_TABLE_SIZE = 0x01       # Default: 4096
SETTINGS_ENABLE_PUSH = 0x02            # Default: 1
SETTINGS_MAX_CONCURRENT_STREAMS = 0x03  # Default: unlimited
SETTINGS_INITIAL_WINDOW_SIZE = 0x04     # Default: 65535
SETTINGS_MAX_FRAME_SIZE = 0x05          # Default: 16384
SETTINGS_MAX_HEADER_LIST_SIZE = 0x06    # Default: unlimited

SETTINGS_NAMES = {
    SETTINGS_HEADER_TABLE_SIZE: "HEADER_TABLE_SIZE",
    SETTINGS_ENABLE_PUSH: "ENABLE_PUSH",
    SETTINGS_MAX_CONCURRENT_STREAMS: "MAX_CONCURRENT_STREAMS",
    SETTINGS_INITIAL_WINDOW_SIZE: "INITIAL_WINDOW_SIZE",
    SETTINGS_MAX_FRAME_SIZE: "MAX_FRAME_SIZE",
    SETTINGS_MAX_HEADER_LIST_SIZE: "MAX_HEADER_LIST_SIZE",
}


# ── Known server-side SETTINGS defaults ──────────────────────────────

# These are the known default SETTINGS values for common HTTP/2 server
# implementations. The scanner compares observed values against these
# profiles to infer the server runtime.

KNOWN_SERVER_PROFILES = {
    "go_net_http2": {
        "label": "Go net/http2",
        "settings": {
            SETTINGS_HEADER_TABLE_SIZE: 4096,
            SETTINGS_ENABLE_PUSH: 0,           # Go disables push by default
            SETTINGS_MAX_CONCURRENT_STREAMS: 250,
            SETTINGS_INITIAL_WINDOW_SIZE: 1048576,  # 1MB — distinctive!
            SETTINGS_MAX_FRAME_SIZE: 16384,
        },
        "distinguishing_features": [
            "INITIAL_WINDOW_SIZE=1048576 (16x RFC default, highly distinctive)",
            "ENABLE_PUSH=0 (most other servers default to 1 or omit)",
            "MAX_CONCURRENT_STREAMS=250",
        ],
    },
    "nodejs_http2": {
        "label": "Node.js http2",
        "settings": {
            SETTINGS_HEADER_TABLE_SIZE: 4096,
            SETTINGS_MAX_CONCURRENT_STREAMS: 100,
            SETTINGS_INITIAL_WINDOW_SIZE: 65535,
            SETTINGS_MAX_FRAME_SIZE: 16384,
        },
        "distinguishing_features": [
            "Closely follows RFC 7540 defaults",
            "MAX_CONCURRENT_STREAMS=100 (lower than Go/nginx)",
            "Node may send fewer SETTINGS params (only non-default ones)",
        ],
    },
    "nginx": {
        "label": "nginx",
        "settings": {
            SETTINGS_MAX_CONCURRENT_STREAMS: 128,
            SETTINGS_INITIAL_WINDOW_SIZE: 65535,
            SETTINGS_MAX_FRAME_SIZE: 16384,
        },
        "distinguishing_features": [
            "MAX_CONCURRENT_STREAMS=128 (nginx-specific default)",
            "Other params typically match RFC defaults",
        ],
    },
    "apache_mod_http2": {
        "label": "Apache mod_http2",
        "settings": {
            SETTINGS_MAX_CONCURRENT_STREAMS: 100,
            SETTINGS_INITIAL_WINDOW_SIZE: 65535,
            SETTINGS_MAX_FRAME_SIZE: 16384,
        },
        "distinguishing_features": [
            "MAX_CONCURRENT_STREAMS=100 (same as Node.js)",
            "Difficult to distinguish from Node.js by SETTINGS alone",
        ],
    },
}


def format_settings_fingerprint(settings: Dict[int, int]) -> str:
    """
    Format SETTINGS dict as a fingerprint string.

    Example output: "1=4096;2=0;3=250;4=1048576;5=16384"

    Parameters are sorted by ID for consistency.
    """
    parts = [f"{setting_id}={value}" for setting_id, value in sorted(settings.items())]
    return ";".join(parts)


def infer_runtime_from_settings(
    settings: Dict[int, int],
) -> Tuple[Optional[str], float]:
    """
    Compare observed SETTINGS against known server profiles.

    Returns (runtime_label, confidence) tuple.

    The matching logic:
    1. If INITIAL_WINDOW_SIZE >= 1048576, very likely Go (0.85 confidence)
    2. If ENABLE_PUSH == 0 AND MAX_CONCURRENT_STREAMS == 250, Go (0.90)
    3. If MAX_CONCURRENT_STREAMS == 128, likely nginx (0.70)
    4. If MAX_CONCURRENT_STREAMS == 100, likely Node.js or Apache (0.50)
    5. Otherwise, unknown
    """
    window_size = settings.get(SETTINGS_INITIAL_WINDOW_SIZE)
    enable_push = settings.get(SETTINGS_ENABLE_PUSH)
    max_streams = settings.get(SETTINGS_MAX_CONCURRENT_STREAMS)

    # Go's 1MB initial window size is highly distinctive
    if window_size is not None and window_size >= 1048576:
        confidence = 0.85
        if enable_push == 0 and max_streams == 250:
            confidence = 0.92
        elif enable_push == 0:
            confidence = 0.88
        return "Go net/http2", confidence

    # nginx default of 128 concurrent streams
    if max_streams == 128:
        return "nginx", 0.70

    # Node.js and Apache both default to 100 — ambiguous
    if max_streams == 100:
        return "Node.js or Apache", 0.50

    return None, 0.0


def extract_h2_fingerprint_httpx(
    host: str,
    port: int,
    timeout: float = 5.0,
    verify_tls: bool = False,
) -> Http2ServerFingerprint:
    """
    Extract HTTP/2 server fingerprint using httpx + h2.

    This is the RECOMMENDED approach. Requires:
        pip install httpx[http2]

    The function:
    1. Establishes an HTTP/2 connection to the target
    2. Reads the server's SETTINGS frame from the connection preface
    3. Records the ALPN negotiation result
    4. Infers the server runtime from SETTINGS defaults

    NOTE: This is a DRAFT implementation. It demonstrates the approach
    but needs integration with the scanner's existing probe infrastructure.
    """
    result = Http2ServerFingerprint()

    try:
        import httpx
    except ImportError:
        result.error = "httpx not installed; run: pip install httpx[http2]"
        return result

    scheme = "https" if port in (443, 8443, 18789) else "http"
    url = f"{scheme}://{host}:{port}/"

    try:
        with httpx.Client(
            http2=True,
            verify=verify_tls,
            timeout=timeout,
        ) as client:
            response = client.get(url)

            # Check if HTTP/2 was actually negotiated
            if response.http_version == "HTTP/2":
                result.h2_supported = True
                result.alpn_protocol = "h2"

                # Access the underlying h2 connection's settings
                # NOTE: httpx exposes this through the transport layer.
                # The exact API depends on the httpx version. This is
                # a simplified representation — production code would
                # need to access the h2 Connection object.
                transport = client._transport
                if hasattr(transport, "_pool"):
                    for connection in transport._pool.connections:
                        if hasattr(connection, "_h2_state"):
                            h2_conn = connection._h2_state
                            # h2 library stores remote settings
                            remote = h2_conn.remote_settings
                            result.settings = {
                                SETTINGS_HEADER_TABLE_SIZE: remote.header_table_size,
                                SETTINGS_ENABLE_PUSH: int(remote.enable_push),
                                SETTINGS_MAX_CONCURRENT_STREAMS: remote.max_concurrent_streams,
                                SETTINGS_INITIAL_WINDOW_SIZE: remote.initial_window_size,
                                SETTINGS_MAX_FRAME_SIZE: remote.max_frame_size,
                                SETTINGS_MAX_HEADER_LIST_SIZE: remote.max_header_list_size,
                            }
            else:
                result.h2_supported = False
                result.alpn_protocol = "http/1.1"

    except Exception as exc:
        result.error = f"HTTP/2 probe failed: {exc}"
        return result

    if result.settings:
        result.settings_fingerprint = format_settings_fingerprint(result.settings)
        runtime, confidence = infer_runtime_from_settings(result.settings)
        result.inferred_runtime = runtime
        result.runtime_confidence = confidence

    return result


# ── New condition types for the rules engine ─────────────────────────

PROPOSED_CONDITION_TYPES = {
    "h2_supported": {
        "description": (
            "Matches when the target does (or does not) support HTTP/2. "
            "Value is a boolean."
        ),
        "example": {"type": "h2_supported", "value": True},
        "implementation_hint": (
            "Check Http2ServerFingerprint.h2_supported. This condition "
            "does not require a path — it's a connection-level property."
        ),
    },
    "h2_settings_match": {
        "description": (
            "Exact match on the full SETTINGS fingerprint string. "
            "Use for matching known server profiles."
        ),
        "example": {
            "type": "h2_settings_match",
            "value": "1=4096;2=0;3=250;4=1048576;5=16384",
        },
    },
    "h2_setting_value": {
        "description": (
            "Match a specific SETTINGS parameter by ID and value, "
            "with optional comparison operator."
        ),
        "example": {
            "type": "h2_setting_value",
            "setting_id": 4,  # INITIAL_WINDOW_SIZE
            "op": ">=",       # eq, gte, lte, gt, lt
            "value": 1048576,
        },
    },
    "h2_runtime_contains": {
        "description": (
            "Match against the inferred runtime label. Useful for "
            "building rules that combine runtime detection with "
            "HTTP-level signals."
        ),
        "example": {"type": "h2_runtime_contains", "value": "Go"},
    },
    "h2_alpn_contains": {
        "description": "Match the ALPN negotiation result.",
        "example": {"type": "h2_alpn_contains", "value": "h2"},
    },
}


# ── Example fingerprint rules using HTTP/2 signals ──────────────────

PROPOSED_FINGERPRINT_RULES = [
    {
        "id": "openclaw-go-h2-settings",
        "family": "openclaw_go_h2",
        "label": "OpenClaw gateway with Go HTTP/2 SETTINGS signature",
        "confidence": 0.75,
        "notes": (
            "Combines Go-specific HTTP/2 SETTINGS (1MB initial window, "
            "push disabled, 250 concurrent streams) with OpenClaw product "
            "markers from HTTP content. The Go runtime signal alone is "
            "not sufficient — many Go apps exist — but combined with "
            "product markers it increases confidence."
        ),
        "all": [
            {
                "type": "h2_setting_value",
                "setting_id": 4,
                "op": ">=",
                "value": 1048576,
            },
            {
                "type": "h2_setting_value",
                "setting_id": 2,
                "op": "eq",
                "value": 0,
            },
            {
                "type": "marker_present",
                "path": "/",
                "value": "openclaw",
            },
        ],
    },
    {
        "id": "openclaw-behind-nginx-h2",
        "family": "openclaw_proxied_nginx",
        "label": "OpenClaw gateway behind nginx reverse proxy (HTTP/2 signal)",
        "confidence": 0.70,
        "notes": (
            "When nginx terminates TLS, its HTTP/2 SETTINGS (128 max "
            "concurrent streams) are visible instead of the backend's. "
            "Combined with OpenClaw content markers and Server: nginx "
            "header, this confirms a proxied deployment."
        ),
        "all": [
            {
                "type": "h2_setting_value",
                "setting_id": 3,
                "op": "eq",
                "value": 128,
            },
            {
                "type": "header_contains",
                "path": "/",
                "header": "server",
                "value": "nginx",
            },
            {
                "type": "marker_present",
                "path": "/",
                "value": "openclaw",
            },
        ],
    },
]


# ── Integration notes ────────────────────────────────────────────────

INTEGRATION_NOTES = """
Integration Plan for HTTP/2 Fingerprinting
==========================================

1. CLI flag: Add --h2 or --http2-fingerprint flag (default: off)
   - HTTP/2 probing adds latency and requires an optional dependency
   - Should not be enabled by default for lightweight scans

2. Dependency: httpx[http2] (pip install httpx[http2])
   - httpx is well-maintained, supports HTTP/2 natively via the h2 lib
   - Alternative: use h2 directly for lower-level control
   - The dependency should be optional (try/except ImportError)

3. Probe flow:
   a. After standard HTTP/1.1 probing completes, if --h2 is set:
   b. Attempt HTTP/2 connection to the target
   c. Extract SETTINGS from server connection preface
   d. Record ALPN negotiation result
   e. Infer runtime from SETTINGS defaults
   f. Store Http2ServerFingerprint in the scan result

4. Rules engine:
   a. Add new condition types (h2_settings_match, h2_setting_value, etc.)
   b. These conditions check the Http2ServerFingerprint stored in results
   c. H2 conditions should be skippable (return False) when --h2 is off

5. Shodan integration:
   - Shodan may expose HTTP/2-related metadata in banner data
   - Check if Shodan banners include h2 SETTINGS information
   - If so, the scanner can do passive H2 fingerprinting from Shodan
     exports without active probing

6. Interaction with other fingerprinting layers:
   - When H2 SETTINGS indicate a reverse proxy (e.g., nginx 128 streams),
     combine with the proxy detection module (Topic #11) to adjust
     confidence for HTTP-level signals
   - H2 runtime inference (e.g., "Go") reinforces /debug/pprof detection
     (Topic #1 additional probe paths)
"""
