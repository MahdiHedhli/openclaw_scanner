"""
Proposed enhancement: Error Response Fingerprinting for OpenClaw Scanner
=========================================================================
Date: 2026-03-23
Research topic: #5 — Error response fingerprinting

This file contains proposed code additions for richer error response
analysis, including malformed request probes, header ordering fingerprints,
body pattern matching, and configurable HTTP methods.

No existing source files are modified — this is a standalone reference.
"""

import hashlib
import re
from typing import Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# 1. New probe definitions: malformed / edge-case requests
# ---------------------------------------------------------------------------
# These extend DEFAULT_PROBE_PATHS in probe.py with method + path tuples

PROPOSED_ADDITIONAL_PROBES = [
    # (method, path, description)
    ("POST", "/api/doesnotexist", "POST to non-existent API route — test method-specific error handling"),
    ("DELETE", "/", "DELETE on root — test method handling policy"),
    ("XYZZY", "/", "Unknown HTTP method — test undefined method handling"),
    ("GET", "/api/v99/nonexistent", "Non-existent API version — test API versioning error format"),
]

# Note: The current probe_candidate() function always uses GET.
# To support these, the probe configuration needs a `method` field.
# Proposed change: convert DEFAULT_PROBE_PATHS from List[str] to List[ProbeConfig].


# ---------------------------------------------------------------------------
# 2. Proposed ProbeConfig dataclass
# ---------------------------------------------------------------------------

from dataclasses import dataclass, field


@dataclass
class ProbeConfig:
    """Configuration for a single HTTP probe."""
    path: str
    method: str = "GET"
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[bytes] = None
    description: str = ""


# Convert existing paths to ProbeConfig objects:
DEFAULT_PROBE_CONFIGS = [
    ProbeConfig(path="/"),
    ProbeConfig(path="/login"),
    ProbeConfig(path="/api"),
    ProbeConfig(path="/api/version"),
    ProbeConfig(path="/api/status"),
    ProbeConfig(path="/api/health"),
    ProbeConfig(path="/health"),
    ProbeConfig(path="/status"),
    ProbeConfig(path="/api/doesnotexist"),
    # New error fingerprinting probes:
    ProbeConfig(path="/api/doesnotexist", method="POST",
                description="POST to non-existent API endpoint"),
    ProbeConfig(path="/", method="DELETE",
                description="DELETE method on root"),
    ProbeConfig(path="/", method="XYZZY",
                description="Unknown HTTP method probe"),
    ProbeConfig(path="/api/v99/nonexistent", method="GET",
                description="Non-existent API version path"),
]


# ---------------------------------------------------------------------------
# 3. New fields on ProbeObservation
# ---------------------------------------------------------------------------
# These would be added to the existing ProbeObservation dataclass in models.py

PROPOSED_NEW_FIELDS = """
    # Add to ProbeObservation in models.py:

    method: str = "GET"                        # HTTP method used for this probe
    header_order: List[str] = field(default_factory=list)  # Ordered list of response header names
    error_text: Optional[str] = None           # First 512 chars of error body, HTML tags stripped
    has_stack_trace: bool = False               # True if response body contains stack trace patterns
"""


# ---------------------------------------------------------------------------
# 4. Header ordering fingerprint extraction
# ---------------------------------------------------------------------------

def extract_header_order(headers_items) -> List[str]:
    """
    Extract the ordered list of response header names.

    Different HTTP server implementations return headers in different orders.
    For example:
      - Apache: Date, Server, X-Powered-By, ...
      - nginx:  Server, Date, Content-Type, ...
      - Express: X-Powered-By, Content-Type, Date, ...
      - Go:     Content-Type, Date, ...

    This ordering is a strong fingerprint even when header values are stripped.
    """
    return [name.lower() for name, _ in headers_items]


def header_order_hash(header_names: List[str]) -> str:
    """Compute a stable hash of the header ordering for compact comparison."""
    joined = "|".join(header_names)
    return hashlib.sha256(joined.encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# 5. Error text extraction (strip HTML, extract first N chars)
# ---------------------------------------------------------------------------

HTML_TAG_RE = re.compile(r"<[^>]+>")
WHITESPACE_RE = re.compile(r"\s+")


def extract_error_text(body: str, max_length: int = 512) -> str:
    """
    Strip HTML tags from an error response body and return the first
    max_length characters of the resulting text.

    Useful for pattern matching against known error message formats.
    """
    text = HTML_TAG_RE.sub(" ", body)
    text = WHITESPACE_RE.sub(" ", text).strip()
    return text[:max_length]


# ---------------------------------------------------------------------------
# 6. Stack trace detection
# ---------------------------------------------------------------------------

STACK_TRACE_PATTERNS = [
    # Node.js / JavaScript
    re.compile(r"at\s+\S+\s+\([^)]+:\d+:\d+\)"),           # "at functionName (/path/file.js:10:5)"
    re.compile(r"at\s+\S+\s+\(\S+\.js:\d+:\d+\)"),          # "at Object.<anonymous> (app.js:15:3)"
    # Python
    re.compile(r'File\s+"[^"]+",\s+line\s+\d+'),             # 'File "/path/file.py", line 42'
    re.compile(r"Traceback \(most recent call last\)"),
    # Java / JVM
    re.compile(r"at\s+[\w.$]+\([\w.]+\.java:\d+\)"),         # "at com.example.Main(Main.java:15)"
    re.compile(r"Caused by:\s+[\w.]+Exception"),
    # Go
    re.compile(r"goroutine\s+\d+\s+\[running\]"),
    re.compile(r"\S+\.go:\d+"),                                # "main.go:42"
    # Rust
    re.compile(r"thread\s+'[^']+'\s+panicked\s+at"),
    # Generic
    re.compile(r"(?:Error|Exception|Panic|Fatal):\s+.{10,}", re.IGNORECASE),
]


def detect_stack_trace(body: str) -> bool:
    """
    Check whether the response body contains patterns indicative of a
    stack trace or debug error output. This is valuable because:
      1. Stack traces often leak exact version strings
      2. The stack trace format reveals the runtime language/framework
      3. Debug mode indicates a development or misconfigured deployment
    """
    for pattern in STACK_TRACE_PATTERNS:
        if pattern.search(body):
            return True
    return False


# ---------------------------------------------------------------------------
# 7. Known error message patterns for OpenClaw family
# ---------------------------------------------------------------------------
# These would be populated from lab captures and used as condition values.

KNOWN_ERROR_PATTERNS = {
    "express_default_404": "Cannot GET",           # Express.js default 404
    "express_default_post_404": "Cannot POST",     # Express.js default POST 404
    "go_default_404": "404 page not found",        # Go net/http default
    "flask_default_404": "Not Found",              # Flask default
    "fastapi_default_404": '"detail":"Not Found"', # FastAPI default JSON 404
    "spring_default_404": '"status":404',          # Spring Boot default JSON 404
    "nextjs_default_404": "This page could not be found",  # Next.js
    "nginx_default_404": "<center>nginx</center>", # nginx default 404 page
}


# ---------------------------------------------------------------------------
# 8. New condition types for the rules engine
# ---------------------------------------------------------------------------
# Add these to _condition_matches() in inference.py

PROPOSED_ERROR_CONDITIONS = """
    if condition_type == "error_pattern":
        # Regex match against the stripped error text
        pattern = re.compile(condition["value"], re.IGNORECASE)
        return any(
            obs.error_text and pattern.search(obs.error_text)
            for obs in candidate_observations
        )

    if condition_type == "header_order":
        # Match exact header ordering (as pipe-delimited string)
        expected = condition["value"].lower()
        return any(
            "|".join(obs.header_order) == expected
            for obs in candidate_observations
        )

    if condition_type == "header_order_prefix":
        # Match the first N headers in order
        expected_prefix = condition["value"].lower().split("|")
        return any(
            obs.header_order[:len(expected_prefix)] == expected_prefix
            for obs in candidate_observations
        )

    if condition_type == "body_contains":
        # Substring match on raw response body text (more flexible than body_hash)
        needle = condition["value"].lower()
        return any(
            obs.error_text and needle in obs.error_text.lower()
            for obs in candidate_observations
        )

    if condition_type == "has_stack_trace":
        expected = condition.get("value", True)
        return any(
            obs.has_stack_trace == expected
            for obs in candidate_observations
        )

    if condition_type == "method_status":
        # Match a specific HTTP method + status code combination
        expected_method = condition["method"].upper()
        expected_statuses = {int(s) for s in condition.get("statuses", [])}
        return any(
            obs.method == expected_method and obs.status in expected_statuses
            for obs in candidate_observations
        )
"""


# ---------------------------------------------------------------------------
# 9. Example fingerprint rules using error response conditions
# ---------------------------------------------------------------------------

EXAMPLE_ERROR_RULES = [
    {
        "id": "openclaw-express-error-pattern",
        "family": "openclaw_express_backend",
        "label": "OpenClaw gateway with Express.js-style error responses",
        "confidence": 0.80,
        "notes": "Detected by the distinctive 'Cannot GET' / 'Cannot POST' error "
                 "pattern returned by Express.js default error handler on unknown routes.",
        "all": [
            {
                "type": "title_contains",
                "path": "/",
                "value": "OpenClaw Control",
            },
            {
                "type": "error_pattern",
                "path": "/api/doesnotexist",
                "value": "Cannot GET",
            },
        ],
    },
    {
        "id": "openclaw-json-error-keys",
        "family": "openclaw_api_error_format",
        "label": "OpenClaw gateway with structured JSON error responses",
        "confidence": 0.82,
        "notes": "API endpoints return JSON errors with 'error' and 'message' keys, "
                 "indicating a specific error handling middleware.",
        "all": [
            {
                "type": "path_status",
                "path": "/api/doesnotexist",
                "statuses": [404],
            },
            {
                "type": "json_key",
                "path": "/api/doesnotexist",
                "value": "error",
            },
            {
                "type": "json_key",
                "path": "/api/doesnotexist",
                "value": "message",
            },
        ],
    },
    {
        "id": "openclaw-header-order-node",
        "family": "openclaw_node_header_order",
        "label": "OpenClaw gateway with Node.js-characteristic header ordering",
        "confidence": 0.70,
        "notes": "Node.js/Express typically returns headers in the order: "
                 "x-powered-by, content-type, date, connection, ... "
                 "Replace with actual observed ordering from lab captures.",
        "all": [
            {
                "type": "header_order_prefix",
                "path": "/",
                "value": "x-powered-by|content-type|date",
                # ^^^ PLACEHOLDER — replace with actual lab-captured ordering
            },
        ],
    },
    {
        "id": "openclaw-debug-mode-leak",
        "family": "openclaw_debug_mode",
        "label": "OpenClaw gateway running in debug/development mode (stack trace leak)",
        "confidence": 0.88,
        "notes": "Debug mode deployments leak stack traces in error responses, "
                 "which often contain exact version strings and file paths.",
        "all": [
            {
                "type": "title_contains",
                "path": "/",
                "value": "OpenClaw Control",
            },
            {
                "type": "has_stack_trace",
                "path": "/api/doesnotexist",
                "value": True,
            },
        ],
    },
]
