"""
Proposed Change: Additional Probe Paths for OpenClaw Gateway Detection
======================================================================
Date: 2026-03-24
Research topic: #1 Additional probe paths

This file contains proposed new probe configurations to add to
openclaw_scanner/probe.py's DEFAULT_PROBE_CONFIGS list, along with
example fingerprint rules that leverage responses from these new paths.

These paths were selected based on research into common IoT gateway
endpoints, well-known discovery paths (RFC 9116, OWASP WSTG), API
documentation conventions, monitoring/debug endpoints, and OpenClaw-
specific surfaces referenced in known CVEs.
"""

# ── New ProbeConfig entries to add to DEFAULT_PROBE_CONFIGS ──────────

PROPOSED_NEW_PROBE_CONFIGS = [
    # ── High Priority: OpenClaw-specific API surfaces ──
    # The /api/skills path maps directly to CVE-2026-26326 (skills.status
    # config disclosure). Even a 401/403 confirms endpoint existence.
    {"path": "/api/skills", "method": "GET"},

    # Agent management is a core OpenClaw feature; multiple CVEs target
    # the agent_runtime surface (CVE-2026-27001, CVE-2026-29607, etc.)
    {"path": "/api/agents", "method": "GET"},

    # Device management endpoint — OpenClaw manages "devices" that pair
    # with the gateway (CVE-2026-32042 references device identities)
    {"path": "/api/devices", "method": "GET"},

    # Configuration endpoint — likely auth-protected, but the specific
    # 401/403 response format is itself a fingerprint signal
    {"path": "/api/config", "method": "GET"},

    # System info endpoint — common in IoT gateways for exposing firmware
    # version, model, uptime, etc.
    {"path": "/api/system/info", "method": "GET"},

    # ── High Priority: Monitoring & Schema Endpoints ──
    # Prometheus metrics endpoint. If present, typically contains:
    # - go_info{version="go1.x.y"} (pins Go runtime version)
    # - process_start_time_seconds (uptime information)
    # - Application-specific counters with product-identifying labels
    {"path": "/metrics", "method": "GET"},

    # OpenAPI/Swagger spec — if present, contains product name in
    # info.title and version in info.version; extremely high value
    {"path": "/swagger.json", "method": "GET"},

    # SPA runtime configuration file — many deployment patterns inject
    # version strings, API base URLs, and feature flags here
    {"path": "/env.js", "method": "GET"},

    # ── Medium Priority: Well-Known & Standard Paths ──
    # RFC 9116 security policy file. May contain vendor contact info.
    {"path": "/.well-known/security.txt", "method": "GET"},

    # Robots exclusion — framework-specific defaults are informative
    {"path": "/robots.txt", "method": "GET"},

    # Go runtime debug endpoints — mere presence confirms Go runtime
    {"path": "/debug/pprof", "method": "GET"},
    {"path": "/debug/pprof/", "method": "GET"},

    # WebSocket endpoint existence check (standard GET, not upgrade)
    {"path": "/ws", "method": "GET"},

    # Socket.IO transport negotiation — returns distinctive JSON
    # {"sid":"...","upgrades":["websocket"],...} if present
    {"path": "/socket.io/", "method": "GET"},

    # ── Low Priority: Additional Discovery Paths ──
    # GraphQL endpoint
    {"path": "/api/graphql", "method": "GET"},

    # API documentation UI
    {"path": "/api/docs", "method": "GET"},

    # OpenID Connect discovery (if gateway implements OIDC)
    {"path": "/.well-known/openid-configuration", "method": "GET"},

    # Alternate SPA config path
    {"path": "/config.js", "method": "GET"},
]


# ── Example fingerprint rules leveraging new probe paths ─────────────

PROPOSED_FINGERPRINT_RULES = [
    {
        "id": "openclaw-has-skills-api",
        "family": "openclaw_skills_api",
        "label": "OpenClaw gateway exposes /api/skills endpoint",
        "confidence": 0.80,
        "notes": (
            "The /api/skills endpoint is referenced in CVE-2026-26326. "
            "A non-404 response (200, 401, 403) confirms this endpoint "
            "exists, which is a strong OpenClaw-specific signal."
        ),
        "all": [
            {
                "type": "title_contains",
                "path": "/",
                "value": "Control",
            },
            {
                "type": "path_status",
                "path": "/api/skills",
                "statuses": [200, 401, 403],
            },
        ],
    },
    {
        "id": "openclaw-has-agents-api",
        "family": "openclaw_agents_api",
        "label": "OpenClaw gateway exposes /api/agents endpoint",
        "confidence": 0.78,
        "notes": (
            "Agent management is core OpenClaw functionality. Multiple "
            "CVEs target the agent_runtime surface. A non-404 response "
            "confirms this endpoint."
        ),
        "all": [
            {
                "type": "title_contains",
                "path": "/",
                "value": "Control",
            },
            {
                "type": "path_status",
                "path": "/api/agents",
                "statuses": [200, 401, 403],
            },
        ],
    },
    {
        "id": "openclaw-go-runtime-pprof",
        "family": "openclaw_go_runtime",
        "label": "Gateway exposes Go pprof debug endpoint",
        "confidence": 0.65,
        "notes": (
            "The /debug/pprof/ endpoint is a Go net/http/pprof handler. "
            "Its presence confirms Go as the runtime. Combined with other "
            "OpenClaw signals, this increases confidence. Lower standalone "
            "confidence because other Go apps also expose this."
        ),
        "all": [
            {
                "type": "path_status",
                "path": "/debug/pprof/",
                "statuses": [200],
            },
            {
                "type": "body_contains",
                "path": "/debug/pprof/",
                "value": "pprof",
            },
        ],
    },
    {
        "id": "openclaw-prometheus-metrics",
        "family": "openclaw_prometheus_metrics",
        "label": "Gateway exposes Prometheus metrics with Go runtime info",
        "confidence": 0.60,
        "notes": (
            "Prometheus /metrics endpoint with go_info label indicates "
            "Go runtime. Product-specific metric names (if present) would "
            "increase confidence. Standalone confidence is moderate."
        ),
        "all": [
            {
                "type": "path_status",
                "path": "/metrics",
                "statuses": [200],
            },
            {
                "type": "header_contains",
                "path": "/metrics",
                "header": "content-type",
                "value": "text/plain",
            },
        ],
    },
    {
        "id": "openclaw-swagger-spec-identified",
        "family": "openclaw_swagger_spec",
        "label": "Gateway serves OpenAPI spec with OpenClaw product identifier",
        "confidence": 0.95,
        "notes": (
            "If /swagger.json returns a valid OpenAPI spec with 'openclaw' "
            "or 'claw' in the title or description, this is a near-certain "
            "identification. The spec also contains the version."
        ),
        "all": [
            {
                "type": "path_status",
                "path": "/swagger.json",
                "statuses": [200],
            },
            {
                "type": "header_contains",
                "path": "/swagger.json",
                "header": "content-type",
                "value": "json",
            },
            {
                "type": "marker_present",
                "path": "/swagger.json",
                "value": "openclaw",
            },
        ],
    },
]


# ── New condition type proposal: path_status_not ─────────────────────
# Some rules need to confirm an endpoint does NOT return 404, without
# listing every possible success/error code. A negation condition would
# simplify rules like "any status except 404".

PROPOSED_CONDITION_TYPE_SPEC = {
    "type": "path_status_not",
    "description": (
        "Matches when the response status for the given path is NOT "
        "in the specified list. Useful for confirming endpoint existence "
        "without enumerating all possible success codes."
    ),
    "example": {
        "type": "path_status_not",
        "path": "/api/skills",
        "statuses": [404],
    },
}
