"""
Proposed changes: Timing-Based Fingerprinting
==============================================
Date: 2026-03-24  (Research Run 5, Topic #4)

Adds optional response-time measurement to the probe engine and timing-
based condition types to the rules engine for supplementary fingerprinting.

Key design decisions
--------------------
* Timing is OPT-IN via a --timing CLI flag (default: off) because it
  requires multiple requests per path to get stable medians, which
  increases scan duration and network footprint.
* Absolute times are stored but *relative* timing ratios are the primary
  signal — they cancel out network latency/jitter.
* The timing profile is a dict mapping path pairs to their TTFB ratio.
* WAF/middleware detection is a byproduct: anomalously fast 4xx responses
  (faster than static 200s) suggest an intermediary is short-circuiting
  the request before it reaches the application.

Files affected
--------------
* openclaw_scanner/models.py   — add response_time_ms to ProbeObservation
* openclaw_scanner/probe.py    — measure TTFB, optional multi-sample mode
* openclaw_scanner/inference.py — new condition types
* openclaw_scanner/cli.py       — --timing flag
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# 1.  Model addition — add to ProbeObservation
# ---------------------------------------------------------------------------

# In models.py, add this field to the ProbeObservation dataclass:
#
#     response_time_ms: Optional[float] = None
#     """Wall-clock time-to-first-byte in milliseconds (median of N samples
#     when timing mode is enabled, single sample otherwise)."""


# ---------------------------------------------------------------------------
# 2.  Timing measurement wrapper — add to probe.py
# ---------------------------------------------------------------------------

def measure_ttfb(fetch_fn, *, samples: int = 1) -> Tuple[float, ...]:
    """Call *fetch_fn* up to *samples* times and return the TTFB in ms for
    each call.  The caller should use the **median** to reduce jitter."""
    timings: List[float] = []
    for _ in range(samples):
        start = time.monotonic()
        fetch_fn()
        elapsed_ms = (time.monotonic() - start) * 1000.0
        timings.append(elapsed_ms)
    return tuple(timings)


def median(values: Tuple[float, ...]) -> float:
    """Return the median of a non-empty tuple of floats."""
    ordered = sorted(values)
    n = len(ordered)
    mid = n // 2
    if n % 2 == 0:
        return (ordered[mid - 1] + ordered[mid]) / 2.0
    return ordered[mid]


# In probe.py _fetch(), wrap the urlopen call:
#
#     start = time.monotonic()
#     with urlopen(request, ...) as response:
#         ttfb_ms = (time.monotonic() - start) * 1000.0
#         ...
#     observation.response_time_ms = ttfb_ms
#
# When --timing is enabled, probe_candidate() should call _fetch() N times
# per probe (default N=3) and store the median TTFB.


# ---------------------------------------------------------------------------
# 3.  Timing profile computation
# ---------------------------------------------------------------------------

@dataclass
class TimingProfile:
    """Timing ratios between paths, relative to the root path."""
    root_ms: float
    path_ratios: Dict[str, float] = field(default_factory=dict)
    anomalies: List[str] = field(default_factory=list)


def compute_timing_profile(
    observations: Dict[str, "ProbeObservation"],  # type: ignore[name-defined]
) -> Optional[TimingProfile]:
    """Compute timing ratios relative to the root path.

    Returns None if timing data is unavailable or the root path has no
    timing measurement.
    """
    root_obs = observations.get("/")
    if root_obs is None or root_obs.response_time_ms is None:
        return None

    root_ms = root_obs.response_time_ms
    if root_ms <= 0:
        return None

    profile = TimingProfile(root_ms=root_ms)

    for path, obs in observations.items():
        if path == "/" or obs.response_time_ms is None:
            continue
        ratio = obs.response_time_ms / root_ms
        profile.path_ratios[path] = round(ratio, 3)

        # Anomaly detection: 4xx response faster than root suggests
        # middleware/WAF interception
        if obs.status is not None and obs.status >= 400:
            if obs.response_time_ms < root_ms * 0.5:
                profile.anomalies.append(
                    f"{path} returned {obs.status} in {obs.response_time_ms:.0f}ms "
                    f"({ratio:.2f}x root) — possible WAF/middleware interception"
                )

    return profile


# ---------------------------------------------------------------------------
# 4.  New condition types for inference.py
# ---------------------------------------------------------------------------

# Add these condition type handlers inside _condition_matches():

def _timing_ratio_gt(condition, observations, _version_hints) -> bool:
    """True if the timing ratio (path_ms / reference_path_ms) exceeds
    the threshold.

    Rule format:
        {
            "type": "timing_ratio_gt",
            "path": "/api/version",
            "reference_path": "/",
            "value": 2.0
        }
    """
    target_path = condition["path"]
    ref_path = condition.get("reference_path", "/")
    threshold = float(condition["value"])

    target_obs = observations.get(target_path)
    ref_obs = observations.get(ref_path)
    if (
        target_obs is None
        or ref_obs is None
        or target_obs.response_time_ms is None
        or ref_obs.response_time_ms is None
        or ref_obs.response_time_ms <= 0
    ):
        return False

    ratio = target_obs.response_time_ms / ref_obs.response_time_ms
    return ratio > threshold


def _timing_ratio_lt(condition, observations, _version_hints) -> bool:
    """True if the timing ratio (path_ms / reference_path_ms) is below
    the threshold.  Useful for detecting WAF-intercepted paths.

    Rule format:
        {
            "type": "timing_ratio_lt",
            "path": "/api/doesnotexist",
            "reference_path": "/",
            "value": 0.5
        }
    """
    target_path = condition["path"]
    ref_path = condition.get("reference_path", "/")
    threshold = float(condition["value"])

    target_obs = observations.get(target_path)
    ref_obs = observations.get(ref_path)
    if (
        target_obs is None
        or ref_obs is None
        or target_obs.response_time_ms is None
        or ref_obs.response_time_ms is None
        or ref_obs.response_time_ms <= 0
    ):
        return False

    ratio = target_obs.response_time_ms / ref_obs.response_time_ms
    return ratio < threshold


def _has_server_timing_header(condition, observations, _version_hints) -> bool:
    """True if the Server-Timing header is present on the specified path.

    Rule format:
        {"type": "has_server_timing", "path": "/api/status"}
    """
    target_path = condition.get("path")
    for obs in observations.values():
        if target_path and obs.path != target_path:
            continue
        if "server-timing" in obs.headers:
            return True
    return False


def _timing_fast_error(condition, observations, _version_hints) -> bool:
    """True if any 4xx/5xx response on the path is faster than half the
    root TTFB — indicates WAF or middleware interception.

    Rule format:
        {"type": "timing_fast_error", "path": "/api/doesnotexist"}
    """
    root_obs = observations.get("/")
    if root_obs is None or root_obs.response_time_ms is None:
        return False

    target_path = condition.get("path")
    for obs in observations.values():
        if target_path and obs.path != target_path:
            continue
        if (
            obs.status is not None
            and obs.status >= 400
            and obs.response_time_ms is not None
            and obs.response_time_ms < root_obs.response_time_ms * 0.5
        ):
            return True
    return False


# ---------------------------------------------------------------------------
# 5.  Example fingerprint rules using timing conditions
# ---------------------------------------------------------------------------

EXAMPLE_TIMING_RULES = [
    {
        "id": "openclaw-spa-timing-signature",
        "family": "openclaw_spa_timing",
        "label": "OpenClaw SPA with characteristic timing profile — API paths slower than root",
        "confidence": 0.55,
        "notes": (
            "SPA-based gateways like OpenClaw serve the same HTML shell for "
            "all routes (fast static response), but API routes that hit "
            "application logic are measurably slower. A ratio > 1.5x on "
            "/api/status vs / suggests an active API backend behind the SPA. "
            "Low confidence — timing alone is not definitive."
        ),
        "all": [
            {
                "type": "title_contains",
                "path": "/",
                "value": "OpenClaw Control"
            },
            {
                "type": "timing_ratio_gt",
                "path": "/api/status",
                "reference_path": "/",
                "value": 1.5
            }
        ]
    },
    {
        "id": "waf-intercepted-404-detection",
        "family": "waf_interception_detected",
        "label": "WAF/middleware intercepting 404 responses — anomalously fast error",
        "confidence": 0.40,
        "notes": (
            "A 404 response on /api/doesnotexist that arrives faster than "
            "half the root TTFB suggests a WAF or reverse proxy is "
            "generating the error before the request reaches the application. "
            "This is a proxy-detection signal, not a product fingerprint."
        ),
        "all": [
            {
                "type": "path_status",
                "path": "/api/doesnotexist",
                "statuses": [404]
            },
            {
                "type": "timing_fast_error",
                "path": "/api/doesnotexist"
            }
        ]
    },
]


# ---------------------------------------------------------------------------
# 6.  CLI integration sketch
# ---------------------------------------------------------------------------

# In cli.py, add:
#
# parser.add_argument(
#     "--timing",
#     action="store_true",
#     default=False,
#     help="Enable timing-based fingerprinting (measures TTFB per probe, "
#          "3 samples each). Increases scan duration ~3x.",
# )
# parser.add_argument(
#     "--timing-samples",
#     type=int,
#     default=3,
#     metavar="N",
#     help="Number of timing samples per probe (default: 3).",
# )
#
# When --timing is set, probe_candidate() should run each probe N times
# and record the median TTFB on the ProbeObservation.


# ---------------------------------------------------------------------------
# 7.  Future: JA4T TCP fingerprinting
# ---------------------------------------------------------------------------

# JA4T requires raw socket access (SYN packet crafting) and is best
# implemented as an optional external tool integration:
#
# 1. Check if `ja4tscan` binary is available on PATH
# 2. Shell out to: ja4tscan --json <target_ip>:<port>
# 3. Parse the JSON output for the JA4T fingerprint string
# 4. Store in a new `ja4t` field on the scan result
# 5. Add `ja4t_hash` and `ja4t_prefix` condition types
#
# This is deferred due to the external dependency and raw socket
# requirement (may need root/CAP_NET_RAW privileges).
