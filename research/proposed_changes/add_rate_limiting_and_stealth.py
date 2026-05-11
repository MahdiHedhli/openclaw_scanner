"""
Proposed changes: Rate Limiting, WAF Evasion, and Scan Stealth
==============================================================

Research date: 2026-03-25
Topic: #13 — Rate limiting and WAF evasion

This file contains proposed implementations for making the OpenClaw Scanner
more resilient to rate limiting, WAF detection, and IDS alerting.

Changes are organized into independent modules that can be integrated
into the existing scanner architecture.
"""

import random
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# 1. User-Agent Rotation Pool
# ---------------------------------------------------------------------------

# 25 realistic User-Agent strings from current browser versions (2025-2026)
# Mix of Chrome, Firefox, Safari, Edge across Windows, macOS, Linux
USER_AGENT_POOL = [
    # Chrome on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
    # Chrome on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    # Chrome on Linux
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    # Firefox on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
    # Firefox on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:132.0) Gecko/20100101 Firefox/132.0",
    # Firefox on Linux
    "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0",
    # Safari on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
    # Edge on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0",
    # Edge on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
    # Chrome on Android (mobile representation)
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
    # Safari on iOS
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1",
    # Brave (Chrome-based)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Brave/131",
    # Vivaldi
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Vivaldi/7.0",
    # Opera
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 OPR/117.0.0.0",
    # Older Chrome (for diversity)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
]


def get_random_user_agent() -> str:
    """Return a random User-Agent string from the pool."""
    return random.choice(USER_AGENT_POOL)


# ---------------------------------------------------------------------------
# 2. Scan Speed Profiles
# ---------------------------------------------------------------------------

@dataclass
class ScanSpeedProfile:
    """Configuration for a named scan speed profile."""
    name: str
    delay_ms: int               # Base delay between probes to same target
    max_concurrent_per_host: int # Max parallel connections per target
    max_retries: int            # Max retries on transient errors
    jitter_ms: int              # Random jitter added to delays
    rotate_user_agent: bool     # Whether to rotate UA per request
    randomize_probe_order: bool # Whether to shuffle probe path order
    description: str = ""


# Modeled after nmap's T0-T5 but adapted for HTTP fingerprinting
SCAN_SPEED_PROFILES: Dict[str, ScanSpeedProfile] = {
    "paranoid": ScanSpeedProfile(
        name="paranoid",
        delay_ms=5000,
        max_concurrent_per_host=1,
        max_retries=1,
        jitter_ms=2000,
        rotate_user_agent=True,
        randomize_probe_order=True,
        description="Maximum stealth. 5s+ between probes. For IDS-monitored targets.",
    ),
    "slow": ScanSpeedProfile(
        name="slow",
        delay_ms=1500,
        max_concurrent_per_host=1,
        max_retries=2,
        jitter_ms=750,
        rotate_user_agent=True,
        randomize_probe_order=True,
        description="Slow scan. ~1.5s between probes. Good for WAF-protected targets.",
    ),
    "polite": ScanSpeedProfile(
        name="polite",
        delay_ms=400,
        max_concurrent_per_host=2,
        max_retries=3,
        jitter_ms=200,
        rotate_user_agent=True,
        randomize_probe_order=True,
        description="Polite scan. ~400ms between probes. Recommended for internet scanning.",
    ),
    "normal": ScanSpeedProfile(
        name="normal",
        delay_ms=100,
        max_concurrent_per_host=4,
        max_retries=3,
        jitter_ms=50,
        rotate_user_agent=False,
        randomize_probe_order=False,
        description="Normal speed. No artificial delays beyond 100ms. Default profile.",
    ),
    "fast": ScanSpeedProfile(
        name="fast",
        delay_ms=0,
        max_concurrent_per_host=8,
        max_retries=2,
        jitter_ms=0,
        rotate_user_agent=False,
        randomize_probe_order=False,
        description="Maximum speed. No delays. For lab/local network use only.",
    ),
}


def get_scan_profile(name: str) -> ScanSpeedProfile:
    """Get a scan speed profile by name. Defaults to 'normal'."""
    return SCAN_SPEED_PROFILES.get(name.lower(), SCAN_SPEED_PROFILES["normal"])


# ---------------------------------------------------------------------------
# 3. Adaptive Rate Limiter (per-host)
# ---------------------------------------------------------------------------

@dataclass
class HostRateState:
    """Tracks rate limiting state for a single target host."""
    last_request_time: float = 0.0
    consecutive_errors: int = 0
    current_delay_ms: int = 0
    is_circuit_open: bool = False
    total_probes_sent: int = 0
    total_probes_succeeded: int = 0
    total_probes_failed: int = 0


class AdaptiveRateLimiter:
    """
    Per-host adaptive rate limiter with exponential backoff and circuit breaker.

    Usage:
        limiter = AdaptiveRateLimiter(profile=get_scan_profile("polite"))

        for target in targets:
            for probe in probes:
                limiter.wait_before_request(target)
                response = send_probe(target, probe)
                limiter.record_result(target, response.status_code)
                if limiter.is_target_blocked(target):
                    break  # Skip remaining probes for this target
    """

    # Status codes that indicate rate limiting or blocking
    RATE_LIMIT_CODES = {429}
    TRANSIENT_ERROR_CODES = {429, 503, 502, 504}
    CIRCUIT_BREAKER_THRESHOLD = 5  # consecutive failures to open circuit

    def __init__(self, profile: ScanSpeedProfile):
        self.profile = profile
        self._host_states: Dict[str, HostRateState] = {}

    def _get_state(self, host: str) -> HostRateState:
        if host not in self._host_states:
            self._host_states[host] = HostRateState(
                current_delay_ms=self.profile.delay_ms,
            )
        return self._host_states[host]

    def wait_before_request(self, host: str) -> None:
        """Sleep for the appropriate delay before sending a request to host."""
        state = self._get_state(host)
        if state.last_request_time > 0:
            elapsed_ms = (time.time() - state.last_request_time) * 1000
            required_delay = state.current_delay_ms
            if self.profile.jitter_ms > 0:
                required_delay += random.randint(0, self.profile.jitter_ms)
            remaining = required_delay - elapsed_ms
            if remaining > 0:
                time.sleep(remaining / 1000.0)
        state.last_request_time = time.time()
        state.total_probes_sent += 1

    def record_result(
        self, host: str, status_code: Optional[int], error: Optional[str] = None
    ) -> None:
        """Record the result of a probe and adjust rate limiting accordingly."""
        state = self._get_state(host)

        if error or (status_code and status_code in self.TRANSIENT_ERROR_CODES):
            state.consecutive_errors += 1
            state.total_probes_failed += 1

            # Exponential backoff: double the delay on each consecutive error
            backoff_delay = self.profile.delay_ms * (2 ** state.consecutive_errors)
            # Cap at 30 seconds
            state.current_delay_ms = min(backoff_delay, 30000)

            # Circuit breaker: stop scanning this host after too many failures
            if state.consecutive_errors >= self.CIRCUIT_BREAKER_THRESHOLD:
                state.is_circuit_open = True
        else:
            state.consecutive_errors = 0
            state.current_delay_ms = self.profile.delay_ms
            state.total_probes_succeeded += 1

    def is_target_blocked(self, host: str) -> bool:
        """Check if a target should be skipped due to circuit breaker."""
        return self._get_state(host).is_circuit_open

    def should_retry(self, host: str, status_code: Optional[int]) -> bool:
        """Check if a failed probe should be retried."""
        state = self._get_state(host)
        if state.is_circuit_open:
            return False
        if state.consecutive_errors > self.profile.max_retries:
            return False
        if status_code and status_code in self.TRANSIENT_ERROR_CODES:
            return True
        return False

    def get_scan_completeness(self, host: str, total_probes: int) -> float:
        """Return the fraction of probes that succeeded for a host."""
        state = self._get_state(host)
        if total_probes == 0:
            return 0.0
        return state.total_probes_succeeded / total_probes

    def get_host_summary(self, host: str) -> Dict:
        """Return a summary of rate limiting state for a host."""
        state = self._get_state(host)
        return {
            "host": host,
            "probes_sent": state.total_probes_sent,
            "probes_succeeded": state.total_probes_succeeded,
            "probes_failed": state.total_probes_failed,
            "circuit_open": state.is_circuit_open,
            "current_delay_ms": state.current_delay_ms,
        }


# ---------------------------------------------------------------------------
# 4. Probe Order Randomization
# ---------------------------------------------------------------------------

def randomize_probe_order(
    probe_configs: List, seed: Optional[int] = None
) -> List:
    """
    Return a shuffled copy of probe configs.

    Keeps the root path "/" first (it's needed for basic signal detection)
    and randomizes the rest.
    """
    if not probe_configs:
        return probe_configs

    shuffled = list(probe_configs)
    # Separate root probe from the rest
    root_probes = [p for p in shuffled if getattr(p, 'path', '') == '/']
    other_probes = [p for p in shuffled if getattr(p, 'path', '') != '/']

    rng = random.Random(seed)
    rng.shuffle(other_probes)

    return root_probes + other_probes


# ---------------------------------------------------------------------------
# 5. Request Header Randomization
# ---------------------------------------------------------------------------

ACCEPT_HEADERS = [
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "text/html, application/xhtml+xml, application/xml;q=0.9, */*;q=0.8",
]

ACCEPT_LANGUAGE_HEADERS = [
    "en-US,en;q=0.9",
    "en-US,en;q=0.5",
    "en-GB,en;q=0.9,en-US;q=0.8",
    "en,en-US;q=0.9",
    "en-US",
]

ACCEPT_ENCODING_HEADERS = [
    "gzip, deflate, br",
    "gzip, deflate, br, zstd",
    "gzip, deflate",
]


def build_stealth_headers(user_agent: Optional[str] = None) -> Dict[str, str]:
    """
    Build a set of realistic browser-like headers for a single request.

    If user_agent is None, a random one is selected from the pool.
    """
    headers = {
        "User-Agent": user_agent or get_random_user_agent(),
        "Accept": random.choice(ACCEPT_HEADERS),
        "Accept-Language": random.choice(ACCEPT_LANGUAGE_HEADERS),
        "Accept-Encoding": random.choice(ACCEPT_ENCODING_HEADERS),
        "Connection": "keep-alive",
    }
    # Occasionally add optional headers for realism
    if random.random() < 0.3:
        headers["DNT"] = "1"
    if random.random() < 0.4:
        headers["Upgrade-Insecure-Requests"] = "1"

    return headers


# ---------------------------------------------------------------------------
# 6. WAF Detection Heuristics
# ---------------------------------------------------------------------------

# Known WAF/CDN indicator headers (lowercase)
WAF_INDICATOR_HEADERS = {
    "cf-ray": "Cloudflare",
    "cf-cache-status": "Cloudflare",
    "x-sucuri-id": "Sucuri",
    "x-sucuri-cache": "Sucuri",
    "x-akamai-transformed": "Akamai",
    "x-cdn": "Generic CDN",
    "x-amzn-trace-id": "AWS ALB/CloudFront",
    "x-amzn-requestid": "AWS ALB/CloudFront",
    "x-azure-ref": "Azure Front Door",
    "x-ms-request-id": "Azure",
    "x-cache": "CDN Cache",
    "x-served-by": "Fastly/Varnish",
    "x-timer": "Fastly",
    "x-varnish": "Varnish",
    "x-kong-proxy-latency": "Kong",
    "x-ratelimit-limit": "Rate Limiter Active",
    "x-ratelimit-remaining": "Rate Limiter Active",
    "retry-after": "Rate Limiter Active",
}

# Server header values that indicate WAF/proxy (lowercase substring match)
WAF_SERVER_SIGNATURES = [
    "cloudflare",
    "akamaighost",
    "sucuri",
    "incapsula",
    "imperva",
    "barracuda",
    "f5 big-ip",
    "citrix",
    "fortinet",
    "aws",
    "awselb",
]


@dataclass
class WafDetectionResult:
    """Result of WAF/CDN detection analysis."""
    waf_detected: bool = False
    waf_name: Optional[str] = None
    rate_limiter_detected: bool = False
    confidence: float = 0.0
    indicators: List[str] = field(default_factory=list)
    recommendation: str = ""


def detect_waf_from_headers(headers: Dict[str, str]) -> WafDetectionResult:
    """
    Analyze response headers to detect WAF/CDN presence.

    This function should be called on the first successful response from a target.
    If WAF is detected, the scanner should switch to a more conservative scan profile.
    """
    result = WafDetectionResult()
    normalized = {k.lower(): v for k, v in headers.items()}

    # Check for WAF indicator headers
    for header_name, waf_name in WAF_INDICATOR_HEADERS.items():
        if header_name in normalized:
            result.indicators.append(f"Header '{header_name}' → {waf_name}")
            if not result.waf_name:
                result.waf_name = waf_name
            if "rate limit" in waf_name.lower():
                result.rate_limiter_detected = True

    # Check Server header
    server = normalized.get("server", "").lower()
    for signature in WAF_SERVER_SIGNATURES:
        if signature in server:
            result.indicators.append(f"Server header contains '{signature}'")
            if not result.waf_name:
                result.waf_name = signature.title()

    # Confidence scoring
    if result.indicators:
        result.waf_detected = True
        result.confidence = min(0.95, 0.4 + 0.15 * len(result.indicators))

    # Recommendation
    if result.waf_detected and result.rate_limiter_detected:
        result.recommendation = (
            "WAF with active rate limiting detected. "
            "Recommend switching to 'slow' or 'paranoid' scan profile."
        )
    elif result.waf_detected:
        result.recommendation = (
            "WAF/CDN detected. Recommend switching to 'polite' scan profile "
            "and enabling User-Agent rotation."
        )
    else:
        result.recommendation = "No WAF detected. Normal scan profile is appropriate."

    return result


# ---------------------------------------------------------------------------
# 7. Scan Completeness Metric
# ---------------------------------------------------------------------------

@dataclass
class ScanCompletenessReport:
    """Report on how complete a scan was for a given target."""
    target: str
    total_probes_planned: int
    total_probes_completed: int
    total_probes_blocked: int
    total_probes_errored: int
    completeness_ratio: float  # 0.0 to 1.0
    was_circuit_broken: bool
    waf_detected: bool
    effective_scan_profile: str

    @property
    def is_partial(self) -> bool:
        return self.completeness_ratio < 1.0

    @property
    def quality_label(self) -> str:
        if self.completeness_ratio >= 0.95:
            return "complete"
        elif self.completeness_ratio >= 0.7:
            return "mostly_complete"
        elif self.completeness_ratio >= 0.4:
            return "partial"
        else:
            return "minimal"


# ---------------------------------------------------------------------------
# 8. Proposed CLI Flags
# ---------------------------------------------------------------------------

"""
Proposed new CLI arguments for scan.py:

  --scan-speed {paranoid,slow,polite,normal,fast}
      Named scan speed profile. Default: normal.

  --delay MILLISECONDS
      Override per-host delay between probes (overrides --scan-speed delay).

  --max-retries N
      Maximum retries on transient errors per probe. Default: 3.

  --rotate-ua
      Enable User-Agent rotation (random UA per request).

  --randomize-probes
      Randomize probe path order per target.

  --stealth
      Shorthand for: --scan-speed polite --rotate-ua --randomize-probes
      Enables all stealth features with sensible defaults.

  --proxy-list FILE
      Path to a file containing SOCKS5/HTTP proxy URLs, one per line.
      Probes will be distributed across proxies.

  --max-connections-per-host N
      Maximum concurrent connections to a single target. Default: 4.
"""


# ---------------------------------------------------------------------------
# 9. Integration Points
# ---------------------------------------------------------------------------

"""
How to integrate these changes into the existing scanner:

1. probe.py — _fetch() function:
   - Accept optional `stealth_headers` parameter
   - If stealth mode, use build_stealth_headers() instead of fixed UA
   - Add response_time_ms measurement (start_time = time.monotonic())

2. probe.py — probe_candidate() function:
   - Accept AdaptiveRateLimiter instance
   - Call limiter.wait_before_request() before each probe
   - Call limiter.record_result() after each probe
   - Check limiter.is_target_blocked() to short-circuit
   - If profile.randomize_probe_order, shuffle probes

3. scan.py — main scan loop:
   - Create AdaptiveRateLimiter with selected profile
   - On first response from target, call detect_waf_from_headers()
   - If WAF detected, optionally switch to slower profile
   - After scan, generate ScanCompletenessReport per target
   - Add completeness info to JSON output

4. models.py — ProbeObservation:
   - Add response_time_ms: Optional[float] field
   - Add user_agent_used: Optional[str] field (for debugging)

5. models.py — ScanResult:
   - Add scan_completeness: float field
   - Add waf_detected: Optional[str] field
   - Add scan_profile_used: str field
"""
