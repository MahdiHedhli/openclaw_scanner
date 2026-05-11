"""
Proposed addition: Passive TCP/IP Stack Fingerprinting via JA4TScan
====================================================================
Research date: 2026-03-26
Topic: Cross-cutting X2 — Passive TCP/IP Stack Fingerprinting

This module adds JA4TScan-based TCP server fingerprinting to the scanner.
JA4TScan sends a single crafted SYN packet per target and captures the
SYN-ACK response attributes plus retransmission timing to build a robust
server fingerprint. This identifies OS, runtime, and intermediary proxies.

Requirements:
- Optional dependency: ja4tscan (FoxIO-LLC/ja4tscan) or scapy for raw packet capture
- CAP_NET_RAW capability (root or setcap) for raw socket access
- Gated behind --ja4t CLI flag (opt-in only)

Integration points:
- New field `ja4tscan` on ScanResult model
- New condition types in rules engine: `ja4tscan_prefix`, `ja4tscan_retransmit`
- Cross-references with JARM (Topic #7) and HTTP/2 SETTINGS (Topic #3)
"""

from dataclasses import dataclass, field
from typing import Optional, List, Dict
from enum import Enum


# ---------------------------------------------------------------------------
# Known TCP stack profiles (from JA4TScan documentation and research)
# ---------------------------------------------------------------------------

class TcpStackProfile(Enum):
    """Known TCP stack profiles identified by JA4TScan fingerprints."""
    LINUX_5X = "linux_5x"
    LINUX_6X = "linux_6x"
    WINDOWS_SERVER_2022 = "win_server_2022"
    WINDOWS_11 = "win_11"
    MACOS_14 = "macos_14"
    GO_RUNTIME = "go_runtime"       # Go net/http uses OS stack but with specific tuning
    NODEJS_RUNTIME = "nodejs"       # Node.js inherits OS TCP defaults
    ALPINE_MUSL = "alpine_musl"     # Alpine Linux with musl libc has distinct TCP behavior
    UNKNOWN = "unknown"


@dataclass
class TcpFingerprint:
    """Represents a JA4TScan-style TCP server fingerprint."""

    # Core SYN-ACK attributes
    initial_ttl: Optional[int] = None           # Original TTL (inferred from observed)
    window_size: Optional[int] = None           # TCP window size in SYN-ACK
    mss: Optional[int] = None                   # Maximum Segment Size
    window_scale: Optional[int] = None          # Window Scale factor
    tcp_options_order: Optional[str] = None     # Ordered list of TCP options (e.g., "MSS,NOP,WS,NOP,NOP,TS,NOP,NOP,SACK")
    df_bit: Optional[bool] = None               # Don't Fragment bit set
    tcp_timestamps: Optional[bool] = None       # TCP Timestamps option present
    sack_permitted: Optional[bool] = None       # SACK Permitted option present

    # Retransmission timing (JA4TScan-specific)
    retransmit_intervals: List[float] = field(default_factory=list)  # Seconds between SYN-ACK retransmissions
    retransmit_count: int = 0                   # Number of retransmissions observed

    # Computed fingerprint
    ja4tscan_hash: Optional[str] = None         # Full JA4TScan fingerprint string

    # Inferred attributes
    inferred_os: Optional[str] = None           # Inferred OS from TCP stack
    inferred_profile: TcpStackProfile = TcpStackProfile.UNKNOWN
    confidence: float = 0.0


# ---------------------------------------------------------------------------
# Known retransmission timing signatures
# ---------------------------------------------------------------------------

KNOWN_RETRANSMIT_PATTERNS: Dict[str, List[float]] = {
    # Linux (net.ipv4.tcp_syn_retries default = 6, exponential backoff)
    "linux_default": [1.0, 2.0, 4.0, 8.0, 16.0, 32.0],
    # Windows (TcpMaxConnectRetransmissions default = 2-3, shorter)
    "windows_default": [1.0, 2.0, 4.0, 8.0, 16.0],
    # macOS (net.inet.tcp.rexmt_slop, different timing)
    "macos_default": [1.0, 1.0, 2.0, 4.0, 8.0, 16.0],
    # Go net/http (inherits OS but may have custom KeepAlive settings)
    "go_linux": [1.0, 2.0, 4.0, 8.0, 16.0, 32.0],
}


# ---------------------------------------------------------------------------
# Known TCP stack signatures (initial TTL + window size + options order)
# ---------------------------------------------------------------------------

KNOWN_STACK_SIGNATURES = {
    # Format: (initial_ttl, window_size_range, window_scale, options_pattern) -> profile
    # Linux 5.x / 6.x with default sysctl
    (64, (29200, 65535), 7, "MSS,SACK,TS,NOP,WS"): TcpStackProfile.LINUX_6X,
    # Windows Server 2022
    (128, (65535, 65535), 8, "MSS,NOP,WS,NOP,NOP,TS,NOP,NOP,SACK"): TcpStackProfile.WINDOWS_SERVER_2022,
    # macOS 14+
    (64, (65535, 65535), 6, "MSS,NOP,WS,NOP,NOP,TS,SACK,NOP"): TcpStackProfile.MACOS_14,
    # Alpine Linux (musl libc — slightly different defaults)
    (64, (14600, 29200), 7, "MSS,SACK,TS,NOP,WS"): TcpStackProfile.ALPINE_MUSL,
}


# ---------------------------------------------------------------------------
# Inference logic
# ---------------------------------------------------------------------------

def infer_tcp_profile(fp: TcpFingerprint) -> TcpFingerprint:
    """
    Infer OS/runtime profile from TCP fingerprint attributes.

    Uses a multi-signal approach:
    1. Initial TTL narrows to OS family (64 = Linux/macOS, 128 = Windows)
    2. Window size + scale factor narrows to OS version
    3. TCP options ordering provides strong discrimination
    4. Retransmission timing confirms or overrides
    """
    confidence = 0.0
    inferred_os = "unknown"
    profile = TcpStackProfile.UNKNOWN

    # Step 1: TTL-based OS family
    if fp.initial_ttl is not None:
        if fp.initial_ttl <= 64:
            inferred_os = "linux_or_macos"
            confidence += 0.2
        elif fp.initial_ttl <= 128:
            inferred_os = "windows"
            confidence += 0.3  # Windows TTL is more distinctive
        elif fp.initial_ttl <= 255:
            inferred_os = "bsd_or_solaris"
            confidence += 0.2

    # Step 2: Window size discrimination
    if fp.window_size is not None and fp.window_scale is not None:
        if fp.window_scale == 7 and inferred_os == "linux_or_macos":
            inferred_os = "linux"
            confidence += 0.15
        elif fp.window_scale == 6 and inferred_os == "linux_or_macos":
            inferred_os = "macos"
            confidence += 0.15
        elif fp.window_scale == 8 and inferred_os == "windows":
            confidence += 0.15

    # Step 3: TCP options ordering (strongest single signal)
    if fp.tcp_options_order:
        for sig_key, sig_profile in KNOWN_STACK_SIGNATURES.items():
            expected_ttl, ws_range, expected_scale, expected_opts = sig_key
            ttl_match = fp.initial_ttl == expected_ttl if fp.initial_ttl else True
            ws_match = (ws_range[0] <= fp.window_size <= ws_range[1]) if fp.window_size else True
            scale_match = fp.window_scale == expected_scale if fp.window_scale else True
            opts_match = fp.tcp_options_order == expected_opts

            if ttl_match and ws_match and scale_match and opts_match:
                profile = sig_profile
                confidence += 0.35
                break

    # Step 4: Retransmission timing confirmation
    if fp.retransmit_intervals and len(fp.retransmit_intervals) >= 3:
        best_match_name = None
        best_match_score = 0.0

        for pattern_name, pattern in KNOWN_RETRANSMIT_PATTERNS.items():
            # Compare first N intervals (where N = min of available)
            n = min(len(fp.retransmit_intervals), len(pattern))
            if n < 3:
                continue

            # Allow ±0.5s tolerance for network jitter
            matches = sum(
                1 for i in range(n)
                if abs(fp.retransmit_intervals[i] - pattern[i]) <= 0.5
            )
            score = matches / n

            if score > best_match_score:
                best_match_score = score
                best_match_name = pattern_name

        if best_match_score >= 0.8:
            confidence += 0.15
            if best_match_name and "linux" in best_match_name and profile == TcpStackProfile.UNKNOWN:
                profile = TcpStackProfile.LINUX_6X  # Default to latest

    fp.inferred_os = inferred_os
    fp.inferred_profile = profile
    fp.confidence = min(confidence, 0.95)  # Cap at 0.95 (never 100% certain from TCP alone)

    return fp


def detect_proxy_from_tcp(tcp_fp: TcpFingerprint, http_server_header: Optional[str] = None,
                          h2_runtime: Optional[str] = None) -> Dict[str, any]:
    """
    Cross-reference TCP fingerprint with HTTP-level signals to detect reverse proxies.

    Returns a dict with:
    - proxy_likely: bool
    - proxy_confidence: float (0.0 - 1.0)
    - reason: str
    """
    result = {"proxy_likely": False, "proxy_confidence": 0.0, "reason": ""}

    if tcp_fp.inferred_profile == TcpStackProfile.UNKNOWN:
        return result

    # Check: TCP says Alpine/Linux but HTTP/2 says Go runtime
    # This is EXPECTED for OpenClaw on bare metal — not a proxy signal

    # Check: TCP says Linux but HTTP Server header says "cloudflare" or "nginx"
    if http_server_header:
        server_lower = http_server_header.lower()
        cdn_indicators = ["cloudflare", "akamai", "fastly", "aws", "gcp"]

        for cdn in cdn_indicators:
            if cdn in server_lower:
                result["proxy_likely"] = True
                result["proxy_confidence"] = 0.85
                result["reason"] = (
                    f"TCP stack fingerprint ({tcp_fp.inferred_profile.value}) "
                    f"with CDN Server header ({http_server_header}) suggests CDN termination"
                )
                return result

    # Check: TCP says Windows but application claims Go-based (unlikely for OpenClaw)
    if tcp_fp.inferred_profile in (TcpStackProfile.WINDOWS_SERVER_2022, TcpStackProfile.WINDOWS_11):
        if h2_runtime and "go" in h2_runtime.lower():
            result["proxy_likely"] = True
            result["proxy_confidence"] = 0.70
            result["reason"] = (
                "TCP stack fingerprint is Windows but HTTP/2 runtime is Go — "
                "likely Windows reverse proxy (IIS/nginx-win) in front of Linux OpenClaw backend"
            )
            return result

    return result


# ---------------------------------------------------------------------------
# Proposed new condition types for openclaw_rules.json
# ---------------------------------------------------------------------------

NEW_CONDITION_TYPES = """
New condition types to add to the rules engine for TCP fingerprinting:

1. ja4tscan_prefix
   - Matches the first portion of the JA4TScan fingerprint (OS/runtime identifier)
   - Example: {"type": "ja4tscan_prefix", "value": "t13d1516h2"}
   - Useful for matching a known OpenClaw TCP profile

2. ja4tscan_retransmit_pattern
   - Matches the retransmission timing portion of the JA4TScan fingerprint
   - Example: {"type": "ja4tscan_retransmit_pattern", "value": "1_2_4_8_16_32"}
   - Useful for confirming Linux-based stack (OpenClaw's expected runtime)

3. tcp_ttl
   - Matches the inferred initial TTL
   - Example: {"type": "tcp_ttl", "value": 64}
   - Quick OS family check (64 = Linux/macOS, 128 = Windows)

4. tcp_proxy_detected
   - Boolean condition based on cross-layer proxy detection
   - Example: {"type": "tcp_proxy_detected", "value": true}
   - Used in composite scoring to adjust weight of other layers
"""


# ---------------------------------------------------------------------------
# Proposed CLI integration
# ---------------------------------------------------------------------------

CLI_FLAGS = """
Proposed CLI flags:

--ja4t                Enable JA4TScan TCP fingerprinting for each target
                      Requires root/CAP_NET_RAW. Adds ~2 minutes per target
                      (for retransmission capture). Can be combined with --jarm.

--ja4t-timeout SEC    Retransmission capture timeout in seconds (default: 120)
                      Shorter values capture fewer retransmissions but scan faster.

--ja4t-only           Run JA4TScan without HTTP probing (TCP-layer scan only).
                      Useful for quick OS identification sweep.
"""


# ---------------------------------------------------------------------------
# Example fingerprint rules using TCP fingerprinting
# ---------------------------------------------------------------------------

EXAMPLE_RULES = [
    {
        "id": "openclaw-go-linux-tcp-profile",
        "family": "openclaw_go_linux",
        "label": "OpenClaw on Linux with Go runtime TCP stack",
        "confidence": 0.40,
        "notes": "Low-confidence rule based on TCP stack alone. Boosts to 0.85+ when combined with HTTP content fingerprints.",
        "all": [
            {"type": "tcp_ttl", "value": 64},
            {"type": "ja4tscan_retransmit_pattern", "value": "1_2_4_8_16_32"}
        ]
    },
    {
        "id": "openclaw-behind-cdn-tcp-mismatch",
        "family": "openclaw_behind_proxy",
        "label": "OpenClaw likely behind CDN/proxy (TCP mismatch)",
        "confidence": 0.30,
        "notes": "TCP fingerprint suggests CDN termination. HTTP content rules should be weighted higher for product identification.",
        "all": [
            {"type": "tcp_proxy_detected", "value": True},
            {"type": "title_contains", "path": "/", "value": "OpenClaw"}
        ]
    }
]
