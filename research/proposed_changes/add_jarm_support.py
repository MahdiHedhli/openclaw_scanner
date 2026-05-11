"""
Proposed change: Add optional JARM TLS fingerprinting support.

This module outlines the integration pattern for JARM fingerprinting.
JARM requires raw socket TLS probing, which is a heavier operation than
HTTP probing, so it should be opt-in via a CLI flag.

STATUS: Draft — requires pyjarm or vendored JARM logic.
DATE: 2026-03-19
"""

# --- CLI addition (__main__.py) ---
# Add argument:
#     parser.add_argument(
#         "--jarm",
#         action="store_true",
#         default=False,
#         help="Compute JARM TLS fingerprint for each target (requires pyjarm).",
#     )


# --- New module: openclaw_scanner/jarm_probe.py ---

from typing import Optional, Tuple


def compute_jarm(host: str, port: int = 443) -> Tuple[Optional[str], Optional[str]]:
    """
    Compute the JARM fingerprint for a host:port.

    Returns (jarm_hash, error_message).

    The JARM hash is a 62-character string:
    - First 30 chars: cipher+version for each of 10 probes (3 chars each)
    - Last 32 chars: truncated SHA-256 of cumulative server extensions

    A hash of all zeros means the server refused all 10 handshakes.
    """
    try:
        from jarm.scanner.scanner import Scanner  # pyjarm
        result = Scanner.scan(host, port)
        return result[0], None  # (hash, None)
    except ImportError:
        return None, "pyjarm not installed. Install with: pip install pyjarm"
    except Exception as exc:
        return None, f"JARM scan failed: {exc}"


# --- Addition to ScanResult model (models.py) ---
# Add field:
#     jarm_hash: Optional[str] = None


# --- Integration in scanner.py or the main scan loop ---
# After HTTP probing, if --jarm is enabled:
#
#     if args.jarm:
#         from .jarm_probe import compute_jarm
#         host, port = parse_host_port(target)
#         jarm_hash, jarm_error = compute_jarm(host, port)
#         result.jarm_hash = jarm_hash
#         if jarm_error:
#             result.errors.append(jarm_error)


# --- New condition type for inference.py ---
# Add to _condition_matches():
#
#     if condition_type == "jarm_prefix":
#         prefix = condition["value"]
#         return any(
#             obs.jarm_hash and obs.jarm_hash.startswith(prefix)
#             for obs in candidate_observations
#         )
#
#     if condition_type == "jarm_hash":
#         expected = condition["value"].lower()
#         return any(
#             obs.jarm_hash and obs.jarm_hash.lower() == expected
#             for obs in candidate_observations
#         )


# --- Example rules using JARM ---

EXAMPLE_JARM_RULES = [
    {
        "id": "openclaw-jarm-nodejs-default",
        "family": "openclaw_nodejs_tls",
        "label": "OpenClaw gateway with Node.js TLS stack (JARM match)",
        "confidence": 0.70,
        "notes": "JARM prefix for Node.js HTTP server. Low confidence alone, but boosts combined signal.",
        "all": [
            {
                "type": "jarm_prefix",
                "value": "PLACEHOLDER"  # Replace with lab-derived JARM prefix
            }
        ]
    },
    {
        "id": "openclaw-2026.2.x-jarm-exact",
        "version": "2026.2.x",
        "confidence": 0.65,
        "notes": "JARM hash for OpenClaw 2026.2.x lab build with default TLS config.",
        "all": [
            {
                "type": "jarm_hash",
                "value": "PLACEHOLDER"  # Replace with lab-derived full JARM hash
            },
            {
                "type": "title_contains",
                "path": "/",
                "value": "OpenClaw Control"
            }
        ]
    }
]


# --- Known JARM hashes for common platforms (for reference/exclusion) ---
# These can be used to EXCLUDE false positives:
#
# Cloudflare:          27d27d27d29d27d1dc27d27d27d27d... (varies by region)
# nginx default:       varies significantly by version and config
# Apache default:      varies significantly
#
# Key insight: JARM is most useful when combined with HTTP-level signals.
# A JARM match alone should have lower confidence (0.5-0.7) but combined
# with title/marker matches it becomes a strong confirmatory signal.
