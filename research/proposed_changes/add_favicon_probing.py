"""
Proposed change: Add favicon.ico probing and MurmurHash3 hashing.

This module shows the additions needed to probe.py and models.py to support
favicon-based fingerprinting.

STATUS: Draft — requires lab-derived favicon hashes before rules can be written.
DATE: 2026-03-19
"""

# --- Addition to DEFAULT_PROBE_PATHS in probe.py ---
# Add these paths to the existing list:
NEW_PROBE_PATHS = [
    "/favicon.ico",
    "/manifest.json",       # React/SPA apps often expose version info here
    "/asset-manifest.json", # Create-React-App standard manifest
]


# --- New helper function for probe.py ---
# Pure-Python MurmurHash3 (32-bit, signed) to avoid mmh3 dependency.
# This matches Shodan's favicon hash algorithm.

import struct
import base64


def _murmurhash3_32(data: bytes, seed: int = 0) -> int:
    """Pure-Python MurmurHash3 (x86, 32-bit) matching mmh3.hash() output."""
    length = len(data)
    nblocks = length // 4
    h1 = seed & 0xFFFFFFFF

    c1 = 0xCC9E2D51
    c2 = 0x1B873593

    # Body
    for block_start in range(0, nblocks * 4, 4):
        k1 = struct.unpack_from("<I", data, block_start)[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF

    # Tail
    tail_index = nblocks * 4
    tail_size = length & 3
    k1 = 0
    if tail_size >= 3:
        k1 ^= data[tail_index + 2] << 16
    if tail_size >= 2:
        k1 ^= data[tail_index + 1] << 8
    if tail_size >= 1:
        k1 ^= data[tail_index]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1

    # Finalization
    h1 ^= length
    h1 ^= (h1 >> 16)
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= (h1 >> 13)
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= (h1 >> 16)

    # Convert to signed 32-bit (matching mmh3.hash behavior)
    if h1 >= 0x80000000:
        h1 -= 0x100000000
    return h1


def compute_favicon_hash(raw_favicon_bytes: bytes) -> int:
    """
    Compute the Shodan-compatible favicon hash.

    Process:
    1. Base64-encode with line breaks every 76 chars (base64.encodebytes)
    2. MurmurHash3 the resulting bytes
    """
    b64_encoded = base64.encodebytes(raw_favicon_bytes)
    return _murmurhash3_32(b64_encoded)


# --- Addition to ProbeObservation model (models.py) ---
# Add this field to the ProbeObservation dataclass:
#
#     favicon_hash: Optional[int] = None
#
# This stores the MurmurHash3 of the favicon for the "/" path observation.


# --- New condition type for inference.py ---
# Add to _condition_matches():
#
#     if condition_type == "favicon_hash":
#         expected = int(condition["value"])
#         return any(
#             obs.favicon_hash is not None and obs.favicon_hash == expected
#             for obs in candidate_observations
#         )


# --- Example rule using favicon_hash ---
EXAMPLE_FAVICON_RULE = {
    "id": "openclaw-favicon-default",
    "family": "openclaw_default_favicon",
    "label": "OpenClaw gateway with default favicon",
    "confidence": 0.85,
    "notes": "Matches the default OpenClaw favicon hash. Hash must be derived from lab capture.",
    "all": [
        {
            "type": "favicon_hash",
            "path": "/favicon.ico",
            "value": "PLACEHOLDER_HASH"  # Replace with actual hash from lab capture
        }
    ]
}
