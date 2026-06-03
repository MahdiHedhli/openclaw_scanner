"""Shared OpenClaw-family version parsing helpers.

All scanner paths use this module so build suffixes and prerelease counters are
not truncated differently between live probes, passive imports, and corpus tools.
"""
from __future__ import annotations

import re
from typing import Any, List, Optional, Tuple

_VERSION_SUFFIX = r"(?:-[0-9A-Za-z][0-9A-Za-z-]*(?:\.\d+)*)?"

VERSION_TOKEN = r"20\d{2}\.\d+\.\d+" + _VERSION_SUFFIX

EXACT_VERSION_RE = re.compile(r"^(?:" + VERSION_TOKEN + r")$")

VERSION_SEARCH_RE = re.compile(
    r"(?<![0-9A-Za-z])(" + VERSION_TOKEN + r")(?=$|[^0-9A-Za-z])"
)

MARKER_ANCHORED_RE = re.compile(
    r"(?<![0-9A-Za-z])"
    r"(?:openclaw|clawdbot|moltbot|gateway|version|release|build)"
    r"[^0-9]{0,24}"
    r"(" + VERSION_TOKEN + r")"
    r"(?=$|[^0-9A-Za-z])",
    re.IGNORECASE,
)

PACKAGE_VERSION_RE = re.compile(
    r"(?:openclaw|clawdbot|moltbot)@(" + VERSION_TOKEN + r")",
    re.IGNORECASE,
)


def find_versions(text: Optional[str]) -> List[str]:
    """Return boundary-guarded version tokens from arbitrary text."""
    if not text:
        return []
    found = set(VERSION_SEARCH_RE.findall(str(text)))
    return sorted(found, key=version_sort_key, reverse=True)


def find_versions_near_markers(text: Optional[str]) -> List[str]:
    """Return versions adjacent to product/build markers for precision paths."""
    if not text:
        return []
    found = set(MARKER_ANCHORED_RE.findall(str(text)))
    return sorted(found, key=version_sort_key, reverse=True)


def find_package_version(text: Optional[str]) -> Optional[str]:
    """Return the version from an explicit package@version string, if present."""
    if not text:
        return None
    match = PACKAGE_VERSION_RE.search(str(text))
    return match.group(1) if match else None


def is_exact_version(value: Optional[str]) -> bool:
    """True when value is exactly one supported OpenClaw-family version token."""
    return bool(value) and bool(EXACT_VERSION_RE.match(str(value)))


def version_sort_key(value: str) -> Tuple[Any, ...]:
    """Comparable key that preserves numeric and prerelease/build components."""
    parts = re.split(r"[._-]", str(value))
    key: List[Any] = []
    for part in parts:
        if part.isdigit():
            key.append((0, int(part)))
        else:
            key.append((1, part.lower()))
    return tuple(key)
