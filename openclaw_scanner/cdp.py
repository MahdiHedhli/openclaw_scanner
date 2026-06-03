"""Chromium DevTools Protocol evidence helpers.

This module does not add CDP probes or connect to debugger websocket endpoints.
It only grades already-collected CDP-like facts as approximate, non-correlating
version-window evidence.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from .models import ProbeObservation, VersionMatch


@dataclass
class CdpFacts:
    present: bool = False
    engine: Optional[str] = None
    chromium_version: Optional[str] = None
    chromium_major: Optional[int] = None
    headless: Optional[bool] = None
    protocol_version: Optional[str] = None
    v8_version: Optional[str] = None
    devtools_revision: Optional[int] = None


@dataclass
class ChromiumWindowRule:
    version: str
    confidence: float
    chromium_major_min: Optional[int] = None
    chromium_major_max: Optional[int] = None
    devtools_rev_min: Optional[int] = None
    devtools_rev_max: Optional[int] = None
    notes: Optional[str] = None


CHROMIUM_WINDOW_RULES: List[ChromiumWindowRule] = [
    ChromiumWindowRule(
        version="2026.1.x",
        confidence=0.55,
        devtools_rev_min=1574000,
        devtools_rev_max=1596000,
        notes=(
            "Seed approximate window from passive devtools-protocol metadata; "
            "not sufficient for exact version or vulnerability correlation."
        ),
    ),
]


def extract_cdp_facts(
    observations: Dict[str, ProbeObservation],
    metadata: Optional[Dict[str, Any]] = None,
) -> CdpFacts:
    facts = CdpFacts()
    for observation in observations.values():
        cdp = observation.cdp
        if not cdp:
            continue
        facts.present = True
        facts.engine = cdp.get("engine") or cdp.get("browser_family") or facts.engine
        chromium_version = cdp.get("chromium_version")
        if chromium_version:
            facts.chromium_version = chromium_version
            major = str(chromium_version).split(".", 1)[0]
            if major.isdigit():
                facts.chromium_major = int(major)
        headless = cdp.get("headless")
        if headless is not None:
            facts.headless = str(headless).lower() == "true"
        facts.protocol_version = cdp.get("protocol_version") or facts.protocol_version
        facts.v8_version = cdp.get("v8_version") or facts.v8_version

    revision = (metadata or {}).get("mdns_devtools_revision")
    if revision is not None:
        try:
            facts.devtools_revision = int(revision)
        except (TypeError, ValueError):
            facts.devtools_revision = None

    return facts


def cdp_version_candidates(
    observations: Dict[str, ProbeObservation],
    metadata: Optional[Dict[str, Any]] = None,
    rules: Optional[List[ChromiumWindowRule]] = None,
) -> List[VersionMatch]:
    facts = extract_cdp_facts(observations, metadata)
    if not facts.present and facts.devtools_revision is None:
        return []

    matches: List[VersionMatch] = []
    for rule in rules if rules is not None else CHROMIUM_WINDOW_RULES:
        if not _window_matches(rule, facts):
            continue
        matches.append(
            VersionMatch(
                version=rule.version,
                confidence=min(float(rule.confidence), 0.7),
                source="cdp_chromium_window",
                notes=rule.notes
                or "Approximate window from Chromium/CDP metadata.",
                exact=False,
                correlate=False,
            )
        )
    return matches


def _window_matches(rule: ChromiumWindowRule, facts: CdpFacts) -> bool:
    matched_any = False

    if rule.chromium_major_min is not None or rule.chromium_major_max is not None:
        if facts.chromium_major is None:
            return False
        if rule.chromium_major_min is not None and facts.chromium_major < rule.chromium_major_min:
            return False
        if rule.chromium_major_max is not None and facts.chromium_major > rule.chromium_major_max:
            return False
        matched_any = True

    if rule.devtools_rev_min is not None or rule.devtools_rev_max is not None:
        if facts.devtools_revision is None:
            if not matched_any:
                return False
        else:
            if rule.devtools_rev_min is not None and facts.devtools_revision < rule.devtools_rev_min:
                return False
            if rule.devtools_rev_max is not None and facts.devtools_revision > rule.devtools_rev_max:
                return False
            matched_any = True

    return matched_any
