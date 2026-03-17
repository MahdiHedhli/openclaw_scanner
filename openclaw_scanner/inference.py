import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from .models import FingerprintMatch, ProbeObservation, VersionMatch, VulnerabilityMatch

VERSION_RE = re.compile(r"(?<![0-9A-Za-z])(20\d{2}\.\d+\.\d+(?:-[A-Za-z0-9]+)?)(?=$|[^0-9A-Za-z])")


def load_rules(rules_file: Optional[str]) -> Dict[str, Any]:
    base_dir = Path(__file__).resolve().parent
    default_path = base_dir / "data" / "openclaw_rules.json"
    path = Path(rules_file) if rules_file else default_path
    return json.loads(path.read_text(encoding="utf-8"))


def infer_product_confidence(
    observations: Dict[str, ProbeObservation], rules: Dict[str, Any]
) -> float:
    score = 0.0
    markers = {marker for obs in observations.values() for marker in obs.body_markers}
    titles = [obs.title.lower() for obs in observations.values() if obs.title]
    scripts = [script.lower() for obs in observations.values() for script in obs.js_files]
    headers = {
        key: value.lower()
        for obs in observations.values()
        for key, value in obs.headers.items()
    }

    product_names = [name.lower() for name in rules.get("product_markers", [])]
    if any(name in marker for marker in markers for name in product_names):
        score += 0.55
    if any(any(name in title for name in product_names) for title in titles):
        score += 0.30
    if any("openclaw" in script or "claw" in script for script in scripts):
        score += 0.15
    if any("openclaw" in value or "claw" in value for value in headers.values()):
        score += 0.10
    if any(obs.version_hints for obs in observations.values()):
        score += 0.20

    return min(score, 1.0)


def infer_versions(
    observations: Dict[str, ProbeObservation], rules: Dict[str, Any]
) -> List[VersionMatch]:
    matches: List[VersionMatch] = []
    version_hints = _collect_version_hints(observations.values())

    for version in version_hints:
        matches.append(
            VersionMatch(
                version=version,
                confidence=0.97,
                source="direct_version_hint",
                notes="Extracted from HTTP content or headers.",
                exact=True,
            )
        )

    for rule in rules.get("version_rules", []):
        if _rule_matches(rule, observations, version_hints):
            matches.append(
                VersionMatch(
                    version=rule["version"],
                    confidence=float(rule.get("confidence", 0.7)),
                    source=rule.get("id", "custom_rule"),
                    notes=rule.get("notes"),
                    exact=bool(rule.get("exact", False)),
                )
            )

    deduped: Dict[Tuple[str, str], VersionMatch] = {}
    for match in matches:
        key = (match.version, match.source)
        existing = deduped.get(key)
        if existing is None or existing.confidence < match.confidence:
            deduped[key] = match

    ordered = sorted(
        deduped.values(),
        key=lambda item: (1 if item.exact else 0, item.confidence, _version_sort_key(item.version)),
        reverse=True,
    )
    return ordered


def infer_fingerprint_matches(
    observations: Dict[str, ProbeObservation], rules: Dict[str, Any]
) -> List[FingerprintMatch]:
    matches: List[FingerprintMatch] = []
    version_hints = _collect_version_hints(observations.values())

    for rule in rules.get("fingerprint_rules", []):
        if not _rule_matches(rule, observations, version_hints):
            continue

        matches.append(
            FingerprintMatch(
                family=rule["family"],
                confidence=float(rule.get("confidence", 0.75)),
                source=rule.get("id", "custom_rule"),
                label=rule.get("label"),
                notes=rule.get("notes"),
            )
        )

    deduped: Dict[Tuple[str, str], FingerprintMatch] = {}
    for match in matches:
        key = (match.family, match.source)
        existing = deduped.get(key)
        if existing is None or existing.confidence < match.confidence:
            deduped[key] = match

    return sorted(
        deduped.values(),
        key=lambda item: (item.confidence, item.family),
        reverse=True,
    )


def correlate_vulnerabilities(
    versions: Sequence[VersionMatch], rules: Dict[str, Any]
) -> List[VulnerabilityMatch]:
    vulns: List[VulnerabilityMatch] = []

    for version_match in versions:
        for vuln in rules.get("vulnerabilities", []):
            affected, reasoning = _version_is_affected(version_match.version, vuln)
            if not affected:
                continue

            confidence = 0.95 if version_match.exact else min(version_match.confidence, 0.75)
            reasoning = f"{reasoning} Version source: {version_match.source}."
            vulns.append(
                VulnerabilityMatch(
                    id=vuln["id"],
                    title=vuln["title"],
                    affected=True,
                    confidence=confidence,
                    reasoning=reasoning,
                    fixed_in=vuln.get("fixed_in"),
                    severity=vuln.get("severity"),
                    surface=list(vuln.get("surface", [])),
                    requires_auth=vuln.get("requires_auth"),
                    references=list(vuln.get("references", [])),
                )
            )

    deduped: Dict[str, VulnerabilityMatch] = {}
    for vuln in vulns:
        existing = deduped.get(vuln.id)
        if existing is None or existing.confidence < vuln.confidence:
            deduped[vuln.id] = vuln

    return sorted(
        deduped.values(),
        key=lambda item: (-item.confidence, item.id),
    )


def _collect_version_hints(observations: Iterable[ProbeObservation]) -> List[str]:
    hints = set()
    for observation in observations:
        for version in observation.version_hints:
            hints.add(version)
        for script in observation.js_files:
            hints.update(_extract_versions_from_string(script))
        for key, value in observation.headers.items():
            if "version" in key.lower():
                hints.update(_extract_versions_from_string(value))
    return sorted(hints, key=_version_sort_key, reverse=True)


def _extract_versions_from_string(value: str) -> List[str]:
    return VERSION_RE.findall(value)


def _rule_matches(
    rule: Dict[str, Any],
    observations: Dict[str, ProbeObservation],
    version_hints: Sequence[str],
) -> bool:
    all_conditions = rule.get("all", [])
    any_conditions = rule.get("any", [])

    if all_conditions and not all(
        _condition_matches(condition, observations, version_hints)
        for condition in all_conditions
    ):
        return False

    if any_conditions and not any(
        _condition_matches(condition, observations, version_hints)
        for condition in any_conditions
    ):
        return False

    return bool(all_conditions or any_conditions)


def _condition_matches(
    condition: Dict[str, Any],
    observations: Dict[str, ProbeObservation],
    version_hints: Sequence[str],
) -> bool:
    condition_type = condition["type"]
    target_path = condition.get("path")
    if target_path:
        candidate_observations = (
            [observations[target_path]] if target_path in observations else []
        )
    else:
        candidate_observations = list(observations.values())

    if condition_type == "path_status":
        statuses = {int(value) for value in condition.get("statuses", [])}
        return any(obs.status in statuses for obs in candidate_observations)

    if condition_type == "title_contains":
        needle = condition["value"].lower()
        return any(obs.title and needle in obs.title.lower() for obs in candidate_observations)

    if condition_type == "marker_present":
        needle = condition["value"].lower()
        return any(needle in obs.body_markers for obs in candidate_observations)

    if condition_type == "script_contains":
        needle = condition["value"].lower()
        return any(
            needle in script.lower()
            for obs in candidate_observations
            for script in obs.js_files
        )

    if condition_type == "header_contains":
        header_name = condition["header"].lower()
        needle = condition["value"].lower()
        return any(
            needle in obs.headers.get(header_name, "").lower()
            for obs in candidate_observations
        )

    if condition_type == "json_key":
        key_name = condition["value"]
        return any(key_name in obs.json_keys for obs in candidate_observations)

    if condition_type == "body_hash":
        expected = condition["value"].lower()
        return any(
            obs.body_sha256 and obs.body_sha256.lower() == expected
            for obs in candidate_observations
        )

    if condition_type == "version_hint_prefix":
        prefix = condition["value"]
        return any(version.startswith(prefix) for version in version_hints)

    return False


def _version_is_affected(version: str, vuln: Dict[str, Any]) -> Tuple[bool, str]:
    affected_ranges = vuln.get("affected_ranges", [])
    for range_rule in affected_ranges:
        if _matches_range(version, range_rule):
            explanation = _describe_range(version, range_rule, vuln)
            return True, explanation
    return False, ""


def _matches_range(version: str, range_rule: Dict[str, Any]) -> bool:
    lower = range_rule.get("gte")
    upper = range_rule.get("lt")
    exact = range_rule.get("eq")

    if exact is not None and _compare_versions(version, exact) != 0:
        return False
    if lower is not None and _compare_versions(version, lower) < 0:
        return False
    if upper is not None and _compare_versions(version, upper) >= 0:
        return False
    return True


def _describe_range(version: str, range_rule: Dict[str, Any], vuln: Dict[str, Any]) -> str:
    if range_rule.get("eq"):
        return f"Matched exact affected version {version} for {vuln['id']}."
    lower = range_rule.get("gte")
    upper = range_rule.get("lt")
    if lower and upper:
        return f"Version {version} falls in affected range {lower} <= v < {upper}."
    if upper:
        return f"Version {version} is older than fixed version {upper}."
    if lower:
        return f"Version {version} is at or above affected floor {lower}."
    return f"Version {version} matches an affected range for {vuln['id']}."


def _compare_versions(left: str, right: str) -> int:
    left_key = _version_sort_key(left)
    right_key = _version_sort_key(right)
    if left_key < right_key:
        return -1
    if left_key > right_key:
        return 1
    return 0


def _version_sort_key(value: str) -> Tuple[Any, ...]:
    parts = re.split(r"[._-]", value)
    key: List[Any] = []
    for part in parts:
        if part.isdigit():
            key.append((0, int(part)))
        else:
            key.append((1, part.lower()))
    return tuple(key)
