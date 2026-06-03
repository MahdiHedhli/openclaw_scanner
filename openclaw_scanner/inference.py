from collections import Counter
import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from .models import FingerprintMatch, ProbeObservation, VersionMatch, VulnerabilityMatch
from .versions import (
    find_versions,
    find_versions_near_markers,
    is_exact_version,
    version_sort_key,
)


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
    if _has_json_auth_surface(observations, "/tools/invoke", method="POST"):
        score += 0.35
    if any(
        _has_json_auth_surface(observations, path, method="POST")
        for path in ("/v1/embeddings", "/v1/chat/completions", "/v1/responses")
    ):
        score += 0.15
    if _has_openai_models_surface(observations):
        score += 0.10

    return min(score, 1.0)


def infer_versions(
    observations: Dict[str, ProbeObservation], rules: Dict[str, Any]
) -> List[VersionMatch]:
    matches: List[VersionMatch] = []
    version_hints = _collect_version_hints(observations.values())
    direct_hints = _collect_direct_version_hints(observations.values())
    passive_hints = _collect_passive_banner_version_hints(observations.values())

    for version in direct_hints:
        matches.append(
            VersionMatch(
                version=version,
                confidence=0.97,
                source="direct_version_hint",
                notes="Extracted from live HTTP content or headers.",
                exact=True,
                correlate=True,
            )
        )

    for version in passive_hints:
        matches.append(
            VersionMatch(
                version=version,
                confidence=0.45,
                source="passive_banner_text",
                notes="Version-like token observed in passive banner text only.",
                exact=False,
                correlate=False,
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
                    correlate=bool(rule.get("correlate", rule.get("exact", False))),
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
        key=lambda item: (
            1 if item.exact else 0,
            1 if item.correlate else 0,
            item.confidence,
            version_sort_key(item.version),
        ),
        reverse=True,
    )
    return ordered


def mdns_version_candidates(metadata: Dict[str, Any]) -> List[VersionMatch]:
    version = str((metadata or {}).get("mdns_version") or "").strip()
    if not version or not is_exact_version(version):
        return []

    source = str((metadata or {}).get("mdns_version_source") or "txt").strip().lower()
    if source in {"cli_path_package", "package_metadata", "package", "cli_path"}:
        return [
            VersionMatch(
                version=version,
                confidence=0.97,
                source="mdns_cli_path",
                notes="Exact version from explicit mDNS package/cliPath metadata.",
                exact=True,
                correlate=True,
            )
        ]

    return [
        VersionMatch(
            version=version,
            confidence=0.62,
            source="mdns_txt",
            notes="Version-like token from passive mDNS TXT metadata.",
            exact=False,
            correlate=False,
        )
    ]


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
    versions: Sequence[VersionMatch],
    rules: Dict[str, Any],
    platform: Optional[str] = None,
    shodan_vulns: Optional[Sequence[str]] = None,
) -> List[VulnerabilityMatch]:
    vulns: List[VulnerabilityMatch] = []
    shodan_vuln_ids = {str(value) for value in shodan_vulns or [] if value}

    for version_match in versions:
        if not version_match.correlate:
            continue
        for vuln in rules.get("vulnerabilities", []):
            affected, reasoning = _version_is_affected(version_match.version, vuln)
            if not affected:
                continue

            applicable, platform_reason, confidence_cap = _platform_matches(vuln, platform)
            if not applicable:
                continue

            confidence = 0.95 if version_match.exact else min(version_match.confidence, 0.75)
            confidence = min(confidence, confidence_cap)
            reasoning = f"{reasoning} {platform_reason} Version source: {version_match.source}.".strip()
            if vuln["id"] in shodan_vuln_ids:
                confidence = min(0.99, confidence + 0.03)
                reasoning = f"{reasoning} Shodan also flagged this CVE."
            vulns.append(
                VulnerabilityMatch(
                    id=vuln["id"],
                    title=vuln["title"],
                    affected=True,
                    confidence=confidence,
                    reasoning=reasoning,
                    fixed_in=vuln.get("fixed_in"),
                    severity=vuln.get("severity"),
                    platform=vuln.get("platform"),
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


def _platform_matches(
    vuln: Dict[str, Any],
    platform: Optional[str],
) -> Tuple[bool, str, float]:
    expected = vuln.get("platform")
    if not expected:
        return True, "", 1.0

    if not platform:
        return (
            True,
            f"Platform-specific advisory for {expected}; target platform is unknown so this match is tentative.",
            0.55,
        )

    if str(platform).lower() != str(expected).lower():
        return False, "", 0.0

    return True, f"Target platform {platform} matches the advisory scope.", 1.0


def _collect_version_hints(observations: Iterable[ProbeObservation]) -> List[str]:
    hints = set()
    for observation in observations:
        hints.update(_normalize_versions(observation.version_hints))
        for script in observation.js_files:
            hints.update(find_versions_near_markers(script))
        for key, value in observation.headers.items():
            if "version" in key.lower():
                hints.update(find_versions(value))
            else:
                hints.update(find_versions_near_markers(value))
    return sorted(hints, key=version_sort_key, reverse=True)


def _collect_direct_version_hints(
    observations: Iterable[ProbeObservation],
) -> List[str]:
    hints = set()
    for observation in observations:
        if _is_passive_observation(observation):
            continue
        hints.update(_normalize_versions(observation.version_hints))
        for script in observation.js_files:
            hints.update(find_versions_near_markers(script))
        for key, value in observation.headers.items():
            if "version" in key.lower() or "openclaw" in key.lower() or "clawdbot" in key.lower():
                hints.update(find_versions(value))
            else:
                hints.update(find_versions_near_markers(value))
    return sorted(hints, key=version_sort_key, reverse=True)


def _collect_passive_banner_version_hints(
    observations: Iterable[ProbeObservation],
) -> List[str]:
    hints = set()
    for observation in observations:
        if not _is_passive_observation(observation):
            continue
        hints.update(_normalize_versions(observation.version_hints))
        for script in observation.js_files:
            hints.update(find_versions(script))
        for value in observation.headers.values():
            hints.update(find_versions(value))
    return sorted(hints, key=version_sort_key, reverse=True)


def _normalize_versions(values: Iterable[str]) -> List[str]:
    versions = set()
    for value in values:
        versions.update(find_versions(str(value)))
    return sorted(versions, key=version_sort_key, reverse=True)


def _is_passive_observation(observation: ProbeObservation) -> bool:
    return observation.url.startswith("shodan://") or observation.path == "/__shodan__"


def _get_observation(
    observations: Dict[str, ProbeObservation],
    path: str,
    method: str = "GET",
) -> Optional[ProbeObservation]:
    normalized_path = path if path.startswith("/") else f"/{path}"
    normalized_method = method.upper()
    key = normalized_path if normalized_method == "GET" else f"{normalized_method} {normalized_path}"
    return observations.get(key)


def _has_json_auth_surface(
    observations: Dict[str, ProbeObservation],
    path: str,
    method: str = "GET",
) -> bool:
    observation = _get_observation(observations, path=path, method=method)
    if not observation or observation.status not in {400, 401, 403, 429}:
        return False

    content_type = (observation.content_type or "").lower()
    if "json" not in content_type and not observation.json_keys:
        return False

    error_text = (observation.error_text or "").lower()
    if any(
        needle in error_text
        for needle in ("unauthor", "forbidden", "auth", "token", "rate", "too many")
    ):
        return True

    return any(str(key).lower() == "error" for key in observation.json_keys)


def _has_openai_models_surface(observations: Dict[str, ProbeObservation]) -> bool:
    for path in ("/v1/models", "/v1/models/openclaw/default"):
        observation = _get_observation(observations, path=path, method="GET")
        if not observation or observation.status not in {200, 401, 403, 429}:
            continue

        content_type = (observation.content_type or "").lower()
        if "json" in content_type:
            return True

        json_keys = {str(key).lower() for key in observation.json_keys}
        if {"data", "object"} & json_keys or "id" in json_keys:
            return True

    return False


def _extract_versions_from_string(value: str) -> List[str]:
    return find_versions_near_markers(value)


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
    target_method = str(condition.get("method") or "").upper() or None
    target_probe = str(condition.get("probe_name") or "").strip().lower() or None
    candidate_observations = [
        observation
        for observation in observations.values()
        if (target_path is None or observation.path == target_path)
        and (target_method is None or observation.method.upper() == target_method)
        and (
            target_probe is None
            or (observation.probe_name or "").strip().lower() == target_probe
        )
    ]

    if condition_type == "path_status":
        statuses = {int(value) for value in condition.get("statuses", [])}
        return any(obs.status in statuses for obs in candidate_observations)

    if condition_type == "status_distribution_signature":
        expected = str(condition["value"]).strip()
        return _status_distribution_signature(observations) == expected

    if condition_type == "path_status_not":
        statuses = {int(value) for value in condition.get("statuses", [])}
        return any(obs.status is not None and obs.status not in statuses for obs in candidate_observations)

    if condition_type == "method_status":
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

    if condition_type == "cdp_present":
        expected = bool(condition.get("value", True))
        return any((obs.cdp.get("present") == "true") == expected for obs in candidate_observations)

    if condition_type == "cdp_debugger_url_present":
        expected = bool(condition.get("value", True))
        return any(
            (obs.cdp.get("debugger_url_present") == "true") == expected
            for obs in candidate_observations
        )

    if condition_type == "cdp_browser_family":
        expected = str(condition["value"]).strip().lower()
        return any(
            obs.cdp.get("browser_family", "").strip().lower() == expected
            for obs in candidate_observations
        )

    if condition_type == "cdp_engine":
        expected = str(condition["value"]).strip().lower()
        return any(
            obs.cdp.get("engine", "").strip().lower() == expected
            for obs in candidate_observations
        )

    if condition_type == "body_hash":
        expected = condition["value"].lower()
        return any(
            obs.body_sha256 and obs.body_sha256.lower() == expected
            for obs in candidate_observations
        )

    if condition_type == "body_contains":
        needle = condition["value"].lower()
        return any(
            obs.error_text and needle in obs.error_text.lower()
            for obs in candidate_observations
        )

    if condition_type == "error_pattern":
        pattern = re.compile(condition["value"], re.IGNORECASE)
        return any(
            obs.error_text and pattern.search(obs.error_text)
            for obs in candidate_observations
        )

    if condition_type == "header_order":
        expected = [
            part.strip().lower()
            for part in str(condition["value"]).split("|")
            if part.strip()
        ]
        return any(obs.header_order == expected for obs in candidate_observations)

    if condition_type == "has_stack_trace":
        expected = bool(condition.get("value", True))
        return any(obs.has_stack_trace == expected for obs in candidate_observations)

    if condition_type == "favicon_hash":
        expected = int(condition["value"])
        return any(obs.favicon_hash == expected for obs in candidate_observations)

    if condition_type == "ws_upgrade_supported":
        expected = bool(condition.get("value", True))
        return any((obs.status == 101) == expected for obs in candidate_observations)

    if condition_type == "ws_upgrade_status":
        statuses = {int(value) for value in condition.get("statuses", [])}
        return any(obs.status in statuses for obs in candidate_observations)

    if condition_type == "ws_subprotocol_contains":
        needle = condition["value"].lower()
        return any(
            needle in obs.headers.get("sec-websocket-protocol", "").lower()
            for obs in candidate_observations
        )

    if condition_type == "ws_extension_contains":
        needle = condition["value"].lower()
        return any(
            needle in obs.headers.get("sec-websocket-extensions", "").lower()
            for obs in candidate_observations
        )

    if condition_type == "version_hint_prefix":
        prefix = condition["value"]
        return any(version.startswith(prefix) for version in version_hints)

    return False


def _status_distribution_signature(
    observations: Dict[str, ProbeObservation]
) -> str:
    counts = Counter(
        observation.status
        for observation in observations.values()
        if observation.status is not None
    )
    return ";".join(f"{status}:{counts[status]}" for status in sorted(counts))


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
    left_key = version_sort_key(left)
    right_key = version_sort_key(right)
    if left_key < right_key:
        return -1
    if left_key > right_key:
        return 1
    return 0
