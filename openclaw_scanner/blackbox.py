import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from .models import ProbeObservation, ScanResult

EXACT_VERSION_RE = re.compile(r"^20\d{2}\.\d+\.\d+(?:-[0-9A-Za-z][0-9A-Za-z-]*(?:\.\d+)*)?$")
SKIPPED_INPUT_PRETTY_LIMIT = 12


def build_capture_bundle(
    results: Sequence[ScanResult],
    probe_paths: Iterable[str],
    declared_version: Optional[str] = None,
    capture_name: Optional[str] = None,
    notes: Optional[str] = None,
) -> Dict[str, object]:
    return {
        "schema_version": 1,
        "bundle_type": "openclaw_blackbox_capture",
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "capture_name": capture_name,
        "declared_version": declared_version,
        "notes": notes,
        "probe_paths": list(probe_paths),
        "capture_count": len(results),
        "captures": [_capture_entry(result) for result in results],
    }


def load_capture_bundles(path_value: str) -> List[Dict[str, object]]:
    bundles, _ = load_capture_bundle_inputs(path_value)
    return bundles


def load_capture_bundle_inputs(path_value: str) -> Tuple[List[Dict[str, object]], List[Dict[str, object]]]:
    path = Path(path_value)
    if path.is_dir():
        bundles: List[Dict[str, object]] = []
        skipped_inputs: List[Dict[str, object]] = []
        for item in sorted(path.rglob("*.json")):
            try:
                loaded = _load_capture_file(item)
            except json.JSONDecodeError as exc:
                skipped_inputs.append(
                    {
                        "path": _display_path(item, path),
                        "reason": f"invalid JSON: {exc.msg}",
                    }
                )
                continue
            capture_bundles = [
                bundle for bundle in loaded if _is_capture_bundle(bundle)
            ]
            if capture_bundles:
                bundles.extend(capture_bundles)
            else:
                skipped_inputs.append(
                    {
                        "path": _display_path(item, path),
                        "reason": "not an openclaw_blackbox_capture bundle",
                    }
                )
        return bundles, skipped_inputs

    return _load_capture_file(path), []


def generate_rule_suggestions(
    bundles: Sequence[Dict[str, object]],
    max_conditions: int = 3,
    skipped_inputs: Optional[Sequence[Dict[str, object]]] = None,
) -> Dict[str, object]:
    bundle_entries = []
    diagnostics_by_version: Dict[str, List[Dict[str, object]]] = defaultdict(list)
    skipped = []

    for bundle in bundles:
        declared_version = str(bundle.get("declared_version") or "").strip()
        if not declared_version:
            skipped.append(
                {
                    "capture_name": bundle.get("capture_name"),
                    "reason": "missing declared_version",
                }
            )
            continue

        captures = bundle.get("captures") or []
        for capture in captures:
            if not isinstance(capture, dict):
                continue
            signals = {
                str(value)
                for value in capture.get("signals", [])
                if isinstance(value, str) and value
            }
            capture_index = len(diagnostics_by_version[declared_version]) + 1
            diagnostics_by_version[declared_version].append(
                _capture_diagnostics(
                    capture,
                    capture_name=bundle.get("capture_name"),
                    capture_index=capture_index,
                    signals=signals,
                )
            )
            bundle_entries.append(
                {
                    "declared_version": declared_version,
                    "capture_name": bundle.get("capture_name"),
                    "input_target": capture.get("input_target"),
                    "signals": signals,
                }
            )

    versions: Dict[str, List[Set[str]]] = defaultdict(list)
    for entry in bundle_entries:
        versions[entry["declared_version"]].append(entry["signals"])

    stable_by_version: Dict[str, Set[str]] = {}
    for version, signal_sets in versions.items():
        if not signal_sets:
            stable_by_version[version] = set()
            continue
        stable = set(signal_sets[0])
        for signal_set in signal_sets[1:]:
            stable &= signal_set
        stable_by_version[version] = stable

    similarity_by_version = _build_similarity_report(versions, stable_by_version)

    suggestions = []
    for version in sorted(stable_by_version.keys(), key=_version_sort_key, reverse=True):
        stable_signals = stable_by_version[version]
        other_stable = set().union(
            *[
                signals
                for other_version, signals in stable_by_version.items()
                if other_version != version
            ]
        )
        unique_signals = stable_signals - other_stable
        selected_signals = _select_rule_signals(
            unique_signals=unique_signals,
            stable_signals=stable_signals,
            capture_count=len(versions[version]),
            max_conditions=max(max_conditions, 1),
        )
        similarity = similarity_by_version.get(version, {})

        candidate_rule = _build_candidate_rule(
            version=version,
            selected_signals=selected_signals,
            capture_count=len(versions[version]),
        )
        suggestions.append(
            {
                "version": version,
                "capture_count": len(versions[version]),
                "stable_signal_count": len(stable_signals),
                "unique_signal_count": len(unique_signals),
                "stable_signals": sorted(stable_signals),
                "unique_signals": sorted(unique_signals),
                "selected_signals": selected_signals,
                "capture_diagnostics": diagnostics_by_version.get(version, []),
                "similarity": similarity,
                "promotion": _build_promotion_readiness(
                    capture_count=len(versions[version]),
                    unique_signal_count=len(unique_signals),
                    selected_signal_count=len(selected_signals),
                    similarity=similarity,
                ),
                "candidate_rule": candidate_rule,
            }
        )

    return {
        "schema_version": 1,
        "bundle_type": "openclaw_blackbox_rule_suggestions",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "bundle_count": len(bundles),
        "capture_entry_count": len(bundle_entries),
        "versions": suggestions,
        "skipped_bundles": skipped,
        "skipped_input_summary": _summarize_skipped_inputs(skipped_inputs or []),
        "skipped_inputs": list(skipped_inputs or []),
    }


def render_rule_suggestions(report: Dict[str, object], output_format: str) -> str:
    if output_format == "json":
        return json.dumps(report, indent=2, sort_keys=True)

    lines = [
        f"Capture bundles: {report.get('bundle_count', 0)}",
        f"Capture entries: {report.get('capture_entry_count', 0)}",
    ]
    versions = report.get("versions") or []
    if not versions:
        lines.append("Candidate version rules: none")
    else:
        lines.append("Candidate version rules:")
        for item in versions:
            candidate_rule = item.get("candidate_rule") or {}
            lines.append(
                f"  - {item['version']} from {item['capture_count']} capture(s)"
            )
            lines.append(
                f"    unique signals={item['unique_signal_count']} stable signals={item['stable_signal_count']}"
            )
            similarity = item.get("similarity") or {}
            if similarity:
                lines.append(
                    "    similarity: "
                    f"intra_avg={_format_score(similarity.get('intra_version_avg_jaccard'))} "
                    f"intra_min={_format_score(similarity.get('intra_version_min_jaccard'))} "
                    f"nearest_other={similarity.get('nearest_other_version') or 'none'} "
                    f"jaccard={_format_score(similarity.get('nearest_other_jaccard'))}"
                )
            promotion = item.get("promotion") or {}
            if promotion:
                status = promotion.get("status") or "unknown"
                ready = "yes" if promotion.get("ready_for_review") else "no"
                lines.append(f"    promotion: {status} ready_for_review={ready}")
                reasons = promotion.get("reasons") or []
                if reasons:
                    lines.append("    promotion reasons: " + "; ".join(reasons))
                blockers = promotion.get("blockers") or []
                if blockers:
                    lines.append("    promotion blockers: " + "; ".join(blockers))
            if candidate_rule:
                lines.append(
                    "    rule: "
                    f"{candidate_rule.get('id')} confidence={candidate_rule.get('confidence')}"
                )
            if item.get("selected_signals"):
                lines.append(
                    "    selected: " + "; ".join(item["selected_signals"])
                )
            diagnostics = item.get("capture_diagnostics") or []
            noisy_diagnostics = [
                entry for entry in diagnostics
                if entry.get("error_count") or entry.get("timeout_error_count")
            ]
            if noisy_diagnostics:
                lines.append(
                    "    capture diagnostics: "
                    + "; ".join(
                        "#"
                        + str(entry.get("capture_index"))
                        + f" signals={entry.get('signal_count')} observations={entry.get('observation_count')}"
                        + f" errors={entry.get('error_count')} timeouts={entry.get('timeout_error_count')}"
                        for entry in noisy_diagnostics
                    )
                )

    skipped = report.get("skipped_bundles") or []
    if skipped:
        lines.append("Skipped bundles:")
        for item in skipped:
            lines.append(
                f"  - {item.get('capture_name') or 'unnamed'}: {item.get('reason')}"
            )

    skipped_inputs = report.get("skipped_inputs") or []
    if skipped_inputs:
        skipped_input_summary = report.get("skipped_input_summary") or _summarize_skipped_inputs(skipped_inputs)
        if skipped_input_summary:
            lines.append("Skipped input summary:")
            for item in skipped_input_summary:
                lines.append(
                    f"  - {item.get('count', 0)} file(s): {item.get('reason') or 'unknown'}"
                )
        lines.append("Skipped input files:")
        for item in skipped_inputs[:SKIPPED_INPUT_PRETTY_LIMIT]:
            lines.append(
                f"  - {item.get('path') or 'unknown'}: {item.get('reason')}"
            )
        remaining = len(skipped_inputs) - SKIPPED_INPUT_PRETTY_LIMIT
        if remaining > 0:
            lines.append(f"  - ... {remaining} more skipped input file(s)")

    return "\n".join(lines) + "\n"


def _capture_entry(result: ScanResult) -> Dict[str, object]:
    observations = {
        path: observation.to_dict()
        for path, observation in result.observations.items()
    }
    return {
        "input_target": result.input_target,
        "source": result.source,
        "probed_base": result.probed_base,
        "metadata": result.metadata,
        "product_confidence": result.product_confidence,
        "observations": observations,
        "errors": list(result.errors),
        "signals": sorted(_signals_from_result(result)),
    }


def _summarize_skipped_inputs(skipped_inputs: Sequence[Dict[str, object]]) -> List[Dict[str, object]]:
    counts = Counter(str(item.get("reason") or "unknown") for item in skipped_inputs)
    return [
        {
            "reason": reason,
            "count": count,
        }
        for reason, count in sorted(
            counts.items(),
            key=lambda item: (-item[1], item[0]),
        )
    ]


def _capture_diagnostics(
    capture: Dict[str, object],
    *,
    capture_name: object,
    capture_index: int,
    signals: Set[str],
) -> Dict[str, object]:
    observations = capture.get("observations")
    observation_count = len(observations) if isinstance(observations, dict) else 0
    errors = [
        str(error)
        for error in capture.get("errors", [])
        if isinstance(error, str) and error
    ]
    timeout_paths = sorted(
        {
            label
            for error in errors
            if _is_timeout_error(error)
            for label in [_error_probe_label(error)]
            if label
        }
    )
    return {
        "capture_index": capture_index,
        "capture_name": capture_name,
        "signal_count": len(signals),
        "observation_count": observation_count,
        "error_count": len(errors),
        "timeout_error_count": sum(1 for error in errors if _is_timeout_error(error)),
        "timeout_probe_labels": timeout_paths,
    }


def _is_timeout_error(error: str) -> bool:
    normalized = error.lower()
    return "timed out" in normalized or "timeout" in normalized


def _error_probe_label(error: str) -> str:
    without_url = re.sub(r"^https?://\S+\s+", "", error.strip())
    return (without_url.split(":", 1)[0].strip() or "unknown")[:120]


def _signals_from_result(result: ScanResult) -> Set[str]:
    signals: Set[str] = set()
    for observation in result.observations.values():
        signals.update(_signals_from_observation(observation))
    return signals


def _signals_from_observation(observation: ProbeObservation) -> Set[str]:
    signals: Set[str] = set()
    path = observation.path
    if observation.status is not None:
        signals.add(f"path_status|{path}|{observation.status}")
        signals.add(
            f"method_status|{observation.method.upper()}|{observation.path}|{observation.status}"
        )
    if observation.probe_name == "ws-upgrade":
        if observation.status is not None:
            signals.add(f"ws_upgrade_status|{path}|{observation.status}")
            signals.add(
                f"ws_upgrade_supported|{path}|{str(observation.status == 101).lower()}"
            )
        subprotocol = observation.headers.get("sec-websocket-protocol")
        if subprotocol:
            signals.add(f"ws_subprotocol_contains|{path}|{subprotocol}")
        extensions = observation.headers.get("sec-websocket-extensions")
        if extensions:
            signals.add(f"ws_extension_contains|{path}|{extensions}")
    if observation.title:
        title = observation.title.strip()
        if title:
            signals.add(f"title_contains|{path}|{title}")
    content_type = _normalize_content_type(observation.content_type)
    if content_type:
        signals.add(f"header_contains|{path}|content-type|{content_type}")
    if observation.body_sha256:
        signals.add(f"body_hash|{path}|{observation.body_sha256.lower()}")
    if observation.favicon_hash is not None:
        signals.add(f"favicon_hash|{path}|{observation.favicon_hash}")
    for key in sorted(set(observation.json_keys)):
        signals.add(f"json_key|{path}|{key}")
    for marker in sorted(set(observation.body_markers)):
        signals.add(f"marker_present|{path}|{marker}")
    for script in sorted(set(observation.js_files)):
        signals.add(f"script_contains|{path}|{script}")
    return signals


def _normalize_content_type(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    return value.split(";", 1)[0].strip().lower() or None


def _build_similarity_report(
    versions: Dict[str, List[Set[str]]],
    stable_by_version: Dict[str, Set[str]],
) -> Dict[str, Dict[str, object]]:
    report: Dict[str, Dict[str, object]] = {}
    for version, signal_sets in versions.items():
        intra = _pairwise_jaccard_stats(signal_sets)
        nearest_version = None
        nearest_score = None
        stable_nearest_version = None
        stable_nearest_score = None

        for other_version, other_signal_sets in versions.items():
            if other_version == version:
                continue

            for signal_set in signal_sets:
                for other_signal_set in other_signal_sets:
                    score = _jaccard(signal_set, other_signal_set)
                    if nearest_score is None or score > nearest_score:
                        nearest_version = other_version
                        nearest_score = score

            stable_score = _jaccard(
                stable_by_version.get(version, set()),
                stable_by_version.get(other_version, set()),
            )
            if stable_nearest_score is None or stable_score > stable_nearest_score:
                stable_nearest_version = other_version
                stable_nearest_score = stable_score

        report[version] = {
            "intra_version_pair_count": intra["pair_count"],
            "intra_version_min_jaccard": intra["min_jaccard"],
            "intra_version_avg_jaccard": intra["avg_jaccard"],
            "nearest_other_version": nearest_version,
            "nearest_other_jaccard": _round_score(nearest_score),
            "stable_nearest_other_version": stable_nearest_version,
            "stable_nearest_other_jaccard": _round_score(stable_nearest_score),
        }
    return report


def _build_promotion_readiness(
    capture_count: int,
    unique_signal_count: int,
    selected_signal_count: int,
    similarity: Dict[str, object],
) -> Dict[str, object]:
    reasons = []
    blockers = []

    if capture_count < 2:
        blockers.append("needs at least two captures for same-version stability")
    else:
        reasons.append("has at least two same-version captures")

    if selected_signal_count <= 0:
        blockers.append("no selected rule signals")

    if unique_signal_count <= 0:
        blockers.append("no stable signals unique to this version")
    else:
        reasons.append(f"{unique_signal_count} stable unique signal(s)")

    intra_min = similarity.get("intra_version_min_jaccard")
    if capture_count > 1 and isinstance(intra_min, (int, float)):
        if float(intra_min) < 0.85:
            if (
                float(intra_min) >= 0.75
                and unique_signal_count > 0
                and selected_signal_count > 0
            ):
                reasons.append(
                    "intra-version surface varied "
                    f"({float(intra_min):.4f}); selected stable unique signals remained"
                )
            else:
                blockers.append(f"intra-version Jaccard is low ({float(intra_min):.4f})")
        else:
            reasons.append(f"intra-version Jaccard is stable ({float(intra_min):.4f})")

    nearest_other = similarity.get("nearest_other_jaccard")
    if isinstance(nearest_other, (int, float)):
        if float(nearest_other) >= 0.5:
            if unique_signal_count <= 0 or selected_signal_count <= 0:
                blockers.append(
                    f"nearest other version is too similar ({float(nearest_other):.4f})"
                )
            else:
                reasons.append(
                    "nearest other version has a similar overall surface "
                    f"({float(nearest_other):.4f}); selected stable unique signals distinguish it"
                )
        else:
            reasons.append(
                f"nearest other version is distinct ({float(nearest_other):.4f})"
            )

    if blockers:
        return {
            "ready_for_review": False,
            "status": "needs_more_evidence",
            "reasons": reasons,
            "blockers": blockers,
        }

    return {
        "ready_for_review": True,
        "status": "review_candidate",
        "reasons": reasons,
        "blockers": [],
    }


def _pairwise_jaccard_stats(signal_sets: Sequence[Set[str]]) -> Dict[str, object]:
    scores = []
    for index, signal_set in enumerate(signal_sets):
        for other_signal_set in signal_sets[index + 1:]:
            scores.append(_jaccard(signal_set, other_signal_set))

    if not scores:
        return {
            "pair_count": 0,
            "min_jaccard": None,
            "avg_jaccard": None,
        }

    return {
        "pair_count": len(scores),
        "min_jaccard": _round_score(min(scores)),
        "avg_jaccard": _round_score(sum(scores) / len(scores)),
    }


def _jaccard(left: Set[str], right: Set[str]) -> float:
    if not left and not right:
        return 1.0
    union = left | right
    if not union:
        return 0.0
    return len(left & right) / len(union)


def _round_score(value: Optional[float]) -> Optional[float]:
    if value is None:
        return None
    return round(value, 4)


def _format_score(value: object) -> str:
    if value is None:
        return "n/a"
    try:
        return f"{float(value):.4f}"
    except (TypeError, ValueError):
        return "n/a"


def _load_capture_file(path: Path) -> List[Dict[str, object]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if isinstance(data, dict):
        return [data]
    return []


def _is_capture_bundle(value: Dict[str, object]) -> bool:
    return value.get("bundle_type") == "openclaw_blackbox_capture"


def _display_path(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def _select_rule_signals(
    unique_signals: Set[str],
    stable_signals: Set[str],
    capture_count: int,
    max_conditions: int,
) -> List[str]:
    candidates = unique_signals or stable_signals
    ranked = sorted(
        candidates,
        key=lambda item: (_signal_rank(item, capture_count), item),
        reverse=True,
    )
    selected = []
    for signal in ranked:
        if _signal_is_too_generic(signal):
            continue
        selected.append(signal)
        if len(selected) >= max_conditions:
            break
    return selected


def _signal_rank(signal: str, capture_count: int) -> int:
    signal_type = signal.split("|", 1)[0]
    priorities = {
        "script_contains": 100,
        "favicon_hash": 95,
        "json_key": 90,
        "body_hash": 80 if capture_count > 1 else 35,
        "header_contains": 70,
        "ws_extension_contains": 68,
        "ws_subprotocol_contains": 67,
        "title_contains": 60,
        "ws_upgrade_status": 58,
        "ws_upgrade_supported": 57,
        "method_status": 55,
        "path_status": 50,
        "marker_present": 25,
    }
    return priorities.get(signal_type, 10)


def _signal_is_too_generic(signal: str) -> bool:
    if signal.startswith("marker_present|") and signal.endswith("|openclaw"):
        return True
    if signal.startswith("marker_present|") and signal.endswith("|clawdbot"):
        return True
    if signal.startswith("marker_present|") and signal.endswith("|moltbot"):
        return True
    return False


def _build_candidate_rule(
    version: str,
    selected_signals: Sequence[str],
    capture_count: int,
) -> Dict[str, object]:
    if not selected_signals:
        return {}

    exact = bool(EXACT_VERSION_RE.match(version))
    confidence = 0.62 + min(capture_count, 4) * 0.06 + min(len(selected_signals), 3) * 0.05
    if capture_count == 1:
        confidence = min(confidence, 0.74)
    confidence = round(min(confidence, 0.93), 2)

    return {
        "id": f"lab-capture-{_sanitize_rule_id(version)}",
        "version": version,
        "confidence": confidence,
        "exact": exact,
        "notes": (
            "Candidate rule derived from black-box captures against known-version test nodes. "
            "Review before promoting into openclaw_rules.json."
        ),
        "all": [_signal_to_condition(signal) for signal in selected_signals],
    }


def _signal_to_condition(signal: str) -> Dict[str, object]:
    parts = signal.split("|")
    signal_type = parts[0]
    if signal_type == "path_status":
        _, path, status = parts
        return {"type": "path_status", "path": path, "statuses": [int(status)]}
    if signal_type == "method_status":
        _, method, path, status = parts
        return {
            "type": "method_status",
            "method": method,
            "path": path,
            "statuses": [int(status)],
        }
    if signal_type == "title_contains":
        _, path, value = parts
        return {"type": "title_contains", "path": path, "value": value}
    if signal_type == "marker_present":
        _, path, value = parts
        return {"type": "marker_present", "path": path, "value": value}
    if signal_type == "script_contains":
        _, path, value = parts
        return {"type": "script_contains", "path": path, "value": value}
    if signal_type == "header_contains":
        _, path, header, value = parts
        return {"type": "header_contains", "path": path, "header": header, "value": value}
    if signal_type == "json_key":
        _, path, value = parts
        return {"type": "json_key", "path": path, "value": value}
    if signal_type == "body_hash":
        _, path, value = parts
        return {"type": "body_hash", "path": path, "value": value}
    if signal_type == "favicon_hash":
        _, path, value = parts
        return {"type": "favicon_hash", "path": path, "value": int(value)}
    if signal_type == "ws_upgrade_status":
        _, path, status = parts
        return {
            "type": "ws_upgrade_status",
            "path": path,
            "probe_name": "ws-upgrade",
            "statuses": [int(status)],
        }
    if signal_type == "ws_upgrade_supported":
        _, path, value = parts
        return {
            "type": "ws_upgrade_supported",
            "path": path,
            "probe_name": "ws-upgrade",
            "value": value.lower() == "true",
        }
    if signal_type == "ws_subprotocol_contains":
        _, path, value = parts
        return {
            "type": "ws_subprotocol_contains",
            "path": path,
            "probe_name": "ws-upgrade",
            "value": value,
        }
    if signal_type == "ws_extension_contains":
        _, path, value = parts
        return {
            "type": "ws_extension_contains",
            "path": path,
            "probe_name": "ws-upgrade",
            "value": value,
        }
    raise ValueError(f"Unsupported signal: {signal}")


def _sanitize_rule_id(version: str) -> str:
    sanitized = re.sub(r"[^0-9A-Za-z]+", "-", version).strip("-").lower()
    return sanitized or "unknown-version"


def _version_sort_key(value: str) -> Tuple[int, ...]:
    parts = re.findall(r"\d+", value)
    return tuple(int(part) for part in parts) if parts else (0,)
