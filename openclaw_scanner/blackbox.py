import json
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from .models import ProbeObservation, ScanResult

EXACT_VERSION_RE = re.compile(r"^20\d{2}\.\d+\.\d+(?:-[A-Za-z0-9]+)?$")


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
    path = Path(path_value)
    if path.is_dir():
        bundles: List[Dict[str, object]] = []
        for item in sorted(path.glob("*.json")):
            bundles.extend(_load_capture_file(item))
        return bundles

    return _load_capture_file(path)


def generate_rule_suggestions(
    bundles: Sequence[Dict[str, object]],
    max_conditions: int = 3,
) -> Dict[str, object]:
    bundle_entries = []
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
            if candidate_rule:
                lines.append(
                    "    rule: "
                    f"{candidate_rule.get('id')} confidence={candidate_rule.get('confidence')}"
                )
            if item.get("selected_signals"):
                lines.append(
                    "    selected: " + "; ".join(item["selected_signals"])
                )

    skipped = report.get("skipped_bundles") or []
    if skipped:
        lines.append("Skipped bundles:")
        for item in skipped:
            lines.append(
                f"  - {item.get('capture_name') or 'unnamed'}: {item.get('reason')}"
            )

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


def _load_capture_file(path: Path) -> List[Dict[str, object]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if isinstance(data, dict):
        return [data]
    return []


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
