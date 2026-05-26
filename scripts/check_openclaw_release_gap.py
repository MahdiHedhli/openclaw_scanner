#!/usr/bin/env python3
"""Compare published OpenClaw versions with corpus captures and promoted rules."""

from __future__ import annotations

import argparse
import json
import re
import shlex
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence, Tuple


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RULES_FILE = REPO_ROOT / "openclaw_scanner" / "data" / "openclaw_rules.json"
VERSION_RE = re.compile(r"^(\d+(?:\.\d+)*)(?:-([0-9A-Za-z.-]+))?$")
PRERELEASE_RANKS = {
    "alpha": 0,
    "beta": 1,
    "rc": 2,
}


def utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def version_key(version: str) -> Tuple[Tuple[int, ...], int, Tuple[int, ...], str]:
    match = VERSION_RE.match(version.strip())
    if not match:
        return ((-1,), -1, (), version)

    core = tuple(int(part) for part in match.group(1).split("."))
    prerelease = match.group(2)
    if not prerelease:
        return (core, 3, (), version)

    parts = prerelease.split(".")
    label = parts[0].lower()
    numeric_parts = tuple(int(part) for part in parts[1:] if part.isdigit())
    if label.isdigit():
        return (core, -1, (int(label),), version)
    return (core, PRERELEASE_RANKS.get(label, -1), numeric_parts, version)


def latest_version(versions: Iterable[str]) -> str | None:
    normalized = [str(version).strip() for version in versions if str(version).strip()]
    if not normalized:
        return None
    return max(normalized, key=version_key)


def load_versions_json(path: str | None, raw_json: str | None) -> List[str]:
    if raw_json:
        loaded = json.loads(raw_json)
    elif path:
        loaded = json.loads(Path(path).read_text(encoding="utf-8"))
    else:
        loaded = json.loads(sys.stdin.read())

    if not isinstance(loaded, list):
        raise ValueError("published versions input must be a JSON array")
    return [str(item).strip() for item in loaded if str(item).strip()]


def is_capture_bundle(value: Dict[str, Any]) -> bool:
    return value.get("bundle_type") == "openclaw_blackbox_capture"


def captured_versions(input_root: Path) -> Counter[str]:
    paths = [input_root] if input_root.is_file() else sorted(input_root.rglob("*.json"))
    versions: Counter[str] = Counter()
    for path in paths:
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        if not isinstance(loaded, dict) or not is_capture_bundle(loaded):
            continue
        declared = str(loaded.get("declared_version") or "").strip()
        captures = loaded.get("captures") or []
        if declared and isinstance(captures, list):
            versions[declared] += len(captures)
    return versions


def promoted_versions(rules_file: Path) -> List[str]:
    loaded = json.loads(rules_file.read_text(encoding="utf-8"))
    rules = loaded.get("version_rules") or []
    versions = {
        str(rule.get("version") or "").strip()
        for rule in rules
        if isinstance(rule, dict) and rule.get("exact") and str(rule.get("version") or "").strip()
    }
    return sorted(versions, key=version_key)


def versions_after(versions: Iterable[str], baseline: str | None) -> List[str]:
    normalized = [str(version).strip() for version in versions if str(version).strip()]
    if not baseline:
        return sorted(normalized, key=version_key)
    baseline_key = version_key(baseline)
    return sorted(
        [version for version in normalized if version_key(version) > baseline_key],
        key=version_key,
    )


def build_report(
    *,
    published_versions: Sequence[str],
    capture_root: Path,
    rules_file: Path,
    include_prereleases: bool,
) -> Dict[str, Any]:
    captures = captured_versions(capture_root)
    promoted = promoted_versions(rules_file)
    latest_published = latest_version(published_versions)
    latest_captured = latest_version(captures.keys())
    latest_promoted = latest_version(promoted)

    captured_set = set(captures)
    promoted_set = set(promoted)
    uncaptured = [
        version for version in versions_after(published_versions, latest_captured)
        if version not in captured_set
    ]
    unpromoted_captured = sorted(captured_set - promoted_set, key=version_key)
    stable_uncaptured = [version for version in uncaptured if "-" not in version]
    prerelease_uncaptured = [version for version in uncaptured if "-" in version]
    capture_needed_versions = uncaptured if include_prereleases else stable_uncaptured

    return {
        "schema_version": 1,
        "bundle_type": "openclaw_release_gap_check",
        "generated_at": utc_now(),
        "package": "openclaw",
        "capture_root": str(capture_root),
        "rules_file": str(rules_file),
        "published_version_count": len(published_versions),
        "latest_published_version": latest_published,
        "latest_captured_version": latest_captured,
        "latest_promoted_exact_version": latest_promoted,
        "captured_versions": [
            {"version": version, "capture_count": captures[version]}
            for version in sorted(captures, key=version_key)
        ],
        "promoted_exact_versions": promoted,
        "captured_unpromoted_versions": unpromoted_captured,
        "uncaptured_versions_after_latest_capture": uncaptured,
        "stable_uncaptured_versions_after_latest_capture": stable_uncaptured,
        "prerelease_uncaptured_versions_after_latest_capture": prerelease_uncaptured,
        "capture_needed_versions": capture_needed_versions,
        "capture_needed": bool(capture_needed_versions),
        "decision": "launch_single_vm_capture" if capture_needed_versions else "no_vm_needed",
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Report whether published OpenClaw versions need new corpus captures."
    )
    parser.add_argument("--versions-file", help="JSON file containing the npm versions array.")
    parser.add_argument("--versions-json", help="Inline JSON array containing published versions.")
    parser.add_argument(
        "--capture-root",
        default="artifacts/lab",
        help="Capture bundle file or lab artifact directory.",
    )
    parser.add_argument(
        "--rules-file",
        default=str(DEFAULT_RULES_FILE),
        help="Scanner rules file with promoted exact version rules.",
    )
    parser.add_argument(
        "--include-prereleases",
        action="store_true",
        help="Treat uncaptured prerelease packages as capture-needed targets.",
    )
    parser.add_argument("--output", help="Write JSON report to this path.")
    parser.add_argument(
        "--manifest",
        help="Update the lab manifest's release_gap summary with this report.",
    )
    return parser


def manifest_release_gap_summary(
    report: Dict[str, Any],
    *,
    artifact: str | None,
    command: str | None,
) -> Dict[str, Any]:
    return {
        "checked_at": report.get("generated_at"),
        "command": command,
        "artifact": artifact,
        "package": report.get("package"),
        "decision": report.get("decision"),
        "capture_needed": bool(report.get("capture_needed")),
        "capture_needed_versions": list(report.get("capture_needed_versions") or []),
        "latest_published_version": report.get("latest_published_version"),
        "latest_captured_version": report.get("latest_captured_version"),
        "latest_promoted_exact_version": report.get("latest_promoted_exact_version"),
        "captured_version_count": len(report.get("captured_versions") or []),
        "promoted_exact_version_count": len(report.get("promoted_exact_versions") or []),
        "captured_unpromoted_versions": list(report.get("captured_unpromoted_versions") or []),
        "stable_uncaptured_versions_after_latest_capture": list(
            report.get("stable_uncaptured_versions_after_latest_capture") or []
        ),
        "prerelease_uncaptured_versions_after_latest_capture": list(
            report.get("prerelease_uncaptured_versions_after_latest_capture") or []
        ),
    }


def update_manifest_release_gap(
    manifest_path: str,
    report: Dict[str, Any],
    *,
    artifact: str | None,
    command: str | None,
) -> None:
    path = Path(manifest_path)
    manifest = json.loads(path.read_text(encoding="utf-8"))
    manifest["release_gap"] = manifest_release_gap_summary(
        report,
        artifact=artifact,
        command=command,
    )
    path.write_text(json.dumps(manifest, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def command_for_manifest(raw_argv: Sequence[str]) -> str:
    sanitized: List[str] = []
    redact_next = False
    for part in raw_argv:
        if redact_next:
            sanitized.append("<versions-json>")
            redact_next = False
            continue
        if part == "--versions-json":
            sanitized.append(part)
            redact_next = True
            continue
        if part.startswith("--versions-json="):
            sanitized.append("--versions-json=<versions-json>")
            continue
        sanitized.append(part)
    return "python3 scripts/check_openclaw_release_gap.py " + " ".join(
        shlex.quote(part) for part in sanitized
    )


def write_json(report: Dict[str, Any], output: str | None) -> None:
    text = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if output:
        path = Path(output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)


def main(argv: List[str] | None = None) -> int:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    args = build_parser().parse_args(raw_argv)
    versions = load_versions_json(args.versions_file, args.versions_json)
    report = build_report(
        published_versions=versions,
        capture_root=Path(args.capture_root),
        rules_file=Path(args.rules_file),
        include_prereleases=args.include_prereleases,
    )
    write_json(report, args.output)
    if args.manifest:
        update_manifest_release_gap(
            args.manifest,
            report,
            artifact=args.output,
            command=command_for_manifest(raw_argv),
        )
    return 1 if report["capture_needed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
