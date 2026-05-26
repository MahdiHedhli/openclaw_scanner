#!/usr/bin/env python3
"""Validate saved OpenClaw capture bundles against the current inference rules.

The report intentionally excludes target URLs, raw observation URLs, and IPs so
it can be preserved beside corpus artifacts without leaking short-lived lab
addresses.
"""

from __future__ import annotations

import argparse
import json
import shlex
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Set, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from openclaw_scanner.inference import infer_versions, load_rules  # noqa: E402
from openclaw_scanner.models import ProbeObservation  # noqa: E402


OBSERVATION_FIELDS = set(ProbeObservation.__dataclass_fields__)


def utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def display_path(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def is_capture_bundle(value: Dict[str, Any]) -> bool:
    return value.get("bundle_type") == "openclaw_blackbox_capture"


def summarize_skipped(skipped_inputs: Iterable[Dict[str, str]]) -> List[Dict[str, Any]]:
    counts = Counter(item.get("reason") or "unknown" for item in skipped_inputs)
    return [
        {"reason": reason, "count": count}
        for reason, count in sorted(counts.items())
    ]


def load_capture_bundle_files(root: Path) -> Tuple[List[Tuple[Path, Dict[str, Any]]], List[Dict[str, str]]]:
    if root.is_file():
        paths = [root]
        display_root = root.parent
    else:
        paths = sorted(root.rglob("*.json"))
        display_root = root

    bundles: List[Tuple[Path, Dict[str, Any]]] = []
    skipped: List[Dict[str, str]] = []
    for path in paths:
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            skipped.append({
                "path": display_path(path, display_root),
                "reason": f"invalid JSON: {exc.msg}",
            })
            continue
        except OSError:
            skipped.append({
                "path": display_path(path, display_root),
                "reason": "unreadable JSON file",
            })
            continue

        if isinstance(loaded, dict) and is_capture_bundle(loaded):
            bundles.append((path, loaded))
        else:
            skipped.append({
                "path": display_path(path, display_root),
                "reason": "not an openclaw_blackbox_capture bundle",
            })

    return bundles, skipped


def build_observations(capture: Dict[str, Any]) -> Tuple[Dict[str, ProbeObservation], int]:
    observations: Dict[str, ProbeObservation] = {}
    malformed = 0
    raw_observations = capture.get("observations") or {}
    if not isinstance(raw_observations, dict):
        return observations, 1

    for key, value in raw_observations.items():
        if not isinstance(value, dict):
            malformed += 1
            continue
        filtered = {
            field: value[field]
            for field in OBSERVATION_FIELDS
            if field in value
        }
        try:
            observations[str(key)] = ProbeObservation(**filtered)
        except TypeError:
            malformed += 1
    return observations, malformed


def normalize_versions(versions: Iterable[str] | None) -> Set[str]:
    if not versions:
        return set()
    return {str(version).strip() for version in versions if str(version).strip()}


def summarize_versions(records: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    summaries: Dict[str, Dict[str, Any]] = {}
    for record in records:
        declared_version = record.get("declared_version") or "unknown"
        summary = summaries.setdefault(
            str(declared_version),
            {
                "declared_version": declared_version,
                "capture_count": 0,
                "evaluated_capture_count": 0,
                "ignored_capture_count": 0,
                "declared_exact_match_count": 0,
                "declared_no_exact_match_count": 0,
                "ignored_declared_no_exact_match_count": 0,
                "top_versions": [],
                "exact_sources": [],
            },
        )
        summary["capture_count"] += 1

        ignored = bool(record.get("ignored_for_exact_requirement"))
        exact = bool(record.get("declared_exact_match"))
        if ignored:
            summary["ignored_capture_count"] += 1
            if not exact:
                summary["ignored_declared_no_exact_match_count"] += 1
        else:
            summary["evaluated_capture_count"] += 1
            if exact:
                summary["declared_exact_match_count"] += 1
            else:
                summary["declared_no_exact_match_count"] += 1

        if record.get("top_version"):
            summary["top_versions"].append(str(record["top_version"]))
        for source in record.get("exact_sources") or []:
            summary["exact_sources"].append(str(source))

    version_summaries: List[Dict[str, Any]] = []
    for version, summary in sorted(summaries.items()):
        top_version_counts = Counter(summary.pop("top_versions"))
        exact_sources = sorted(set(summary["exact_sources"]))
        summary["top_version_counts"] = [
            {"version": top_version, "count": count}
            for top_version, count in sorted(top_version_counts.items())
        ]
        summary["exact_sources"] = exact_sources
        version_summaries.append(summary)
    return version_summaries


def validate_capture_root(
    input_root: str,
    rules_file: str | None = None,
    ignore_versions: Iterable[str] | None = None,
) -> Dict[str, Any]:
    root = Path(input_root)
    rules = load_rules(rules_file)
    bundles, skipped_inputs = load_capture_bundle_files(root)
    records: List[Dict[str, Any]] = []
    ignored_versions = normalize_versions(ignore_versions)

    for bundle_path, bundle in bundles:
        declared_version = str(bundle.get("declared_version") or "").strip() or None
        capture_name = bundle.get("capture_name")
        captures = bundle.get("captures") or []
        if not isinstance(captures, list):
            captures = []

        for index, capture in enumerate(captures, start=1):
            ignored_for_exact_requirement = bool(
                declared_version and declared_version in ignored_versions
            )
            if not isinstance(capture, dict):
                records.append({
                    "capture_path": display_path(bundle_path, root if root.is_dir() else root.parent),
                    "capture_index": index,
                    "capture_name": capture_name,
                    "declared_version": declared_version,
                    "ignored_for_exact_requirement": ignored_for_exact_requirement,
                    "observation_count": 0,
                    "malformed_observation_count": 1,
                    "matched_version_count": 0,
                    "top_version": None,
                    "top_source": None,
                    "top_exact": None,
                    "declared_exact_match": False,
                    "exact_sources": [],
                })
                continue

            observations, malformed_count = build_observations(capture)
            versions = infer_versions(observations, rules)
            exact_sources = [
                match.source
                for match in versions
                if declared_version and match.version == declared_version and match.exact
            ]
            records.append({
                "capture_path": display_path(bundle_path, root if root.is_dir() else root.parent),
                "capture_index": index,
                "capture_name": capture_name,
                "declared_version": declared_version,
                "ignored_for_exact_requirement": ignored_for_exact_requirement,
                "observation_count": len(observations),
                "malformed_observation_count": malformed_count,
                "matched_version_count": len(versions),
                "top_version": versions[0].version if versions else None,
                "top_source": versions[0].source if versions else None,
                "top_exact": versions[0].exact if versions else None,
                "declared_exact_match": bool(exact_sources),
                "exact_sources": exact_sources,
            })

    missing_versions = sorted({
        str(item["declared_version"])
        for item in records
        if item.get("declared_version") and not item.get("declared_exact_match")
        and not item.get("ignored_for_exact_requirement")
    })
    evaluated_records = [
        item for item in records if not item.get("ignored_for_exact_requirement")
    ]
    ignored_records = [
        item for item in records if item.get("ignored_for_exact_requirement")
    ]
    return {
        "schema_version": 1,
        "bundle_type": "openclaw_saved_capture_inference_validation",
        "generated_at": utc_now(),
        "input_root": str(root),
        "rules_file": str(rules_file) if rules_file else None,
        "ignored_versions": sorted(ignored_versions),
        "ignored_versions_present": sorted({
            str(item["declared_version"])
            for item in ignored_records
            if item.get("declared_version")
        }),
        "bundle_count": len(bundles),
        "capture_count": len(records),
        "evaluated_capture_count": len(evaluated_records),
        "ignored_capture_count": len(ignored_records),
        "declared_exact_match_count": sum(
            1 for item in evaluated_records if item.get("declared_exact_match")
        ),
        "declared_no_exact_match_count": sum(
            1 for item in evaluated_records if not item.get("declared_exact_match")
        ),
        "ignored_declared_no_exact_match_count": sum(
            1 for item in ignored_records if not item.get("declared_exact_match")
        ),
        "declared_versions_without_exact_match": missing_versions,
        "version_summary": summarize_versions(records),
        "skipped_input_summary": summarize_skipped(skipped_inputs),
        "skipped_inputs": skipped_inputs,
        "records": records,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate saved OpenClaw capture bundles against inference rules."
    )
    parser.add_argument("--input-root", required=True, help="Capture bundle file or lab artifact directory.")
    parser.add_argument("--rules-file", help="Optional rules file. Defaults to bundled scanner rules.")
    parser.add_argument("--output", help="Write sanitized JSON report to this path.")
    parser.add_argument(
        "--require-all-exact",
        action="store_true",
        help="Exit nonzero if any declared capture lacks an exact version match.",
    )
    parser.add_argument(
        "--ignore-version",
        action="append",
        default=[],
        help=(
            "Declared version to exclude from --require-all-exact enforcement. "
            "Repeat for multiple intentionally unpromoted or unstable versions."
        ),
    )
    parser.add_argument(
        "--manifest",
        help="Update the lab manifest's saved_capture_inference summary with this report.",
    )
    return parser


def manifest_saved_capture_summary(
    report: Dict[str, Any],
    *,
    artifact: str | None,
    command: str | None,
    require_all_exact: bool,
) -> Dict[str, Any]:
    return {
        "checked_at": report.get("generated_at"),
        "command": command,
        "artifact": artifact,
        "passed": (not require_all_exact)
        or not bool(report.get("declared_no_exact_match_count")),
        "require_all_exact": require_all_exact,
        "bundle_count": report.get("bundle_count", 0),
        "capture_count": report.get("capture_count", 0),
        "evaluated_capture_count": report.get("evaluated_capture_count", 0),
        "ignored_capture_count": report.get("ignored_capture_count", 0),
        "declared_exact_match_count": report.get("declared_exact_match_count", 0),
        "declared_no_exact_match_count": report.get("declared_no_exact_match_count", 0),
        "ignored_declared_no_exact_match_count": report.get(
            "ignored_declared_no_exact_match_count", 0
        ),
        "declared_versions_without_exact_match": list(
            report.get("declared_versions_without_exact_match") or []
        ),
        "ignored_versions": list(report.get("ignored_versions") or []),
        "ignored_versions_present": list(report.get("ignored_versions_present") or []),
        "version_summary": list(report.get("version_summary") or []),
        "skipped_input_summary": list(report.get("skipped_input_summary") or []),
    }


def update_manifest_saved_capture(
    manifest_path: str,
    report: Dict[str, Any],
    *,
    artifact: str | None,
    command: str | None,
    require_all_exact: bool,
) -> None:
    path = Path(manifest_path)
    manifest = json.loads(path.read_text(encoding="utf-8"))
    manifest["saved_capture_inference"] = manifest_saved_capture_summary(
        report,
        artifact=artifact,
        command=command,
        require_all_exact=require_all_exact,
    )
    path.write_text(json.dumps(manifest, indent=2, sort_keys=False) + "\n", encoding="utf-8")


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
    report = validate_capture_root(
        args.input_root,
        rules_file=args.rules_file,
        ignore_versions=args.ignore_version,
    )
    write_json(report, args.output)
    if args.manifest:
        command = "python3 scripts/validate_saved_capture_inference.py " + " ".join(
            shlex.quote(part) for part in raw_argv
        )
        update_manifest_saved_capture(
            args.manifest,
            report,
            artifact=args.output,
            command=command,
            require_all_exact=args.require_all_exact,
        )
    if args.require_all_exact and report["declared_no_exact_match_count"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
