#!/usr/bin/env python3
"""Run the secret-safe OpenClaw corpus heartbeat checks.

This script intentionally does not create, boot, stop, or delete VMs. It
collects the read-only gate state that decides whether a later lifecycle run
should launch exactly one short-lived VLAN 30 corpus VM.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RULES_FILE = REPO_ROOT / "openclaw_scanner" / "data" / "openclaw_rules.json"


def utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def load_script_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


preflight = load_script_module(
    "proxmox_corpus_preflight",
    REPO_ROOT / "scripts" / "proxmox_corpus_preflight.py",
)
release_gap = load_script_module(
    "check_openclaw_release_gap",
    REPO_ROOT / "scripts" / "check_openclaw_release_gap.py",
)
saved_capture = load_script_module(
    "validate_saved_capture_inference",
    REPO_ROOT / "scripts" / "validate_saved_capture_inference.py",
)


def fetch_npm_versions() -> List[str]:
    result = subprocess.run(
        ["npm", "view", "openclaw", "versions", "--json"],
        check=True,
        capture_output=True,
        text=True,
    )
    loaded = json.loads(result.stdout)
    if not isinstance(loaded, list):
        raise ValueError("npm versions output was not a JSON array")
    return [str(item).strip() for item in loaded if str(item).strip()]


def load_versions(args: argparse.Namespace) -> List[str]:
    if args.versions_json:
        loaded = json.loads(args.versions_json)
        if not isinstance(loaded, list):
            raise ValueError("--versions-json must be a JSON array")
        return [str(item).strip() for item in loaded if str(item).strip()]
    if args.versions_file:
        loaded = json.loads(Path(args.versions_file).read_text(encoding="utf-8"))
        if not isinstance(loaded, list):
            raise ValueError("--versions-file must contain a JSON array")
        return [str(item).strip() for item in loaded if str(item).strip()]
    return fetch_npm_versions()


def write_json(path: Path, value: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def summarize_preflight(report: Dict[str, Any]) -> Dict[str, Any]:
    inventory = report.get("vm_inventory") or {}
    return {
        "vm_lifecycle_allowed": bool(report.get("vm_lifecycle_allowed")),
        "blockers": list(report.get("blockers") or []),
        "vm_inventory": {
            "created": inventory.get("created", 0),
            "reused": inventory.get("reused", 0),
            "shut_down": inventory.get("shut_down", 0),
            "destroyed": inventory.get("destroyed", 0),
            "still_running": inventory.get("still_running", 0),
            "next_cleanup_deadline": inventory.get("next_cleanup_deadline"),
        },
    }


def summarize_release_gap(report: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "decision": report.get("decision"),
        "capture_needed": bool(report.get("capture_needed")),
        "capture_needed_versions": list(report.get("capture_needed_versions") or []),
        "latest_published_version": report.get("latest_published_version"),
        "latest_captured_version": report.get("latest_captured_version"),
        "latest_promoted_exact_version": report.get("latest_promoted_exact_version"),
    }


def summarize_saved_capture(report: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "passed": not bool(report.get("declared_no_exact_match_count")),
        "bundle_count": report.get("bundle_count", 0),
        "capture_count": report.get("capture_count", 0),
        "evaluated_capture_count": report.get("evaluated_capture_count", 0),
        "ignored_capture_count": report.get("ignored_capture_count", 0),
        "declared_no_exact_match_count": report.get("declared_no_exact_match_count", 0),
        "ignored_versions_present": list(report.get("ignored_versions_present") or []),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run read-only OpenClaw corpus heartbeat gate checks."
    )
    parser.add_argument(
        "--artifact-dir",
        required=True,
        help="Directory for heartbeat reports, for example artifacts/lab/YYYY-MM-DD.",
    )
    parser.add_argument(
        "--manifest",
        required=True,
        help="Lab manifest to update with component summaries.",
    )
    parser.add_argument(
        "--capture-root",
        default="artifacts/lab",
        help="Capture root passed to release-gap and saved-capture validation.",
    )
    parser.add_argument(
        "--rules-file",
        default=str(DEFAULT_RULES_FILE),
        help="Scanner rules file used by release-gap and saved-capture validation.",
    )
    parser.add_argument("--versions-file", help="JSON file containing npm versions.")
    parser.add_argument("--versions-json", help="Inline JSON array containing npm versions.")
    parser.add_argument(
        "--ignore-version",
        action="append",
        default=[],
        help="Declared capture version ignored by strict saved-capture validation.",
    )
    parser.add_argument(
        "--label",
        default="heartbeat",
        help="Filename label for generated artifacts.",
    )
    parser.add_argument(
        "--preflight-timeout",
        type=float,
        default=5.0,
        help="Proxmox preflight HTTP timeout in seconds.",
    )
    parser.add_argument(
        "--env-file",
        default=str(preflight.DEFAULT_ENV_PATH),
        help="Ignored Proxmox env file used by preflight.",
    )
    parser.add_argument("--output", help="Write heartbeat summary to this path.")
    return parser


def main(argv: List[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    artifact_dir = Path(args.artifact_dir)
    output = Path(args.output) if args.output else artifact_dir / f"openclaw-corpus-{args.label}.json"
    preflight_output = artifact_dir / f"proxmox-preflight-{args.label}.json"
    release_output = artifact_dir / f"openclaw-release-gap-{args.label}.json"
    saved_output = artifact_dir / f"saved-capture-inference-check-promoted-{args.label}.json"

    versions = load_versions(args)

    preflight_values = preflight.load_env(Path(args.env_file))
    _, preflight_report = preflight.run_preflight(
        preflight_values,
        timeout=max(args.preflight_timeout, 1.0),
    )
    write_json(preflight_output, preflight_report)
    preflight.update_manifest_preflight(
        args.manifest,
        preflight_report,
        artifact=str(preflight_output),
        command=(
            "python3 scripts/proxmox_corpus_preflight.py "
            f"--timeout {args.preflight_timeout:g} --format json "
            f"--output {preflight_output} --manifest {args.manifest}"
        ),
    )

    release_report = release_gap.build_report(
        published_versions=versions,
        capture_root=Path(args.capture_root),
        rules_file=Path(args.rules_file),
        include_prereleases=False,
    )
    write_json(release_output, release_report)
    release_gap.update_manifest_release_gap(
        args.manifest,
        release_report,
        artifact=str(release_output),
        command=(
            "python3 scripts/check_openclaw_release_gap.py "
            "--versions-json '<versions-json>' "
            f"--capture-root {args.capture_root} --rules-file {args.rules_file} "
            f"--output {release_output} --manifest {args.manifest}"
        ),
    )

    saved_report = saved_capture.validate_capture_root(
        args.capture_root,
        rules_file=args.rules_file,
        ignore_versions=args.ignore_version,
    )
    write_json(saved_output, saved_report)
    saved_capture.update_manifest_saved_capture(
        args.manifest,
        saved_report,
        artifact=str(saved_output),
        command=(
            "python3 scripts/validate_saved_capture_inference.py "
            f"--input-root {args.capture_root} --rules-file {args.rules_file} "
            f"--output {saved_output} --require-all-exact "
            + " ".join(f"--ignore-version {version}" for version in args.ignore_version)
            + f" --manifest {args.manifest}"
        ),
        require_all_exact=True,
    )

    preflight_summary = summarize_preflight(preflight_report)
    release_summary = summarize_release_gap(release_report)
    saved_summary = summarize_saved_capture(saved_report)
    summary = {
        "schema_version": 1,
        "bundle_type": "openclaw_corpus_heartbeat_check",
        "generated_at": utc_now(),
        "artifacts": {
            "preflight": str(preflight_output),
            "release_gap": str(release_output),
            "saved_capture_inference": str(saved_output),
        },
        "published_version_count": len(versions),
        "latest_published_version": release_summary["latest_published_version"],
        "preflight": preflight_summary,
        "release_gap": release_summary,
        "saved_capture_inference": saved_summary,
        "vm_action_recommended": bool(
            preflight_summary["vm_lifecycle_allowed"]
            and release_summary["capture_needed"]
        ),
        "decision": (
            "launch_single_vm_capture"
            if preflight_summary["vm_lifecycle_allowed"] and release_summary["capture_needed"]
            else "no_vm_needed"
        ),
        "vm_inventory": preflight_summary["vm_inventory"],
    }
    write_json(output, summary)
    sys.stdout.write(json.dumps(summary, indent=2, sort_keys=True) + "\n")

    if not preflight_summary["vm_lifecycle_allowed"]:
        return 2
    if saved_report.get("declared_no_exact_match_count"):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
