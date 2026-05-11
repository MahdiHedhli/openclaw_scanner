#!/usr/bin/env python3
import argparse
import json
import sys


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Render scanner targets from Terraform JSON output."
    )
    parser.add_argument(
        "--input",
        help="Path to Terraform JSON output. Defaults to stdin.",
    )
    parser.add_argument(
        "--format",
        choices=("targets", "json"),
        default="targets",
        help="Output format.",
    )
    parser.add_argument(
        "--version",
        help="Only output nodes for this declared OpenClaw version.",
    )
    args = parser.parse_args()

    raw = (
        open(args.input, "r", encoding="utf-8").read()
        if args.input
        else sys.stdin.read()
    )
    payload = json.loads(raw)
    nodes = _extract_nodes(payload)
    if args.version:
        nodes = [
            node for node in nodes
            if node.get("openclaw_version") == args.version
        ]

    if args.format == "json":
        sys.stdout.write(json.dumps(nodes, indent=2, sort_keys=True))
        sys.stdout.write("\n")
        return 0

    for node in nodes:
        sys.stdout.write(f"{node['scanner_target']}\n")
    return 0


def _extract_nodes(payload):
    if isinstance(payload, dict) and "value" in payload and isinstance(payload["value"], dict):
        payload = payload["value"]
    elif (
        isinstance(payload, dict)
        and "calibration_nodes" in payload
        and isinstance(payload["calibration_nodes"], dict)
        and "value" in payload["calibration_nodes"]
    ):
        payload = payload["calibration_nodes"]["value"]

    if not isinstance(payload, dict):
        raise ValueError("Expected a Terraform calibration_nodes map.")

    return [
        {
            "name": name,
            "public_ip": value.get("public_ip"),
            "openclaw_version": value.get("openclaw_version"),
            "gateway_port": value.get("gateway_port"),
            "scanner_target": value.get("scanner_target"),
        }
        for name, value in sorted(payload.items())
        if isinstance(value, dict) and value.get("scanner_target")
    ]


if __name__ == "__main__":
    raise SystemExit(main())
