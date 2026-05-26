#!/usr/bin/env python3
"""Secret-safe Proxmox preflight for OpenClaw corpus VM work.

This helper performs read-only API checks before any clone, boot, shutdown, or
delete action is attempted. It intentionally never prints credential values.
"""

from __future__ import annotations

import argparse
import json
import shlex
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple


DEFAULT_ENV_PATH = Path(__file__).resolve().parents[1] / ".env"
DEFAULT_ENV_OVERLAY_PATH = Path(__file__).resolve().parents[1] / ".env.local"


def load_env_file(path: Path) -> Dict[str, str]:
    values: Dict[str, str] = {}
    if not path.exists():
        return values

    for raw in path.read_text(errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip("\"").strip("'")
    return values


def load_env(path: Path) -> Dict[str, str]:
    values = load_env_file(path)
    if path.resolve() == DEFAULT_ENV_PATH.resolve():
        values.update(load_env_file(DEFAULT_ENV_OVERLAY_PATH))
    return values


def normalize_api_url(value: str) -> str:
    api = value.rstrip("/")
    suffix = "/api2/json"
    if api.endswith(suffix):
        api = api[: -len(suffix)]
    return api


def build_auth_header(values: Dict[str, str]) -> str:
    if values.get("OPENCLAW_PROXMOX_AUTH_HEADER"):
        return values["OPENCLAW_PROXMOX_AUTH_HEADER"]

    token_id = values.get("OPENCLAW_PROXMOX_TOKEN_ID")
    token_secret = values.get("OPENCLAW_PROXMOX_TOKEN_SECRET")
    if token_id and token_secret:
        return f"PVEAPIToken={token_id}={token_secret}"
    return ""


def network_error_summary(exc: BaseException) -> str:
    reason = getattr(exc, "reason", exc)
    if isinstance(reason, TimeoutError):
        return "network timeout"
    if isinstance(reason, ssl.SSLError):
        return "TLS error"
    if isinstance(reason, OSError):
        return reason.__class__.__name__
    return exc.__class__.__name__


def api_get(api_base: str, auth_header: str, path: str, timeout: float) -> Tuple[int, Dict[str, Any]]:
    request = urllib.request.Request(
        api_base + "/api2/json" + path,
        headers={"Authorization": auth_header},
    )
    context = ssl._create_unverified_context()
    try:
        with urllib.request.urlopen(request, context=context, timeout=timeout) as response:
            return response.status, json.loads(response.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")
        try:
            return exc.code, json.loads(body)
        except json.JSONDecodeError:
            return exc.code, {"message": body[:160]}
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return 0, {"message": network_error_summary(exc)}


def permission_map(payload: Dict[str, Any], path: str) -> Dict[str, Any]:
    data = payload.get("data") or {}
    if not isinstance(data, dict):
        return {}
    if isinstance(data.get(path), dict):
        return data[path]
    return {
        key: value
        for key, value in data.items()
        if isinstance(key, str) and "." in key
    }


def permission_has(payload: Dict[str, Any], path: str, permission: str) -> bool:
    return permission in permission_map(payload, path)


def corpus_vms(resources: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    matches = []
    for item in resources:
        name = str(item.get("name") or "").lower()
        if "openclaw" in name or "corpus" in name:
            matches.append(
                {
                    "vmid": item.get("vmid"),
                    "name": item.get("name"),
                    "status": item.get("status"),
                }
            )
    return matches


def template_readiness(config: Dict[str, Any]) -> Dict[str, Any]:
    agent_value = str(config.get("agent", "")).lower()
    agent_enabled = (
        agent_value == "1"
        or agent_value == "enabled"
        or agent_value.startswith("enabled=1")
    )
    cloudinit_attached = any(
        (
            str(key).startswith(("ide", "sata", "scsi", "virtio"))
            and (
                "cloudinit" in str(value).lower()
                or "media=cdrom" in str(value).lower()
            )
        )
        for key, value in config.items()
    )
    return {
        "template": bool(config.get("template")),
        "name": config.get("name"),
        "agent_enabled": agent_enabled,
        "cloudinit_attached": cloudinit_attached,
        "serial_console": config.get("serial0") == "socket"
        and config.get("vga") == "serial0",
        "boot_order": config.get("boot"),
    }


def clone_identity_readiness(values: Dict[str, str], template_config: Dict[str, Any]) -> Dict[str, Any]:
    env_ciuser = bool(values.get("OPENCLAW_PROXMOX_CIUSER"))
    env_sshkeys_file = bool(values.get("OPENCLAW_PROXMOX_SSHKEYS_FILE"))
    env_ssh_public_key = bool(values.get("OPENCLAW_PROXMOX_SSH_PUBLIC_KEY"))
    env_cicustom = bool(values.get("OPENCLAW_PROXMOX_CICUSTOM"))
    template_ciuser = bool(template_config.get("ciuser"))
    template_sshkeys = bool(template_config.get("sshkeys"))
    template_cicustom = bool(template_config.get("cicustom"))
    has_user = env_ciuser or template_ciuser or env_cicustom or template_cicustom
    has_key_source = (
        env_sshkeys_file
        or env_ssh_public_key
        or env_cicustom
        or template_sshkeys
        or template_cicustom
    )
    return {
        "ok": has_user and has_key_source,
        "env_ciuser_present": env_ciuser,
        "env_sshkeys_file_present": env_sshkeys_file,
        "env_ssh_public_key_present": env_ssh_public_key,
        "env_cicustom_present": env_cicustom,
        "template_ciuser_present": template_ciuser,
        "template_sshkeys_present": template_sshkeys,
        "template_cicustom_present": template_cicustom,
        "has_user_source": has_user,
        "has_key_source": has_key_source,
    }


def default_permission_paths(values: Dict[str, str]) -> List[Tuple[str, str]]:
    node = values.get("OPENCLAW_PROXMOX_NODE", "pve01")
    bridge = values.get("OPENCLAW_PROXMOX_DEFAULT_BRIDGE", "vmbr0")
    vlan = values.get("OPENCLAW_PROXMOX_DEFAULT_VLAN", "30")
    pool = values.get("OPENCLAW_PROXMOX_POOL", "openclaw-scanner")
    template = values.get("OPENCLAW_PROXMOX_TEMPLATE_VMID", "9000")
    return [
        (f"/nodes/{node}", "Sys.Audit"),
        (f"/pool/{pool}", "VM.Clone"),
        (f"/vms/{template}", "VM.Clone"),
        (f"/sdn/zones/localnetwork/{bridge}", "SDN.Use"),
        (f"/sdn/zones/localnetwork/{bridge}/{vlan}", "SDN.Use"),
    ]


def run_preflight(values: Dict[str, str], timeout: float) -> Tuple[int, Dict[str, Any]]:
    api_base = normalize_api_url(values.get("OPENCLAW_PROXMOX_API_URL", ""))
    auth_header = build_auth_header(values)
    report: Dict[str, Any] = {
        "schema_version": 1,
        "checked_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "vm_lifecycle_allowed": False,
        "checks": [],
        "blockers": [],
        "vm_inventory": {
            "created": 0,
            "reused": 0,
            "shut_down": 0,
            "destroyed": 0,
            "still_running": 0,
            "next_cleanup_deadline": None,
        },
    }

    if not api_base:
        report["blockers"].append("missing OPENCLAW_PROXMOX_API_URL")
    if not auth_header:
        report["blockers"].append("missing Proxmox token auth configuration")
    if report["blockers"]:
        return 2, report

    status, version = api_get(api_base, auth_header, "/version", timeout)
    report["checks"].append(
        {
            "name": "api_version",
            "status": status,
            "ok": status == 200,
            "version": (version.get("data") or {}).get("version") if status == 200 else None,
        }
    )
    if status != 200:
        if status == 0:
            report["blockers"].append(
                "Proxmox API version check failed before HTTP response: "
                f"{version.get('message') or 'network error'}"
            )
            return 1, report
        report["blockers"].append(f"Proxmox API version check failed with HTTP {status}")

    status, resources = api_get(api_base, auth_header, "/cluster/resources?type=vm", timeout)
    vms = corpus_vms(resources.get("data") or []) if status == 200 else []
    running_vms = [vm for vm in vms if vm.get("status") == "running"]
    report["checks"].append(
        {
            "name": "corpus_vm_inventory",
            "status": status,
            "ok": status == 200,
            "openclaw_related_vms": len(vms),
            "openclaw_running_vms": len(running_vms),
            "vms": vms,
        }
    )
    report["vm_inventory"]["still_running"] = len(running_vms)
    if status != 200:
        report["blockers"].append(f"VM inventory check failed with HTTP {status}")
    elif running_vms:
        running_labels = ", ".join(
            f"{vm.get('vmid')}:{vm.get('name')}" for vm in running_vms
        )
        report["blockers"].append(
            f"running OpenClaw/corpus VM(s) require cleanup before new lifecycle work: {running_labels}"
        )

    node = values.get("OPENCLAW_PROXMOX_NODE", "pve01")
    template = values.get("OPENCLAW_PROXMOX_TEMPLATE_VMID", "9000")
    status, payload = api_get(
        api_base,
        auth_header,
        f"/nodes/{node}/qemu/{template}/config",
        timeout,
    )
    template_config = (payload.get("data") or {}) if status == 200 else {}
    readiness = template_readiness(template_config) if status == 200 else {}
    report["checks"].append(
        {
            "name": "template_readiness",
            "status": status,
            "ok": status == 200
            and readiness.get("template")
            and readiness.get("agent_enabled")
            and readiness.get("cloudinit_attached"),
            "template_vmid": template,
            "template_name": readiness.get("name"),
            "is_template": readiness.get("template"),
            "agent_enabled": readiness.get("agent_enabled"),
            "cloudinit_attached": readiness.get("cloudinit_attached"),
            "serial_console": readiness.get("serial_console"),
            "boot_order": readiness.get("boot_order"),
        }
    )
    if status != 200:
        report["blockers"].append(f"template {template} config check failed with HTTP {status}")
    elif not readiness.get("template"):
        report["blockers"].append(f"template {template} is not marked as a Proxmox template")
    elif not readiness.get("agent_enabled"):
        report["blockers"].append(
            f"template {template} does not enable the QEMU guest agent needed for IP discovery"
        )
    elif not readiness.get("cloudinit_attached"):
        report["blockers"].append(f"template {template} does not expose a cloud-init drive")

    identity = clone_identity_readiness(values, template_config) if status == 200 else {}
    report["checks"].append(
        {
            "name": "clone_identity_readiness",
            "ok": bool(identity.get("ok")),
            "env_ciuser_present": identity.get("env_ciuser_present"),
            "env_sshkeys_file_present": identity.get("env_sshkeys_file_present"),
            "env_ssh_public_key_present": identity.get("env_ssh_public_key_present"),
            "env_cicustom_present": identity.get("env_cicustom_present"),
            "template_ciuser_present": identity.get("template_ciuser_present"),
            "template_sshkeys_present": identity.get("template_sshkeys_present"),
            "template_cicustom_present": identity.get("template_cicustom_present"),
            "has_user_source": identity.get("has_user_source"),
            "has_key_source": identity.get("has_key_source"),
        }
    )
    if status == 200 and not identity.get("ok"):
        report["blockers"].append(
            "clone cloud-init identity is incomplete; configure a clone user plus SSH key source or cicustom before launching another VM"
        )

    for path, permission in default_permission_paths(values):
        encoded = urllib.parse.quote(path, safe="")
        status, payload = api_get(
            api_base,
            auth_header,
            f"/access/permissions?path={encoded}",
            timeout,
        )
        pmap = permission_map(payload, path) if status == 200 else {}
        present = permission in pmap
        report["checks"].append(
            {
                "name": "permission",
                "path": path,
                "permission": permission,
                "status": status,
                "present": present,
                "propagates": bool(pmap.get(permission)) if present else False,
                "ok": status == 200 and present,
            }
        )
        if status != 200:
            report["blockers"].append(f"{permission} check failed for {path} with HTTP {status}")
        elif not present:
            report["blockers"].append(f"missing {permission} on {path}")

    report["vm_lifecycle_allowed"] = not report["blockers"]
    return (1 if report["blockers"] else 0), report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run secret-safe read-only Proxmox checks before OpenClaw corpus VM work."
    )
    parser.add_argument(
        "--env-file",
        default=str(DEFAULT_ENV_PATH),
        help="Path to the ignored Proxmox .env file.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=12.0,
        help="HTTP timeout in seconds.",
    )
    parser.add_argument(
        "--format",
        choices=("pretty", "json"),
        default="pretty",
        help="Output format.",
    )
    parser.add_argument(
        "--output",
        help="Write the preflight report to a file instead of stdout.",
    )
    parser.add_argument(
        "--manifest",
        help="Update the lab manifest's proxmox_preflight summary with this report.",
    )
    return parser


def check_by_name(report: Dict[str, Any], name: str) -> Dict[str, Any]:
    for check in report.get("checks", []):
        if check.get("name") == name:
            return check
    return {}


def manifest_preflight_summary(
    report: Dict[str, Any],
    *,
    artifact: str | None,
    command: str | None,
) -> Dict[str, Any]:
    api_version = check_by_name(report, "api_version")
    inventory = check_by_name(report, "corpus_vm_inventory")
    template = check_by_name(report, "template_readiness")
    identity = check_by_name(report, "clone_identity_readiness")
    summary: Dict[str, Any] = {
        "checked_at": report.get("checked_at"),
        "command": command,
        "artifact": artifact,
        "passed": bool(report.get("vm_lifecycle_allowed")),
        "vm_lifecycle_allowed": bool(report.get("vm_lifecycle_allowed")),
        "blockers": list(report.get("blockers") or []),
        "api_version": api_version.get("version"),
        "template_ready": bool(template.get("ok")),
        "clone_identity_ready": bool(identity.get("ok")),
        "clone_identity_sources": {
            "has_user_source": bool(identity.get("has_user_source")),
            "has_key_source": bool(identity.get("has_key_source")),
            "env_ciuser_present": bool(identity.get("env_ciuser_present")),
            "env_sshkeys_file_present": bool(identity.get("env_sshkeys_file_present")),
            "env_ssh_public_key_present": bool(identity.get("env_ssh_public_key_present")),
            "env_cicustom_present": bool(identity.get("env_cicustom_present")),
            "template_ciuser_present": bool(identity.get("template_ciuser_present")),
            "template_sshkeys_present": bool(identity.get("template_sshkeys_present")),
            "template_cicustom_present": bool(identity.get("template_cicustom_present")),
        },
        "openclaw_related_vms": inventory.get("openclaw_related_vms", 0),
        "openclaw_running_vms": inventory.get("openclaw_running_vms", 0),
    }
    return summary


def update_manifest_preflight(
    manifest_path: str,
    report: Dict[str, Any],
    *,
    artifact: str | None,
    command: str | None,
) -> None:
    path = Path(manifest_path)
    manifest = json.loads(path.read_text(encoding="utf-8"))
    manifest["proxmox_preflight"] = manifest_preflight_summary(
        report,
        artifact=artifact,
        command=command,
    )
    path.write_text(json.dumps(manifest, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def render_pretty(report: Dict[str, Any]) -> str:
    lines = ["OpenClaw Proxmox corpus preflight"]
    for check in report.get("checks", []):
        if check.get("name") == "api_version":
            lines.append(
                f"- api_version: status={check.get('status')} ok={check.get('ok')} version={check.get('version') or 'unknown'}"
            )
        elif check.get("name") == "corpus_vm_inventory":
            lines.append(
                "- corpus_vm_inventory: "
                f"status={check.get('status')} ok={check.get('ok')} "
                f"openclaw_related_vms={check.get('openclaw_related_vms')} "
                f"openclaw_running_vms={check.get('openclaw_running_vms')}"
            )
        elif check.get("name") == "template_readiness":
            lines.append(
                "- template_readiness: "
                f"status={check.get('status')} ok={check.get('ok')} "
                f"template_vmid={check.get('template_vmid')} "
                f"agent_enabled={check.get('agent_enabled')} "
                f"cloudinit_attached={check.get('cloudinit_attached')}"
            )
        elif check.get("name") == "clone_identity_readiness":
            lines.append(
                "- clone_identity_readiness: "
                f"ok={check.get('ok')} "
                f"has_user_source={check.get('has_user_source')} "
                f"has_key_source={check.get('has_key_source')} "
                f"env_ciuser_present={check.get('env_ciuser_present')} "
                f"env_sshkeys_file_present={check.get('env_sshkeys_file_present')} "
                f"env_ssh_public_key_present={check.get('env_ssh_public_key_present')} "
                f"env_cicustom_present={check.get('env_cicustom_present')}"
            )
        elif check.get("name") == "permission":
            lines.append(
                "- permission: "
                f"path={check.get('path')} permission={check.get('permission')} "
                f"present={check.get('present')} propagates={check.get('propagates')}"
            )

    blockers = report.get("blockers") or []
    if blockers:
        lines.append("Blockers:")
        for blocker in blockers:
            lines.append(f"- {blocker}")
    else:
        lines.append("Blockers: none")
    lines.append(
        "VM lifecycle allowed: "
        f"{'yes' if report.get('vm_lifecycle_allowed') else 'no'}"
    )

    inventory = report.get("vm_inventory") or {}
    lines.append(
        "VM inventory: "
        f"created {inventory.get('created', 0)}, "
        f"reused {inventory.get('reused', 0)}, "
        f"shut down {inventory.get('shut_down', 0)}, "
        f"destroyed {inventory.get('destroyed', 0)}, "
        f"still running {inventory.get('still_running', 0)}, "
        f"next cleanup deadline {inventory.get('next_cleanup_deadline') or 'n/a'}"
    )
    return "\n".join(lines) + "\n"


def render_report(report: Dict[str, Any], output_format: str) -> str:
    if output_format == "json":
        return json.dumps(report, indent=2, sort_keys=True) + "\n"
    return render_pretty(report)


def write_report(text: str, output: str | None) -> None:
    if not output:
        sys.stdout.write(text)
        return

    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def main(argv: List[str] | None = None) -> int:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    args = build_parser().parse_args(raw_argv)
    values = load_env(Path(args.env_file))
    exit_code, report = run_preflight(values, timeout=max(args.timeout, 1.0))
    write_report(render_report(report, args.format), args.output)
    if args.manifest:
        command = "python3 scripts/proxmox_corpus_preflight.py " + " ".join(
            shlex.quote(part) for part in raw_argv
        )
        update_manifest_preflight(
            args.manifest,
            report,
            artifact=args.output,
            command=command,
        )
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
