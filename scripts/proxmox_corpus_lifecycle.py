#!/usr/bin/env python3
"""Secret-safe Proxmox lifecycle helpers for OpenClaw corpus VMs.

The helpers here avoid subnet scans. IP discovery is bounded and accepts only
guest-agent output or passive ARP/DHCP observations for the VM's exact MAC on
the expected corpus VLAN.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import ipaddress
import json
import re
import secrets
import shlex
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Sequence, Tuple

try:
    import proxmox_corpus_preflight as preflight
except ModuleNotFoundError:  # Allows importlib-based tests from the repo root.
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import proxmox_corpus_preflight as preflight


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ENV_PATH = REPO_ROOT / ".env"
DEFAULT_LAB_ROOT = REPO_ROOT / "artifacts" / "lab" / "2026-05-18"
DEFAULT_VLAN_SUBNETS = {
    "30": "10.0.30.0/24",
}
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
MAC_RE = re.compile(r"\b[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}\b")
NIC_MODELS = ("virtio", "e1000", "e1000e", "rtl8139", "vmxnet3")


def utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def normalize_version_for_name(version: str) -> str:
    return re.sub(r"[^0-9a-zA-Z]+", "-", version).strip("-").lower()


def canonical_mac(value: str) -> str:
    return value.strip().lower()


def mac_digest(value: str) -> str:
    return hashlib.sha256(canonical_mac(value).encode("utf-8")).hexdigest()[:16]


def generated_proxmox_mac() -> str:
    tail = [secrets.randbelow(256) for _ in range(3)]
    return "BC:24:11:" + ":".join(f"{item:02X}" for item in tail)


def allowed_network(values: Dict[str, str], override: str | None = None) -> ipaddress.IPv4Network:
    if override:
        return ipaddress.ip_network(override)
    if values.get("OPENCLAW_PROXMOX_DEFAULT_SUBNET"):
        return ipaddress.ip_network(values["OPENCLAW_PROXMOX_DEFAULT_SUBNET"])

    vlan = values.get("OPENCLAW_PROXMOX_DEFAULT_VLAN", "30")
    if vlan not in DEFAULT_VLAN_SUBNETS:
        raise ValueError(
            "OPENCLAW_PROXMOX_DEFAULT_SUBNET is required for VLANs without a safe default"
        )
    return ipaddress.ip_network(DEFAULT_VLAN_SUBNETS[vlan])


def encode_cloud_init_sshkeys(value: str) -> str:
    stripped = value.strip()
    if not stripped:
        return ""
    if any(char.isspace() for char in stripped):
        return urllib.parse.quote(stripped, safe="")
    return stripped


def clone_cloud_init_identity_config(values: Dict[str, str]) -> Tuple[Dict[str, Any], List[str]]:
    config: Dict[str, Any] = {}
    warnings: List[str] = []
    ciuser = values.get("OPENCLAW_PROXMOX_CIUSER")
    cicustom = values.get("OPENCLAW_PROXMOX_CICUSTOM")
    ssh_public_key = values.get("OPENCLAW_PROXMOX_SSH_PUBLIC_KEY")
    ssh_keys_file = values.get("OPENCLAW_PROXMOX_SSHKEYS_FILE")

    if ciuser:
        config["ciuser"] = ciuser
    if cicustom:
        config["cicustom"] = cicustom

    if ssh_keys_file:
        try:
            key_text = Path(ssh_keys_file).expanduser().read_text(encoding="utf-8").strip()
        except OSError:
            warnings.append("configured SSH public key file was not readable")
        else:
            if key_text:
                ssh_public_key = key_text
            else:
                warnings.append("configured SSH public key file was empty")

    if ssh_public_key:
        encoded = encode_cloud_init_sshkeys(ssh_public_key)
        if encoded:
            config["sshkeys"] = encoded

    return config, warnings


def safe_ipv4(value: str, network: ipaddress.IPv4Network) -> str | None:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return None
    if ip.version != 4:
        return None
    if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
        return None
    if ip not in network:
        return None
    return str(ip)


def api_request(
    api_base: str,
    auth_header: str,
    method: str,
    path: str,
    timeout: float,
    data: Dict[str, Any] | None = None,
) -> Tuple[int, Dict[str, Any]]:
    encoded = None
    headers = {"Authorization": auth_header}
    if data is not None:
        encoded = urllib.parse.urlencode(data).encode("utf-8")
        headers["Content-Type"] = "application/x-www-form-urlencoded"

    request = urllib.request.Request(
        api_base + "/api2/json" + path,
        data=encoded,
        headers=headers,
        method=method,
    )
    context = preflight.ssl._create_unverified_context()
    try:
        with urllib.request.urlopen(request, context=context, timeout=timeout) as response:
            return response.status, json.loads(response.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")
        try:
            return exc.code, json.loads(body)
        except json.JSONDecodeError:
            return exc.code, {"message": body[:160]}


def write_current_report(report: Dict[str, Any]) -> None:
    artifact = report.get("artifact")
    if not artifact:
        return
    path = Path(str(artifact))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")


def wait_for_task(
    api_base: str,
    auth_header: str,
    node: str,
    upid: str,
    timeout: float,
    poll_interval: float = 1.0,
) -> Dict[str, Any]:
    deadline = time.monotonic() + max(timeout, 1.0)
    encoded_upid = urllib.parse.quote(upid, safe="")
    last_status: int | None = None
    while time.monotonic() < deadline:
        status, payload = api_request(
            api_base,
            auth_header,
            "GET",
            f"/nodes/{node}/tasks/{encoded_upid}/status",
            timeout=5.0,
        )
        last_status = status
        data = payload.get("data") or {}
        if status == 200 and data.get("status") == "stopped":
            return {
                "ok": data.get("exitstatus") == "OK",
                "exitstatus": data.get("exitstatus"),
                "status": data.get("status"),
            }
        time.sleep(max(poll_interval, 0.25))
    return {
        "ok": False,
        "exitstatus": None,
        "status": "timeout",
        "last_http_status": last_status,
    }


def task_step(
    api_base: str,
    auth_header: str,
    node: str,
    method: str,
    path: str,
    data: Dict[str, Any] | None,
    name: str,
    http_timeout: float,
    task_timeout: float,
) -> Dict[str, Any]:
    status, payload = api_request(api_base, auth_header, method, path, http_timeout, data)
    if status not in (200, 202):
        return {"name": name, "ok": False, "http_status": status}
    upid = (payload.get("data") if isinstance(payload, dict) else None)
    if not isinstance(upid, str) or not upid.startswith("UPID:"):
        return {"name": name, "ok": True, "http_status": status}
    task = wait_for_task(api_base, auth_header, node, upid, timeout=task_timeout)
    return {
        "name": name,
        "ok": task.get("ok") is True,
        "http_status": status,
        "exitstatus": task.get("exitstatus"),
        "task_status": task.get("status"),
        "upid_redacted": True,
    }


def guest_agent_cloud_init_status(
    api_base: str,
    auth_header: str,
    node: str,
    vmid: str,
    timeout: float,
) -> Dict[str, Any]:
    status, payload = api_request(
        api_base,
        auth_header,
        "POST",
        f"/nodes/{node}/qemu/{vmid}/agent/exec",
        timeout=max(timeout, 1.0),
        data={"command": "cloud-init status --long"},
    )
    if status != 200:
        return {"ok": False, "http_status": status, "reason": "exec_unavailable"}
    data = payload.get("data")
    pid = data.get("pid") if isinstance(data, dict) else data
    if pid is None:
        return {"ok": False, "http_status": status, "reason": "missing_pid"}

    encoded_pid = urllib.parse.quote(str(pid), safe="")
    deadline = time.monotonic() + max(timeout, 1.0)
    last_payload: Dict[str, Any] = {}
    while time.monotonic() < deadline:
        poll_status, poll_payload = api_request(
            api_base,
            auth_header,
            "GET",
            f"/nodes/{node}/qemu/{vmid}/agent/exec-status?pid={encoded_pid}",
            timeout=max(min(timeout, 3.0), 1.0),
        )
        last_payload = poll_payload
        poll_data = poll_payload.get("data") if isinstance(poll_payload, dict) else {}
        if poll_status == 200 and isinstance(poll_data, dict) and poll_data.get("exited"):
            stdout = str(poll_data.get("out-data") or "")
            stderr = str(poll_data.get("err-data") or "")
            return {
                "ok": True,
                "exitcode": poll_data.get("exitcode"),
                "stdout_excerpt": stdout[:240],
                "stderr_excerpt": stderr[:240],
            }
        time.sleep(0.5)
    return {
        "ok": False,
        "reason": "exec_status_timeout",
        "last_response_keys": sorted((last_payload.get("data") or {}).keys())
        if isinstance(last_payload.get("data"), dict)
        else [],
    }


def guest_agent_ping(
    api_base: str,
    auth_header: str,
    node: str,
    vmid: str,
    timeout: float,
) -> Dict[str, Any]:
    status, _payload = api_request(
        api_base,
        auth_header,
        "POST",
        f"/nodes/{node}/qemu/{vmid}/agent/ping",
        timeout=max(timeout, 1.0),
    )
    return {"ok": status == 200, "http_status": status}


def guest_agent_exec_capture(
    api_base: str,
    auth_header: str,
    node: str,
    vmid: str,
    command: str,
    timeout: float,
    max_output_chars: int = 360,
) -> Dict[str, Any]:
    status, payload = api_request(
        api_base,
        auth_header,
        "POST",
        f"/nodes/{node}/qemu/{vmid}/agent/exec",
        timeout=max(timeout, 1.0),
        data={"command": command},
    )
    if status != 200:
        return {"ok": False, "http_status": status, "reason": "exec_unavailable"}

    data = payload.get("data")
    pid = data.get("pid") if isinstance(data, dict) else data
    if pid is None:
        return {"ok": False, "http_status": status, "reason": "missing_pid"}

    encoded_pid = urllib.parse.quote(str(pid), safe="")
    deadline = time.monotonic() + max(timeout, 1.0)
    while time.monotonic() < deadline:
        poll_status, poll_payload = api_request(
            api_base,
            auth_header,
            "GET",
            f"/nodes/{node}/qemu/{vmid}/agent/exec-status?pid={encoded_pid}",
            timeout=max(min(timeout, 3.0), 1.0),
        )
        poll_data = poll_payload.get("data") if isinstance(poll_payload, dict) else {}
        if poll_status == 200 and isinstance(poll_data, dict) and poll_data.get("exited"):
            stdout = str(poll_data.get("out-data") or "")
            stderr = str(poll_data.get("err-data") or "")
            return {
                "ok": True,
                "exitcode": poll_data.get("exitcode"),
                "stdout_excerpt": stdout[:max_output_chars],
                "stderr_excerpt": stderr[:max_output_chars],
            }
        time.sleep(0.5)

    return {"ok": False, "reason": "exec_status_timeout"}


def guest_agent_template_diagnostics(
    api_base: str,
    auth_header: str,
    node: str,
    vmid: str,
    timeout: float,
) -> Dict[str, Any]:
    commands = {
        "cloud_init_status": "cloud-init status --long",
        "ip_brief_link": "ip -brief link",
        "ip_brief_addr": "ip -brief addr",
        "ip_route": "ip route",
        "qemu_guest_agent_active": "systemctl is-active qemu-guest-agent",
        "qemu_guest_agent_enabled": "systemctl is-enabled qemu-guest-agent",
    }
    return {
        name: guest_agent_exec_capture(
            api_base,
            auth_header,
            node,
            vmid,
            command,
            timeout=timeout,
        )
        for name, command in commands.items()
    }


def guest_agent_interfaces(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    data = payload.get("data")
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if isinstance(data, dict):
        result = data.get("result")
        if isinstance(result, list):
            return [item for item in result if isinstance(item, dict)]
    return []


def extract_guest_agent_ipv4(
    payload: Dict[str, Any],
    network: ipaddress.IPv4Network,
) -> str | None:
    for interface in guest_agent_interfaces(payload):
        addresses = interface.get("ip-addresses") or interface.get("ip_addresses") or []
        if not isinstance(addresses, list):
            continue
        for address in addresses:
            if not isinstance(address, dict):
                continue
            if address.get("ip-address-type") not in (None, "ipv4"):
                continue
            candidate = address.get("ip-address") or address.get("ip_address")
            if not isinstance(candidate, str):
                continue
            safe = safe_ipv4(candidate, network)
            if safe:
                return safe
    return None


def bounded_guest_agent_ipv4(
    api_get: Callable[[str], Tuple[int, Dict[str, Any]]],
    node: str,
    vmid: str,
    network: ipaddress.IPv4Network,
    attempts: int,
    interval_seconds: float,
    sleep: Callable[[float], None] = time.sleep,
) -> Dict[str, Any]:
    path = f"/nodes/{node}/qemu/{vmid}/agent/network-get-interfaces"
    last_status: int | None = None
    for attempt in range(1, max(attempts, 1) + 1):
        status, payload = api_get(path)
        last_status = status
        if status == 200:
            ip = extract_guest_agent_ipv4(payload, network)
            if ip:
                return {
                    "ok": True,
                    "method": "guest-agent",
                    "ip": ip,
                    "attempts": attempt,
                }
        if attempt < attempts and interval_seconds > 0:
            sleep(interval_seconds)

    return {
        "ok": False,
        "method": "guest-agent",
        "attempts": max(attempts, 1),
        "last_status": last_status,
        "reason": "guest_agent_no_ipv4",
    }


def parse_net_value(value: str) -> Dict[str, str]:
    parsed: Dict[str, str] = {}
    for item in str(value).split(","):
        if "=" not in item:
            continue
        key, raw_value = item.split("=", 1)
        parsed[key.strip()] = raw_value.strip()
    return parsed


def vm_network_facts(
    config: Dict[str, Any],
    expected_bridge: str,
    expected_vlan: str,
) -> Dict[str, Any]:
    for key, value in sorted(config.items()):
        if not str(key).startswith("net"):
            continue
        parsed = parse_net_value(str(value))
        mac = next((parsed.get(model) for model in NIC_MODELS if parsed.get(model)), None)
        if not mac or not MAC_RE.fullmatch(mac):
            continue
        bridge = parsed.get("bridge")
        vlan = parsed.get("tag")
        if bridge != expected_bridge:
            return {
                "ok": False,
                "reason": "unexpected_bridge",
                "bridge": bridge,
                "vlan": vlan,
            }
        if vlan != expected_vlan:
            return {
                "ok": False,
                "reason": "unexpected_vlan",
                "bridge": bridge,
                "vlan": vlan,
            }
        return {
            "ok": True,
            "device": key,
            "bridge": bridge,
            "vlan": vlan,
            "mac": canonical_mac(mac),
            "mac_digest": mac_digest(mac),
        }
    return {"ok": False, "reason": "vm_network_mac_not_found"}


def candidate_ips_from_text(
    text: str,
    mac: str,
    network: ipaddress.IPv4Network,
) -> List[str]:
    target = canonical_mac(mac)
    seen = set()
    ips: List[str] = []
    for line in text.splitlines():
        if target not in line.lower():
            continue
        for raw_ip in IPV4_RE.findall(line):
            ip = safe_ipv4(raw_ip, network)
            if ip and ip not in seen:
                seen.add(ip)
                ips.append(ip)
    return ips


def read_observation_files(paths: Iterable[str]) -> List[Tuple[str, str]]:
    observations = []
    for raw_path in paths:
        path = Path(raw_path)
        try:
            observations.append((str(path), path.read_text(errors="replace")))
        except OSError:
            continue
    return observations


def local_neighbor_observations(
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> List[Tuple[str, str]]:
    observations: List[Tuple[str, str]] = []
    commands = (("arp", "-an"), ("ip", "neigh", "show"))
    for command in commands:
        try:
            completed = runner(
                list(command),
                check=False,
                capture_output=True,
                text=True,
                timeout=3,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if completed.returncode == 0 and completed.stdout:
            observations.append((" ".join(command), completed.stdout))
    return observations


def ssh_neighbor_observation(target: str, connect_timeout: int = 4) -> List[Tuple[str, str]]:
    if not target:
        return []
    command = [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        f"ConnectTimeout={connect_timeout}",
        "-o",
        "StrictHostKeyChecking=accept-new",
        target,
        "ip neigh show",
    ]
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=connect_timeout + 3,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    if completed.returncode != 0 or not completed.stdout:
        return []
    return [(f"ssh {target} ip neigh show", completed.stdout)]


def ssh_exec_capture(
    target: str,
    command: str,
    connect_timeout: int,
    timeout: float,
    max_output_chars: int = 800,
) -> Dict[str, Any]:
    ssh_command = [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        f"ConnectTimeout={max(connect_timeout, 1)}",
        "-o",
        "StrictHostKeyChecking=accept-new",
        target,
        "sh",
        "-lc",
        shlex.quote(command),
    ]
    try:
        completed = subprocess.run(
            ssh_command,
            check=False,
            capture_output=True,
            text=True,
            timeout=max(timeout, 1.0),
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "reason": "ssh_timeout"}
    except OSError as exc:
        return {"ok": False, "reason": type(exc).__name__}

    return {
        "ok": completed.returncode == 0,
        "returncode": completed.returncode,
        "stdout_excerpt": (completed.stdout or "")[:max_output_chars],
        "stderr_excerpt": (completed.stderr or "")[:max_output_chars],
    }


def ssh_template_diagnostics(
    target: str,
    attempts: int,
    interval_seconds: float,
    connect_timeout: int,
    command_timeout: float,
) -> Dict[str, Any]:
    report: Dict[str, Any] = {
        "ok": False,
        "target": target,
        "attempts": 0,
        "commands": {},
    }
    for attempt in range(1, max(attempts, 1) + 1):
        report["attempts"] = attempt
        probe = ssh_exec_capture(
            target,
            "true",
            connect_timeout=connect_timeout,
            timeout=command_timeout,
            max_output_chars=120,
        )
        if probe.get("ok"):
            report["ok"] = True
            break
        report["last_probe"] = probe
        if attempt < attempts and interval_seconds > 0:
            time.sleep(interval_seconds)

    if not report["ok"]:
        report["reason"] = "ssh_unavailable"
        return report

    commands = {
        "cloud_init_status": "cloud-init status --long 2>&1 || true",
        "ip_brief_link": "ip -brief link 2>&1 || true",
        "ip_brief_addr": "ip -brief addr 2>&1 || true",
        "ip_route": "ip route 2>&1 || true",
        "qemu_guest_agent_package": (
            "dpkg-query -W -f='${db:Status-Abbrev} ${Version}\\n' "
            "qemu-guest-agent 2>&1 || true"
        ),
        "qemu_guest_agent_binary": "command -v qemu-ga 2>&1 || true",
        "qemu_guest_agent_enabled": "systemctl is-enabled qemu-guest-agent 2>&1 || true",
        "qemu_guest_agent_active": "systemctl is-active qemu-guest-agent 2>&1 || true",
        "qemu_guest_agent_state": (
            "systemctl show qemu-guest-agent "
            "-p LoadState -p ActiveState -p SubState -p UnitFileState "
            "-p FragmentPath --no-pager 2>&1 || true"
        ),
        "qemu_guest_agent_socket": (
            "test -S /dev/virtio-ports/org.qemu.guest_agent.0 "
            "&& echo present || echo missing"
        ),
    }
    report["commands"] = {
        name: ssh_exec_capture(
            target,
            command,
            connect_timeout=connect_timeout,
            timeout=command_timeout,
        )
        for name, command in commands.items()
    }
    report["qga_summary"] = summarize_ssh_qga_diagnostics(report["commands"])
    return report


def command_stdout(commands: Dict[str, Dict[str, Any]], name: str) -> str:
    value = commands.get(name) or {}
    return str(value.get("stdout_excerpt") or "").strip()


def summarize_ssh_qga_diagnostics(commands: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    package = command_stdout(commands, "qemu_guest_agent_package")
    binary = command_stdout(commands, "qemu_guest_agent_binary")
    enabled = command_stdout(commands, "qemu_guest_agent_enabled")
    active = command_stdout(commands, "qemu_guest_agent_active")
    socket = command_stdout(commands, "qemu_guest_agent_socket")
    state = command_stdout(commands, "qemu_guest_agent_state")

    installed = package.startswith("ii ") or bool(binary)
    unit_state = enabled.splitlines()[0] if enabled else ""
    service_enabled = unit_state in ("enabled", "static")
    service_active = active.splitlines()[0] == "active" if active else False
    socket_present = socket.splitlines()[0] == "present" if socket else False

    reason = None
    if not installed:
        reason = "qemu_guest_agent_not_installed"
    elif not service_enabled:
        reason = "qemu_guest_agent_not_enabled"
    elif not service_active:
        reason = "qemu_guest_agent_not_active"
    else:
        reason = "qemu_guest_agent_guest_side_healthy"

    return {
        "installed": installed,
        "enabled": service_enabled,
        "active": service_active,
        "virtio_socket_present": socket_present,
        "reason": reason,
        "systemd_state_excerpt": state[:360],
    }


def ssh_qga_repair(target: str, connect_timeout: int, command_timeout: float) -> Dict[str, Any]:
    commands = {
        "cloud_init_wait": "cloud-init status --wait >/tmp/openclaw-cloud-init-wait.log 2>&1 || true; echo cloud_init_checked",
        "apt_update": (
            "sudo apt-get -o DPkg::Lock::Timeout=120 -o Acquire::Retries=3 update "
            ">/tmp/openclaw-qga-apt-update.log 2>&1 && echo apt_update_ok || "
            "{ rc=$?; tail -n 80 /tmp/openclaw-qga-apt-update.log; exit $rc; }"
        ),
        "install_qga": (
            "sudo DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=120 -o Acquire::Retries=3 "
            "install -y qemu-guest-agent >/tmp/openclaw-qga-apt-install.log 2>&1 "
            "&& echo qga_install_ok || "
            "{ rc=$?; tail -n 80 /tmp/openclaw-qga-apt-install.log; exit $rc; }"
        ),
        "enable_qga": "sudo systemctl enable --now qemu-guest-agent >/tmp/openclaw-qga-systemctl.log 2>&1 && echo qga_enabled",
        "qga_status": (
            "dpkg-query -W -f='${db:Status-Abbrev} ${Version}\\n' qemu-guest-agent 2>&1; "
            "systemctl is-enabled qemu-guest-agent 2>&1; "
            "systemctl is-active qemu-guest-agent 2>&1; "
            "test -S /dev/virtio-ports/org.qemu.guest_agent.0 && echo socket_present || echo socket_missing"
        ),
    }
    report: Dict[str, Any] = {
        "ok": False,
        "commands": {},
    }
    for name, command in commands.items():
        result = ssh_exec_capture(
            target,
            command,
            connect_timeout=connect_timeout,
            timeout=command_timeout,
            max_output_chars=600,
        )
        report["commands"][name] = result
        if not result.get("ok"):
            report["reason"] = f"{name}_failed"
            return report

    status = str(report["commands"]["qga_status"].get("stdout_excerpt") or "")
    installed = "ii " in status
    active = "\nactive\n" in f"\n{status}\n"
    configured = "\nenabled\n" in f"\n{status}\n" or "\nstatic\n" in f"\n{status}\n"
    socket_present = "socket_present" in status
    report["installed"] = installed
    report["configured"] = configured
    report["active"] = active
    report["virtio_socket_present"] = socket_present
    report["requires_reboot"] = not socket_present
    report["ok"] = installed and configured and active
    if not report["ok"]:
        report["reason"] = "qga_guest_side_verification_failed"
    return report


def ssh_template_cleanup(target: str, connect_timeout: int, command_timeout: float) -> Dict[str, Any]:
    command = (
        "sudo cloud-init clean --logs && "
        "sudo truncate -s 0 /etc/machine-id && "
        "sudo rm -f /var/lib/dbus/machine-id && "
        "sudo ln -sf /etc/machine-id /var/lib/dbus/machine-id && "
        "echo template_cleaned"
    )
    return ssh_exec_capture(
        target,
        command,
        connect_timeout=connect_timeout,
        timeout=command_timeout,
        max_output_chars=400,
    )


def verify_proxmox_guest_agent(
    api_base: str,
    auth_header: str,
    node: str,
    vmid: str,
    network: ipaddress.IPv4Network,
    attempts: int,
    interval_seconds: float,
    timeout: float,
) -> Dict[str, Any]:
    report: Dict[str, Any] = {
        "ok": False,
        "attempts": 0,
        "ping": None,
        "network_get_interfaces": None,
        "ip": None,
    }
    for attempt in range(1, max(attempts, 1) + 1):
        report["attempts"] = attempt
        ping = guest_agent_ping(api_base, auth_header, node, vmid, timeout=timeout)
        status, payload = api_request(
            api_base,
            auth_header,
            "GET",
            f"/nodes/{node}/qemu/{vmid}/agent/network-get-interfaces",
            timeout=max(timeout, 1.0),
        )
        ip = extract_guest_agent_ipv4(payload, network) if status == 200 else None
        report["ping"] = ping
        report["network_get_interfaces"] = {
            "http_status": status,
            "interface_count": len(guest_agent_interfaces(payload)) if status == 200 else 0,
        }
        report["ip"] = ip
        if ping.get("ok") and status == 200 and ip:
            report["ok"] = True
            return report
        if attempt < attempts and interval_seconds > 0:
            time.sleep(interval_seconds)

    report["reason"] = "proxmox_guest_agent_verification_failed"
    return report


def summarize_l2_capture_output(text: str, mac: str) -> Dict[str, Any]:
    target = canonical_mac(mac)
    lines = [line for line in text.splitlines() if line.strip()]
    matching_lines = [line for line in lines if target in line.lower()]
    dhcp_lines = [
        line
        for line in matching_lines
        if "bootp" in line.lower() or "dhcp" in line.lower()
    ]
    arp_lines = [
        line
        for line in matching_lines
        if "ethertype arp" in line.lower() or " arp," in f" {line.lower()}"
    ]
    arp_tell_ips: List[str] = []
    seen_tell_ips = set()
    for line in arp_lines:
        match = re.search(r"\btell\s+((?:\d{1,3}\.){3}\d{1,3})\b", line)
        if not match:
            continue
        raw_ip = match.group(1)
        if raw_ip in seen_tell_ips:
            continue
        try:
            ip = ipaddress.ip_address(raw_ip)
        except ValueError:
            continue
        if ip.version == 4 and not ip.is_unspecified and not ip.is_multicast:
            seen_tell_ips.add(raw_ip)
            arp_tell_ips.append(raw_ip)
    return {
        "line_count": len(lines),
        "mac_line_count": len(matching_lines),
        "dhcp_seen": bool(dhcp_lines),
        "arp_seen": bool(arp_lines),
        "arp_tell_ipv4_candidates": arp_tell_ips,
        "excerpt": matching_lines[:12],
    }


def start_ssh_l2_capture(
    target: str | None,
    mac: str,
    duration_seconds: int,
    interface: str,
    connect_timeout: int = 4,
) -> Dict[str, Any]:
    if not target:
        return {"started": False, "reason": "no_vlan_observer"}
    if not MAC_RE.fullmatch(mac):
        return {"started": False, "reason": "invalid_mac"}

    duration = max(int(duration_seconds), 5)
    capture_interface = interface.strip() or "eth0"
    remote_command = (
        f"sudo -n timeout {duration} "
        f"tcpdump -l -nn -e -i {shlex.quote(capture_interface)} "
        + shlex.quote(f"ether host {canonical_mac(mac)} and (arp or udp port 67 or udp port 68)")
    )
    command = [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        f"ConnectTimeout={connect_timeout}",
        "-o",
        "StrictHostKeyChecking=accept-new",
        target,
        remote_command,
    ]
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except OSError as exc:
        return {"started": False, "reason": type(exc).__name__}

    return {
        "started": True,
        "target": target,
        "duration_seconds": duration,
        "interface": capture_interface,
        "mac_digest": mac_digest(mac),
        "process": process,
    }


def finish_ssh_l2_capture(capture: Dict[str, Any], mac: str, timeout: float = 5.0) -> Dict[str, Any]:
    result = {key: value for key, value in capture.items() if key != "process"}
    process = capture.get("process")
    if not process:
        return result

    try:
        stdout, stderr = process.communicate(timeout=max(timeout, 1.0))
    except subprocess.TimeoutExpired:
        process.terminate()
        try:
            stdout, stderr = process.communicate(timeout=2.0)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate(timeout=2.0)
        result["terminated_by_helper"] = True

    result["returncode"] = process.returncode
    result["summary"] = summarize_l2_capture_output(stdout or "", mac)
    if stderr:
        result["stderr_excerpt"] = stderr[:240]
    return result


def passive_arp_dhcp_ipv4(
    api_get: Callable[[str], Tuple[int, Dict[str, Any]]],
    node: str,
    vmid: str,
    bridge: str,
    vlan: str,
    network: ipaddress.IPv4Network,
    observation_files: Sequence[str],
    use_local_neighbor_cache: bool,
) -> Dict[str, Any]:
    status, payload = api_get(f"/nodes/{node}/qemu/{vmid}/config")
    if status != 200:
        return {
            "ok": False,
            "method": "passive-arp-dhcp",
            "reason": "vm_config_unavailable",
            "status": status,
        }

    facts = vm_network_facts(payload.get("data") or {}, bridge, vlan)
    if not facts.get("ok"):
        return {
            "ok": False,
            "method": "passive-arp-dhcp",
            "reason": facts.get("reason"),
            "bridge": facts.get("bridge"),
            "vlan": facts.get("vlan"),
        }

    observations = read_observation_files(observation_files)
    if use_local_neighbor_cache:
        observations.extend(local_neighbor_observations())

    for source, text in observations:
        ips = candidate_ips_from_text(text, facts["mac"], network)
        if ips:
            return {
                "ok": True,
                "method": "passive-arp-dhcp",
                "ip": ips[0],
                "source": source,
                "mac_digest": facts["mac_digest"],
                "bridge": facts["bridge"],
                "vlan": facts["vlan"],
            }

    return {
        "ok": False,
        "method": "passive-arp-dhcp",
        "reason": "no_passive_vlan_candidate",
        "mac_digest": facts["mac_digest"],
        "bridge": facts["bridge"],
        "vlan": facts["vlan"],
        "sources_checked": len(observations),
    }


def bounded_mac_driven_discovery(
    api_get: Callable[[str], Tuple[int, Dict[str, Any]]],
    node: str,
    vmid: str,
    bridge: str,
    vlan: str,
    network: ipaddress.IPv4Network,
    attempts: int,
    interval_seconds: float,
    observation_files: Sequence[str],
    vlan_observer: str | None,
    cloud_init_status: Callable[[], Dict[str, Any]] | None = None,
) -> Dict[str, Any]:
    guest_agent_path = f"/nodes/{node}/qemu/{vmid}/agent/network-get-interfaces"
    config_path = f"/nodes/{node}/qemu/{vmid}/config"
    facts: Dict[str, Any] | None = None
    evidence: List[Dict[str, Any]] = []
    cloud_init_checked = False

    for attempt in range(1, max(attempts, 1) + 1):
        with ThreadPoolExecutor(max_workers=2) as executor:
            agent_future = executor.submit(api_get, guest_agent_path)
            observer_future = executor.submit(ssh_neighbor_observation, vlan_observer or "")
            status, payload = agent_future.result()
            observer_observations = observer_future.result()

        if status == 200:
            ip = extract_guest_agent_ipv4(payload, network)
            if ip:
                return {
                    "ok": True,
                    "method": "guest-agent",
                    "ip": ip,
                    "attempts": attempt,
                    "evidence": evidence,
                }
            if cloud_init_status is not None and not cloud_init_checked:
                cloud_init_checked = True
                evidence.append(
                    {
                        "attempt": attempt,
                        "cloud_init_status": cloud_init_status(),
                    }
                )
            evidence.append({"attempt": attempt, "guest_agent_http_status": status})
        else:
            evidence.append({"attempt": attempt, "guest_agent_http_status": status})

        if facts is None:
            config_status, config_payload = api_get(config_path)
            if config_status == 200:
                facts = vm_network_facts(config_payload.get("data") or {}, bridge, vlan)
            else:
                facts = {"ok": False, "reason": "vm_config_unavailable", "status": config_status}

        if facts.get("ok"):
            observations = read_observation_files(observation_files)
            observations.extend(observer_observations)
            observations.extend(local_neighbor_observations())
            for source, text in observations:
                ips = candidate_ips_from_text(text, facts["mac"], network)
                if ips:
                    return {
                        "ok": True,
                        "method": "passive-arp-dhcp",
                        "ip": ips[0],
                        "attempts": attempt,
                        "source": source,
                        "mac_digest": facts["mac_digest"],
                        "bridge": facts["bridge"],
                        "vlan": facts["vlan"],
                        "evidence": evidence,
                    }
            evidence.append(
                {
                    "attempt": attempt,
                    "passive_sources_checked": len(observations),
                    "mac_digest": facts["mac_digest"],
                }
            )
        else:
            evidence.append({"attempt": attempt, "passive_unavailable": facts.get("reason")})

        if attempt < attempts and interval_seconds > 0:
            time.sleep(interval_seconds)

    return {
        "ok": False,
        "method": "mac-driven-discovery",
        "reason": "no_ip_discovered",
        "attempts": max(attempts, 1),
        "evidence": evidence,
        "network_facts": copy.deepcopy(facts),
    }


def bounded_template_diagnostics(
    api_base: str,
    auth_header: str,
    api_get: Callable[[str], Tuple[int, Dict[str, Any]]],
    node: str,
    vmid: str,
    bridge: str,
    vlan: str,
    network: ipaddress.IPv4Network,
    attempts: int,
    interval_seconds: float,
    observation_files: Sequence[str],
    vlan_observer: str | None,
    agent_call_timeout: float,
) -> Dict[str, Any]:
    config_status, config_payload = api_get(f"/nodes/{node}/qemu/{vmid}/config")
    facts = (
        vm_network_facts(config_payload.get("data") or {}, bridge, vlan)
        if config_status == 200
        else {"ok": False, "reason": "vm_config_unavailable", "status": config_status}
    )
    report: Dict[str, Any] = {
        "ok": False,
        "method": "template-diagnostics",
        "network_facts": copy.deepcopy(facts),
        "guest_agent_healthy": False,
        "guest_agent_network_ipv4": None,
        "passive_ipv4": None,
        "cloud_init": None,
        "attempts": [],
    }
    guest_commands_collected = False

    for attempt in range(1, max(attempts, 1) + 1):
        with ThreadPoolExecutor(max_workers=2) as executor:
            agent_future = executor.submit(
                api_request,
                api_base,
                auth_header,
                "GET",
                f"/nodes/{node}/qemu/{vmid}/agent/network-get-interfaces",
                max(agent_call_timeout, 1.0),
            )
            observer_future = executor.submit(
                ssh_neighbor_observation,
                vlan_observer or "",
                2,
            )
            agent_status, agent_payload = agent_future.result()
            observer_observations = observer_future.result()

        ping = guest_agent_ping(
            api_base,
            auth_header,
            node,
            vmid,
            timeout=max(agent_call_timeout, 1.0),
        )
        attempt_report: Dict[str, Any] = {
            "attempt": attempt,
            "checked_at": utc_now(),
            "guest_agent_ping": ping,
            "guest_agent_network_http_status": agent_status,
            "passive_sources_checked": 0,
            "passive_match": False,
        }
        if ping.get("ok"):
            report["guest_agent_healthy"] = True

        if agent_status == 200:
            ip = extract_guest_agent_ipv4(agent_payload, network)
            attempt_report["guest_agent_interface_count"] = len(
                guest_agent_interfaces(agent_payload)
            )
            if ip:
                report["guest_agent_network_ipv4"] = ip
                attempt_report["guest_agent_ipv4"] = ip

        if ping.get("ok") and not guest_commands_collected:
            guest_commands_collected = True
            commands = guest_agent_template_diagnostics(
                api_base,
                auth_header,
                node,
                vmid,
                timeout=max(agent_call_timeout, 1.0),
            )
            report["guest_commands"] = commands
            report["cloud_init"] = commands.get("cloud_init_status")
            attempt_report["guest_commands_collected"] = True

        if facts.get("ok"):
            observations = read_observation_files(observation_files)
            observations.extend(observer_observations)
            observations.extend(local_neighbor_observations())
            attempt_report["passive_sources_checked"] = len(observations)
            for source, text in observations:
                ips = candidate_ips_from_text(text, facts["mac"], network)
                if ips:
                    report["passive_ipv4"] = ips[0]
                    attempt_report["passive_match"] = True
                    attempt_report["passive_source"] = source
                    attempt_report["mac_digest"] = facts["mac_digest"]
                    break
        else:
            attempt_report["passive_unavailable"] = facts.get("reason")

        report["attempts"].append(attempt_report)

        if report.get("guest_agent_healthy") and report.get("guest_agent_network_ipv4"):
            report["ok"] = True
            report["outcome"] = "template_network_validated"
            return report

        if attempt < attempts and interval_seconds > 0:
            time.sleep(interval_seconds)

    if report.get("passive_ipv4") and not report.get("guest_agent_healthy"):
        report["outcome"] = "dhcp_observed_guest_agent_unhealthy"
        report["reason"] = "passive_ip_without_guest_agent"
    elif report.get("guest_agent_healthy") and not report.get("guest_agent_network_ipv4"):
        report["outcome"] = "guest_agent_healthy_no_dhcp_ip"
        report["reason"] = "guest_agent_no_vlan30_ipv4"
    else:
        report["outcome"] = "no_ip_discovered"
        report["reason"] = "no_guest_or_passive_vlan30_ip"
    return report


def discover_ip(values: Dict[str, str], args: argparse.Namespace) -> Tuple[int, Dict[str, Any]]:
    api_base = preflight.normalize_api_url(values.get("OPENCLAW_PROXMOX_API_URL", ""))
    auth_header = preflight.build_auth_header(values)
    node = values.get("OPENCLAW_PROXMOX_NODE", "pve01")
    bridge = values.get("OPENCLAW_PROXMOX_DEFAULT_BRIDGE", "vmbr0")
    vlan = values.get("OPENCLAW_PROXMOX_DEFAULT_VLAN", "30")
    network = allowed_network(values, args.subnet)
    report: Dict[str, Any] = {
        "schema_version": 1,
        "checked_at": utc_now(),
        "vmid": args.vmid,
        "node": node,
        "allowed_subnet": str(network),
        "guest_agent": None,
        "fallback": None,
        "ok": False,
        "ip": None,
    }

    if not api_base:
        report["reason"] = "missing OPENCLAW_PROXMOX_API_URL"
        return 2, report
    if not auth_header:
        report["reason"] = "missing Proxmox token auth configuration"
        return 2, report

    def get(path: str) -> Tuple[int, Dict[str, Any]]:
        return preflight.api_get(api_base, auth_header, path, timeout=max(args.timeout, 1.0))

    guest_agent = bounded_guest_agent_ipv4(
        get,
        node=node,
        vmid=args.vmid,
        network=network,
        attempts=max(args.guest_agent_attempts, 1),
        interval_seconds=max(args.guest_agent_interval, 0.0),
    )
    report["guest_agent"] = guest_agent
    if guest_agent.get("ok"):
        report["ok"] = True
        report["ip"] = guest_agent["ip"]
        report["method"] = guest_agent["method"]
        return 0, report

    fallback = passive_arp_dhcp_ipv4(
        get,
        node=node,
        vmid=args.vmid,
        bridge=bridge,
        vlan=vlan,
        network=network,
        observation_files=args.observation_file or [],
        use_local_neighbor_cache=not args.no_local_neighbor_cache,
    )
    report["fallback"] = fallback
    if fallback.get("ok"):
        report["ok"] = True
        report["ip"] = fallback["ip"]
        report["method"] = fallback["method"]
        return 0, report

    report["reason"] = "ip_discovery_failed_closed"
    return 1, report


def next_vmid(api_base: str, auth_header: str, timeout: float) -> int:
    status, payload = api_request(api_base, auth_header, "GET", "/cluster/nextid", timeout)
    if status != 200:
        raise RuntimeError(f"nextid failed with HTTP {status}")
    return int(payload.get("data"))


def http_get_status(url: str, timeout: float) -> Tuple[int | None, str | None]:
    request = urllib.request.Request(url, headers={"User-Agent": "openclaw-corpus-lifecycle/0.1"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            response.read(1024)
            return response.status, None
    except urllib.error.HTTPError as exc:
        return exc.code, None
    except (OSError, urllib.error.URLError) as exc:
        return None, type(exc).__name__


def render_deploy_command(command_template: str, version: str, ip: str, port: int) -> Tuple[str, List[str]]:
    replacements = {
        "{version}": version,
        "{ip}": ip,
        "{port}": str(port),
    }
    command = command_template
    used: List[str] = []
    for marker, value in replacements.items():
        if marker in command:
            command = command.replace(marker, shlex.quote(str(value)))
            used.append(marker.strip("{}"))
    return command, used


def wait_for_ssh_ready(
    target: str,
    *,
    attempts: int,
    interval_seconds: float,
    connect_timeout: int,
    command_timeout: float,
) -> Dict[str, Any]:
    report: Dict[str, Any] = {
        "ok": False,
        "attempts": 0,
        "stdout_recorded": False,
        "stderr_recorded": False,
    }
    last_probe: Dict[str, Any] = {}
    for attempt in range(1, max(attempts, 0) + 1):
        report["attempts"] = attempt
        probe = ssh_exec_capture(
            target,
            "true",
            connect_timeout=connect_timeout,
            timeout=command_timeout,
            max_output_chars=0,
        )
        last_probe = probe
        if probe.get("ok"):
            report["ok"] = True
            report["returncode"] = probe.get("returncode")
            return report
        if attempt < max(attempts, 0) and interval_seconds > 0:
            time.sleep(interval_seconds)

    report["reason"] = last_probe.get("reason") or "ssh_unavailable"
    report["returncode"] = last_probe.get("returncode")
    return report


def relative_to_or_none(path: Path, parent: Path) -> Path | None:
    try:
        return path.relative_to(parent)
    except ValueError:
        return None


def deploy_command_file_git_safety(path: Path, repo_root: Path = REPO_ROOT) -> Tuple[bool, str | None]:
    try:
        resolved = path.expanduser().resolve(strict=False)
        resolved_repo = repo_root.resolve(strict=False)
    except OSError:
        return False, "deploy_command_file_path_unreadable"

    relative = relative_to_or_none(resolved, resolved_repo)
    if relative is None:
        return True, None

    relative_text = str(relative)
    try:
        tracked = subprocess.run(
            ["git", "ls-files", "--error-unmatch", "--", relative_text],
            cwd=resolved_repo,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except OSError:
        return False, "deploy_command_file_ignore_check_failed"
    if tracked.returncode == 0:
        return False, "deploy_command_file_tracked"

    try:
        ignored = subprocess.run(
            ["git", "check-ignore", "--quiet", "--", relative_text],
            cwd=resolved_repo,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except OSError:
        return False, "deploy_command_file_ignore_check_failed"
    if ignored.returncode == 0:
        return True, None
    if ignored.returncode == 1:
        return False, "deploy_command_file_not_ignored"
    return False, "deploy_command_file_ignore_check_failed"


def read_deploy_command_file(path: str, repo_root: Path = REPO_ROOT) -> Tuple[str | None, str | None]:
    path_obj = Path(path).expanduser()
    safe, reason = deploy_command_file_git_safety(path_obj, repo_root=repo_root)
    if not safe:
        return None, reason
    try:
        command = path_obj.read_text(encoding="utf-8").strip()
    except OSError:
        return None, "deploy_command_file_unreadable"
    if not command:
        return None, "deploy_command_file_empty"
    return command, None


def run_known_version_deploy(
    ip: str,
    version: str,
    port: int,
    ssh_user: str,
    command_template: str | None,
    command_label: str,
    connect_timeout: int,
    timeout: float,
    skip_deploy: bool = False,
    command_source: str = "argument",
    ssh_ready_attempts: int = 0,
    ssh_ready_interval: float = 0.0,
) -> Dict[str, Any]:
    if skip_deploy:
        return {
            "ok": True,
            "skipped": True,
            "reason": "assume_predeployed",
            "command_recorded": False,
            "stdout_recorded": False,
            "stderr_recorded": False,
        }
    if not command_template:
        return {
            "ok": False,
            "reason": "deployment_not_configured",
            "command_recorded": False,
            "stdout_recorded": False,
            "stderr_recorded": False,
        }

    command, placeholders = render_deploy_command(command_template, version, ip, port)
    target = f"{ssh_user}@{ip}"
    ssh_ready: Dict[str, Any] | None = None
    if ssh_ready_attempts > 0:
        ssh_ready = wait_for_ssh_ready(
            target,
            attempts=ssh_ready_attempts,
            interval_seconds=ssh_ready_interval,
            connect_timeout=connect_timeout,
            command_timeout=min(max(timeout, 1.0), max(connect_timeout + 5, 6)),
        )
        if not ssh_ready.get("ok"):
            return {
                "ok": False,
                "method": "ssh-command",
                "command_label": command_label,
                "command_source": command_source,
                "command_recorded": False,
                "placeholders_used": placeholders,
                "reason": "ssh_unavailable",
                "returncode": ssh_ready.get("returncode"),
                "ssh_ready": ssh_ready,
                "stdout_recorded": False,
                "stderr_recorded": False,
            }

    raw = ssh_exec_capture(
        target,
        command,
        connect_timeout=connect_timeout,
        timeout=timeout,
        max_output_chars=0,
    )
    report = {
        "ok": raw.get("ok") is True,
        "method": "ssh-command",
        "command_label": command_label,
        "command_source": command_source,
        "command_recorded": False,
        "placeholders_used": placeholders,
        "returncode": raw.get("returncode"),
        "stdout_recorded": False,
        "stderr_recorded": False,
    }
    if ssh_ready is not None:
        report["ssh_ready"] = ssh_ready
    if not report["ok"]:
        report["reason"] = raw.get("reason") or "deploy_command_failed"
    return report


def validate_deploy_command_input(
    *,
    version: str,
    command_template: str | None,
    command_file: str | None,
    command_label: str,
    ip: str,
    port: int,
) -> Tuple[int, Dict[str, Any]]:
    source = "argument" if command_template else None
    if command_file:
        command_template, reason = read_deploy_command_file(command_file)
        source = "file"
        if reason:
            return 1, {
                "ok": False,
                "reason": reason,
                "command_label": command_label,
                "command_source": "file",
                "command_recorded": False,
                "stdout_recorded": False,
                "stderr_recorded": False,
            }
    if not command_template:
        return 1, {
            "ok": False,
            "reason": "deployment_not_configured",
            "command_label": command_label,
            "command_source": source or "argument",
            "command_recorded": False,
            "stdout_recorded": False,
            "stderr_recorded": False,
        }

    _command, placeholders = render_deploy_command(command_template, version, ip, port)
    return 0, {
        "ok": True,
        "reason": None,
        "command_label": command_label,
        "command_source": source or "argument",
        "command_recorded": False,
        "stdout_recorded": False,
        "stderr_recorded": False,
        "placeholders_used": placeholders,
        "uses_version_placeholder": "version" in placeholders,
        "uses_ip_placeholder": "ip" in placeholders,
        "uses_port_placeholder": "port" in placeholders,
    }


def wait_for_gateway_health(
    url: str,
    timeout: float,
    attempts: int,
    interval_seconds: float,
    expected_status: int = 200,
) -> Dict[str, Any]:
    report: Dict[str, Any] = {
        "ok": False,
        "url": "http://<ip>:18789/health",
        "expected_http_status": expected_status,
        "attempts": [],
        "http_status": None,
        "error": None,
    }
    for attempt in range(1, max(attempts, 1) + 1):
        status, error = http_get_status(url, timeout=max(timeout, 1.0))
        attempt_report = {
            "attempt": attempt,
            "http_status": status,
            "error": error,
        }
        report["attempts"].append(attempt_report)
        report["http_status"] = status
        report["error"] = error
        if status is not None:
            report["ok"] = True
            report["expected_status_matched"] = status == expected_status
            return report
        if attempt < attempts and interval_seconds > 0:
            time.sleep(interval_seconds)

    report["reason"] = "gateway_health_unreachable"
    report["expected_status_matched"] = False
    return report


def run_scanner_capture(
    ip: str,
    version: str,
    capture_name: str,
    output_dir: Path,
    timeout: float,
) -> Dict[str, Any]:
    scan_path = output_dir / "scan.json"
    capture_path = output_dir / "capture.json"
    command = [
        sys.executable,
        "-m",
        "openclaw_scanner",
        "--target",
        f"http://{ip}:18789",
        "--capture-version",
        version,
        "--capture-name",
        capture_name,
        "--capture-output",
        str(capture_path),
        "--format",
        "json",
        "--output",
        str(scan_path),
    ]
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "reason": "scanner_timeout",
            "command": "python3 -m openclaw_scanner --target http://<ip>:18789 --capture-version <version> --capture-name <name> --capture-output <capture> --format json --output <scan>",
            "scan_artifact": str(scan_path) if scan_path.exists() else None,
            "capture_artifact": str(capture_path) if capture_path.exists() else None,
        }
    return {
        "ok": completed.returncode == 0 and capture_path.exists() and scan_path.exists(),
        "returncode": completed.returncode,
        "command": "python3 -m openclaw_scanner --target http://<ip>:18789 --capture-version <version> --capture-name <name> --capture-output <capture> --format json --output <scan>",
        "scan_artifact": str(scan_path) if scan_path.exists() else None,
        "capture_artifact": str(capture_path) if capture_path.exists() else None,
    }


def capture_has_signals(path: str | None) -> bool:
    if not path:
        return False
    try:
        bundle = json.loads(Path(path).read_text())
    except (OSError, json.JSONDecodeError):
        return False
    for capture in bundle.get("captures") or []:
        if not isinstance(capture, dict):
            continue
        if capture.get("signals") or capture.get("observations"):
            return True
    return False


def update_manifest(manifest_path: Path, report: Dict[str, Any]) -> None:
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text())
    else:
        manifest = {
            "run_id": f"{manifest_path.parent.name}-openclaw-corpus",
            "vms": [],
            "vm_inventory": {
                "created": 0,
                "reused": 0,
                "shut_down": 0,
                "destroyed": 0,
                "still_running": 0,
                "next_cleanup_deadline": None,
            },
        }

    inventory = manifest.setdefault(
        "vm_inventory",
        {
            "created": 0,
            "reused": 0,
            "shut_down": 0,
            "destroyed": 0,
            "still_running": 0,
            "next_cleanup_deadline": None,
        },
    )
    lifecycle = report.get("lifecycle") or {}
    if lifecycle.get("created_at"):
        inventory["created"] = int(inventory.get("created") or 0) + 1
    if lifecycle.get("stopped_at"):
        inventory["shut_down"] = int(inventory.get("shut_down") or 0) + 1
    if lifecycle.get("deleted_at"):
        inventory["destroyed"] = int(inventory.get("destroyed") or 0) + 1
    inventory["still_running"] = 0 if lifecycle.get("deleted_at") else int(inventory.get("still_running") or 0)
    inventory["next_cleanup_deadline"] = None if lifecycle.get("deleted_at") else report.get("cleanup_deadline")

    vm_entry = {
        "artifact": str(report.get("artifact")),
        "attempt_id": report.get("attempt_id"),
        "auth_mode": "token",
        "capture_artifact": report.get("scanner_result", {}).get("capture_artifact"),
        "created_at": lifecycle.get("created_at"),
        "deleted_at": lifecycle.get("deleted_at"),
        "deployment_method": report.get("deployment_method") or "proxmox-vm",
        "deployment_result": {
            "status": "passed"
            if (report.get("deployment_result") or {}).get("ok")
            else "failed"
            if report.get("deployment_result")
            else "not_run",
            "reason": (report.get("deployment_result") or {}).get("reason"),
            "command_label": (report.get("deployment_result") or {}).get("command_label"),
            "command_recorded": (report.get("deployment_result") or {}).get("command_recorded"),
        },
        "ip_or_hostname": report.get("ip"),
        "notes": report.get("notes"),
        "port": report.get("port", 18789),
        "product_family": report.get("product_family") or "openclaw",
        "scan_artifact": report.get("scanner_result", {}).get("scan_artifact"),
        "scanner_command": report.get("scanner_result", {}).get("command"),
        "scanner_result": {
            "status": report.get("outcome"),
            "reason": report.get("reason"),
        },
        "started_at": lifecycle.get("started_at"),
        "stopped_at": lifecycle.get("stopped_at"),
        "version": report.get("version"),
        "vlan": int(report.get("vlan") or 30),
        "vm_id": report.get("vmid"),
        "vm_name": report.get("vm_name"),
    }
    manifest.setdefault("vms", []).append(vm_entry)
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")


def diagnose_template(values: Dict[str, str], args: argparse.Namespace) -> Tuple[int, Dict[str, Any]]:
    api_base = preflight.normalize_api_url(values.get("OPENCLAW_PROXMOX_API_URL", ""))
    auth_header = preflight.build_auth_header(values)
    node = values.get("OPENCLAW_PROXMOX_NODE", "pve01")
    bridge = values.get("OPENCLAW_PROXMOX_DEFAULT_BRIDGE", "vmbr0")
    vlan = values.get("OPENCLAW_PROXMOX_DEFAULT_VLAN", "30")
    pool = values.get("OPENCLAW_PROXMOX_POOL", "openclaw-scanner")
    storage = values.get("OPENCLAW_PROXMOX_STORAGE")
    template = values.get("OPENCLAW_PROXMOX_TEMPLATE_VMID", "9000")
    network = allowed_network(values, args.subnet)
    attempt_slug = normalize_version_for_name(args.attempt_id)
    output_dir = Path(args.output_dir or (DEFAULT_LAB_ROOT / "template-diagnostics"))
    output_dir.mkdir(parents=True, exist_ok=True)
    artifact_path = output_dir / f"proxmox-template-diagnostic-{attempt_slug}.json"
    report: Dict[str, Any] = {
        "schema_version": 1,
        "artifact": str(artifact_path),
        "attempt_id": args.attempt_id,
        "checked_at": utc_now(),
        "diagnostic_type": "template_network_validation",
        "deployment_method": "proxmox-template-diagnostic-vm",
        "product_family": "proxmox-template",
        "version": "template-validation",
        "port": None,
        "vlan": int(vlan),
        "allowed_subnet": str(network),
        "vmid": None,
        "vm_name": None,
        "mac": None,
        "mac_digest": None,
        "ip": None,
        "outcome": "diagnostic_failed",
        "reason": None,
        "secret_values_recorded": False,
        "scanner_capture_attempted": False,
        "steps": [],
        "lifecycle": {
            "created_at": None,
            "started_at": None,
            "stopped_at": None,
            "deleted_at": None,
        },
    }
    created = False
    started = False
    l2_capture: Dict[str, Any] | None = None

    def record_step(step: Dict[str, Any]) -> None:
        report["steps"].append(step)

    try:
        if not api_base:
            report["outcome"] = "preflight_failed"
            report["reason"] = "missing OPENCLAW_PROXMOX_API_URL"
            return 2, report
        if not auth_header:
            report["outcome"] = "preflight_failed"
            report["reason"] = "missing Proxmox token auth configuration"
            return 2, report

        exit_code, preflight_report = preflight.run_preflight(values, timeout=max(args.timeout, 1.0))
        report["preflight"] = {
            "checked_at": preflight_report.get("checked_at"),
            "vm_lifecycle_allowed": preflight_report.get("vm_lifecycle_allowed"),
            "blockers": preflight_report.get("blockers") or [],
        }
        if exit_code != 0:
            report["outcome"] = "preflight_failed"
            report["reason"] = "preflight_blockers"
            return 1, report

        vmid = next_vmid(api_base, auth_header, timeout=max(args.timeout, 1.0))
        name = f"openclaw-template-diag-{attempt_slug}"
        mac = generated_proxmox_mac()
        report["vmid"] = vmid
        report["vm_name"] = name
        report["mac"] = canonical_mac(mac)
        report["mac_digest"] = mac_digest(mac)
        write_current_report(report)

        clone_data: Dict[str, Any] = {
            "newid": vmid,
            "name": name,
            "full": 1,
            "pool": pool,
        }
        if storage:
            clone_data["storage"] = storage
        step = task_step(
            api_base,
            auth_header,
            node,
            "POST",
            f"/nodes/{node}/qemu/{template}/clone",
            clone_data,
            "clone",
            http_timeout=max(args.timeout, 1.0),
            task_timeout=max(args.task_timeout, 30.0),
        )
        record_step(step)
        if not step.get("ok"):
            report["outcome"] = "create_failed"
            report["reason"] = "clone_failed"
            return 1, report
        created = True
        report["lifecycle"]["created_at"] = utc_now()

        cloud_init_identity, cloud_init_warnings = clone_cloud_init_identity_config(values)
        if cloud_init_warnings:
            report.setdefault("warnings", []).extend(cloud_init_warnings)
        config_steps = [
            (
                "config:resources",
                {
                    "cores": 2,
                    "memory": 4096,
                    "onboot": 0,
                    "agent": "enabled=1",
                },
            ),
            (
                "config:network",
                {
                    "net0": f"virtio={mac},bridge={bridge},tag={vlan},firewall=1",
                },
            ),
        ]
        if cloud_init_identity:
            config_steps.append(("config:cloudinit_identity", cloud_init_identity))
        config_steps.append(
            (
                "config:cloudinit",
                {
                    "ipconfig0": "ip=dhcp",
                },
            )
        )
        for name_step, data in config_steps:
            status, _payload = api_request(
                api_base,
                auth_header,
                "POST",
                f"/nodes/{node}/qemu/{vmid}/config",
                timeout=max(args.timeout, 1.0),
                data=data,
            )
            step = {"name": name_step, "ok": status == 200, "http_status": status}
            record_step(step)
            if status != 200:
                report["outcome"] = "create_failed"
                report["reason"] = name_step.replace(":", "_") + "_failed"
                return 1, report

        step = task_step(
            api_base,
            auth_header,
            node,
            "PUT",
            f"/nodes/{node}/qemu/{vmid}/resize",
            {"disk": "scsi0", "size": "40G"},
            "resize:scsi0",
            http_timeout=max(args.timeout, 1.0),
            task_timeout=max(args.task_timeout, 30.0),
        )
        record_step(step)
        if not step.get("ok"):
            report["notes"] = "Resize failed; diagnostic continued with cloned disk size."

        def get(path: str) -> Tuple[int, Dict[str, Any]]:
            return preflight.api_get(api_base, auth_header, path, timeout=max(args.timeout, 1.0))

        config_status, config_payload = api_request(
            api_base,
            auth_header,
            "GET",
            f"/nodes/{node}/qemu/{vmid}/config",
            timeout=max(args.timeout, 1.0),
        )
        facts = vm_network_facts(config_payload.get("data") or {}, bridge, vlan) if config_status == 200 else {}
        report["network_facts"] = {
            "ok": facts.get("ok"),
            "device": facts.get("device"),
            "bridge": facts.get("bridge"),
            "vlan": facts.get("vlan"),
            "mac": facts.get("mac"),
            "mac_digest": facts.get("mac_digest"),
            "reason": facts.get("reason"),
        }
        write_current_report(report)
        if not facts.get("ok"):
            report["outcome"] = "create_failed"
            report["reason"] = facts.get("reason") or "network_facts_failed"
            return 1, report

        l2_capture = start_ssh_l2_capture(
            args.vlan_observer,
            facts["mac"],
            duration_seconds=max(args.l2_capture_seconds, 5),
            interface=args.l2_capture_interface,
        )
        report["l2_capture"] = {key: value for key, value in l2_capture.items() if key != "process"}
        write_current_report(report)

        step = task_step(
            api_base,
            auth_header,
            node,
            "POST",
            f"/nodes/{node}/qemu/{vmid}/status/start",
            None,
            "start",
            http_timeout=max(args.timeout, 1.0),
            task_timeout=max(args.task_timeout, 30.0),
        )
        record_step(step)
        if not step.get("ok"):
            report["outcome"] = "create_failed"
            report["reason"] = "start_failed"
            return 1, report
        started = True
        report["lifecycle"]["started_at"] = utc_now()
        write_current_report(report)

        diagnostics = bounded_template_diagnostics(
            api_base,
            auth_header,
            get,
            node=node,
            vmid=str(vmid),
            bridge=bridge,
            vlan=vlan,
            network=network,
            attempts=max(args.diagnostic_attempts, 1),
            interval_seconds=max(args.diagnostic_interval, 0.0),
            observation_files=args.observation_file or [],
            vlan_observer=args.vlan_observer,
            agent_call_timeout=max(args.agent_call_timeout, 1.0),
        )
        report["template_diagnostics"] = diagnostics
        report["ip"] = diagnostics.get("guest_agent_network_ipv4") or diagnostics.get("passive_ipv4")
        report["outcome"] = diagnostics.get("outcome") or "diagnostic_failed"
        report["reason"] = diagnostics.get("reason")
        if l2_capture:
            report["l2_capture"] = finish_ssh_l2_capture(l2_capture, str(report.get("mac") or ""))
            l2_capture = None
            l2_summary = report["l2_capture"].get("summary") or {}
            l2_ip_candidates = l2_summary.get("arp_tell_ipv4_candidates") or []
            if l2_ip_candidates:
                report["ip"] = l2_ip_candidates[0]
                diagnostics["l2_ipv4"] = l2_ip_candidates[0]
                if not diagnostics.get("guest_agent_healthy"):
                    report["outcome"] = "dhcp_observed_guest_agent_unhealthy"
                    report["reason"] = "guest_agent_unhealthy_after_dhcp"
            elif l2_summary.get("dhcp_seen") and report.get("outcome") == "no_ip_discovered":
                report["outcome"] = "dhcp_request_seen_no_address_confirmed"
                report["reason"] = "dhcp_request_seen_without_guest_agent_or_arp_tell"

        if args.ssh_diagnostics and report.get("ip"):
            ssh_target = f"{args.ssh_user}@{report['ip']}"
            ssh_diagnostics = ssh_template_diagnostics(
                ssh_target,
                attempts=max(args.ssh_diagnostic_attempts, 1),
                interval_seconds=max(args.ssh_diagnostic_interval, 0.0),
                connect_timeout=max(int(args.ssh_connect_timeout), 1),
                command_timeout=max(args.ssh_command_timeout, 1.0),
            )
            report["ssh_template_diagnostics"] = ssh_diagnostics
            qga_summary = ssh_diagnostics.get("qga_summary") or {}
            if qga_summary:
                diagnostics["ssh_qga_summary"] = qga_summary
                if not diagnostics.get("guest_agent_healthy"):
                    report["reason"] = qga_summary.get("reason") or report.get("reason")
        return (0 if diagnostics.get("ok") else 1), report
    except Exception as exc:  # noqa: BLE001 - preserve cleanup and redacted report.
        report["outcome"] = report.get("outcome") or "diagnostic_failed"
        report["reason"] = type(exc).__name__
        report.setdefault("errors", []).append({"type": type(exc).__name__, "step": "template_diagnostic"})
        return 1, report
    finally:
        vmid = report.get("vmid")
        if api_base and auth_header and vmid:
            if started:
                step = task_step(
                    api_base,
                    auth_header,
                    node,
                    "POST",
                    f"/nodes/{node}/qemu/{vmid}/status/stop",
                    {"timeout": 20},
                    "stop",
                    http_timeout=max(args.timeout, 1.0),
                    task_timeout=max(args.task_timeout, 30.0),
                )
                record_step(step)
                if step.get("ok"):
                    report["lifecycle"]["stopped_at"] = utc_now()
            if created:
                step = task_step(
                    api_base,
                    auth_header,
                    node,
                    "DELETE",
                    f"/nodes/{node}/qemu/{vmid}",
                    None,
                    "delete",
                    http_timeout=max(args.timeout, 1.0),
                    task_timeout=max(args.task_timeout, 30.0),
                )
                record_step(step)
                if step.get("ok"):
                    report["lifecycle"]["deleted_at"] = utc_now()
        if l2_capture:
            report["l2_capture"] = finish_ssh_l2_capture(l2_capture, str(report.get("mac") or ""))
            l2_summary = report["l2_capture"].get("summary") or {}
            l2_ip_candidates = l2_summary.get("arp_tell_ipv4_candidates") or []
            if l2_ip_candidates:
                report["ip"] = l2_ip_candidates[0]
                diagnostics = report.setdefault("template_diagnostics", {})
                diagnostics["l2_ipv4"] = l2_ip_candidates[0]
                if not diagnostics.get("guest_agent_healthy"):
                    report["outcome"] = "dhcp_observed_guest_agent_unhealthy"
                    report["reason"] = "guest_agent_unhealthy_after_dhcp"
            elif l2_summary.get("dhcp_seen") and report.get("outcome") == "no_ip_discovered":
                report["outcome"] = "dhcp_request_seen_no_address_confirmed"
                report["reason"] = "dhcp_request_seen_without_guest_agent_or_arp_tell"
        artifact_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        if args.update_manifest:
            update_manifest(Path(args.manifest), report)


def repair_template(values: Dict[str, str], args: argparse.Namespace) -> Tuple[int, Dict[str, Any]]:
    api_base = preflight.normalize_api_url(values.get("OPENCLAW_PROXMOX_API_URL", ""))
    auth_header = preflight.build_auth_header(values)
    node = values.get("OPENCLAW_PROXMOX_NODE", "pve01")
    bridge = values.get("OPENCLAW_PROXMOX_DEFAULT_BRIDGE", "vmbr0")
    vlan = values.get("OPENCLAW_PROXMOX_DEFAULT_VLAN", "30")
    pool = values.get("OPENCLAW_PROXMOX_POOL", "openclaw-scanner")
    storage = values.get("OPENCLAW_PROXMOX_STORAGE")
    template = values.get("OPENCLAW_PROXMOX_TEMPLATE_VMID", "9000")
    network = allowed_network(values, args.subnet)
    attempt_slug = normalize_version_for_name(args.attempt_id)
    output_dir = Path(args.output_dir or (DEFAULT_LAB_ROOT / "template-repairs"))
    output_dir.mkdir(parents=True, exist_ok=True)
    artifact_path = output_dir / f"proxmox-template-repair-{attempt_slug}.json"
    ssh_user = args.ssh_user or values.get("OPENCLAW_PROXMOX_CIUSER") or "claude"
    report: Dict[str, Any] = {
        "schema_version": 1,
        "artifact": str(artifact_path),
        "attempt_id": args.attempt_id,
        "checked_at": utc_now(),
        "diagnostic_type": "template_qga_repair",
        "deployment_method": "proxmox-template-repair-vm",
        "product_family": "proxmox-template",
        "version": "template-qga-repair",
        "source_template_vmid": template,
        "new_template_name": args.new_template_name,
        "port": None,
        "vlan": int(vlan),
        "allowed_subnet": str(network),
        "vmid": None,
        "vm_name": None,
        "mac": None,
        "mac_digest": None,
        "ip": None,
        "outcome": "template_repair_failed",
        "reason": None,
        "secret_values_recorded": False,
        "scanner_capture_attempted": False,
        "steps": [],
        "lifecycle": {
            "created_at": None,
            "started_at": None,
            "stopped_at": None,
            "deleted_at": None,
            "converted_to_template_at": None,
        },
    }
    created = False
    started = False
    stopped = False
    converted = False
    l2_capture: Dict[str, Any] | None = None

    def record_step(step: Dict[str, Any]) -> None:
        report["steps"].append(step)

    try:
        if not api_base:
            report["outcome"] = "preflight_failed"
            report["reason"] = "missing OPENCLAW_PROXMOX_API_URL"
            return 2, report
        if not auth_header:
            report["outcome"] = "preflight_failed"
            report["reason"] = "missing Proxmox token auth configuration"
            return 2, report

        exit_code, preflight_report = preflight.run_preflight(values, timeout=max(args.timeout, 1.0))
        report["preflight"] = {
            "checked_at": preflight_report.get("checked_at"),
            "vm_lifecycle_allowed": preflight_report.get("vm_lifecycle_allowed"),
            "blockers": preflight_report.get("blockers") or [],
        }
        if exit_code != 0:
            report["outcome"] = "preflight_failed"
            report["reason"] = "preflight_blockers"
            return 1, report

        status, resources = api_request(
            api_base,
            auth_header,
            "GET",
            "/cluster/resources?type=vm",
            timeout=max(args.timeout, 1.0),
        )
        if status != 200:
            report["outcome"] = "preflight_failed"
            report["reason"] = "template_name_inventory_unavailable"
            return 1, report
        for item in resources.get("data") or []:
            if str(item.get("name") or "") == args.new_template_name:
                report["outcome"] = "preflight_failed"
                report["reason"] = "target_template_name_already_exists"
                report["existing_template_vmid"] = item.get("vmid")
                return 1, report

        vmid = next_vmid(api_base, auth_header, timeout=max(args.timeout, 1.0))
        name = args.working_vm_name or f"openclaw-template-repair-{attempt_slug}"
        mac = generated_proxmox_mac()
        report["vmid"] = vmid
        report["vm_name"] = name
        report["mac"] = canonical_mac(mac)
        report["mac_digest"] = mac_digest(mac)
        write_current_report(report)

        clone_data: Dict[str, Any] = {
            "newid": vmid,
            "name": name,
            "full": 1,
            "pool": pool,
        }
        if storage:
            clone_data["storage"] = storage
        step = task_step(
            api_base,
            auth_header,
            node,
            "POST",
            f"/nodes/{node}/qemu/{template}/clone",
            clone_data,
            "clone",
            http_timeout=max(args.timeout, 1.0),
            task_timeout=max(args.task_timeout, 30.0),
        )
        record_step(step)
        if not step.get("ok"):
            report["outcome"] = "create_failed"
            report["reason"] = "clone_failed"
            return 1, report
        created = True
        report["lifecycle"]["created_at"] = utc_now()

        cloud_init_identity, cloud_init_warnings = clone_cloud_init_identity_config(values)
        if cloud_init_warnings:
            report.setdefault("warnings", []).extend(cloud_init_warnings)
        config_steps = [
            (
                "config:resources",
                {
                    "cores": 2,
                    "memory": 4096,
                    "onboot": 0,
                    "agent": "enabled=1",
                },
            ),
            (
                "config:network",
                {
                    "net0": f"virtio={mac},bridge={bridge},tag={vlan},firewall=1",
                },
            ),
        ]
        if cloud_init_identity:
            config_steps.append(("config:cloudinit_identity", cloud_init_identity))
        config_steps.append(("config:cloudinit", {"ipconfig0": "ip=dhcp"}))
        for name_step, data in config_steps:
            status, _payload = api_request(
                api_base,
                auth_header,
                "POST",
                f"/nodes/{node}/qemu/{vmid}/config",
                timeout=max(args.timeout, 1.0),
                data=data,
            )
            step = {"name": name_step, "ok": status == 200, "http_status": status}
            record_step(step)
            if status != 200:
                report["outcome"] = "create_failed"
                report["reason"] = name_step.replace(":", "_") + "_failed"
                return 1, report

        step = task_step(
            api_base,
            auth_header,
            node,
            "PUT",
            f"/nodes/{node}/qemu/{vmid}/resize",
            {"disk": "scsi0", "size": "40G"},
            "resize:scsi0",
            http_timeout=max(args.timeout, 1.0),
            task_timeout=max(args.task_timeout, 30.0),
        )
        record_step(step)
        if not step.get("ok"):
            report["notes"] = "Resize failed; repair continued with cloned disk size."

        config_status, config_payload = api_request(
            api_base,
            auth_header,
            "GET",
            f"/nodes/{node}/qemu/{vmid}/config",
            timeout=max(args.timeout, 1.0),
        )
        facts = vm_network_facts(config_payload.get("data") or {}, bridge, vlan) if config_status == 200 else {}
        report["network_facts"] = {
            "ok": facts.get("ok"),
            "device": facts.get("device"),
            "bridge": facts.get("bridge"),
            "vlan": facts.get("vlan"),
            "mac": facts.get("mac"),
            "mac_digest": facts.get("mac_digest"),
            "reason": facts.get("reason"),
        }
        write_current_report(report)
        if not facts.get("ok"):
            report["outcome"] = "create_failed"
            report["reason"] = facts.get("reason") or "network_facts_failed"
            return 1, report

        l2_capture = start_ssh_l2_capture(
            args.vlan_observer,
            facts["mac"],
            duration_seconds=max(args.l2_capture_seconds, 5),
            interface=args.l2_capture_interface,
        )
        report["l2_capture"] = {key: value for key, value in l2_capture.items() if key != "process"}
        write_current_report(report)

        step = task_step(
            api_base,
            auth_header,
            node,
            "POST",
            f"/nodes/{node}/qemu/{vmid}/status/start",
            None,
            "start",
            http_timeout=max(args.timeout, 1.0),
            task_timeout=max(args.task_timeout, 30.0),
        )
        record_step(step)
        if not step.get("ok"):
            report["outcome"] = "create_failed"
            report["reason"] = "start_failed"
            return 1, report
        started = True
        report["lifecycle"]["started_at"] = utc_now()
        write_current_report(report)

        def get(path: str) -> Tuple[int, Dict[str, Any]]:
            return preflight.api_get(api_base, auth_header, path, timeout=max(args.timeout, 1.0))

        diagnostics = bounded_template_diagnostics(
            api_base,
            auth_header,
            get,
            node=node,
            vmid=str(vmid),
            bridge=bridge,
            vlan=vlan,
            network=network,
            attempts=max(args.discovery_attempts, 1),
            interval_seconds=max(args.discovery_interval, 0.0),
            observation_files=args.observation_file or [],
            vlan_observer=args.vlan_observer,
            agent_call_timeout=max(args.agent_call_timeout, 1.0),
        )
        report["template_diagnostics"] = diagnostics
        report["ip"] = diagnostics.get("guest_agent_network_ipv4") or diagnostics.get("passive_ipv4")
        if l2_capture:
            report["l2_capture"] = finish_ssh_l2_capture(l2_capture, str(report.get("mac") or ""))
            l2_capture = None
            l2_summary = report["l2_capture"].get("summary") or {}
            l2_ip_candidates = l2_summary.get("arp_tell_ipv4_candidates") or []
            if l2_ip_candidates:
                report["ip"] = l2_ip_candidates[0]
                diagnostics["l2_ipv4"] = l2_ip_candidates[0]
        if not report.get("ip"):
            report["outcome"] = "no_ip_discovered"
            report["reason"] = "no_guest_or_passive_vlan30_ip"
            return 1, report

        ssh_target = f"{ssh_user}@{report['ip']}"
        repair = ssh_qga_repair(
            ssh_target,
            connect_timeout=max(int(args.ssh_connect_timeout), 1),
            command_timeout=max(args.ssh_command_timeout, 1.0),
        )
        report["ssh_qga_repair"] = repair
        if not repair.get("ok"):
            report["outcome"] = "template_repair_failed"
            report["reason"] = repair.get("reason") or "ssh_qga_repair_failed"
            return 1, report

        step = task_step(
            api_base,
            auth_header,
            node,
            "POST",
            f"/nodes/{node}/qemu/{vmid}/status/shutdown",
            {"timeout": 60},
            "shutdown_after_qga_install",
            http_timeout=max(args.timeout, 1.0),
            task_timeout=max(args.shutdown_timeout, 30.0),
        )
        record_step(step)
        if not step.get("ok"):
            step = task_step(
                api_base,
                auth_header,
                node,
                "POST",
                f"/nodes/{node}/qemu/{vmid}/status/stop",
                {"timeout": 20},
                "stop_after_qga_install_shutdown_failed",
                http_timeout=max(args.timeout, 1.0),
                task_timeout=max(args.task_timeout, 30.0),
            )
            record_step(step)
        if not step.get("ok"):
            report["outcome"] = "template_repair_failed"
            report["reason"] = "qga_install_restart_shutdown_failed"
            return 1, report
        report["lifecycle"]["stopped_at"] = utc_now()
        started = False
        stopped = True

        step = task_step(
            api_base,
            auth_header,
            node,
            "POST",
            f"/nodes/{node}/qemu/{vmid}/status/start",
            None,
            "start_after_qga_install",
            http_timeout=max(args.timeout, 1.0),
            task_timeout=max(args.task_timeout, 30.0),
        )
        record_step(step)
        if not step.get("ok"):
            report["outcome"] = "template_repair_failed"
            report["reason"] = "qga_install_restart_start_failed"
            return 1, report
        started = True
        stopped = False
        report["lifecycle"]["restarted_at"] = utc_now()

        verification = verify_proxmox_guest_agent(
            api_base,
            auth_header,
            node,
            str(vmid),
            network=network,
            attempts=max(args.qga_verify_attempts, 1),
            interval_seconds=max(args.qga_verify_interval, 0.0),
            timeout=max(args.agent_call_timeout, 1.0),
        )
        report["proxmox_qga_verification"] = verification
        if not verification.get("ok"):
            report["outcome"] = "template_repair_failed"
            report["reason"] = verification.get("reason") or "proxmox_qga_verification_failed"
            return 1, report
        report["ip"] = verification.get("ip") or report.get("ip")

        ssh_target = f"{ssh_user}@{report['ip']}"
        cleanup = ssh_template_cleanup(
            ssh_target,
            connect_timeout=max(int(args.ssh_connect_timeout), 1),
            command_timeout=max(args.ssh_command_timeout, 1.0),
        )
        report["guest_template_cleanup"] = cleanup
        if not cleanup.get("ok"):
            report["outcome"] = "template_repair_failed"
            report["reason"] = "guest_template_cleanup_failed"
            return 1, report

        status, _payload = api_request(
            api_base,
            auth_header,
            "POST",
            f"/nodes/{node}/qemu/{vmid}/config",
            timeout=max(args.timeout, 1.0),
            data={"name": args.new_template_name, "onboot": 0},
        )
        step = {"name": "config:new_template_name", "ok": status == 200, "http_status": status}
        record_step(step)
        if status != 200:
            report["outcome"] = "template_repair_failed"
            report["reason"] = "rename_template_failed"
            return 1, report
        report["vm_name"] = args.new_template_name

        step = task_step(
            api_base,
            auth_header,
            node,
            "POST",
            f"/nodes/{node}/qemu/{vmid}/status/shutdown",
            {"timeout": 60},
            "shutdown",
            http_timeout=max(args.timeout, 1.0),
            task_timeout=max(args.shutdown_timeout, 30.0),
        )
        record_step(step)
        if not step.get("ok"):
            step = task_step(
                api_base,
                auth_header,
                node,
                "POST",
                f"/nodes/{node}/qemu/{vmid}/status/stop",
                {"timeout": 20},
                "stop_after_shutdown_failed",
                http_timeout=max(args.timeout, 1.0),
                task_timeout=max(args.task_timeout, 30.0),
            )
            record_step(step)
        if not step.get("ok"):
            report["outcome"] = "template_repair_failed"
            report["reason"] = "shutdown_failed"
            return 1, report
        started = False
        stopped = True
        report["lifecycle"]["stopped_at"] = utc_now()

        step = task_step(
            api_base,
            auth_header,
            node,
            "POST",
            f"/nodes/{node}/qemu/{vmid}/template",
            None,
            "convert_to_template",
            http_timeout=max(args.timeout, 1.0),
            task_timeout=max(args.task_timeout, 30.0),
        )
        record_step(step)
        if not step.get("ok"):
            report["outcome"] = "template_repair_failed"
            report["reason"] = "convert_to_template_failed"
            return 1, report
        converted = True
        report["lifecycle"]["converted_to_template_at"] = utc_now()
        report["outcome"] = "template_created"
        report["reason"] = "qga_installed_and_template_created"
        return 0, report
    except Exception as exc:  # noqa: BLE001 - preserve cleanup and redacted report.
        report["outcome"] = report.get("outcome") or "template_repair_failed"
        report["reason"] = type(exc).__name__
        report.setdefault("errors", []).append({"type": type(exc).__name__, "step": "template_repair"})
        return 1, report
    finally:
        vmid = report.get("vmid")
        if api_base and auth_header and vmid and not converted:
            if started:
                step = task_step(
                    api_base,
                    auth_header,
                    node,
                    "POST",
                    f"/nodes/{node}/qemu/{vmid}/status/stop",
                    {"timeout": 20},
                    "stop",
                    http_timeout=max(args.timeout, 1.0),
                    task_timeout=max(args.task_timeout, 30.0),
                )
                record_step(step)
                if step.get("ok") and not stopped:
                    report["lifecycle"]["stopped_at"] = utc_now()
            if created:
                step = task_step(
                    api_base,
                    auth_header,
                    node,
                    "DELETE",
                    f"/nodes/{node}/qemu/{vmid}",
                    None,
                    "delete_failed_repair_vm",
                    http_timeout=max(args.timeout, 1.0),
                    task_timeout=max(args.task_timeout, 30.0),
                )
                record_step(step)
                if step.get("ok"):
                    report["lifecycle"]["deleted_at"] = utc_now()
        if l2_capture:
            report["l2_capture"] = finish_ssh_l2_capture(l2_capture, str(report.get("mac") or ""))
        artifact_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        if args.update_manifest:
            update_manifest(Path(args.manifest), report)


def run_once(values: Dict[str, str], args: argparse.Namespace) -> Tuple[int, Dict[str, Any]]:
    api_base = preflight.normalize_api_url(values.get("OPENCLAW_PROXMOX_API_URL", ""))
    auth_header = preflight.build_auth_header(values)
    node = values.get("OPENCLAW_PROXMOX_NODE", "pve01")
    bridge = values.get("OPENCLAW_PROXMOX_DEFAULT_BRIDGE", "vmbr0")
    vlan = values.get("OPENCLAW_PROXMOX_DEFAULT_VLAN", "30")
    pool = values.get("OPENCLAW_PROXMOX_POOL", "openclaw-scanner")
    storage = values.get("OPENCLAW_PROXMOX_STORAGE")
    template = values.get("OPENCLAW_PROXMOX_TEMPLATE_VMID", "9000")
    network = allowed_network(values, args.subnet)
    version_slug = normalize_version_for_name(args.version)
    output_dir = Path(args.output_dir or (DEFAULT_LAB_ROOT / f"openclaw-{args.version}"))
    output_dir.mkdir(parents=True, exist_ok=True)
    artifact_path = output_dir / f"proxmox-attempt-{args.attempt_id}.json"
    ip_discovery_path = output_dir / "ip-discovery.json"
    report: Dict[str, Any] = {
        "schema_version": 1,
        "artifact": str(artifact_path),
        "attempt_id": args.attempt_id,
        "checked_at": utc_now(),
        "version": args.version,
        "vlan": int(vlan),
        "port": 18789,
        "allowed_subnet": str(network),
        "vmid": None,
        "vm_name": None,
        "mac": None,
        "mac_digest": None,
        "ip": None,
        "outcome": "no_ip_discovered",
        "reason": None,
        "secret_values_recorded": False,
        "deployment_method": "proxmox-vm-ssh-deploy",
        "deployment_result": None,
        "scanner_capture_attempted": False,
        "steps": [],
        "lifecycle": {
            "created_at": None,
            "started_at": None,
            "stopped_at": None,
            "deleted_at": None,
        },
    }
    created = False
    started = False

    def record_step(step: Dict[str, Any]) -> None:
        report["steps"].append(step)

    try:
        deploy_command = args.deploy_command
        deploy_command_source = "argument" if deploy_command else None
        if args.deploy_command_file:
            deploy_command, deploy_command_error = read_deploy_command_file(args.deploy_command_file)
            deploy_command_source = "file"
            if deploy_command_error:
                report["outcome"] = "deployment_failed"
                report["reason"] = deploy_command_error
                report["deployment_result"] = {
                    "ok": False,
                    "reason": deploy_command_error,
                    "command_source": "file",
                    "command_recorded": False,
                    "stdout_recorded": False,
                    "stderr_recorded": False,
                }
                return 1, report
        if not deploy_command and not args.skip_deploy:
            report["outcome"] = "deployment_failed"
            report["reason"] = "deployment_not_configured"
            report["deployment_result"] = {
                "ok": False,
                "reason": "deployment_not_configured",
                "command_recorded": False,
                "stdout_recorded": False,
                "stderr_recorded": False,
            }
            return 1, report
        if not api_base:
            report["outcome"] = "preflight_failed"
            report["reason"] = "missing OPENCLAW_PROXMOX_API_URL"
            return 2, report
        if not auth_header:
            report["outcome"] = "preflight_failed"
            report["reason"] = "missing Proxmox token auth configuration"
            return 2, report

        exit_code, preflight_report = preflight.run_preflight(values, timeout=max(args.timeout, 1.0))
        report["preflight"] = {
            "checked_at": preflight_report.get("checked_at"),
            "vm_lifecycle_allowed": preflight_report.get("vm_lifecycle_allowed"),
            "blockers": preflight_report.get("blockers") or [],
        }
        if exit_code != 0:
            report["outcome"] = "preflight_failed"
            report["reason"] = "preflight_blockers"
            return 1, report

        vmid = next_vmid(api_base, auth_header, timeout=max(args.timeout, 1.0))
        name = f"openclaw-corpus-{version_slug}-{args.attempt_id}"
        mac = generated_proxmox_mac()
        report["vmid"] = vmid
        report["vm_name"] = name
        report["mac"] = canonical_mac(mac)
        report["mac_digest"] = mac_digest(mac)
        write_current_report(report)

        clone_data: Dict[str, Any] = {
            "newid": vmid,
            "name": name,
            "full": 1,
            "pool": pool,
        }
        if storage:
            clone_data["storage"] = storage
        step = task_step(
            api_base,
            auth_header,
            node,
            "POST",
            f"/nodes/{node}/qemu/{template}/clone",
            clone_data,
            "clone",
            http_timeout=max(args.timeout, 1.0),
            task_timeout=max(args.task_timeout, 30.0),
        )
        record_step(step)
        if not step.get("ok"):
            report["outcome"] = "create_failed"
            report["reason"] = "clone_failed"
            return 1, report
        created = True
        report["lifecycle"]["created_at"] = utc_now()

        cloud_init_identity, cloud_init_warnings = clone_cloud_init_identity_config(values)
        if cloud_init_warnings:
            report.setdefault("warnings", []).extend(cloud_init_warnings)
        config_steps = [
            (
                "config:resources",
                {
                    "cores": 2,
                    "memory": 4096,
                    "onboot": 0,
                    "agent": "enabled=1",
                },
            ),
            (
                "config:network",
                {
                    "net0": f"virtio={mac},bridge={bridge},tag={vlan},firewall=1",
                },
            ),
        ]
        if cloud_init_identity:
            config_steps.append(("config:cloudinit_identity", cloud_init_identity))
        config_steps.append(
            (
                "config:cloudinit",
                {
                    "ipconfig0": "ip=dhcp",
                },
            )
        )
        for name_step, data in config_steps:
            status, _payload = api_request(
                api_base,
                auth_header,
                "POST",
                f"/nodes/{node}/qemu/{vmid}/config",
                timeout=max(args.timeout, 1.0),
                data=data,
            )
            step = {"name": name_step, "ok": status == 200, "http_status": status}
            record_step(step)
            if status != 200:
                report["outcome"] = "create_failed"
                report["reason"] = name_step.replace(":", "_") + "_failed"
                return 1, report

        step = task_step(
            api_base,
            auth_header,
            node,
            "PUT",
            f"/nodes/{node}/qemu/{vmid}/resize",
            {"disk": "scsi0", "size": "40G"},
            "resize:scsi0",
            http_timeout=max(args.timeout, 1.0),
            task_timeout=max(args.task_timeout, 30.0),
        )
        record_step(step)
        if not step.get("ok"):
            report["notes"] = "Resize failed; lifecycle continued with cloned disk size."

        config_status, config_payload = api_request(
            api_base,
            auth_header,
            "GET",
            f"/nodes/{node}/qemu/{vmid}/config",
            timeout=max(args.timeout, 1.0),
        )
        facts = vm_network_facts(config_payload.get("data") or {}, bridge, vlan) if config_status == 200 else {}
        report["network_facts"] = {
            "ok": facts.get("ok"),
            "device": facts.get("device"),
            "bridge": facts.get("bridge"),
            "vlan": facts.get("vlan"),
            "mac": facts.get("mac"),
            "mac_digest": facts.get("mac_digest"),
            "reason": facts.get("reason"),
        }
        write_current_report(report)
        if not facts.get("ok"):
            report["outcome"] = "create_failed"
            report["reason"] = facts.get("reason") or "network_facts_failed"
            return 1, report

        step = task_step(
            api_base,
            auth_header,
            node,
            "POST",
            f"/nodes/{node}/qemu/{vmid}/status/start",
            None,
            "start",
            http_timeout=max(args.timeout, 1.0),
            task_timeout=max(args.task_timeout, 30.0),
        )
        record_step(step)
        if not step.get("ok"):
            report["outcome"] = "create_failed"
            report["reason"] = "start_failed"
            return 1, report
        started = True
        report["lifecycle"]["started_at"] = utc_now()
        write_current_report(report)

        def get(path: str) -> Tuple[int, Dict[str, Any]]:
            return preflight.api_get(api_base, auth_header, path, timeout=max(args.agent_call_timeout, 1.0))

        def get_cloud_init_status() -> Dict[str, Any]:
            return guest_agent_cloud_init_status(
                api_base,
                auth_header,
                node,
                str(vmid),
                timeout=max(args.agent_call_timeout, 1.0),
            )

        discovery = bounded_mac_driven_discovery(
            get,
            node=node,
            vmid=str(vmid),
            bridge=bridge,
            vlan=vlan,
            network=network,
            attempts=max(args.discovery_attempts, 1),
            interval_seconds=max(args.discovery_interval, 0.0),
            observation_files=args.observation_file or [],
            vlan_observer=args.vlan_observer,
            cloud_init_status=get_cloud_init_status,
        )
        report["ip_discovery"] = discovery
        ip_discovery_path.write_text(json.dumps(discovery, indent=2, sort_keys=True) + "\n")
        if not discovery.get("ok"):
            report["outcome"] = "no_ip_discovered"
            report["reason"] = discovery.get("reason") or "no_ip_discovered"
            return 1, report

        report["ip"] = discovery.get("ip")
        ssh_user = args.deploy_ssh_user or values.get("OPENCLAW_PROXMOX_CIUSER") or "claude"
        deployment = run_known_version_deploy(
            str(report["ip"]),
            args.version,
            port=18789,
            ssh_user=ssh_user,
            command_template=deploy_command,
            command_label=args.deploy_command_label,
            connect_timeout=max(args.deploy_ssh_connect_timeout, 1),
            timeout=max(args.deploy_timeout, 1.0),
            skip_deploy=args.skip_deploy,
            command_source=deploy_command_source or "argument",
            ssh_ready_attempts=max(args.deploy_ssh_ready_attempts, 0),
            ssh_ready_interval=max(args.deploy_ssh_ready_interval, 0.0),
        )
        report["deployment_result"] = deployment
        if not deployment.get("ok"):
            report["outcome"] = "deployment_failed"
            report["reason"] = deployment.get("reason") or "deployment_failed"
            return 1, report
        if deployment.get("skipped"):
            report["deployment_method"] = "proxmox-vm-assume-predeployed"

        gateway_health = wait_for_gateway_health(
            f"http://{report['ip']}:18789/health",
            timeout=max(args.gateway_timeout, 1.0),
            attempts=max(args.gateway_attempts, 1),
            interval_seconds=max(args.gateway_interval, 0.0),
        )
        report["gateway_health"] = gateway_health
        if not gateway_health.get("ok"):
            report["outcome"] = "gateway_unreachable"
            report["reason"] = gateway_health.get("reason") or "gateway_health_unreachable"
            return 1, report

        capture_name = f"openclaw-{args.version}-lab"
        report["scanner_capture_attempted"] = True
        scanner_result = run_scanner_capture(
            report["ip"],
            args.version,
            capture_name,
            output_dir,
            timeout=max(args.scanner_timeout, 5.0),
        )
        report["scanner_result"] = scanner_result
        if scanner_result.get("ok") and capture_has_signals(scanner_result.get("capture_artifact")):
            report["outcome"] = "captured"
            return 0, report
        report["outcome"] = "capture_failed"
        report["reason"] = scanner_result.get("reason") or "scanner_capture_failed"
        return 1, report
    except Exception as exc:  # noqa: BLE001 - preserve cleanup and redacted report.
        report["outcome"] = report.get("outcome") or "failed"
        report["reason"] = type(exc).__name__
        report.setdefault("errors", []).append({"type": type(exc).__name__, "step": "lifecycle"})
        return 1, report
    finally:
        vmid = report.get("vmid")
        if api_base and auth_header and vmid:
            if started:
                step = task_step(
                    api_base,
                    auth_header,
                    node,
                    "POST",
                    f"/nodes/{node}/qemu/{vmid}/status/stop",
                    {"timeout": 20},
                    "stop",
                    http_timeout=max(args.timeout, 1.0),
                    task_timeout=max(args.task_timeout, 30.0),
                )
                record_step(step)
                if step.get("ok"):
                    report["lifecycle"]["stopped_at"] = utc_now()
            if created:
                step = task_step(
                    api_base,
                    auth_header,
                    node,
                    "DELETE",
                    f"/nodes/{node}/qemu/{vmid}",
                    None,
                    "delete",
                    http_timeout=max(args.timeout, 1.0),
                    task_timeout=max(args.task_timeout, 30.0),
                )
                record_step(step)
                if step.get("ok"):
                    report["lifecycle"]["deleted_at"] = utc_now()
        artifact_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        if args.update_manifest:
            update_manifest(Path(args.manifest), report)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run bounded OpenClaw corpus VM lifecycle helpers without printing secrets."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    discover = subparsers.add_parser(
        "discover-ip",
        help="Discover a corpus VM IPv4 through guest-agent, then passive VLAN ARP/DHCP observations.",
    )
    discover.add_argument("--vmid", required=True, help="Corpus VMID.")
    discover.add_argument(
        "--env-file",
        default=str(DEFAULT_ENV_PATH),
        help="Path to the ignored Proxmox .env file.",
    )
    discover.add_argument("--timeout", type=float, default=12.0, help="HTTP timeout in seconds.")
    discover.add_argument(
        "--guest-agent-attempts",
        type=int,
        default=12,
        help="Maximum guest-agent polling attempts before fallback.",
    )
    discover.add_argument(
        "--guest-agent-interval",
        type=float,
        default=5.0,
        help="Seconds to wait between guest-agent attempts.",
    )
    discover.add_argument(
        "--subnet",
        help="Allowed IPv4 subnet. Defaults to OPENCLAW_PROXMOX_DEFAULT_SUBNET or VLAN 30 safe default.",
    )
    discover.add_argument(
        "--observation-file",
        action="append",
        help="Passive ARP/DHCP observation file to inspect for the VM MAC.",
    )
    discover.add_argument(
        "--no-local-neighbor-cache",
        action="store_true",
        help="Do not read local arp/ip-neigh cache as passive fallback input.",
    )
    discover.add_argument("--output", help="Write JSON report to a file instead of stdout.")
    diagnostic = subparsers.add_parser(
        "diagnose-template",
        help="Boot one short-lived VLAN 30 VM to validate template NIC, DHCP, and guest-agent readiness, then destroy it.",
    )
    diagnostic.add_argument("--attempt-id", default="template-01", help="Diagnostic attempt identifier.")
    diagnostic.add_argument(
        "--env-file",
        default=str(DEFAULT_ENV_PATH),
        help="Path to the ignored Proxmox .env file.",
    )
    diagnostic.add_argument("--timeout", type=float, default=12.0, help="HTTP timeout in seconds.")
    diagnostic.add_argument("--task-timeout", type=float, default=180.0, help="Proxmox task timeout in seconds.")
    diagnostic.add_argument(
        "--agent-call-timeout",
        type=float,
        default=5.0,
        help="Per-call guest-agent HTTP timeout in seconds.",
    )
    diagnostic.add_argument(
        "--diagnostic-attempts",
        type=int,
        default=36,
        help="Bounded diagnostic polling attempts before failing closed.",
    )
    diagnostic.add_argument(
        "--diagnostic-interval",
        type=float,
        default=10.0,
        help="Seconds between diagnostic polling attempts.",
    )
    diagnostic.add_argument("--subnet", help="Allowed IPv4 subnet. Defaults to VLAN 30 safe default.")
    diagnostic.add_argument(
        "--vlan-observer",
        default="claude@10.0.30.10",
        help="VLAN 30 host used for passive neighbor evidence.",
    )
    diagnostic.add_argument(
        "--l2-capture-seconds",
        type=int,
        default=360,
        help="Seconds to run bounded DHCP/ARP capture on the VLAN observer for the VM MAC.",
    )
    diagnostic.add_argument(
        "--l2-capture-interface",
        default="eth0",
        help="Interface on the VLAN observer used for DHCP/ARP packet capture.",
    )
    diagnostic.add_argument(
        "--observation-file",
        action="append",
        help="Passive ARP/DHCP observation file to inspect for the VM MAC.",
    )
    diagnostic.add_argument(
        "--no-ssh-diagnostics",
        dest="ssh_diagnostics",
        action="store_false",
        help="Do not SSH into a positively identified diagnostic clone IP for template health checks.",
    )
    diagnostic.set_defaults(ssh_diagnostics=True)
    diagnostic.add_argument(
        "--ssh-user",
        default="claude",
        help="SSH user for diagnostic clone health checks after MAC-driven IP discovery.",
    )
    diagnostic.add_argument(
        "--ssh-diagnostic-attempts",
        type=int,
        default=12,
        help="SSH readiness attempts for template health checks.",
    )
    diagnostic.add_argument(
        "--ssh-diagnostic-interval",
        type=float,
        default=5.0,
        help="Seconds between SSH readiness attempts.",
    )
    diagnostic.add_argument(
        "--ssh-connect-timeout",
        type=int,
        default=4,
        help="SSH connection timeout for template health checks.",
    )
    diagnostic.add_argument(
        "--ssh-command-timeout",
        type=float,
        default=8.0,
        help="Per-command SSH timeout for template health checks.",
    )
    diagnostic.add_argument(
        "--output-dir",
        help="Artifact directory. Defaults to artifacts/lab/2026-05-18/template-diagnostics/.",
    )
    diagnostic.add_argument(
        "--manifest",
        default=str(DEFAULT_LAB_ROOT / "manifest.json"),
        help="Manifest to update.",
    )
    diagnostic.add_argument("--update-manifest", action="store_true", help="Append diagnostic outcome to manifest.")
    diagnostic.add_argument("--output", help="Write final JSON report to a file instead of stdout.")
    repair = subparsers.add_parser(
        "repair-template",
        help="Clone the source template, install QGA through SSH, clean the guest, and convert the clone into a new template.",
    )
    repair.add_argument("--attempt-id", default="qga-01", help="Template repair attempt identifier.")
    repair.add_argument(
        "--new-template-name",
        default="ubuntu-2404-cloudinit-qga",
        help="Name for the repaired template clone.",
    )
    repair.add_argument(
        "--working-vm-name",
        help="Temporary VM name before conversion. Defaults to openclaw-template-repair-<attempt>.",
    )
    repair.add_argument(
        "--env-file",
        default=str(DEFAULT_ENV_PATH),
        help="Path to the ignored Proxmox .env file.",
    )
    repair.add_argument("--timeout", type=float, default=12.0, help="HTTP timeout in seconds.")
    repair.add_argument("--task-timeout", type=float, default=180.0, help="Proxmox task timeout in seconds.")
    repair.add_argument("--shutdown-timeout", type=float, default=120.0, help="Shutdown task timeout in seconds.")
    repair.add_argument(
        "--agent-call-timeout",
        type=float,
        default=5.0,
        help="Per-call guest-agent HTTP timeout in seconds.",
    )
    repair.add_argument(
        "--discovery-attempts",
        type=int,
        default=24,
        help="Bounded IP discovery attempts before failing closed.",
    )
    repair.add_argument(
        "--discovery-interval",
        type=float,
        default=10.0,
        help="Seconds between bounded discovery attempts.",
    )
    repair.add_argument("--subnet", help="Allowed IPv4 subnet. Defaults to VLAN 30 safe default.")
    repair.add_argument(
        "--vlan-observer",
        default="claude@10.0.30.10",
        help="VLAN 30 host used for passive neighbor evidence.",
    )
    repair.add_argument(
        "--l2-capture-seconds",
        type=int,
        default=300,
        help="Seconds to run bounded DHCP/ARP capture on the VLAN observer for the VM MAC.",
    )
    repair.add_argument(
        "--l2-capture-interface",
        default="eth0",
        help="Interface on the VLAN observer used for DHCP/ARP packet capture.",
    )
    repair.add_argument(
        "--observation-file",
        action="append",
        help="Passive ARP/DHCP observation file to inspect for the VM MAC.",
    )
    repair.add_argument(
        "--ssh-user",
        help="SSH user for the repair VM. Defaults to OPENCLAW_PROXMOX_CIUSER or claude.",
    )
    repair.add_argument("--ssh-connect-timeout", type=int, default=4, help="SSH connection timeout.")
    repair.add_argument("--ssh-command-timeout", type=float, default=240.0, help="Per-command SSH timeout.")
    repair.add_argument("--qga-verify-attempts", type=int, default=18, help="Proxmox QGA verification attempts.")
    repair.add_argument("--qga-verify-interval", type=float, default=5.0, help="Seconds between QGA verification attempts.")
    repair.add_argument(
        "--output-dir",
        help="Artifact directory. Defaults to artifacts/lab/2026-05-18/template-repairs/.",
    )
    repair.add_argument(
        "--manifest",
        default=str(DEFAULT_LAB_ROOT / "manifest.json"),
        help="Manifest to update.",
    )
    repair.add_argument("--update-manifest", action="store_true", help="Append repair outcome to manifest.")
    repair.add_argument("--output", help="Write final JSON report to a file instead of stdout.")
    validate = subparsers.add_parser(
        "validate-deploy-command",
        help="Validate deploy command/file safety and placeholders without Proxmox access or VM creation.",
    )
    validate.add_argument("--version", required=True, help="Known OpenClaw version label used for placeholder validation.")
    validate_group = validate.add_mutually_exclusive_group(required=True)
    validate_group.add_argument(
        "--deploy-command",
        help="SSH deploy/start command template. The command text is not printed.",
    )
    validate_group.add_argument(
        "--deploy-command-file",
        help="Path to a local deploy/start command file. In-repo files must be ignored and untracked.",
    )
    validate.add_argument(
        "--deploy-command-label",
        default="custom-deploy-command",
        help="Non-secret label recorded for the deploy command.",
    )
    validate.add_argument(
        "--ip",
        default="10.0.30.55",
        help="Placeholder validation IP. Defaults to a VLAN 30 documentation address.",
    )
    validate.add_argument("--port", type=int, default=18789, help="Placeholder validation port.")
    validate.add_argument("--output", help="Write final JSON report to a file instead of stdout.")
    run = subparsers.add_parser(
        "run-once",
        help="Create exactly one VLAN 30 corpus VM, discover IP by MAC, capture if reachable, then destroy it.",
    )
    run.add_argument("--version", required=True, help="Known OpenClaw version label.")
    run.add_argument("--attempt-id", default="04", help="Manifest/lifecycle attempt identifier.")
    run.add_argument(
        "--env-file",
        default=str(DEFAULT_ENV_PATH),
        help="Path to the ignored Proxmox .env file.",
    )
    run.add_argument("--timeout", type=float, default=12.0, help="HTTP timeout in seconds.")
    run.add_argument("--task-timeout", type=float, default=180.0, help="Proxmox task timeout in seconds.")
    run.add_argument(
        "--agent-call-timeout",
        type=float,
        default=5.0,
        help="Per-call guest-agent HTTP timeout in seconds.",
    )
    run.add_argument("--discovery-attempts", type=int, default=18, help="Bounded IP discovery attempts.")
    run.add_argument(
        "--discovery-interval",
        type=float,
        default=5.0,
        help="Seconds between bounded discovery attempts.",
    )
    deploy_group = run.add_mutually_exclusive_group()
    deploy_group.add_argument(
        "--deploy-command",
        help=(
            "SSH command to deploy/start the known OpenClaw version after MAC-driven IP "
            "discovery. Supports {version}, {ip}, and {port} placeholders."
        ),
    )
    deploy_group.add_argument(
        "--deploy-command-file",
        help=(
            "Path to a local ignored file containing the SSH deploy/start command. "
            "The command content is not recorded in artifacts."
        ),
    )
    run.add_argument(
        "--deploy-command-label",
        default="custom-deploy-command",
        help="Non-secret label recorded for the deploy command; the command itself is not recorded.",
    )
    run.add_argument(
        "--deploy-timeout",
        type=float,
        default=600.0,
        help="Deployment SSH command timeout in seconds.",
    )
    run.add_argument(
        "--deploy-ssh-user",
        help="SSH user for deployment. Defaults to OPENCLAW_PROXMOX_CIUSER or claude.",
    )
    run.add_argument(
        "--deploy-ssh-connect-timeout",
        type=int,
        default=6,
        help="SSH connection timeout for deployment.",
    )
    run.add_argument(
        "--deploy-ssh-ready-attempts",
        type=int,
        default=12,
        help="Bounded SSH readiness probes before running the deployment command.",
    )
    run.add_argument(
        "--deploy-ssh-ready-interval",
        type=float,
        default=5.0,
        help="Seconds between bounded SSH readiness probes before deployment.",
    )
    run.add_argument(
        "--skip-deploy",
        action="store_true",
        help="Assume the VM image already contains the target service; use only for pre-deployed images.",
    )
    run.add_argument("--gateway-timeout", type=float, default=5.0, help="Gateway health timeout.")
    run.add_argument("--gateway-attempts", type=int, default=12, help="Gateway health polling attempts.")
    run.add_argument(
        "--gateway-interval",
        type=float,
        default=5.0,
        help="Seconds between gateway health attempts.",
    )
    run.add_argument("--scanner-timeout", type=float, default=60.0, help="Scanner capture timeout.")
    run.add_argument("--subnet", help="Allowed IPv4 subnet. Defaults to VLAN 30 safe default.")
    run.add_argument(
        "--vlan-observer",
        default="claude@10.0.30.10",
        help="VLAN 30 host used for passive neighbor evidence.",
    )
    run.add_argument(
        "--observation-file",
        action="append",
        help="Passive ARP/DHCP observation file to inspect for the VM MAC.",
    )
    run.add_argument(
        "--output-dir",
        help="Artifact directory. Defaults to artifacts/lab/2026-05-18/openclaw-<version>/.",
    )
    run.add_argument(
        "--manifest",
        default=str(DEFAULT_LAB_ROOT / "manifest.json"),
        help="Manifest to update.",
    )
    run.add_argument("--update-manifest", action="store_true", help="Append lifecycle outcome to manifest.")
    run.add_argument("--output", help="Write final JSON report to a file instead of stdout.")
    return parser


def write_json(report: Dict[str, Any], output: str | None) -> None:
    text = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if not output:
        sys.stdout.write(text)
        return
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def main(argv: List[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "validate-deploy-command":
        exit_code, report = validate_deploy_command_input(
            version=args.version,
            command_template=args.deploy_command,
            command_file=args.deploy_command_file,
            command_label=args.deploy_command_label,
            ip=args.ip,
            port=args.port,
        )
        write_json(report, args.output)
        return exit_code

    values = preflight.load_env(Path(args.env_file))
    if args.command == "discover-ip":
        exit_code, report = discover_ip(values, args)
        write_json(report, args.output)
        return exit_code
    if args.command == "diagnose-template":
        exit_code, report = diagnose_template(values, args)
        write_json(report, args.output)
        return exit_code
    if args.command == "repair-template":
        exit_code, report = repair_template(values, args)
        write_json(report, args.output)
        return exit_code
    if args.command == "run-once":
        exit_code, report = run_once(values, args)
        write_json(report, args.output)
        return exit_code
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
