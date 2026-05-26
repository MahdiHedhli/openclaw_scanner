import importlib.util
import ipaddress
import json
import subprocess
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest.mock import patch


MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "proxmox_corpus_lifecycle.py"
SPEC = importlib.util.spec_from_file_location("proxmox_corpus_lifecycle", MODULE_PATH)
lifecycle = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lifecycle)


class ProxmoxCorpusLifecycleTests(unittest.TestCase):
    def test_extract_guest_agent_ipv4_filters_to_allowed_subnet(self):
        payload = {
            "data": {
                "result": [
                    {
                        "name": "lo",
                        "ip-addresses": [
                            {"ip-address": "127.0.0.1", "ip-address-type": "ipv4"},
                        ],
                    },
                    {
                        "name": "eth0",
                        "ip-addresses": [
                            {"ip-address": "10.0.21.99", "ip-address-type": "ipv4"},
                            {"ip-address": "10.0.30.45", "ip-address-type": "ipv4"},
                        ],
                    },
                ]
            }
        }

        self.assertEqual(
            lifecycle.extract_guest_agent_ipv4(
                payload,
                ipaddress.ip_network("10.0.30.0/24"),
            ),
            "10.0.30.45",
        )

    def test_bounded_guest_agent_stops_after_configured_attempts(self):
        calls = []

        def fake_get(path):
            calls.append(path)
            return 200, {"data": {"result": []}}

        sleeps = []
        result = lifecycle.bounded_guest_agent_ipv4(
            fake_get,
            node="pve01",
            vmid="103",
            network=ipaddress.ip_network("10.0.30.0/24"),
            attempts=3,
            interval_seconds=0.25,
            sleep=sleeps.append,
        )

        self.assertFalse(result["ok"])
        self.assertEqual(result["reason"], "guest_agent_no_ipv4")
        self.assertEqual(result["attempts"], 3)
        self.assertEqual(len(calls), 3)
        self.assertEqual(sleeps, [0.25, 0.25])

    def test_vm_network_facts_requires_expected_bridge_and_vlan(self):
        config = {
            "net0": "virtio=BC:24:11:AA:BB:CC,bridge=vmbr0,tag=30,firewall=1",
        }

        facts = lifecycle.vm_network_facts(config, expected_bridge="vmbr0", expected_vlan="30")

        self.assertTrue(facts["ok"])
        self.assertEqual(facts["mac"], "bc:24:11:aa:bb:cc")
        self.assertEqual(facts["bridge"], "vmbr0")
        self.assertEqual(facts["vlan"], "30")
        self.assertIn("mac_digest", facts)

    def test_vm_network_facts_fails_closed_on_wrong_vlan(self):
        config = {
            "net0": "virtio=BC:24:11:AA:BB:CC,bridge=vmbr0,tag=21,firewall=1",
        }

        facts = lifecycle.vm_network_facts(config, expected_bridge="vmbr0", expected_vlan="30")

        self.assertFalse(facts["ok"])
        self.assertEqual(facts["reason"], "unexpected_vlan")

    def test_clone_cloud_init_identity_config_reads_public_key_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir, "id_ed25519.pub")
            key_path.write_text("ssh-ed25519 AAAATEST openclaw-test\n")

            config, warnings = lifecycle.clone_cloud_init_identity_config(
                {
                    "OPENCLAW_PROXMOX_CIUSER": "claude",
                    "OPENCLAW_PROXMOX_SSHKEYS_FILE": str(key_path),
                }
            )

        self.assertEqual(warnings, [])
        self.assertEqual(config["ciuser"], "claude")
        self.assertEqual(config["sshkeys"], "ssh-ed25519%20AAAATEST%20openclaw-test")

    def test_clone_cloud_init_identity_config_preserves_preencoded_public_key(self):
        config, warnings = lifecycle.clone_cloud_init_identity_config(
            {
                "OPENCLAW_PROXMOX_CIUSER": "claude",
                "OPENCLAW_PROXMOX_SSH_PUBLIC_KEY": "ssh-ed25519%20AAAATEST%20openclaw-test",
            }
        )

        self.assertEqual(warnings, [])
        self.assertEqual(config["ciuser"], "claude")
        self.assertEqual(config["sshkeys"], "ssh-ed25519%20AAAATEST%20openclaw-test")

    def test_clone_cloud_init_identity_config_warns_on_missing_public_key_file(self):
        config, warnings = lifecycle.clone_cloud_init_identity_config(
            {
                "OPENCLAW_PROXMOX_CIUSER": "claude",
                "OPENCLAW_PROXMOX_SSHKEYS_FILE": "/missing/public/key.pub",
            }
        )

        self.assertEqual(config, {"ciuser": "claude"})
        self.assertEqual(warnings, ["configured SSH public key file was not readable"])

    def test_candidate_ips_from_text_requires_mac_and_subnet(self):
        text = "\n".join(
            [
                "? (10.0.30.45) at bc:24:11:aa:bb:cc on en0 ifscope [ethernet]",
                "? (10.0.21.45) at bc:24:11:aa:bb:cc on en0 ifscope [ethernet]",
                "? (10.0.30.46) at bc:24:11:dd:ee:ff on en0 ifscope [ethernet]",
            ]
        )

        self.assertEqual(
            lifecycle.candidate_ips_from_text(
                text,
                "bc:24:11:aa:bb:cc",
                ipaddress.ip_network("10.0.30.0/24"),
            ),
            ["10.0.30.45"],
        )

    def test_passive_arp_dhcp_accepts_exact_vm_mac_on_expected_vlan(self):
        def fake_get(path):
            self.assertEqual(path, "/nodes/pve01/qemu/103/config")
            return 200, {
                "data": {
                    "net0": "virtio=BC:24:11:AA:BB:CC,bridge=vmbr0,tag=30,firewall=1",
                }
            }

        with patch.object(
            lifecycle,
            "local_neighbor_observations",
            return_value=[
                (
                    "arp -an",
                    "? (10.0.30.45) at bc:24:11:aa:bb:cc on en0 ifscope [ethernet]",
                )
            ],
        ):
            result = lifecycle.passive_arp_dhcp_ipv4(
                fake_get,
                node="pve01",
                vmid="103",
                bridge="vmbr0",
                vlan="30",
                network=ipaddress.ip_network("10.0.30.0/24"),
                observation_files=[],
                use_local_neighbor_cache=True,
            )

        self.assertTrue(result["ok"])
        self.assertEqual(result["ip"], "10.0.30.45")
        self.assertEqual(result["method"], "passive-arp-dhcp")

    def test_passive_arp_dhcp_fails_closed_without_candidate(self):
        def fake_get(path):
            return 200, {
                "data": {
                    "net0": "virtio=BC:24:11:AA:BB:CC,bridge=vmbr0,tag=30,firewall=1",
                }
            }

        with patch.object(lifecycle, "local_neighbor_observations", return_value=[]):
            result = lifecycle.passive_arp_dhcp_ipv4(
                fake_get,
                node="pve01",
                vmid="103",
                bridge="vmbr0",
                vlan="30",
                network=ipaddress.ip_network("10.0.30.0/24"),
                observation_files=[],
                use_local_neighbor_cache=True,
            )

        self.assertFalse(result["ok"])
        self.assertEqual(result["reason"], "no_passive_vlan_candidate")

    def test_local_neighbor_observations_does_not_raise_on_missing_commands(self):
        def missing_runner(*args, **kwargs):
            raise FileNotFoundError("missing")

        self.assertEqual(lifecycle.local_neighbor_observations(missing_runner), [])

    def test_local_neighbor_observations_collects_stdout_only(self):
        def runner(command, **kwargs):
            return subprocess.CompletedProcess(command, 0, stdout="neighbor output", stderr="ignored")

        self.assertEqual(
            lifecycle.local_neighbor_observations(runner),
            [("arp -an", "neighbor output"), ("ip neigh show", "neighbor output")],
        )

    def test_summarize_l2_capture_output_flags_dhcp_for_vm_mac(self):
        text = "\n".join(
            [
                "00:00:00 bc:24:11:aa:bb:cc > ff:ff:ff:ff:ff:ff, ethertype IPv4, BOOTP/DHCP, Request from bc:24:11:aa:bb:cc",
                "00:00:01 bc:24:11:dd:ee:ff > ff:ff:ff:ff:ff:ff, ethertype ARP, Request who-has 10.0.30.254",
            ]
        )

        summary = lifecycle.summarize_l2_capture_output(text, "bc:24:11:aa:bb:cc")

        self.assertEqual(summary["line_count"], 2)
        self.assertEqual(summary["mac_line_count"], 1)
        self.assertTrue(summary["dhcp_seen"])
        self.assertFalse(summary["arp_seen"])

    def test_summarize_l2_capture_output_extracts_arp_tell_ip_for_vm_mac(self):
        text = "bc:24:11:aa:bb:cc > ff:ff:ff:ff:ff:ff, ethertype ARP, Request who-has 10.0.30.254 tell 10.0.30.198"

        summary = lifecycle.summarize_l2_capture_output(text, "bc:24:11:aa:bb:cc")

        self.assertTrue(summary["arp_seen"])
        self.assertEqual(summary["arp_tell_ipv4_candidates"], ["10.0.30.198"])

    def test_summarize_ssh_qga_diagnostics_detects_not_installed(self):
        summary = lifecycle.summarize_ssh_qga_diagnostics(
            {
                "qemu_guest_agent_package": {"stdout_excerpt": ""},
                "qemu_guest_agent_binary": {"stdout_excerpt": ""},
                "qemu_guest_agent_enabled": {"stdout_excerpt": "disabled\n"},
                "qemu_guest_agent_active": {"stdout_excerpt": "inactive\n"},
                "qemu_guest_agent_socket": {"stdout_excerpt": "missing\n"},
            }
        )

        self.assertFalse(summary["installed"])
        self.assertEqual(summary["reason"], "qemu_guest_agent_not_installed")

    def test_summarize_ssh_qga_diagnostics_detects_guest_side_healthy(self):
        summary = lifecycle.summarize_ssh_qga_diagnostics(
            {
                "qemu_guest_agent_package": {"stdout_excerpt": "ii  1:8.2.2\n"},
                "qemu_guest_agent_binary": {"stdout_excerpt": "/usr/sbin/qemu-ga\n"},
                "qemu_guest_agent_enabled": {"stdout_excerpt": "enabled\n"},
                "qemu_guest_agent_active": {"stdout_excerpt": "active\n"},
                "qemu_guest_agent_socket": {"stdout_excerpt": "present\n"},
            }
        )

        self.assertTrue(summary["installed"])
        self.assertTrue(summary["enabled"])
        self.assertTrue(summary["active"])
        self.assertTrue(summary["virtio_socket_present"])
        self.assertEqual(summary["reason"], "qemu_guest_agent_guest_side_healthy")

    def test_summarize_ssh_qga_diagnostics_accepts_static_active_unit(self):
        summary = lifecycle.summarize_ssh_qga_diagnostics(
            {
                "qemu_guest_agent_package": {"stdout_excerpt": "ii  1:8.2.2\n"},
                "qemu_guest_agent_binary": {"stdout_excerpt": "/usr/sbin/qemu-ga\n"},
                "qemu_guest_agent_enabled": {"stdout_excerpt": "static\n"},
                "qemu_guest_agent_active": {"stdout_excerpt": "active\n"},
                "qemu_guest_agent_socket": {"stdout_excerpt": "missing\n"},
            }
        )

        self.assertTrue(summary["installed"])
        self.assertTrue(summary["enabled"])
        self.assertTrue(summary["active"])
        self.assertFalse(summary["virtio_socket_present"])
        self.assertEqual(summary["reason"], "qemu_guest_agent_guest_side_healthy")

    def test_ssh_qga_repair_runs_bounded_install_sequence(self):
        calls = []

        def fake_ssh(target, command, connect_timeout, timeout, max_output_chars=800):
            calls.append(command)
            if "dpkg-query" in command:
                return {
                    "ok": True,
                    "stdout_excerpt": "ii  1:8.2.2\nenabled\nactive\nsocket_present\n",
                }
            return {"ok": True, "stdout_excerpt": "ok\n"}

        with patch.object(lifecycle, "ssh_exec_capture", side_effect=fake_ssh):
            report = lifecycle.ssh_qga_repair(
                "claude@10.0.30.50",
                connect_timeout=4,
                command_timeout=120,
            )

        self.assertTrue(report["ok"])
        self.assertEqual(len(calls), 5)
        self.assertIn("apt-get", calls[1])
        self.assertIn("qemu-guest-agent", calls[2])
        self.assertIn("systemctl enable --now qemu-guest-agent", calls[3])

    def test_ssh_qga_repair_accepts_static_service_before_reboot(self):
        def fake_ssh(target, command, connect_timeout, timeout, max_output_chars=800):
            if "dpkg-query" in command:
                return {
                    "ok": True,
                    "stdout_excerpt": "ii  1:8.2.2\nstatic\nactive\nsocket_missing\n",
                }
            return {"ok": True, "stdout_excerpt": "ok\n"}

        with patch.object(lifecycle, "ssh_exec_capture", side_effect=fake_ssh):
            report = lifecycle.ssh_qga_repair(
                "claude@10.0.30.50",
                connect_timeout=4,
                command_timeout=120,
            )

        self.assertTrue(report["ok"])
        self.assertTrue(report["configured"])
        self.assertTrue(report["requires_reboot"])
        self.assertFalse(report["virtio_socket_present"])

    def test_ssh_exec_capture_quotes_remote_shell_command(self):
        seen = {}

        def fake_run(command, **kwargs):
            seen["command"] = command
            return subprocess.CompletedProcess(command, 0, stdout="ok\n", stderr="")

        with patch.object(lifecycle.subprocess, "run", side_effect=fake_run):
            result = lifecycle.ssh_exec_capture(
                "claude@10.0.30.50",
                "sudo apt-get update && echo ok",
                connect_timeout=4,
                timeout=10,
            )

        self.assertTrue(result["ok"])
        self.assertEqual(seen["command"][-3:-1], ["sh", "-lc"])
        self.assertEqual(seen["command"][-1], "'sudo apt-get update && echo ok'")

    def test_render_deploy_command_shell_quotes_placeholders(self):
        command, placeholders = lifecycle.render_deploy_command(
            "install-openclaw --version {version} --listen {ip}:{port}",
            "2026.2.13; touch /tmp/pwned",
            "10.0.30.55",
            18789,
        )

        self.assertEqual(placeholders, ["version", "ip", "port"])
        self.assertIn("'2026.2.13; touch /tmp/pwned'", command)
        self.assertIn("10.0.30.55", command)
        self.assertIn("18789", command)
        self.assertNotIn("{version}", command)

    def test_run_known_version_deploy_fails_closed_without_command(self):
        report = lifecycle.run_known_version_deploy(
            ip="10.0.30.55",
            version="2026.2.13",
            port=18789,
            ssh_user="claude",
            command_template=None,
            command_label="missing",
            connect_timeout=4,
            timeout=60,
        )

        self.assertFalse(report["ok"])
        self.assertEqual(report["reason"], "deployment_not_configured")
        self.assertFalse(report["command_recorded"])

    def test_read_deploy_command_file_returns_command_without_logging_content(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            command_path = Path(tmpdir, "deploy-command.sh")
            command_path.write_text("install-openclaw --version {version}\n", encoding="utf-8")

            command, reason = lifecycle.read_deploy_command_file(str(command_path))

        self.assertEqual(command, "install-openclaw --version {version}")
        self.assertIsNone(reason)

    def test_read_deploy_command_file_fails_closed_on_empty_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            command_path = Path(tmpdir, "deploy-command.sh")
            command_path.write_text("\n", encoding="utf-8")

            command, reason = lifecycle.read_deploy_command_file(str(command_path))

        self.assertIsNone(command)
        self.assertEqual(reason, "deploy_command_file_empty")

    def test_read_deploy_command_file_requires_ignored_in_repo_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            repo_root = Path(tmpdir)
            subprocess.run(["git", "init", "-q"], cwd=repo_root, check=True)
            command_path = repo_root / "deploy-command.sh"
            command_path.write_text("install-openclaw --version {version}\n", encoding="utf-8")

            command, reason = lifecycle.read_deploy_command_file(
                str(command_path),
                repo_root=repo_root,
            )

        self.assertIsNone(command)
        self.assertEqual(reason, "deploy_command_file_not_ignored")

    def test_read_deploy_command_file_accepts_ignored_in_repo_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            repo_root = Path(tmpdir)
            subprocess.run(["git", "init", "-q"], cwd=repo_root, check=True)
            (repo_root / ".gitignore").write_text(".local/\n", encoding="utf-8")
            command_dir = repo_root / ".local"
            command_dir.mkdir()
            command_path = command_dir / "deploy-command.sh"
            command_path.write_text("install-openclaw --version {version}\n", encoding="utf-8")

            command, reason = lifecycle.read_deploy_command_file(
                str(command_path),
                repo_root=repo_root,
            )

        self.assertEqual(command, "install-openclaw --version {version}")
        self.assertIsNone(reason)

    def test_read_deploy_command_file_rejects_tracked_in_repo_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            repo_root = Path(tmpdir)
            subprocess.run(["git", "init", "-q"], cwd=repo_root, check=True)
            command_path = repo_root / "deploy-command.sh"
            command_path.write_text("install-openclaw --version {version}\n", encoding="utf-8")
            subprocess.run(["git", "add", "deploy-command.sh"], cwd=repo_root, check=True)

            command, reason = lifecycle.read_deploy_command_file(
                str(command_path),
                repo_root=repo_root,
            )

        self.assertIsNone(command)
        self.assertEqual(reason, "deploy_command_file_tracked")

    def test_validate_deploy_command_input_records_only_safe_metadata(self):
        exit_code, report = lifecycle.validate_deploy_command_input(
            version="2026.2.13; touch /tmp/pwned",
            command_template="install-openclaw --version {version} --listen {ip}:{port}",
            command_file=None,
            command_label="dry-run",
            ip="10.0.30.55",
            port=18789,
        )

        self.assertEqual(exit_code, 0)
        self.assertTrue(report["ok"])
        self.assertEqual(report["command_label"], "dry-run")
        self.assertEqual(report["command_source"], "argument")
        self.assertEqual(report["placeholders_used"], ["version", "ip", "port"])
        self.assertTrue(report["uses_version_placeholder"])
        self.assertFalse(report["command_recorded"])
        self.assertNotIn("install-openclaw", json.dumps(report))
        self.assertNotIn("pwned", json.dumps(report))

    def test_validate_deploy_command_main_does_not_require_env_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir, "deploy-validation.json")
            exit_code = lifecycle.main(
                [
                    "validate-deploy-command",
                    "--version",
                    "2026.2.13",
                    "--deploy-command",
                    "install-openclaw --version {version}",
                    "--output",
                    str(output),
                ]
            )
            report = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(exit_code, 0)
        self.assertTrue(report["ok"])
        self.assertEqual(report["placeholders_used"], ["version"])
        self.assertNotIn("install-openclaw", json.dumps(report))

    def test_run_known_version_deploy_records_no_command_or_output(self):
        seen = {}

        def fake_ssh(target, command, connect_timeout, timeout, max_output_chars=800):
            seen["target"] = target
            seen["command"] = command
            seen["max_output_chars"] = max_output_chars
            return {
                "ok": False,
                "returncode": 42,
                "stdout_excerpt": "SECRET=do-not-record",
                "stderr_excerpt": "TOKEN=do-not-record",
            }

        with patch.object(lifecycle, "ssh_exec_capture", side_effect=fake_ssh):
            report = lifecycle.run_known_version_deploy(
                ip="10.0.30.55",
                version="2026.2.13",
                port=18789,
                ssh_user="claude",
                command_template="deploy --version {version}",
                command_label="test-deploy",
                connect_timeout=4,
                timeout=60,
                command_source="file",
            )

        self.assertFalse(report["ok"])
        self.assertEqual(report["reason"], "deploy_command_failed")
        self.assertEqual(report["returncode"], 42)
        self.assertEqual(report["command_label"], "test-deploy")
        self.assertEqual(report["command_source"], "file")
        self.assertFalse(report["command_recorded"])
        self.assertFalse(report["stdout_recorded"])
        self.assertFalse(report["stderr_recorded"])
        self.assertNotIn("SECRET", json.dumps(report))
        self.assertNotIn("TOKEN", json.dumps(report))
        self.assertEqual(seen["target"], "claude@10.0.30.55")
        self.assertEqual(seen["max_output_chars"], 0)

    def test_run_known_version_deploy_waits_for_ssh_before_command(self):
        calls = []

        def fake_ssh(target, command, connect_timeout, timeout, max_output_chars=800):
            calls.append(command)
            if command == "true" and len(calls) == 1:
                return {"ok": False, "returncode": 255}
            return {"ok": True, "returncode": 0}

        with patch.object(lifecycle, "ssh_exec_capture", side_effect=fake_ssh):
            with patch.object(lifecycle.time, "sleep") as sleep:
                report = lifecycle.run_known_version_deploy(
                    ip="10.0.30.55",
                    version="2026.2.13",
                    port=18789,
                    ssh_user="claude",
                    command_template="deploy --version {version}",
                    command_label="test-deploy",
                    connect_timeout=4,
                    timeout=60,
                    command_source="file",
                    ssh_ready_attempts=3,
                    ssh_ready_interval=0.5,
                )

        self.assertTrue(report["ok"])
        self.assertEqual(calls, ["true", "true", "deploy --version 2026.2.13"])
        self.assertEqual(report["ssh_ready"]["attempts"], 2)
        self.assertFalse(report["ssh_ready"]["stdout_recorded"])
        self.assertFalse(report["ssh_ready"]["stderr_recorded"])
        sleep.assert_called_once_with(0.5)

    def test_run_known_version_deploy_fails_closed_when_ssh_never_ready(self):
        def fake_ssh(target, command, connect_timeout, timeout, max_output_chars=800):
            return {"ok": False, "returncode": 255, "stdout_excerpt": "SECRET=x"}

        with patch.object(lifecycle, "ssh_exec_capture", side_effect=fake_ssh):
            with patch.object(lifecycle.time, "sleep"):
                report = lifecycle.run_known_version_deploy(
                    ip="10.0.30.55",
                    version="2026.2.13",
                    port=18789,
                    ssh_user="claude",
                    command_template="deploy --version {version}",
                    command_label="test-deploy",
                    connect_timeout=4,
                    timeout=60,
                    command_source="file",
                    ssh_ready_attempts=2,
                    ssh_ready_interval=0.5,
                )

        self.assertFalse(report["ok"])
        self.assertEqual(report["reason"], "ssh_unavailable")
        self.assertEqual(report["returncode"], 255)
        self.assertFalse(report["command_recorded"])
        self.assertFalse(report["stdout_recorded"])
        self.assertFalse(report["stderr_recorded"])
        self.assertNotIn("SECRET", json.dumps(report))

    def test_wait_for_gateway_health_retries_until_reachable(self):
        calls = []

        def fake_http_get_status(url, timeout):
            calls.append((url, timeout))
            if len(calls) == 1:
                return None, "URLError"
            return 404, None

        with patch.object(lifecycle, "http_get_status", side_effect=fake_http_get_status):
            with patch.object(lifecycle.time, "sleep") as sleep:
                report = lifecycle.wait_for_gateway_health(
                    "http://10.0.30.55:18789/health",
                    timeout=2.0,
                    attempts=3,
                    interval_seconds=0.5,
                )

        self.assertTrue(report["ok"])
        self.assertFalse(report["expected_status_matched"])
        self.assertEqual(report["http_status"], 404)
        self.assertEqual(len(report["attempts"]), 2)
        sleep.assert_called_once_with(0.5)

    def test_run_once_missing_deploy_command_fails_before_preflight_or_vm(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            args = Namespace(
                version="2026.2.13",
                attempt_id="no-deploy",
                output_dir=tmpdir,
                subnet=None,
                deploy_command=None,
                deploy_command_file=None,
                skip_deploy=False,
                update_manifest=False,
            )
            with patch.object(lifecycle.preflight, "run_preflight") as run_preflight:
                exit_code, report = lifecycle.run_once({}, args)

            artifact = Path(tmpdir, "proxmox-attempt-no-deploy.json")
            artifact_exists = artifact.exists()

        self.assertEqual(exit_code, 1)
        self.assertEqual(report["outcome"], "deployment_failed")
        self.assertEqual(report["reason"], "deployment_not_configured")
        self.assertIsNone(report["vmid"])
        self.assertIsNone(report["lifecycle"]["created_at"])
        self.assertFalse(report["scanner_capture_attempted"])
        self.assertTrue(artifact_exists)
        run_preflight.assert_not_called()

    def test_ssh_template_cleanup_cleans_cloud_init_and_machine_id(self):
        seen = {}

        def fake_ssh(target, command, connect_timeout, timeout, max_output_chars=800):
            seen["command"] = command
            return {"ok": True, "stdout_excerpt": "template_cleaned\n"}

        with patch.object(lifecycle, "ssh_exec_capture", side_effect=fake_ssh):
            result = lifecycle.ssh_template_cleanup(
                "claude@10.0.30.50",
                connect_timeout=4,
                command_timeout=120,
            )

        self.assertTrue(result["ok"])
        self.assertIn("cloud-init clean --logs", seen["command"])
        self.assertIn("truncate -s 0 /etc/machine-id", seen["command"])
        self.assertIn("ln -sf /etc/machine-id /var/lib/dbus/machine-id", seen["command"])

    def test_capture_has_signals_requires_observations_or_signals(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            empty_capture = Path(tmpdir, "empty.json")
            empty_capture.write_text(
                json.dumps(
                    {
                        "bundle_type": "openclaw_blackbox_capture",
                        "captures": [{"observations": {}, "signals": []}],
                    }
                )
            )
            signal_capture = Path(tmpdir, "signal.json")
            signal_capture.write_text(
                json.dumps(
                    {
                        "bundle_type": "openclaw_blackbox_capture",
                        "captures": [{"observations": {"/": {"status": 200}}, "signals": []}],
                    }
                )
            )

            self.assertFalse(lifecycle.capture_has_signals(str(empty_capture)))
            self.assertTrue(lifecycle.capture_has_signals(str(signal_capture)))

    def test_discover_ip_uses_fallback_after_bounded_guest_agent(self):
        calls = []
        values = {
            "OPENCLAW_PROXMOX_API_URL": "https://pve.example",
            "OPENCLAW_PROXMOX_AUTH_HEADER": "redacted",
            "OPENCLAW_PROXMOX_NODE": "pve01",
            "OPENCLAW_PROXMOX_DEFAULT_BRIDGE": "vmbr0",
            "OPENCLAW_PROXMOX_DEFAULT_VLAN": "30",
        }
        args = Namespace(
            vmid="103",
            subnet=None,
            timeout=1.0,
            guest_agent_attempts=2,
            guest_agent_interval=0.0,
            observation_file=[],
            no_local_neighbor_cache=False,
        )

        def fake_api_get(api_base, auth_header, path, timeout):
            calls.append(path)
            if path.endswith("/agent/network-get-interfaces"):
                return 200, {"data": {"result": []}}
            if path.endswith("/config"):
                return 200, {
                    "data": {
                        "net0": "virtio=BC:24:11:AA:BB:CC,bridge=vmbr0,tag=30,firewall=1",
                    }
                }
            return 404, {}

        with patch.object(lifecycle.preflight, "api_get", side_effect=fake_api_get):
            with patch.object(
                lifecycle,
                "local_neighbor_observations",
                return_value=[
                    (
                        "arp -an",
                        "? (10.0.30.45) at bc:24:11:aa:bb:cc on en0 ifscope [ethernet]",
                    )
                ],
            ):
                exit_code, report = lifecycle.discover_ip(values, args)

        self.assertEqual(exit_code, 0)
        self.assertTrue(report["ok"])
        self.assertEqual(report["method"], "passive-arp-dhcp")
        self.assertEqual(report["ip"], "10.0.30.45")
        self.assertEqual(
            calls,
            [
                "/nodes/pve01/qemu/103/agent/network-get-interfaces",
                "/nodes/pve01/qemu/103/agent/network-get-interfaces",
                "/nodes/pve01/qemu/103/config",
            ],
        )

    def test_bounded_template_diagnostics_validates_guest_agent_and_dhcp(self):
        def fake_get(path):
            self.assertEqual(path, "/nodes/pve01/qemu/104/config")
            return 200, {
                "data": {
                    "net0": "virtio=BC:24:11:AA:BB:CC,bridge=vmbr0,tag=30,firewall=1",
                }
            }

        def fake_api_request(api_base, auth_header, method, path, timeout, data=None):
            if path.endswith("/agent/ping"):
                return 200, {"data": {}}
            if path.endswith("/agent/network-get-interfaces"):
                return 200, {
                    "data": {
                        "result": [
                            {
                                "name": "eth0",
                                "ip-addresses": [
                                    {"ip-address": "10.0.30.45", "ip-address-type": "ipv4"},
                                ],
                            }
                        ]
                    }
                }
            return 404, {}

        with patch.object(lifecycle, "api_request", side_effect=fake_api_request):
            with patch.object(lifecycle, "ssh_neighbor_observation", return_value=[]):
                with patch.object(lifecycle, "local_neighbor_observations", return_value=[]):
                    with patch.object(
                        lifecycle,
                        "guest_agent_template_diagnostics",
                        return_value={"cloud_init_status": {"ok": True, "stdout_excerpt": "status: done"}},
                    ):
                        report = lifecycle.bounded_template_diagnostics(
                            "https://pve.example",
                            "redacted",
                            fake_get,
                            node="pve01",
                            vmid="104",
                            bridge="vmbr0",
                            vlan="30",
                            network=ipaddress.ip_network("10.0.30.0/24"),
                            attempts=3,
                            interval_seconds=0.0,
                            observation_files=[],
                            vlan_observer="claude@10.0.30.10",
                            agent_call_timeout=1.0,
                        )

        self.assertTrue(report["ok"])
        self.assertEqual(report["outcome"], "template_network_validated")
        self.assertEqual(report["guest_agent_network_ipv4"], "10.0.30.45")
        self.assertTrue(report["guest_agent_healthy"])

    def test_bounded_template_diagnostics_fails_closed_without_ip_or_agent(self):
        def fake_get(path):
            return 200, {
                "data": {
                    "net0": "virtio=BC:24:11:AA:BB:CC,bridge=vmbr0,tag=30,firewall=1",
                }
            }

        def fake_api_request(api_base, auth_header, method, path, timeout, data=None):
            return 500, {"data": None}

        with patch.object(lifecycle, "api_request", side_effect=fake_api_request):
            with patch.object(lifecycle, "ssh_neighbor_observation", return_value=[]):
                with patch.object(lifecycle, "local_neighbor_observations", return_value=[]):
                    report = lifecycle.bounded_template_diagnostics(
                        "https://pve.example",
                        "redacted",
                        fake_get,
                        node="pve01",
                        vmid="104",
                        bridge="vmbr0",
                        vlan="30",
                        network=ipaddress.ip_network("10.0.30.0/24"),
                        attempts=2,
                        interval_seconds=0.0,
                        observation_files=[],
                        vlan_observer="claude@10.0.30.10",
                        agent_call_timeout=1.0,
                    )

        self.assertFalse(report["ok"])
        self.assertEqual(report["outcome"], "no_ip_discovered")
        self.assertEqual(report["reason"], "no_guest_or_passive_vlan30_ip")


if __name__ == "__main__":
    unittest.main()
