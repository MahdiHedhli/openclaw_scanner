import importlib.util
import json
import tempfile
import unittest
import urllib.error
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "proxmox_corpus_preflight.py"
SPEC = importlib.util.spec_from_file_location("proxmox_corpus_preflight", MODULE_PATH)
preflight = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(preflight)


class ProxmoxCorpusPreflightTests(unittest.TestCase):
    def test_load_env_uses_local_overlay_for_default_env(self):
        original_default = preflight.DEFAULT_ENV_PATH
        original_overlay = preflight.DEFAULT_ENV_OVERLAY_PATH

        with tempfile.TemporaryDirectory() as tmpdir:
            env_path = Path(tmpdir, ".env")
            overlay_path = Path(tmpdir, ".env.local")
            env_path.write_text(
                "OPENCLAW_PROXMOX_CIUSER=base\n"
                "OPENCLAW_PROXMOX_API_URL=https://pve.example\n",
                encoding="utf-8",
            )
            overlay_path.write_text(
                "OPENCLAW_PROXMOX_CIUSER=overlay\n"
                "OPENCLAW_PROXMOX_SSHKEYS_FILE=/ignored/id.pub\n",
                encoding="utf-8",
            )

            try:
                preflight.DEFAULT_ENV_PATH = env_path
                preflight.DEFAULT_ENV_OVERLAY_PATH = overlay_path
                values = preflight.load_env(env_path)
            finally:
                preflight.DEFAULT_ENV_PATH = original_default
                preflight.DEFAULT_ENV_OVERLAY_PATH = original_overlay

        self.assertEqual(values["OPENCLAW_PROXMOX_CIUSER"], "overlay")
        self.assertEqual(values["OPENCLAW_PROXMOX_API_URL"], "https://pve.example")
        self.assertEqual(values["OPENCLAW_PROXMOX_SSHKEYS_FILE"], "/ignored/id.pub")

    def test_permission_map_reads_nested_proxmox_response(self):
        payload = {
            "data": {
                "/sdn/zones/localnetwork/vmbr0": {
                    "SDN.Use": 1,
                }
            }
        }

        self.assertTrue(
            preflight.permission_has(
                payload,
                "/sdn/zones/localnetwork/vmbr0",
                "SDN.Use",
            )
        )

    def test_permission_map_reads_flat_response(self):
        payload = {"data": {"VM.Clone": 1, "VM.Audit": 1}}

        self.assertTrue(preflight.permission_has(payload, "/vms/9000", "VM.Clone"))

    def test_permission_presence_accepts_non_propagating_entry(self):
        payload = {"data": {"/vms/9000": {"VM.Clone": 0}}}

        self.assertTrue(preflight.permission_has(payload, "/vms/9000", "VM.Clone"))

    def test_corpus_vms_filters_openclaw_related_names(self):
        resources = [
            {"vmid": 100, "name": "openclaw-corpus-2026-2-13-01", "status": "running"},
            {"vmid": 101, "name": "database", "status": "running"},
            {"vmid": 102, "name": "corpus-scratch", "status": "stopped"},
        ]

        self.assertEqual(
            preflight.corpus_vms(resources),
            [
                {
                    "vmid": 100,
                    "name": "openclaw-corpus-2026-2-13-01",
                    "status": "running",
                },
                {"vmid": 102, "name": "corpus-scratch", "status": "stopped"},
            ],
        )

    def test_template_readiness_extracts_safe_flags(self):
        readiness = preflight.template_readiness(
            {
                "agent": "enabled=1",
                "boot": "order=scsi0",
                "ide2": "local-zfs:vm-9000-cloudinit,media=cdrom",
                "name": "ubuntu-2404-cloudinit",
                "serial0": "socket",
                "template": 1,
                "vga": "serial0",
            }
        )

        self.assertTrue(readiness["template"])
        self.assertTrue(readiness["agent_enabled"])
        self.assertTrue(readiness["cloudinit_attached"])
        self.assertTrue(readiness["serial_console"])
        self.assertEqual(readiness["boot_order"], "order=scsi0")

    def test_clone_identity_readiness_accepts_env_user_and_key_file(self):
        readiness = preflight.clone_identity_readiness(
            {
                "OPENCLAW_PROXMOX_CIUSER": "claude",
                "OPENCLAW_PROXMOX_SSHKEYS_FILE": "/ignored/id.pub",
            },
            {},
        )

        self.assertTrue(readiness["ok"])
        self.assertTrue(readiness["has_user_source"])
        self.assertTrue(readiness["has_key_source"])

    def test_clone_identity_readiness_accepts_template_identity(self):
        readiness = preflight.clone_identity_readiness(
            {},
            {
                "ciuser": "claude",
                "sshkeys": "redacted",
            },
        )

        self.assertTrue(readiness["ok"])
        self.assertTrue(readiness["template_ciuser_present"])
        self.assertTrue(readiness["template_sshkeys_present"])

    def test_clone_identity_readiness_reports_missing_identity(self):
        readiness = preflight.clone_identity_readiness({}, {})

        self.assertFalse(readiness["ok"])
        self.assertFalse(readiness["has_user_source"])
        self.assertFalse(readiness["has_key_source"])

    def test_run_preflight_blocks_missing_auth_without_printing_values(self):
        exit_code, report = preflight.run_preflight({}, timeout=1.0)

        self.assertEqual(exit_code, 2)
        self.assertFalse(report["vm_lifecycle_allowed"])
        self.assertRegex(report["checked_at"], r"^20\d{2}-\d{2}-\d{2}T")
        self.assertIn("missing OPENCLAW_PROXMOX_API_URL", report["blockers"])
        self.assertIn("missing Proxmox token auth configuration", report["blockers"])

    def test_api_get_returns_sanitized_network_error(self):
        original_urlopen = preflight.urllib.request.urlopen

        def fake_urlopen(request, context, timeout):
            raise urllib.error.URLError(TimeoutError("handshake timed out"))

        try:
            preflight.urllib.request.urlopen = fake_urlopen
            status, payload = preflight.api_get(
                "https://pve.example",
                "redacted-token",
                "/version",
                timeout=1.0,
            )
        finally:
            preflight.urllib.request.urlopen = original_urlopen

        self.assertEqual(status, 0)
        self.assertEqual(payload, {"message": "network timeout"})

    def test_run_preflight_fails_closed_when_api_unreachable(self):
        original_api_get = preflight.api_get
        calls = []

        def fake_api_get(api_base, auth_header, path, timeout):
            calls.append(path)
            return 0, {"message": "network timeout"}

        try:
            preflight.api_get = fake_api_get
            exit_code, report = preflight.run_preflight(
                {
                    "OPENCLAW_PROXMOX_API_URL": "https://pve.example",
                    "OPENCLAW_PROXMOX_AUTH_HEADER": "redacted",
                },
                timeout=1.0,
            )
        finally:
            preflight.api_get = original_api_get

        self.assertEqual(exit_code, 1)
        self.assertEqual(calls, ["/version"])
        self.assertFalse(report["vm_lifecycle_allowed"])
        self.assertEqual(report["vm_inventory"]["still_running"], 0)
        self.assertEqual(
            report["blockers"],
            [
                "Proxmox API version check failed before HTTP response: network timeout"
            ],
        )

    def test_run_preflight_blocks_running_corpus_vms(self):
        original_api_get = preflight.api_get

        def fake_api_get(api_base, auth_header, path, timeout):
            if path == "/version":
                return 200, {"data": {"version": "9.1.9"}}
            if path == "/cluster/resources?type=vm":
                return 200, {
                    "data": [
                        {
                            "vmid": 100,
                            "name": "openclaw-corpus-2026-2-13-01",
                            "status": "running",
                        }
                    ]
                }
            if path == "/nodes/pve01/qemu/9000/config":
                return 200, {
                    "data": {
                        "agent": "enabled=1",
                        "ide2": "local-zfs:vm-9000-cloudinit,media=cdrom",
                        "template": 1,
                    }
                }
            return 200, {
                "data": {
                    "Sys.Audit": 1,
                    "VM.Clone": 1,
                    "SDN.Use": 1,
                }
            }

        try:
            preflight.api_get = fake_api_get
            exit_code, report = preflight.run_preflight(
                {
                    "OPENCLAW_PROXMOX_API_URL": "https://pve.example",
                    "OPENCLAW_PROXMOX_AUTH_HEADER": "redacted",
                },
                timeout=1.0,
            )
        finally:
            preflight.api_get = original_api_get

        self.assertEqual(exit_code, 1)
        self.assertFalse(report["vm_lifecycle_allowed"])
        self.assertEqual(report["vm_inventory"]["still_running"], 1)
        self.assertIn(
            "running OpenClaw/corpus VM(s) require cleanup before new lifecycle work: "
            "100:openclaw-corpus-2026-2-13-01",
            report["blockers"],
        )

    def test_run_preflight_allows_lifecycle_when_checks_are_clear(self):
        original_api_get = preflight.api_get

        def fake_api_get(api_base, auth_header, path, timeout):
            if path == "/version":
                return 200, {"data": {"version": "9.1.9"}}
            if path == "/cluster/resources?type=vm":
                return 200, {"data": []}
            if path == "/nodes/pve01/qemu/9000/config":
                return 200, {
                    "data": {
                        "agent": "enabled=1",
                        "ide2": "local-zfs:vm-9000-cloudinit,media=cdrom",
                        "template": 1,
                    }
                }
            return 200, {
                "data": {
                    "Sys.Audit": 1,
                    "VM.Clone": 1,
                    "SDN.Use": 1,
                }
            }

        try:
            preflight.api_get = fake_api_get
            exit_code, report = preflight.run_preflight(
                {
                    "OPENCLAW_PROXMOX_API_URL": "https://pve.example",
                    "OPENCLAW_PROXMOX_AUTH_HEADER": "redacted",
                    "OPENCLAW_PROXMOX_CIUSER": "claude",
                    "OPENCLAW_PROXMOX_SSHKEYS_FILE": "/ignored/id.pub",
                },
                timeout=1.0,
            )
        finally:
            preflight.api_get = original_api_get

        self.assertEqual(exit_code, 0)
        self.assertTrue(report["vm_lifecycle_allowed"])
        self.assertEqual(report["blockers"], [])

    def test_run_preflight_blocks_missing_clone_identity(self):
        original_api_get = preflight.api_get

        def fake_api_get(api_base, auth_header, path, timeout):
            if path == "/version":
                return 200, {"data": {"version": "9.1.9"}}
            if path == "/cluster/resources?type=vm":
                return 200, {"data": []}
            if path == "/nodes/pve01/qemu/9000/config":
                return 200, {
                    "data": {
                        "agent": "enabled=1",
                        "ide2": "local-zfs:vm-9000-cloudinit,media=cdrom",
                        "template": 1,
                    }
                }
            return 200, {
                "data": {
                    "Sys.Audit": 1,
                    "VM.Clone": 1,
                    "SDN.Use": 1,
                }
            }

        try:
            preflight.api_get = fake_api_get
            exit_code, report = preflight.run_preflight(
                {
                    "OPENCLAW_PROXMOX_API_URL": "https://pve.example",
                    "OPENCLAW_PROXMOX_AUTH_HEADER": "redacted",
                },
                timeout=1.0,
            )
        finally:
            preflight.api_get = original_api_get

        self.assertEqual(exit_code, 1)
        self.assertFalse(report["vm_lifecycle_allowed"])
        self.assertIn(
            "clone cloud-init identity is incomplete; configure a clone user plus SSH key source or cicustom before launching another VM",
            report["blockers"],
        )

    def test_run_preflight_blocks_template_without_guest_agent(self):
        original_api_get = preflight.api_get

        def fake_api_get(api_base, auth_header, path, timeout):
            if path == "/version":
                return 200, {"data": {"version": "9.1.9"}}
            if path == "/cluster/resources?type=vm":
                return 200, {"data": []}
            if path == "/nodes/pve01/qemu/9000/config":
                return 200, {
                    "data": {
                        "ide2": "local-zfs:vm-9000-cloudinit,media=cdrom",
                        "template": 1,
                    }
                }
            return 200, {
                "data": {
                    "Sys.Audit": 1,
                    "VM.Clone": 1,
                    "SDN.Use": 1,
                }
            }

        try:
            preflight.api_get = fake_api_get
            exit_code, report = preflight.run_preflight(
                {
                    "OPENCLAW_PROXMOX_API_URL": "https://pve.example",
                    "OPENCLAW_PROXMOX_AUTH_HEADER": "redacted",
                },
                timeout=1.0,
            )
        finally:
            preflight.api_get = original_api_get

        self.assertEqual(exit_code, 1)
        self.assertFalse(report["vm_lifecycle_allowed"])
        self.assertIn(
            "template 9000 does not enable the QEMU guest agent needed for IP discovery",
            report["blockers"],
        )

    def test_render_report_json_ends_with_newline(self):
        rendered = preflight.render_report({"schema_version": 1}, "json")

        self.assertTrue(rendered.endswith("\n"))
        self.assertEqual(json.loads(rendered), {"schema_version": 1})

    def test_manifest_preflight_summary_extracts_safe_fields(self):
        report = {
            "checked_at": "2026-05-19T09:42:29Z",
            "vm_lifecycle_allowed": False,
            "blockers": ["blocked"],
            "checks": [
                {
                    "name": "api_version",
                    "version": "9.1.9",
                },
                {
                    "name": "corpus_vm_inventory",
                    "openclaw_related_vms": 1,
                    "openclaw_running_vms": 0,
                },
                {
                    "name": "template_readiness",
                    "ok": True,
                },
                {
                    "name": "clone_identity_readiness",
                    "ok": False,
                    "has_user_source": False,
                    "has_key_source": True,
                    "env_sshkeys_file_present": True,
                },
            ],
        }

        summary = preflight.manifest_preflight_summary(
            report,
            artifact="artifacts/lab/preflight.json",
            command="python3 scripts/proxmox_corpus_preflight.py --format json",
        )

        self.assertFalse(summary["passed"])
        self.assertEqual(summary["api_version"], "9.1.9")
        self.assertTrue(summary["template_ready"])
        self.assertFalse(summary["clone_identity_ready"])
        self.assertTrue(summary["clone_identity_sources"]["has_key_source"])
        self.assertTrue(summary["clone_identity_sources"]["env_sshkeys_file_present"])
        self.assertEqual(summary["openclaw_related_vms"], 1)
        self.assertEqual(summary["openclaw_running_vms"], 0)

    def test_update_manifest_preflight_replaces_preflight_section(self):
        report = {
            "checked_at": "2026-05-19T09:42:29Z",
            "vm_lifecycle_allowed": True,
            "blockers": [],
            "checks": [
                {"name": "api_version", "version": "9.1.9"},
                {
                    "name": "corpus_vm_inventory",
                    "openclaw_related_vms": 0,
                    "openclaw_running_vms": 0,
                },
                {"name": "template_readiness", "ok": True},
                {"name": "clone_identity_readiness", "ok": True},
            ],
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir, "manifest.json")
            path.write_text(
                json.dumps(
                    {
                        "run_id": "test",
                        "proxmox_preflight": {"stale": True},
                        "vm_inventory": {"created": 0},
                    }
                ),
                encoding="utf-8",
            )

            preflight.update_manifest_preflight(
                str(path),
                report,
                artifact="artifacts/lab/preflight.json",
                command="python3 scripts/proxmox_corpus_preflight.py --format json",
            )

            manifest = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(manifest["run_id"], "test")
            self.assertNotIn("stale", manifest["proxmox_preflight"])
            self.assertTrue(manifest["proxmox_preflight"]["passed"])
            self.assertEqual(
                manifest["proxmox_preflight"]["artifact"],
                "artifacts/lab/preflight.json",
            )

    def test_write_report_creates_parent_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir, "nested", "preflight.json")

            preflight.write_report('{"ok": true}\n', str(output))

            self.assertEqual(output.read_text(encoding="utf-8"), '{"ok": true}\n')


if __name__ == "__main__":
    unittest.main()
