import importlib.util
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "run_openclaw_corpus_heartbeat.py"
SPEC = importlib.util.spec_from_file_location("run_openclaw_corpus_heartbeat", MODULE_PATH)
heartbeat = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(heartbeat)


class OpenClawCorpusHeartbeatTests(unittest.TestCase):
    def write_capture(self, root, version):
        (root / "capture.json").write_text(
            json.dumps({
                "bundle_type": "openclaw_blackbox_capture",
                "declared_version": version,
                "captures": [
                    {
                        "input_target": "http://198.51.100.99:18789",
                        "observations": {
                            "/": {
                                "path": "/",
                                "url": "http://198.51.100.99:18789/",
                                "status": 200,
                                "js_files": ["./assets/index-test.js"],
                            }
                        },
                    }
                ],
            }),
            encoding="utf-8",
        )

    def write_rules(self, path, version):
        path.write_text(
            json.dumps({
                "version_rules": [
                    {
                        "id": "lab-capture-test",
                        "version": version,
                        "confidence": 0.89,
                        "exact": True,
                        "all": [
                            {
                                "type": "script_contains",
                                "path": "/",
                                "value": "./assets/index-test.js",
                            }
                        ],
                    }
                ]
            }),
            encoding="utf-8",
        )

    def test_main_writes_sanitized_heartbeat_summary_without_vm_action(self):
        original_load_env = heartbeat.preflight.load_env
        original_run_preflight = heartbeat.preflight.run_preflight
        heartbeat.preflight.load_env = lambda _path: {}
        heartbeat.preflight.run_preflight = lambda _values, timeout: (
            0,
            {
                "checked_at": "2026-05-24T11:55:00Z",
                "vm_lifecycle_allowed": True,
                "blockers": [],
                "vm_inventory": {
                    "created": 0,
                    "reused": 0,
                    "shut_down": 0,
                    "destroyed": 0,
                    "still_running": 0,
                    "next_cleanup_deadline": None,
                },
                "checks": [
                    {"name": "api_version", "version": "test"},
                    {
                        "name": "corpus_vm_inventory",
                        "openclaw_related_vms": 0,
                        "openclaw_running_vms": 0,
                    },
                    {"name": "template_readiness", "ok": True},
                    {
                        "name": "clone_identity_readiness",
                        "ok": True,
                        "has_user_source": True,
                        "has_key_source": True,
                    },
                ],
            },
        )
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                root = Path(tmpdir)
                captures = root / "captures"
                artifacts = root / "artifacts"
                captures.mkdir()
                rules = root / "rules.json"
                manifest = root / "manifest.json"
                output = root / "heartbeat.json"
                manifest.write_text(json.dumps({"run_id": "test-run"}), encoding="utf-8")
                self.write_capture(captures, "2026.9.1")
                self.write_rules(rules, "2026.9.1")

                with redirect_stdout(io.StringIO()):
                    exit_code = heartbeat.main([
                        "--artifact-dir",
                        str(artifacts),
                        "--manifest",
                        str(manifest),
                        "--capture-root",
                        str(captures),
                        "--rules-file",
                        str(rules),
                        "--versions-json",
                        json.dumps(["2026.9.1"]),
                        "--label",
                        "test",
                        "--output",
                        str(output),
                    ])
                summary = json.loads(output.read_text(encoding="utf-8"))
                updated_manifest = json.loads(manifest.read_text(encoding="utf-8"))

            self.assertEqual(exit_code, 0)
            self.assertEqual(summary["decision"], "no_vm_needed")
            self.assertFalse(summary["vm_action_recommended"])
            self.assertEqual(summary["latest_published_version"], "2026.9.1")
            self.assertEqual(summary["vm_inventory"]["still_running"], 0)
            self.assertEqual(summary["saved_capture_inference"]["declared_no_exact_match_count"], 0)
            self.assertIn("release_gap", updated_manifest)
            self.assertIn("saved_capture_inference", updated_manifest)
            rendered = json.dumps(summary)
            self.assertNotIn("198.51.100.99", rendered)
            self.assertNotIn("input_target", rendered)
        finally:
            heartbeat.preflight.load_env = original_load_env
            heartbeat.preflight.run_preflight = original_run_preflight


if __name__ == "__main__":
    unittest.main()
