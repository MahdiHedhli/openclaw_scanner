import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "validate_saved_capture_inference.py"
SPEC = importlib.util.spec_from_file_location("validate_saved_capture_inference", MODULE_PATH)
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)


class SavedCaptureInferenceTests(unittest.TestCase):
    def test_validate_capture_root_reports_exact_match_without_target_urls(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            rules_path = root / "rules.json"
            rules_path.write_text(
                json.dumps({
                    "product": "OpenClaw",
                    "version_rules": [
                        {
                            "id": "lab-capture-2026-9-1",
                            "version": "2026.9.1",
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
                    ],
                }),
                encoding="utf-8",
            )
            capture_dir = root / "openclaw-2026.9.1"
            capture_dir.mkdir()
            (capture_dir / "capture.json").write_text(
                json.dumps({
                    "bundle_type": "openclaw_blackbox_capture",
                    "declared_version": "2026.9.1",
                    "capture_name": "openclaw-2026.9.1-lab",
                    "captures": [
                        {
                            "input_target": "http://198.51.100.99:18789",
                            "probed_base": "http://198.51.100.99:18789",
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

            report = validator.validate_capture_root(str(root), rules_file=str(rules_path))

        self.assertEqual(report["capture_count"], 1)
        self.assertEqual(report["declared_exact_match_count"], 1)
        self.assertEqual(report["declared_no_exact_match_count"], 0)
        self.assertEqual(report["records"][0]["top_version"], "2026.9.1")
        self.assertEqual(
            report["version_summary"],
            [
                {
                    "declared_version": "2026.9.1",
                    "capture_count": 1,
                    "evaluated_capture_count": 1,
                    "ignored_capture_count": 0,
                    "declared_exact_match_count": 1,
                    "declared_no_exact_match_count": 0,
                    "ignored_declared_no_exact_match_count": 0,
                    "exact_sources": ["lab-capture-2026-9-1"],
                    "top_version_counts": [{"count": 1, "version": "2026.9.1"}],
                }
            ],
        )
        rendered = json.dumps(report)
        self.assertNotIn("198.51.100.99", rendered)
        self.assertNotIn("input_target", rendered)
        self.assertNotIn("probed_base", rendered)
        self.assertNotIn("url", rendered)

    def test_require_all_exact_returns_nonzero_for_missing_declared_match(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            rules_path = root / "rules.json"
            rules_path.write_text('{"version_rules":[]}', encoding="utf-8")
            (root / "capture.json").write_text(
                json.dumps({
                    "bundle_type": "openclaw_blackbox_capture",
                    "declared_version": "2026.9.1",
                    "captures": [
                        {
                            "observations": {
                                "/": {
                                    "path": "/",
                                    "url": "http://198.51.100.99:18789/",
                                    "status": 200,
                                }
                            }
                        }
                    ],
                }),
                encoding="utf-8",
            )

            exit_code = validator.main([
                "--input-root",
                str(root),
                "--rules-file",
                str(rules_path),
                "--output",
                str(root / "report.json"),
                "--require-all-exact",
            ])

        self.assertEqual(exit_code, 1)

    def test_ignore_version_excludes_capture_from_require_all_exact(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            rules_path = root / "rules.json"
            report_path = root / "report.json"
            rules_path.write_text('{"version_rules":[]}', encoding="utf-8")
            (root / "capture.json").write_text(
                json.dumps({
                    "bundle_type": "openclaw_blackbox_capture",
                    "declared_version": "2026.9.1-beta.1",
                    "captures": [
                        {
                            "observations": {
                                "/": {
                                    "path": "/",
                                    "url": "http://198.51.100.99:18789/",
                                    "status": 200,
                                }
                            }
                        }
                    ],
                }),
                encoding="utf-8",
            )

            exit_code = validator.main([
                "--input-root",
                str(root),
                "--rules-file",
                str(rules_path),
                "--output",
                str(report_path),
                "--require-all-exact",
                "--ignore-version",
                "2026.9.1-beta.1",
            ])
            report = json.loads(report_path.read_text(encoding="utf-8"))

        self.assertEqual(exit_code, 0)
        self.assertEqual(report["capture_count"], 1)
        self.assertEqual(report["evaluated_capture_count"], 0)
        self.assertEqual(report["ignored_capture_count"], 1)
        self.assertEqual(report["declared_no_exact_match_count"], 0)
        self.assertEqual(report["ignored_declared_no_exact_match_count"], 1)
        self.assertEqual(report["ignored_versions_present"], ["2026.9.1-beta.1"])
        self.assertEqual(report["declared_versions_without_exact_match"], [])
        self.assertTrue(report["records"][0]["ignored_for_exact_requirement"])
        self.assertEqual(
            report["version_summary"],
            [
                {
                    "declared_version": "2026.9.1-beta.1",
                    "capture_count": 1,
                    "evaluated_capture_count": 0,
                    "ignored_capture_count": 1,
                    "declared_exact_match_count": 0,
                    "declared_no_exact_match_count": 0,
                    "ignored_declared_no_exact_match_count": 1,
                    "exact_sources": [],
                    "top_version_counts": [],
                }
            ],
        )

    def test_validate_capture_root_reports_skipped_non_capture_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "manifest.json").write_text('{"vms":[]}', encoding="utf-8")
            (root / "broken.json").write_text('{"bundle_type":', encoding="utf-8")

            report = validator.validate_capture_root(str(root))

        self.assertEqual(report["capture_count"], 0)
        self.assertEqual(
            report["skipped_input_summary"],
            [
                {"count": 1, "reason": "invalid JSON: Expecting value"},
                {"count": 1, "reason": "not an openclaw_blackbox_capture bundle"},
            ],
        )

    def test_main_can_update_manifest_with_saved_capture_summary(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            rules_path = root / "rules.json"
            report_path = root / "report.json"
            manifest_path = root / "manifest.json"
            manifest_path.write_text(json.dumps({"run_id": "test-run"}), encoding="utf-8")
            rules_path.write_text(
                json.dumps({
                    "version_rules": [
                        {
                            "id": "lab-capture-2026-9-1",
                            "version": "2026.9.1",
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
                    ],
                }),
                encoding="utf-8",
            )
            (root / "capture.json").write_text(
                json.dumps({
                    "bundle_type": "openclaw_blackbox_capture",
                    "declared_version": "2026.9.1",
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

            exit_code = validator.main([
                "--input-root",
                str(root),
                "--rules-file",
                str(rules_path),
                "--output",
                str(report_path),
                "--require-all-exact",
                "--manifest",
                str(manifest_path),
            ])
            updated = json.loads(manifest_path.read_text(encoding="utf-8"))

        self.assertEqual(exit_code, 0)
        summary = updated["saved_capture_inference"]
        self.assertTrue(summary["passed"])
        self.assertTrue(summary["require_all_exact"])
        self.assertEqual(summary["capture_count"], 1)
        self.assertEqual(summary["declared_exact_match_count"], 1)
        self.assertEqual(summary["declared_versions_without_exact_match"], [])
        self.assertIn("--manifest", summary["command"])
        self.assertNotIn("198.51.100.99", json.dumps(summary))


if __name__ == "__main__":
    unittest.main()
