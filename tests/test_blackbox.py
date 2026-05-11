import tempfile
import unittest
from pathlib import Path

from openclaw_scanner.blackbox import (
    build_capture_bundle,
    generate_rule_suggestions,
    load_capture_bundles,
)
from openclaw_scanner.models import ProbeObservation, ScanResult


class BlackboxTests(unittest.TestCase):
    def test_build_capture_bundle_records_remote_signals(self):
        result = ScanResult(
            input_target="198.51.100.10:18789",
            source="direct",
            probed_base="http://198.51.100.10:18789",
            observations={
                "/": ProbeObservation(
                    path="/",
                    url="http://198.51.100.10:18789/",
                    status=200,
                    title="OpenClaw Control",
                    content_type="text/html; charset=utf-8",
                    js_files=["/static/dashboard.2026.2.13.js"],
                    body_markers=["openclaw"],
                ),
                "/favicon.ico": ProbeObservation(
                    path="/favicon.ico",
                    url="http://198.51.100.10:18789/favicon.ico",
                    status=200,
                    content_type="image/x-icon",
                    favicon_hash=-1205140012,
                ),
                "POST /api/doesnotexist": ProbeObservation(
                    path="/api/doesnotexist",
                    url="http://198.51.100.10:18789/api/doesnotexist",
                    method="POST",
                    status=404,
                    error_text="Cannot POST /api/doesnotexist",
                ),
                "/health": ProbeObservation(
                    path="/health",
                    url="http://198.51.100.10:18789/health",
                    status=200,
                    content_type="application/json; charset=utf-8",
                    json_keys=["ok", "status"],
                    body_sha256="6191c1f860b8a0225c697e46ebce756193dfb18c189218cfe742037501da05eb",
                ),
            },
        )

        bundle = build_capture_bundle(
            [result],
            probe_paths=["/", "/health"],
            declared_version="2026.2.13",
            capture_name="lab-openclaw-2026-2-13",
        )

        self.assertEqual(bundle["declared_version"], "2026.2.13")
        self.assertEqual(bundle["capture_count"], 1)
        signals = set(bundle["captures"][0]["signals"])
        self.assertIn("script_contains|/|/static/dashboard.2026.2.13.js", signals)
        self.assertIn("json_key|/health|ok", signals)
        self.assertIn("header_contains|/health|content-type|application/json", signals)
        self.assertIn("favicon_hash|/favicon.ico|-1205140012", signals)
        self.assertIn("method_status|POST|/api/doesnotexist|404", signals)

    def test_generate_rule_suggestions_prefers_unique_stable_signals(self):
        version_a_bundle = {
            "bundle_type": "openclaw_blackbox_capture",
            "declared_version": "2026.2.13",
            "captures": [
                {
                    "signals": [
                        "title_contains|/|OpenClaw Control",
                        "script_contains|/|/static/dashboard.2026.2.13.js",
                        "path_status|/api/version|404",
                    ]
                },
                {
                    "signals": [
                        "title_contains|/|OpenClaw Control",
                        "script_contains|/|/static/dashboard.2026.2.13.js",
                        "path_status|/api/version|404",
                    ]
                },
            ],
        }
        version_b_bundle = {
            "bundle_type": "openclaw_blackbox_capture",
            "declared_version": "2026.2.14",
            "captures": [
                {
                    "signals": [
                        "title_contains|/|OpenClaw Control",
                        "script_contains|/|/static/dashboard.2026.2.14.js",
                        "path_status|/api/version|200",
                    ]
                },
                {
                    "signals": [
                        "title_contains|/|OpenClaw Control",
                        "script_contains|/|/static/dashboard.2026.2.14.js",
                        "path_status|/api/version|200",
                    ]
                },
            ],
        }

        report = generate_rule_suggestions(
            [version_a_bundle, version_b_bundle],
            max_conditions=2,
        )

        self.assertEqual(len(report["versions"]), 2)
        first = next(item for item in report["versions"] if item["version"] == "2026.2.13")
        self.assertEqual(first["capture_count"], 2)
        rule = first["candidate_rule"]
        self.assertEqual(rule["version"], "2026.2.13")
        self.assertTrue(any(
            condition["type"] == "script_contains"
            and condition["value"] == "/static/dashboard.2026.2.13.js"
            for condition in rule["all"]
        ))

    def test_load_capture_bundles_accepts_directory(self):
        bundle_a = {"bundle_type": "openclaw_blackbox_capture", "declared_version": "2026.2.13", "captures": []}
        bundle_b = {"bundle_type": "openclaw_blackbox_capture", "declared_version": "2026.2.14", "captures": []}

        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "a.json").write_text('{"bundle_type":"openclaw_blackbox_capture","declared_version":"2026.2.13","captures":[]}', encoding="utf-8")
            Path(tmpdir, "b.json").write_text('{"bundle_type":"openclaw_blackbox_capture","declared_version":"2026.2.14","captures":[]}', encoding="utf-8")
            bundles = load_capture_bundles(tmpdir)

        self.assertEqual(len(bundles), 2)
        self.assertEqual({bundle["declared_version"] for bundle in bundles}, {"2026.2.13", "2026.2.14"})


if __name__ == "__main__":
    unittest.main()
