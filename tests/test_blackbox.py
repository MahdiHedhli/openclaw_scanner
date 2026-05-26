import json
import tempfile
import unittest
from pathlib import Path

from openclaw_scanner.blackbox import (
    build_capture_bundle,
    generate_rule_suggestions,
    load_capture_bundle_inputs,
    load_capture_bundles,
    render_rule_suggestions,
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
                "WS-UPGRADE /ws": ProbeObservation(
                    path="/ws",
                    url="http://198.51.100.10:18789/ws",
                    method="GET",
                    probe_name="ws-upgrade",
                    status=101,
                    headers={
                        "sec-websocket-protocol": "openclaw-gateway",
                        "sec-websocket-extensions": "permessage-deflate",
                    },
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
        self.assertIn("ws_upgrade_status|/ws|101", signals)
        self.assertIn("ws_upgrade_supported|/ws|true", signals)
        self.assertIn("ws_subprotocol_contains|/ws|openclaw-gateway", signals)
        self.assertIn("ws_extension_contains|/ws|permessage-deflate", signals)

    def test_generate_rule_suggestions_prefers_unique_stable_signals(self):
        version_a_bundle = {
            "bundle_type": "openclaw_blackbox_capture",
            "declared_version": "2026.2.13",
            "captures": [
                {
                    "signals": [
                        "title_contains|/|OpenClaw Control",
                        "script_contains|/|/static/dashboard.2026.2.13.js",
                        "ws_upgrade_status|/ws|101",
                        "path_status|/api/version|404",
                    ]
                },
                {
                    "signals": [
                        "title_contains|/|OpenClaw Control",
                        "script_contains|/|/static/dashboard.2026.2.13.js",
                        "ws_upgrade_status|/ws|101",
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
                        "ws_upgrade_status|/ws|403",
                        "path_status|/api/version|200",
                    ]
                },
                {
                    "signals": [
                        "title_contains|/|OpenClaw Control",
                        "script_contains|/|/static/dashboard.2026.2.14.js",
                        "ws_upgrade_status|/ws|403",
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
        similarity = first["similarity"]
        self.assertEqual(similarity["intra_version_pair_count"], 1)
        self.assertEqual(similarity["intra_version_avg_jaccard"], 1.0)
        self.assertEqual(similarity["nearest_other_version"], "2026.2.14")
        self.assertAlmostEqual(similarity["nearest_other_jaccard"], 0.1429)
        promotion = first["promotion"]
        self.assertTrue(promotion["ready_for_review"])
        self.assertEqual(promotion["status"], "review_candidate")
        self.assertEqual(promotion["blockers"], [])
        rule = first["candidate_rule"]
        self.assertEqual(rule["version"], "2026.2.13")
        self.assertTrue(any(
            condition["type"] == "script_contains"
            and condition["value"] == "/static/dashboard.2026.2.13.js"
            for condition in rule["all"]
        ))
        self.assertTrue(any(
            condition["type"] == "ws_upgrade_status"
            and condition["path"] == "/ws"
            and condition["statuses"] == [101]
            and condition["probe_name"] == "ws-upgrade"
            for condition in rule["all"]
        ))

    def test_generate_rule_suggestions_allows_unique_rules_for_similar_family_surfaces(self):
        common_signals = [
            f"path_status|/shared-{index}|200"
            for index in range(20)
        ]
        version_a_bundle = {
            "bundle_type": "openclaw_blackbox_capture",
            "declared_version": "2026.5.19-beta.1",
            "captures": [
                {"signals": common_signals + ["script_contains|/|./assets/index-beta.js"]},
                {"signals": common_signals + ["script_contains|/|./assets/index-beta.js"]},
            ],
        }
        version_b_bundle = {
            "bundle_type": "openclaw_blackbox_capture",
            "declared_version": "2026.5.18",
            "captures": [
                {"signals": common_signals + ["script_contains|/|./assets/index-stable.js"]},
                {"signals": common_signals + ["script_contains|/|./assets/index-stable.js"]},
            ],
        }

        report = generate_rule_suggestions(
            [version_a_bundle, version_b_bundle],
            max_conditions=1,
        )

        beta = next(item for item in report["versions"] if item["version"] == "2026.5.19-beta.1")
        self.assertEqual(beta["similarity"]["nearest_other_jaccard"], 0.9091)
        promotion = beta["promotion"]
        self.assertTrue(promotion["ready_for_review"])
        self.assertEqual(promotion["status"], "review_candidate")
        self.assertEqual(promotion["blockers"], [])
        self.assertTrue(any("selected stable unique signals distinguish it" in reason for reason in promotion["reasons"]))
        rule = beta["candidate_rule"]
        self.assertTrue(rule["exact"])
        self.assertTrue(any(
            condition["type"] == "script_contains"
            and condition["value"] == "./assets/index-beta.js"
            for condition in rule["all"]
        ))

    def test_generate_rule_suggestions_marks_numeric_suffix_versions_exact(self):
        bundle = {
            "bundle_type": "openclaw_blackbox_capture",
            "declared_version": "2026.2.2-1",
            "captures": [
                {"signals": ["script_contains|/|./assets/index-CYRpW51H.js"]},
                {"signals": ["script_contains|/|./assets/index-CYRpW51H.js"]},
            ],
        }

        report = generate_rule_suggestions([bundle], max_conditions=1)

        version = report["versions"][0]
        self.assertEqual(version["version"], "2026.2.2-1")
        self.assertTrue(version["candidate_rule"]["exact"])

    def test_generate_rule_suggestions_allows_moderate_noise_when_selected_signals_are_stable(self):
        common_signals = [
            f"path_status|/shared-{index}|200"
            for index in range(20)
        ]
        version_a_bundle = {
            "bundle_type": "openclaw_blackbox_capture",
            "declared_version": "2026.5.18",
            "captures": [
                {
                    "signals": common_signals
                    + ["script_contains|/|./assets/index-stable.js"]
                    + ["path_status|/sometimes-a|404", "path_status|/sometimes-b|404", "path_status|/sometimes-c|404"]
                },
                {
                    "signals": common_signals
                    + ["script_contains|/|./assets/index-stable.js"]
                    + ["path_status|/sometimes-d|404", "path_status|/sometimes-e|404", "path_status|/sometimes-f|404"]
                },
            ],
        }
        version_b_bundle = {
            "bundle_type": "openclaw_blackbox_capture",
            "declared_version": "2026.5.7",
            "captures": [
                {"signals": common_signals + ["script_contains|/|./assets/index-old.js"]},
                {"signals": common_signals + ["script_contains|/|./assets/index-old.js"]},
            ],
        }

        report = generate_rule_suggestions(
            [version_a_bundle, version_b_bundle],
            max_conditions=1,
        )

        stable = next(item for item in report["versions"] if item["version"] == "2026.5.18")
        self.assertEqual(stable["similarity"]["intra_version_min_jaccard"], 0.7778)
        promotion = stable["promotion"]
        self.assertTrue(promotion["ready_for_review"])
        self.assertEqual(promotion["status"], "review_candidate")
        self.assertEqual(promotion["blockers"], [])
        self.assertTrue(any("selected stable unique signals remained" in reason for reason in promotion["reasons"]))

    def test_load_capture_bundles_accepts_directory(self):
        bundle_a = {"bundle_type": "openclaw_blackbox_capture", "declared_version": "2026.2.13", "captures": []}
        bundle_b = {"bundle_type": "openclaw_blackbox_capture", "declared_version": "2026.2.14", "captures": []}

        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "a.json").write_text('{"bundle_type":"openclaw_blackbox_capture","declared_version":"2026.2.13","captures":[]}', encoding="utf-8")
            Path(tmpdir, "b.json").write_text('{"bundle_type":"openclaw_blackbox_capture","declared_version":"2026.2.14","captures":[]}', encoding="utf-8")
            bundles = load_capture_bundles(tmpdir)

        self.assertEqual(len(bundles), 2)
        self.assertEqual({bundle["declared_version"] for bundle in bundles}, {"2026.2.13", "2026.2.14"})

    def test_load_capture_bundles_recurses_lab_layout_and_skips_non_capture_json(self):
        bundle_a = {
            "bundle_type": "openclaw_blackbox_capture",
            "declared_version": "2026.2.13",
            "captures": [],
        }
        bundle_b = {
            "bundle_type": "openclaw_blackbox_capture",
            "declared_version": "2026.2.14",
            "captures": [],
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            Path(root, "manifest.json").write_text(
                '{"schema_version":1,"vms":[]}',
                encoding="utf-8",
            )
            Path(root, "candidate-version-rules.json").write_text(
                '{"bundle_type":"openclaw_blackbox_rule_suggestions","versions":[]}',
                encoding="utf-8",
            )
            Path(root, "partial.json").write_text(
                '{"bundle_type":',
                encoding="utf-8",
            )
            Path(root, "openclaw-2026.2.13").mkdir()
            Path(root, "openclaw-2026.2.14").mkdir()
            Path(root, "openclaw-2026.2.13", "capture.json").write_text(
                json.dumps(bundle_a),
                encoding="utf-8",
            )
            Path(root, "openclaw-2026.2.14", "capture.json").write_text(
                json.dumps(bundle_b),
                encoding="utf-8",
            )

            bundles = load_capture_bundles(tmpdir)
            bundles_with_report, skipped_inputs = load_capture_bundle_inputs(tmpdir)

        self.assertEqual(len(bundles), 2)
        self.assertEqual(
            {bundle["declared_version"] for bundle in bundles},
            {"2026.2.13", "2026.2.14"},
        )
        self.assertEqual(len(bundles_with_report), 2)
        self.assertEqual(
            {
                (item["path"], item["reason"])
                for item in skipped_inputs
            },
            {
                (
                    "candidate-version-rules.json",
                    "not an openclaw_blackbox_capture bundle",
                ),
                ("manifest.json", "not an openclaw_blackbox_capture bundle"),
                ("partial.json", "invalid JSON: Expecting value"),
            },
        )

    def test_generate_rule_suggestions_blocks_single_capture_promotion(self):
        bundle = {
            "bundle_type": "openclaw_blackbox_capture",
            "declared_version": "2026.2.13",
            "captures": [
                {
                    "signals": [
                        "title_contains|/|OpenClaw Control",
                        "script_contains|/|/static/dashboard.2026.2.13.js",
                    ]
                }
            ],
        }

        report = generate_rule_suggestions([bundle], max_conditions=2)

        promotion = report["versions"][0]["promotion"]
        self.assertFalse(promotion["ready_for_review"])
        self.assertEqual(promotion["status"], "needs_more_evidence")
        self.assertIn(
            "needs at least two captures for same-version stability",
            promotion["blockers"],
        )

    def test_render_rule_suggestions_reports_promotion_blockers(self):
        version_a_bundle = {
            "bundle_type": "openclaw_blackbox_capture",
            "declared_version": "2026.5.22-beta.1",
            "captures": [
                {
                    "signals": [
                        "script_contains|/|./assets/index-beta.js",
                        *[f"path_status|/volatile-a-{index}|200" for index in range(20)],
                    ]
                },
                {
                    "signals": [
                        "script_contains|/|./assets/index-beta.js",
                        *[f"path_status|/volatile-b-{index}|200" for index in range(20)],
                    ]
                },
            ],
        }
        version_b_bundle = {
            "bundle_type": "openclaw_blackbox_capture",
            "declared_version": "2026.5.20",
            "captures": [
                {"signals": ["script_contains|/|./assets/index-stable.js"]},
                {"signals": ["script_contains|/|./assets/index-stable.js"]},
            ],
        }

        report = generate_rule_suggestions(
            [version_a_bundle, version_b_bundle],
            max_conditions=1,
        )

        beta = next(item for item in report["versions"] if item["version"] == "2026.5.22-beta.1")
        self.assertEqual(beta["promotion"]["status"], "needs_more_evidence")
        self.assertIn(
            "intra-version Jaccard is low",
            beta["promotion"]["blockers"][0],
        )

        pretty = render_rule_suggestions(report, "pretty")
        self.assertIn("promotion blockers: intra-version Jaccard is low", pretty)

    def test_render_rule_suggestions_bounds_skipped_input_details(self):
        report = {
            "bundle_count": 0,
            "capture_entry_count": 0,
            "versions": [],
            "skipped_bundles": [],
            "skipped_inputs": [
                {
                    "path": f"artifact-{index}.json",
                    "reason": "not an openclaw_blackbox_capture bundle",
                }
                for index in range(14)
            ],
        }

        pretty = render_rule_suggestions(report, "pretty")

        self.assertIn(
            "Skipped input summary:\n  - 14 file(s): not an openclaw_blackbox_capture bundle",
            pretty,
        )
        self.assertIn("artifact-0.json", pretty)
        self.assertIn("artifact-11.json", pretty)
        self.assertNotIn("artifact-12.json", pretty)
        self.assertNotIn("artifact-13.json", pretty)
        self.assertIn("... 2 more skipped input file(s)", pretty)

    def test_generate_rule_suggestions_summarizes_skipped_inputs(self):
        report = generate_rule_suggestions(
            [],
            skipped_inputs=[
                {"path": "a.json", "reason": "not an openclaw_blackbox_capture bundle"},
                {"path": "b.json", "reason": "invalid JSON: Expecting value"},
                {"path": "c.json", "reason": "not an openclaw_blackbox_capture bundle"},
            ],
        )

        self.assertEqual(
            report["skipped_input_summary"],
            [
                {
                    "reason": "not an openclaw_blackbox_capture bundle",
                    "count": 2,
                },
                {
                    "reason": "invalid JSON: Expecting value",
                    "count": 1,
                },
            ],
        )

    def test_generate_rule_suggestions_reports_sanitized_capture_diagnostics(self):
        bundle = {
            "bundle_type": "openclaw_blackbox_capture",
            "declared_version": "2026.5.22-beta.1",
            "capture_name": "beta-lab",
            "captures": [
                {
                    "observations": {
                        "/": {"status": 200},
                        "/health": {"status": 200},
                    },
                    "errors": [
                        "http://10.0.30.127:18789 /status: timed out",
                        "http://10.0.30.127:18789 WS-UPGRADE /ws: timed out",
                        "http://10.0.30.127:18789 /favicon.ico: connection reset",
                    ],
                    "signals": [
                        "path_status|/|200",
                        "path_status|/health|200",
                    ],
                },
                {
                    "observations": {
                        "/": {"status": 200},
                    },
                    "errors": [],
                    "signals": [
                        "path_status|/|200",
                    ],
                },
            ],
        }

        report = generate_rule_suggestions([bundle], max_conditions=1)

        diagnostics = report["versions"][0]["capture_diagnostics"]
        self.assertEqual(diagnostics[0]["capture_index"], 1)
        self.assertEqual(diagnostics[0]["signal_count"], 2)
        self.assertEqual(diagnostics[0]["observation_count"], 2)
        self.assertEqual(diagnostics[0]["error_count"], 3)
        self.assertEqual(diagnostics[0]["timeout_error_count"], 2)
        self.assertEqual(
            diagnostics[0]["timeout_probe_labels"],
            ["/status", "WS-UPGRADE /ws"],
        )
        self.assertNotIn("10.0.30.127", json.dumps(diagnostics))

        pretty = render_rule_suggestions(report, "pretty")
        self.assertIn("capture diagnostics: #1", pretty)
        self.assertNotIn("10.0.30.127", pretty)


if __name__ == "__main__":
    unittest.main()
