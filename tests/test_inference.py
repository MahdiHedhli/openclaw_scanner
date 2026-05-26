import unittest

from openclaw_scanner.inference import (
    correlate_vulnerabilities,
    infer_fingerprint_matches,
    infer_product_confidence,
    infer_versions,
    load_rules,
)
from openclaw_scanner.models import ProbeObservation


class InferenceTests(unittest.TestCase):
    def test_direct_version_hint_maps_to_vulnerabilities(self):
        rules = load_rules(None)
        observations = {
            "/": ProbeObservation(
                path="/",
                url="https://example.test/",
                status=200,
                title="OpenClaw",
                body_markers=["openclaw"],
                version_hints=["2026.2.13"],
            )
        }

        versions = infer_versions(observations, rules)
        vulns = correlate_vulnerabilities(versions, rules)

        self.assertTrue(any(match.version == "2026.2.13" for match in versions))
        vuln_ids = {vuln.id for vuln in vulns}
        self.assertIn("CVE-2026-26329", vuln_ids)
        self.assertIn("CVE-2026-26322", vuln_ids)
        self.assertNotIn("CVE-2026-32063", vuln_ids)

    def test_direct_version_hint_accepts_dotted_prerelease_suffix(self):
        rules = load_rules(None)
        observations = {
            "/": ProbeObservation(
                path="/",
                url="https://example.test/",
                status=200,
                js_files=["/static/openclaw-2026.5.19-beta.1.js"],
            )
        }

        versions = infer_versions(observations, rules)

        self.assertTrue(any(
            match.version == "2026.5.19-beta.1"
            and match.source == "direct_version_hint"
            and match.exact
            for match in versions
        ))

    def test_lab_promoted_version_rules_match_bundled_assets(self):
        rules = load_rules(None)
        cases = [
            ("2026.5.7", "./assets/index-NYVkUQrq.js"),
            ("2026.5.18", "./assets/index-quv2B8bV.js"),
            ("2026.5.19-beta.1", "./assets/index-B9aIykxh.js"),
            ("2026.5.20", "./assets/index-DIlhMoR6.js"),
        ]

        for expected_version, asset_name in cases:
            with self.subTest(version=expected_version):
                observations = {
                    "/": ProbeObservation(
                        path="/",
                        url="http://example.test/",
                        status=200,
                        js_files=[asset_name],
                    ),
                    "/ws": ProbeObservation(
                        path="/ws",
                        url="http://example.test/ws",
                        status=200,
                        js_files=[asset_name],
                    ),
                    "/v1/models": ProbeObservation(
                        path="/v1/models",
                        url="http://example.test/v1/models",
                        status=200,
                        js_files=[asset_name],
                    ),
                }

                versions = infer_versions(observations, rules)

                self.assertTrue(any(
                    match.version == expected_version
                    and match.source == f"lab-capture-{expected_version.replace('.', '-').replace('-beta-', '-beta-')}"
                    and match.exact
                    for match in versions
                ))

    def test_lab_promoted_2026_5_22_rule_matches_stable_signals(self):
        rules = load_rules(None)
        asset_name = "./assets/index-BtIuF4zW.js"
        observations = {
            "/": ProbeObservation(
                path="/",
                url="http://example.test/",
                status=200,
                js_files=[asset_name],
                body_sha256="c329016b3319a0ab0eaa9315b4413197823adcd0b5c21126d67d83ea34431dff",
            ),
            "/login": ProbeObservation(
                path="/login",
                url="http://example.test/login",
                status=200,
                js_files=[asset_name],
            ),
        }

        versions = infer_versions(observations, rules)

        self.assertTrue(any(
            match.version == "2026.5.22"
            and match.source == "lab-capture-2026-5-22"
            and match.exact
            for match in versions
        ))

    def test_range_with_hyphenated_version(self):
        rules = load_rules(None)
        observations = {
            "/api/version": ProbeObservation(
                path="/api/version",
                url="https://example.test/api/version",
                status=200,
                headers={"x-openclaw-version": "2026.2.20"},
                version_hints=["2026.2.20"],
            )
        }

        versions = infer_versions(observations, rules)
        vulns = correlate_vulnerabilities(versions, rules)
        vuln_ids = {vuln.id for vuln in vulns}
        self.assertIn("CVE-2026-32063", vuln_ids)

    def test_platform_specific_vulnerabilities_are_filtered_when_platform_mismatches(self):
        rules = load_rules(None)
        observations = {
            "/api/version": ProbeObservation(
                path="/api/version",
                url="https://example.test/api/version",
                status=200,
                version_hints=["2026.2.18"],
            )
        }

        versions = infer_versions(observations, rules)
        linux_vulns = correlate_vulnerabilities(versions, rules, platform="linux")
        unknown_vulns = correlate_vulnerabilities(versions, rules, platform=None)

        linux_ids = {vuln.id for vuln in linux_vulns}
        unknown_matches = {vuln.id: vuln for vuln in unknown_vulns}

        self.assertNotIn("CVE-2026-22176", linux_ids)
        self.assertIn("CVE-2026-22176", unknown_matches)
        self.assertLessEqual(unknown_matches["CVE-2026-22176"].confidence, 0.55)

    def test_recent_cve_batch_entries_map_to_matching_versions(self):
        rules = load_rules(None)
        observations = {
            "/api/version": ProbeObservation(
                path="/api/version",
                url="https://example.test/api/version",
                status=200,
                version_hints=["2026.2.16"],
            )
        }

        versions = infer_versions(observations, rules)
        vulns = correlate_vulnerabilities(versions, rules)
        vuln_ids = {vuln.id for vuln in vulns}

        self.assertIn("CVE-2026-32896", vuln_ids)
        self.assertIn("CVE-2026-32061", vuln_ids)

    def test_infers_ui_only_fingerprint_family(self):
        rules = load_rules(None)
        observations = {
            "/": ProbeObservation(
                path="/",
                url="http://example.test/",
                status=200,
                title="OpenClaw Control",
                headers={"content-type": "text/html; charset=utf-8"},
                body_markers=["openclaw"],
            ),
            "/login": ProbeObservation(
                path="/login",
                url="http://example.test/login",
                status=200,
                headers={"content-type": "text/html; charset=utf-8"},
            ),
            "/api": ProbeObservation(
                path="/api",
                url="http://example.test/api",
                status=404,
                headers={"content-type": "text/plain; charset=utf-8"},
                body_sha256="0019dfc4b32d63c1392aa264aed2253c1e0c2fb09216f8e2cc269bbfb8bb49b5",
            ),
            "/api/version": ProbeObservation(
                path="/api/version",
                url="http://example.test/api/version",
                status=404,
                headers={"content-type": "text/plain; charset=utf-8"},
                body_sha256="0019dfc4b32d63c1392aa264aed2253c1e0c2fb09216f8e2cc269bbfb8bb49b5",
            ),
            "/health": ProbeObservation(
                path="/health",
                url="http://example.test/health",
                status=200,
                headers={"content-type": "application/json; charset=utf-8"},
                body_sha256="6191c1f860b8a0225c697e46ebce756193dfb18c189218cfe742037501da05eb",
                json_keys=["ok", "status"],
            ),
        }

        matches = infer_fingerprint_matches(observations, rules)

        self.assertTrue(matches)
        self.assertEqual(matches[0].family, "openclaw_ui_only_404_api")

    def test_path_scoped_rules_do_not_match_when_path_is_missing(self):
        rules = {
            "fingerprint_rules": [
                {
                    "id": "missing-path-test",
                    "family": "should_not_match",
                    "confidence": 0.99,
                    "all": [
                        {
                            "type": "title_contains",
                            "path": "/api/version",
                            "value": "OpenClaw Control",
                        }
                    ],
                }
            ]
        }
        observations = {
            "/": ProbeObservation(
                path="/",
                url="http://example.test/",
                status=200,
                title="OpenClaw Control",
            )
        }

        matches = infer_fingerprint_matches(observations, rules)

        self.assertEqual(matches, [])

    def test_method_aware_error_conditions_can_match(self):
        rules = {
            "fingerprint_rules": [
                {
                    "id": "post-error-family",
                    "family": "openclaw_post_error_family",
                    "confidence": 0.88,
                    "all": [
                        {
                            "type": "method_status",
                            "path": "/api/doesnotexist",
                            "method": "POST",
                            "statuses": [404],
                        },
                        {
                            "type": "body_contains",
                            "path": "/api/doesnotexist",
                            "method": "POST",
                            "value": "cannot post",
                        },
                        {
                            "type": "error_pattern",
                            "path": "/api/doesnotexist",
                            "method": "POST",
                            "value": r"cannot post\s+/api/doesnotexist",
                        },
                        {
                            "type": "header_order",
                            "path": "/api/doesnotexist",
                            "method": "POST",
                            "value": "x-powered-by|content-type|content-length",
                        },
                    ],
                }
            ]
        }
        observations = {
            "POST /api/doesnotexist": ProbeObservation(
                path="/api/doesnotexist",
                url="http://example.test/api/doesnotexist",
                method="POST",
                status=404,
                header_order=["x-powered-by", "content-type", "content-length"],
                error_text="Cannot POST /api/doesnotexist",
            )
        }

        matches = infer_fingerprint_matches(observations, rules)

        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].family, "openclaw_post_error_family")

    def test_path_status_not_condition_matches_non_404_endpoint(self):
        rules = {
            "fingerprint_rules": [
                {
                    "id": "openclaw-endpoint-exists",
                    "family": "openclaw_non_404_endpoint",
                    "confidence": 0.7,
                    "all": [
                        {
                            "type": "path_status_not",
                            "path": "/api/skills",
                            "statuses": [404],
                        }
                    ],
                }
            ]
        }
        observations = {
            "/api/skills": ProbeObservation(
                path="/api/skills",
                url="http://example.test/api/skills",
                status=401,
            )
        }

        matches = infer_fingerprint_matches(observations, rules)

        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].family, "openclaw_non_404_endpoint")

    def test_favicon_hash_rule_matches(self):
        rules = {
            "fingerprint_rules": [
                {
                    "id": "favicon-default",
                    "family": "openclaw_default_favicon",
                    "confidence": 0.84,
                    "all": [
                        {
                            "type": "favicon_hash",
                            "path": "/favicon.ico",
                            "value": 123456789,
                        }
                    ],
                }
            ]
        }
        observations = {
            "/favicon.ico": ProbeObservation(
                path="/favicon.ico",
                url="http://example.test/favicon.ico",
                status=200,
                favicon_hash=123456789,
            )
        }

        matches = infer_fingerprint_matches(observations, rules)

        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].family, "openclaw_default_favicon")

    def test_websocket_upgrade_conditions_match_upgrade_probe(self):
        rules = {
            "fingerprint_rules": [
                {
                    "id": "ws-upgrade-family",
                    "family": "openclaw_ws_gateway",
                    "confidence": 0.86,
                    "all": [
                        {
                            "type": "ws_upgrade_supported",
                            "path": "/ws",
                            "probe_name": "ws-upgrade",
                            "value": True,
                        },
                        {
                            "type": "ws_upgrade_status",
                            "path": "/ws",
                            "probe_name": "ws-upgrade",
                            "statuses": [101],
                        },
                        {
                            "type": "ws_subprotocol_contains",
                            "path": "/ws",
                            "probe_name": "ws-upgrade",
                            "value": "openclaw",
                        },
                        {
                            "type": "ws_extension_contains",
                            "path": "/ws",
                            "probe_name": "ws-upgrade",
                            "value": "permessage-deflate",
                        },
                    ],
                }
            ]
        }
        observations = {
            "WS-UPGRADE /ws": ProbeObservation(
                path="/ws",
                url="http://example.test/ws",
                method="GET",
                probe_name="ws-upgrade",
                status=101,
                headers={
                    "sec-websocket-protocol": "openclaw-gateway-v1",
                    "sec-websocket-extensions": "permessage-deflate",
                },
            )
        }

        matches = infer_fingerprint_matches(observations, rules)

        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].family, "openclaw_ws_gateway")

    def test_tools_invoke_auth_json_is_treated_as_gateway_signal(self):
        rules = load_rules(None)
        observations = {
            "/": ProbeObservation(
                path="/",
                url="http://example.test/",
                status=200,
                title="OpenClaw Control",
            ),
            "POST /tools/invoke": ProbeObservation(
                path="/tools/invoke",
                url="http://example.test/tools/invoke",
                method="POST",
                status=401,
                headers={"content-type": "application/json; charset=utf-8"},
                content_type="application/json; charset=utf-8",
                json_keys=["error"],
                error_text='{"error":{"message":"Unauthorized","type":"unauthorized"}}',
            ),
        }

        confidence = infer_product_confidence(observations, rules)
        matches = infer_fingerprint_matches(observations, rules)
        families = {match.family for match in matches}

        self.assertGreaterEqual(confidence, 0.60)
        self.assertIn("claw_gateway_tools_invoke_auth_json", families)

    def test_openai_chat_surface_rule_matches_structured_auth_response(self):
        rules = load_rules(None)
        observations = {
            "/": ProbeObservation(
                path="/",
                url="http://example.test/",
                status=200,
                title="OpenClaw Control",
                body_markers=["openclaw"],
            ),
            "POST /v1/chat/completions": ProbeObservation(
                path="/v1/chat/completions",
                url="http://example.test/v1/chat/completions",
                method="POST",
                status=401,
                headers={"content-type": "application/json; charset=utf-8"},
                content_type="application/json; charset=utf-8",
                json_keys=["error"],
                error_text='{"error":{"message":"Unauthorized","type":"unauthorized"}}',
            ),
            "POST /tools/invoke": ProbeObservation(
                path="/tools/invoke",
                url="http://example.test/tools/invoke",
                method="POST",
                status=401,
                headers={"content-type": "application/json; charset=utf-8"},
                content_type="application/json; charset=utf-8",
                json_keys=["error"],
                error_text='{"error":{"message":"Unauthorized","type":"unauthorized"}}',
            ),
        }

        matches = infer_fingerprint_matches(observations, rules)
        families = {match.family for match in matches}

        self.assertIn("openclaw_openai_chat_surface_enabled", families)


if __name__ == "__main__":
    unittest.main()
