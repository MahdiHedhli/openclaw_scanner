import unittest

from openclaw_scanner.inference import (
    correlate_vulnerabilities,
    infer_fingerprint_matches,
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


if __name__ == "__main__":
    unittest.main()
