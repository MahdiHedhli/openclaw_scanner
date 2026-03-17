import unittest

from openclaw_scanner.inference import correlate_vulnerabilities, infer_versions, load_rules
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


if __name__ == "__main__":
    unittest.main()
