import unittest
from unittest.mock import patch

from openclaw_scanner import cli
from openclaw_scanner.cdp import ChromiumWindowRule, cdp_version_candidates
from openclaw_scanner.inference import (
    correlate_vulnerabilities,
    infer_fingerprint_matches,
    infer_versions,
    load_rules,
    mdns_version_candidates,
)
from openclaw_scanner.models import ProbeObservation, ScanTarget, VersionMatch
from openclaw_scanner.versions import (
    find_package_version,
    find_versions,
    find_versions_near_markers,
    is_exact_version,
)


def make_rules():
    return {
        "version_rules": [
            {
                "id": "lab-2026-2-13",
                "version": "2026.2.13",
                "exact": True,
                "confidence": 0.9,
                "all": [
                    {
                        "type": "script_contains",
                        "path": "/",
                        "value": "dashboard.deadbeef.js",
                    }
                ],
            }
        ],
        "vulnerabilities": [
            {
                "id": "CVE-TEST-0001",
                "title": "Test pre-2026.3 issue",
                "severity": "high",
                "affected_ranges": [{"lt": "2026.3.0"}],
            }
        ],
    }


class VersionGrammarTests(unittest.TestCase):
    def test_numeric_build_suffixes_are_preserved(self):
        found = find_versions("2026.2.2-1 and 2026.2.2-3 are distinct")

        self.assertIn("2026.2.2-1", found)
        self.assertIn("2026.2.2-3", found)
        self.assertNotIn("2026.2.2", found)

    def test_prerelease_counter_is_preserved(self):
        found = find_versions("OpenClaw 2026.5.19-beta.1")

        self.assertEqual(found, ["2026.5.19-beta.1"])
        self.assertTrue(is_exact_version("2026.5.19-beta.1"))

    def test_marker_anchored_live_finder_preserves_suffix(self):
        self.assertEqual(
            find_versions_near_markers("clawdbot build 2026.2.2-1"),
            ["2026.2.2-1"],
        )

    def test_package_version_extraction_preserves_numeric_suffix(self):
        cli_path = (
            "/root/.pnpm/clawdbot@2026.2.2-1_"
            "devtools-protocol@0.0.1575685/node_modules/clawdbot/dist/entry.js"
        )

        self.assertEqual(find_package_version(cli_path), "2026.2.2-1")


class EvidenceFlowTests(unittest.TestCase):
    def test_raw_passive_banner_text_does_not_correlate_vulnerabilities(self):
        rules = make_rules()
        raw_record = {
            "ip_str": "203.0.113.10",
            "port": 443,
            "http": {
                "status": 200,
                "title": "OpenClaw Control",
                "html": "<html>OpenClaw build 2026.2.2</html>",
            },
        }
        observations = cli._observations_from_shodan_record(raw_record)

        versions = infer_versions(observations, rules)
        candidate = next(match for match in versions if match.version == "2026.2.2")

        self.assertEqual(candidate.source, "passive_banner_text")
        self.assertFalse(candidate.exact)
        self.assertFalse(candidate.correlate)
        self.assertEqual(correlate_vulnerabilities(versions, rules), [])

    def test_explicit_mdns_cli_path_package_version_correlates(self):
        rules = make_rules()
        versions = mdns_version_candidates(
            {
                "mdns_version": "2026.2.2-1",
                "mdns_version_source": "cli_path_package",
            }
        )

        self.assertEqual(len(versions), 1)
        self.assertEqual(versions[0].source, "mdns_cli_path")
        self.assertTrue(versions[0].exact)
        self.assertTrue(versions[0].correlate)
        self.assertTrue(correlate_vulnerabilities(versions, rules))

    def test_generic_mdns_txt_version_does_not_correlate(self):
        versions = mdns_version_candidates(
            {"mdns_version": "2026.2.2-1", "mdns_version_source": "txt"}
        )

        self.assertEqual(len(versions), 1)
        self.assertEqual(versions[0].source, "mdns_txt")
        self.assertFalse(versions[0].exact)
        self.assertFalse(versions[0].correlate)
        self.assertEqual(correlate_vulnerabilities(versions, make_rules()), [])

    def test_mdns_version_survives_rescan_shodan(self):
        target = ScanTarget(
            label="203.0.113.10:18789",
            source="shodan",
            candidates=["https://203.0.113.10:18789"],
            metadata={
                "mdns_version": "2026.2.2-1",
                "mdns_version_source": "cli_path_package",
            },
            raw_record={"ip_str": "203.0.113.10", "port": 18789},
        )
        observation = ProbeObservation(
            path="/",
            url="https://203.0.113.10:18789/",
            status=200,
            title="OpenClaw Control",
            body_markers=["openclaw"],
        )

        with patch("openclaw_scanner.cli.probe_candidate", return_value=({"/": observation}, [])):
            result = cli._scan_single_target(
                target=target,
                rules=make_rules(),
                probe_configs=["/"],
                timeout=1.0,
                max_bytes=1024,
                verify_tls=False,
                user_agent="openclaw-scanner/test",
                rescan_shodan=True,
            )

        promoted = next(
            match for match in result.matched_versions if match.source == "mdns_cli_path"
        )
        self.assertEqual(promoted.version, "2026.2.2-1")
        self.assertTrue(promoted.correlate)
        self.assertTrue(result.vulnerability_matches)

    def test_cdp_approximate_window_never_correlates(self):
        rules = make_rules()
        observations = {
            "/json/version": ProbeObservation(
                path="/json/version",
                url="https://example.test/json/version",
                status=200,
                cdp={
                    "engine": "HeadlessChrome",
                    "chromium_version": "120.0.6099.109",
                    "headless": "true",
                    "protocol_version": "1.3",
                },
            )
        }
        windows = cdp_version_candidates(
            observations,
            {},
            rules=[
                ChromiumWindowRule(
                    version="2026.1.x",
                    confidence=0.6,
                    chromium_major_min=120,
                    chromium_major_max=120,
                )
            ],
        )

        self.assertTrue(windows)
        self.assertTrue(all(not match.exact for match in windows))
        self.assertTrue(all(not match.correlate for match in windows))
        self.assertEqual(correlate_vulnerabilities(windows, rules), [])

    def test_cdp_only_exposed_chrome_stays_generic(self):
        rules = load_rules(None)
        observations = {
            "/json/version": ProbeObservation(
                path="/json/version",
                url="https://example.test/json/version",
                status=200,
                json_keys=["Browser", "Protocol-Version", "webSocketDebuggerUrl"],
                cdp={
                    "present": "true",
                    "browser_family": "Chromium",
                    "engine": "HeadlessChrome",
                    "chromium_version": "120.0.6099.109",
                    "headless": "true",
                    "protocol_version": "1.3",
                    "debugger_url_present": "true",
                },
            )
        }

        families = {match.family for match in infer_fingerprint_matches(observations, rules)}
        merged = cli._merge_version_matches(
            infer_versions(observations, rules),
            cdp_version_candidates(
                observations,
                {},
                rules=[
                    ChromiumWindowRule(
                        version="2026.1.x",
                        confidence=0.6,
                        chromium_major_min=120,
                        chromium_major_max=120,
                    )
                ],
            ),
        )

        self.assertIn("chromium_devtools_exposed", families)
        self.assertNotIn("openclaw_cdp_devtools_exposed", families)
        self.assertFalse(any(match.exact for match in merged))
        self.assertEqual(correlate_vulnerabilities(merged, rules), [])

    def test_cdp_plus_openclaw_marker_can_match_openclaw_family(self):
        rules = load_rules(None)
        observations = {
            "/": ProbeObservation(
                path="/",
                url="https://example.test/",
                status=200,
                title="OpenClaw Control",
                body_markers=["openclaw"],
            ),
            "/json/version": ProbeObservation(
                path="/json/version",
                url="https://example.test/json/version",
                status=200,
                json_keys=["Browser", "Protocol-Version", "webSocketDebuggerUrl"],
                cdp={
                    "present": "true",
                    "browser_family": "Chromium",
                    "engine": "HeadlessChrome",
                    "chromium_version": "120.0.6099.109",
                    "headless": "true",
                    "protocol_version": "1.3",
                    "debugger_url_present": "true",
                },
            ),
        }

        families = {match.family for match in infer_fingerprint_matches(observations, rules)}

        self.assertIn("chromium_devtools_exposed", families)
        self.assertIn("openclaw_cdp_devtools_exposed", families)

    def test_exact_lab_rule_outranks_cdp_window(self):
        exact = VersionMatch(
            version="2026.2.13",
            confidence=0.9,
            source="lab-2026-2-13",
            exact=True,
            correlate=True,
        )
        cdp_window = VersionMatch(
            version="2026.1.x",
            confidence=0.7,
            source="cdp_chromium_window",
            exact=False,
            correlate=False,
        )

        merged = cli._merge_version_matches([cdp_window], [exact])

        self.assertEqual(merged[0].version, "2026.2.13")
        self.assertTrue(correlate_vulnerabilities(merged, make_rules()))


if __name__ == "__main__":
    unittest.main()
