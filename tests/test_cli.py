import csv
import io
import unittest
from unittest.mock import patch

from openclaw_scanner.cli import _observations_from_shodan_record, _scan_single_target, render_results
from openclaw_scanner.inference import (
    correlate_vulnerabilities,
    infer_fingerprint_matches,
    infer_versions,
    load_rules,
)
from openclaw_scanner.models import (
    FingerprintMatch,
    HoneypotAssessment,
    ProbeObservation,
    ProxyDetection,
    ScanResult,
    ScanTarget,
    VersionMatch,
    VulnerabilityMatch,
)


class CliTests(unittest.TestCase):
    def test_offline_shodan_observation_extracts_version(self):
        shodan_record = {
            "ip_str": "203.0.113.50",
            "port": 443,
            "version": "2026.2.13",
            "http": {
                "title": "OpenClaw Gateway",
                "headers": {
                    "content-type": "text/html"
                },
                "html": """
                    <html>
                      <head><title>OpenClaw Gateway</title></head>
                      <body>
                        <script src="/static/openclaw-2026.2.13.js"></script>
                        OpenClaw release 2026.2.13
                      </body>
                    </html>
                """
            }
        }
        rules = load_rules(None)
        observations = _observations_from_shodan_record(shodan_record)
        versions = infer_versions(observations, rules)
        vulns = correlate_vulnerabilities(versions, rules)

        self.assertTrue(any(match.version == "2026.2.13" for match in versions))
        self.assertTrue(any(vuln.id == "CVE-2026-26329" for vuln in vulns))

    def test_scan_single_target_adds_shodan_vuln_cross_reference(self):
        rules = load_rules(None)
        shodan_record = {
            "ip_str": "203.0.113.51",
            "port": 18789,
            "version": "2026.3.0",
            "product": "OpenClaw Gateway",
            "os": "Windows",
            "vulns": {"CVE-2026-32051": {}},
            "http": {
                "title": "OpenClaw Control",
                "html": "OpenClaw version 2026.3.0",
            },
        }
        target = ScanTarget(
            label="203.0.113.51:18789",
            source="shodan",
            candidates=["https://203.0.113.51:18789"],
            metadata={
                "platform": "windows",
                "shodan_vulns": ["CVE-2026-32051"],
                "shodan_product": "OpenClaw Gateway",
            },
            raw_record=shodan_record,
        )

        result = _scan_single_target(
            target=target,
            rules=rules,
            probe_configs=["/"],
            timeout=1.0,
            max_bytes=1024,
            verify_tls=False,
            user_agent="openclaw-scanner/test",
            rescan_shodan=False,
        )

        self.assertIn("shodan_vuln_reference", result.metadata)
        self.assertIn("CVE-2026-32051", result.metadata["shodan_vuln_reference"]["confirmed"])

    def test_offline_mdns_observation_extracts_gateway_version_suffix(self):
        shodan_record = {
            "ip_str": "203.0.113.60",
            "port": 5353,
            "product": "mDNS",
            "data": "mDNS record",
            "mdns": {
                "services": {
                    "18789/tcp clawdbot-gw": {
                        "name": "moltbot-gateway (Clawdbot)",
                        "data": [
                            "role=gateway",
                            "cliPath=/root/.local/share/pnpm/global/5/.pnpm/clawdbot@2026.1.24-3_@types+express/node_modules/clawdbot/dist/entry.js"
                        ],
                        "ptr": "_clawdbot-gw._tcp.local"
                    }
                }
            }
        }
        rules = load_rules(None)
        observations = _observations_from_shodan_record(shodan_record)
        versions = infer_versions(observations, rules)

        self.assertTrue(any(match.version == "2026.1.24-3" for match in versions))
        self.assertGreaterEqual(observations["/__shodan__"].status, 200)

    def test_offline_mdns_observation_matches_passive_gateway_family(self):
        shodan_record = {
            "ip_str": "203.0.113.61",
            "port": 5353,
            "product": "mDNS",
            "mdns": {
                "services": {
                    "18789/tcp openclaw-gw": {
                        "name": "demo (OpenClaw)",
                        "data": [
                            "role=gateway",
                            "gatewayPort=18789",
                            "lanHost=openclaw.local",
                            "transport=gateway",
                        ],
                        "ptr": "_openclaw-gw._tcp.local",
                    }
                },
                "answers": {
                    "PTR": ["_openclaw-gw._tcp.local"],
                },
            },
        }
        rules = load_rules(None)
        observations = _observations_from_shodan_record(shodan_record)
        matches = infer_fingerprint_matches(observations, rules)

        self.assertTrue(
            any(match.family == "openclaw_mdns_gateway_advertisement" for match in matches)
        )
        self.assertIn("mdns_openclaw_gw", observations["/__shodan__"].body_markers)

    def test_offline_shodan_observation_extracts_favicon_hash(self):
        shodan_record = {
            "ip_str": "203.0.113.70",
            "port": 18789,
            "http": {
                "title": "OpenClaw Control",
                "headers": {"content-type": "text/html"},
                "favicon": {"hash": "-1205140012"},
                "html": "<html><head><title>OpenClaw Control</title></head></html>",
            },
        }

        observations = _observations_from_shodan_record(shodan_record)

        self.assertEqual(observations["/__shodan__"].favicon_hash, -1205140012)

    def test_scan_single_target_keeps_errors_for_all_candidate_schemes(self):
        rules = load_rules(None)
        target = ScanTarget(
            label="198.51.100.10:18789",
            source="direct",
            candidates=[
                "https://198.51.100.10:18789",
                "http://198.51.100.10:18789",
            ],
        )
        first_observations = {
            "/": ProbeObservation(path="/", url="https://198.51.100.10:18789/")
        }
        second_observations = {
            "/": ProbeObservation(path="/", url="http://198.51.100.10:18789/")
        }

        with patch(
            "openclaw_scanner.cli.probe_candidate",
            side_effect=[
                (first_observations, ["/: timed out"]),
                (second_observations, ["/: [Errno 61] Connection refused"]),
            ],
        ):
            result = _scan_single_target(
                target=target,
                rules=rules,
                probe_configs=["/"],
                timeout=1.0,
                max_bytes=1024,
                verify_tls=False,
                user_agent="openclaw-scanner/test",
                rescan_shodan=False,
            )

        self.assertEqual(
            result.errors,
            [
                "https://198.51.100.10:18789 /: timed out",
                "http://198.51.100.10:18789 /: [Errno 61] Connection refused",
            ],
        )

    def test_render_results_csv_emits_summary_row(self):
        result = ScanResult(
            input_target="203.0.113.10:18789",
            source="shodan",
            probed_base="https://203.0.113.10:18789",
            metadata={
                "shodan_query": 'product:"mDNS" "clawdbot-gw"',
                "mdns_version": "2026.3.7",
            },
            product_confidence=0.75,
            observations={
                "/": ProbeObservation(
                    path="/",
                    url="https://203.0.113.10:18789/",
                    status=200,
                    body_markers=["openclaw"],
                )
            },
            proxy_detection=ProxyDetection(
                detected=True,
                proxy_type="cloudflare",
                confidence=0.95,
                indicators=["/: cf-ray=abc123-IAD"],
            ),
            honeypot_assessment=HoneypotAssessment(
                probable=True,
                probability=0.91,
                known_signature="cowrie",
                signals=["matched known honeypot signature: cowrie"],
            ),
            fingerprint_matches=[
                FingerprintMatch(
                    family="openclaw_ui_only_404_api",
                    confidence=0.93,
                    source="openclaw-ui-only-404-api",
                    label="OpenClaw UI-only gateway with JSON /health and 404 API paths",
                )
            ],
            matched_versions=[
                VersionMatch(
                    version="2026.1.24-3",
                    confidence=0.97,
                    source="direct_version_hint",
                    exact=True,
                )
            ],
            vulnerability_matches=[
                VulnerabilityMatch(
                    id="CVE-2026-24763",
                    title="Example vuln",
                    affected=True,
                    confidence=0.75,
                    reasoning="Example",
                    severity="HIGH",
                )
            ],
            errors=["https://203.0.113.10:18789 /login: timed out"],
        )

        rendered = render_results([result], "csv")
        reader = csv.DictReader(io.StringIO(rendered))
        rows = list(reader)

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["input_target"], "203.0.113.10:18789")
        self.assertEqual(rows[0]["top_fingerprint_family"], "openclaw_ui_only_404_api")
        self.assertEqual(rows[0]["top_version"], "2026.1.24-3")
        self.assertEqual(rows[0]["top_vulnerability"], "CVE-2026-24763")
        self.assertEqual(rows[0]["mdns_version"], "2026.3.7")
        self.assertEqual(rows[0]["proxy_type"], "cloudflare")
        self.assertEqual(rows[0]["honeypot_probable"], "true")
        self.assertEqual(rows[0]["honeypot_signature"], "cowrie")
        self.assertEqual(rows[0]["markers"], "openclaw")
        self.assertIn("timed out", rows[0]["errors"])


if __name__ == "__main__":
    unittest.main()
