import csv
import io
import unittest
from unittest.mock import patch

from openclaw_scanner.cli import _observations_from_shodan_record, _scan_single_target, render_results
from openclaw_scanner.inference import correlate_vulnerabilities, infer_versions, load_rules
from openclaw_scanner.models import (
    FingerprintMatch,
    ProbeObservation,
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
                probe_paths=["/"],
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
            metadata={"shodan_query": 'product:"mDNS" "clawdbot-gw"'},
            product_confidence=0.75,
            observations={
                "/": ProbeObservation(
                    path="/",
                    url="https://203.0.113.10:18789/",
                    status=200,
                    body_markers=["openclaw"],
                )
            },
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
        self.assertEqual(rows[0]["markers"], "openclaw")
        self.assertIn("timed out", rows[0]["errors"])


if __name__ == "__main__":
    unittest.main()
