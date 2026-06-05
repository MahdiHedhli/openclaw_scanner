import json
import tempfile
import unittest
from pathlib import Path

from openclaw_scanner.cli import _apply_inferences, render_results
from openclaw_scanner.discovery import score_passive_record
from openclaw_scanner.inference import load_rules
from openclaw_scanner.models import ScanResult
from openclaw_scanner.sources import load_targets


class PassiveNoiseTests(unittest.TestCase):
    def test_ivanti_product_downgrades_title_candidate_without_identification(self):
        score = score_passive_record(
            {
                "product": "Ivanti EPMM",
                "http": {
                    "title": "OpenClaw Control",
                    "html": "<title>OpenClaw Control</title>",
                },
            }
        )

        self.assertTrue(score["passive_noise_downgraded"])
        self.assertLessEqual(score["discovery_confidence"], 0.25)
        self.assertIn("ivanti_epmm", score["passive_noise_matched_products"])

        result = _apply_inferences(
            ScanResult(
                input_target="203.0.113.220:443",
                source="shodan",
                probed_base=None,
                metadata=score,
            ),
            load_rules(None),
        )
        self.assertEqual(result.fingerprint_matches, [])
        self.assertEqual(result.matched_versions, [])
        self.assertEqual(result.vulnerability_matches, [])

    def test_generic_apache_default_page_downgrades_only_without_openclaw_evidence(self):
        score = score_passive_record(
            {
                "product": "Apache httpd",
                "http": {
                    "server": "Apache/2.4.58",
                    "html": "Apache2 Ubuntu Default Page: It works!",
                },
            }
        )

        self.assertTrue(score["passive_noise_downgraded"])
        self.assertLessEqual(score["discovery_confidence"], 0.45)
        self.assertIn("apache_default", score["passive_noise_matched_products"])

    def test_active_targets_are_not_suppressed_by_passive_noise_annotation(self):
        record = {
            "ip_str": "203.0.113.221",
            "port": 443,
            "product": "Sophos SSL VPN",
            "http": {"title": "OpenClaw Control"},
        }

        targets = load_targets(shodan_records=[record])

        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0].label, "203.0.113.221:443")
        self.assertTrue(targets[0].metadata["passive_noise_downgraded"])
        self.assertIn(
            "sophos_ssl_vpn",
            targets[0].metadata["passive_noise_matched_products"],
        )

    def test_external_import_preserves_passive_noise_metadata(self):
        data = [
            {
                "ip": "203.0.113.222",
                "services": [
                    {
                        "port": 443,
                        "service_name": "HTTPS",
                        "http": {
                            "response": {
                                "html_title": "OpenClaw Control",
                                "body": "OpenClaw Control",
                                "server": "Ivanti EPMM",
                            }
                        },
                        "software": [{"name": "Ivanti EPMM"}],
                    }
                ],
            }
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "censys.json"
            path.write_text(json.dumps(data), encoding="utf-8")
            targets = load_targets(censys_file=str(path))

        self.assertEqual(len(targets), 1)
        self.assertTrue(targets[0].metadata["passive_noise_downgraded"])

    def test_output_surfaces_passive_noise_downgrade(self):
        result = ScanResult(
            input_target="203.0.113.223:443",
            source="shodan",
            probed_base=None,
            metadata={
                "discovery_confidence": 0.25,
                "passive_noise_downgraded": True,
                "passive_noise_reasons": [
                    "passive product metadata identifies Ivanti EPMM"
                ],
                "passive_noise_matched_products": ["ivanti_epmm"],
            },
        )

        pretty = render_results([result], "pretty")
        csv_rendered = render_results([result], "csv")

        self.assertIn("Passive noise downgrade", pretty)
        self.assertIn("ivanti_epmm", csv_rendered)


if __name__ == "__main__":
    unittest.main()
