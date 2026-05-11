import json
import tempfile
import unittest
from pathlib import Path

from openclaw_scanner.sources import load_targets


class SourceTests(unittest.TestCase):
    def test_targets_without_scheme_get_https_and_http_candidates(self):
        targets = load_targets(direct_targets=["192.0.2.10:18789"])
        self.assertEqual(targets[0].candidates[0], "https://192.0.2.10:18789")
        self.assertEqual(targets[0].candidates[1], "http://192.0.2.10:18789")

    def test_shodan_file_with_matches_object(self):
        data = {
            "matches": [
                {
                    "ip_str": "198.51.100.10",
                    "port": 18789,
                    "ssl": {},
                    "hostnames": ["gateway.example"],
                }
            ]
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "shodan.json"
            path.write_text(json.dumps(data), encoding="utf-8")
            targets = load_targets(shodan_file=str(path))

        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0].source, "shodan")
        self.assertEqual(targets[0].candidates[0], "https://198.51.100.10:18789")
        self.assertIsNotNone(targets[0].raw_record)

    def test_shodan_jsonl_file_is_parsed(self):
        lines = [
            json.dumps({"ip_str": "203.0.113.1", "port": 5353, "data": "OpenClaw"}),
            json.dumps({"ip_str": "203.0.113.2", "port": 5353, "data": "Clawdbot"})
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "shodan.jsonl"
            path.write_text("\n".join(lines), encoding="utf-8")
            targets = load_targets(shodan_file=str(path))

        self.assertEqual(len(targets), 2)
        self.assertEqual(targets[0].source, "shodan")
        self.assertEqual(targets[1].source, "shodan")

    def test_mdns_gateway_port_is_preferred_for_candidates(self):
        data = {
            "matches": [
                {
                    "ip_str": "198.51.100.10",
                    "port": 5353,
                    "mdns": {
                        "services": {
                            "18789/tcp clawdbot-gw": {
                                "data": ["gatewayPort=18789"]
                            }
                        }
                    }
                }
            ]
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "shodan.json"
            path.write_text(json.dumps(data), encoding="utf-8")
            targets = load_targets(shodan_file=str(path))

        self.assertEqual(targets[0].label, "198.51.100.10:18789")
        self.assertEqual(targets[0].metadata["gateway_port"], 18789)
        self.assertEqual(targets[0].candidates[0], "https://198.51.100.10:18789")

    def test_shodan_metadata_extracts_platform_and_pivot_queries(self):
        targets = load_targets(
            shodan_records=[
                {
                    "ip_str": "203.0.113.44",
                    "port": 18789,
                    "product": "OpenClaw Gateway",
                    "version": "2026.2.20",
                    "os": "Windows",
                    "hash": 12345,
                    "vulns": {"CVE-2026-32051": {}},
                    "http": {
                        "title": "OpenClaw Control",
                        "html_hash": 45678,
                        "headers_hash": 56789,
                        "favicon": {"hash": -805544463},
                    },
                    "ssl": {
                        "jarm": "26d26d16d26d26d22c26d26d26d26dfd9c9d14e4f4f67f94f0359f8b28f532",
                    },
                }
            ]
        )

        metadata = targets[0].metadata
        self.assertEqual(metadata["platform"], "windows")
        self.assertEqual(metadata["shodan_product"], "OpenClaw Gateway")
        self.assertEqual(metadata["shodan_version"], "2026.2.20")
        self.assertEqual(metadata["shodan_favicon_hash"], -805544463)
        self.assertIn("http.html_hash:45678", metadata["shodan_pivot_queries"])
        self.assertIn("http.favicon.hash:-805544463", metadata["shodan_pivot_queries"])
        self.assertEqual(metadata["shodan_vulns"], ["CVE-2026-32051"])

    def test_mdns_metadata_is_extracted_into_target_metadata(self):
        targets = load_targets(
            shodan_records=[
                {
                    "ip_str": "203.0.113.61",
                    "port": 5353,
                    "mdns": {
                        "hostname": "openclaw-gw-demo.local.",
                        "services": {
                            "18789/tcp openclaw-gw": {
                                "name": "demo-gw (OpenClaw)",
                                "ptr": "_openclaw-gw._tcp.local",
                                "data": [
                                    "gatewayPort=18789",
                                    "version=2026.3.7",
                                    "lanHost=openclaw-gw-demo.local",
                                ],
                            }
                        },
                        "answers": {
                            "PTR": ["_openclaw-gw._tcp.local"],
                        },
                    },
                }
            ]
        )

        metadata = targets[0].metadata
        self.assertEqual(metadata["mdns_version"], "2026.3.7")
        self.assertEqual(metadata["mdns_hostname"], "openclaw-gw-demo.local")
        self.assertIn("_openclaw-gw._tcp.local", metadata["mdns_service_types"])
        self.assertIn("openclaw", metadata["mdns_product_markers"])
        self.assertEqual(metadata["mdns_advertised_ports"], [18789])


if __name__ == "__main__":
    unittest.main()
