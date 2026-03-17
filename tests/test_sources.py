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


if __name__ == "__main__":
    unittest.main()
