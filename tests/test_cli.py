import unittest

from openclaw_scanner.cli import _observations_from_shodan_record
from openclaw_scanner.inference import correlate_vulnerabilities, infer_versions, load_rules


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


if __name__ == "__main__":
    unittest.main()
