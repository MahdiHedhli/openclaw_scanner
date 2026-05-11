import unittest

from openclaw_scanner.models import ProbeObservation
from openclaw_scanner.proxy import detect_proxy


class ProxyTests(unittest.TestCase):
    def test_detects_cloudflare_from_headers(self):
        observations = {
            "/": ProbeObservation(
                path="/",
                url="https://example.test/",
                status=200,
                title="OpenClaw Control",
                headers={
                    "server": "cloudflare",
                    "cf-ray": "abc123-IAD",
                },
            )
        }

        result = detect_proxy(observations)

        self.assertTrue(result.detected)
        self.assertEqual(result.proxy_type, "cloudflare")
        self.assertGreaterEqual(result.confidence, 0.9)

    def test_detects_generic_proxy_from_passive_waf_signal(self):
        observations = {
            "/": ProbeObservation(
                path="/",
                url="https://example.test/",
                status=200,
                title="OpenClaw Control",
            )
        }

        result = detect_proxy(observations, passive_waf="Some Edge WAF")

        self.assertTrue(result.detected)
        self.assertEqual(result.proxy_type, "generic")
        self.assertGreaterEqual(result.confidence, 0.75)


if __name__ == "__main__":
    unittest.main()
