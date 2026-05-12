import unittest
from unittest.mock import patch

from openclaw_scanner.probe import ProbeConfig, _fetch, _murmurhash3_32, build_probe_configs


class ProbeTests(unittest.TestCase):
    def test_build_probe_configs_includes_external_fingerprint_defaults(self):
        configs = build_probe_configs()
        config_pairs = {(config.method, config.path) for config in configs}

        self.assertIn(("GET", "/favicon.ico"), config_pairs)
        self.assertIn(("GET", "/manifest.json"), config_pairs)
        self.assertIn(("GET", "/asset-manifest.json"), config_pairs)
        self.assertIn(("GET", "/api/skills"), config_pairs)
        self.assertIn(("GET", "/metrics"), config_pairs)
        self.assertIn(("GET", "/ws"), config_pairs)
        self.assertIn(("GET", "/v1/models"), config_pairs)
        self.assertIn(("GET", "/v1/models/openclaw/default"), config_pairs)
        self.assertIn(("POST", "/api/doesnotexist"), config_pairs)
        self.assertIn(("POST", "/v1/embeddings"), config_pairs)
        self.assertIn(("POST", "/v1/chat/completions"), config_pairs)
        self.assertIn(("POST", "/v1/responses"), config_pairs)
        self.assertIn(("POST", "/tools/invoke"), config_pairs)
        self.assertTrue(
            any(
                config.path == "/ws"
                and config.method == "GET"
                and config.probe_name == "ws-upgrade"
                and config.websocket_upgrade
                for config in configs
            )
        )
        self.assertTrue(
            any(
                config.path == "/socket.io/"
                and config.method == "GET"
                and config.probe_name == "ws-upgrade"
                and config.websocket_upgrade
                for config in configs
            )
        )

    def test_websocket_upgrade_101_does_not_read_body(self):
        class UpgradeResponse:
            def __init__(self):
                self.headers = {
                    "Upgrade": "websocket",
                    "Sec-WebSocket-Protocol": "openclaw-gateway",
                }

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def getcode(self):
                return 101

            def geturl(self):
                return "http://example.test/ws"

            def read(self, *_args):
                raise AssertionError("101 upgrade bodies must not be read")

        config = ProbeConfig(path="/ws", probe_name="ws-upgrade", websocket_upgrade=True)
        with patch("openclaw_scanner.probe.urlopen", return_value=UpgradeResponse()):
            observation = _fetch(
                base_url="http://example.test",
                config=config,
                timeout=1.0,
                verify_tls=False,
                user_agent="openclaw-scanner/test",
                max_bytes=1024,
            )

        self.assertEqual(observation.status, 101)
        self.assertEqual(observation.probe_name, "ws-upgrade")
        self.assertEqual(observation.body_length, 0)
        self.assertIsNone(observation.body_sha256)

    def test_murmurhash3_matches_known_vector(self):
        self.assertEqual(_murmurhash3_32(b"hello"), 613153351)


if __name__ == "__main__":
    unittest.main()
