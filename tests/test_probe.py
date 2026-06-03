import unittest
from unittest.mock import patch

from openclaw_scanner.probe import (
    ProbeConfig,
    _fetch,
    _murmurhash3_32,
    build_conditional_deep_probe_configs,
    build_probe_configs,
)


class ProbeTests(unittest.TestCase):
    def test_build_probe_configs_includes_external_fingerprint_defaults_without_post(self):
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
        self.assertIn(("GET", "/json/version"), config_pairs)
        self.assertIn(("GET", "/json/list"), config_pairs)
        self.assertIn(("GET", "/json"), config_pairs)
        self.assertIn(("GET", "/devtools/browser"), config_pairs)
        self.assertNotIn(("OPTIONS", "/"), config_pairs)
        self.assertNotIn(("OPTIONS", "/tools/invoke"), config_pairs)
        self.assertNotIn(("POST", "/api/doesnotexist"), config_pairs)
        self.assertNotIn(("POST", "/v1/embeddings"), config_pairs)
        self.assertNotIn(("POST", "/v1/chat/completions"), config_pairs)
        self.assertNotIn(("POST", "/v1/responses"), config_pairs)
        self.assertNotIn(("POST", "/tools/invoke"), config_pairs)
        self.assertTrue(
            all(
                config.method == "GET"
                for config in configs
            )
        )
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

    def test_post_probe_configs_require_explicit_opt_in(self):
        default_configs = build_conditional_deep_probe_configs(include_post=False)
        default_pairs = {(config.method, config.path) for config in default_configs}
        configs = build_conditional_deep_probe_configs(include_post=True)
        config_pairs = {(config.method, config.path) for config in configs}

        self.assertIn(("OPTIONS", "/"), default_pairs)
        self.assertIn(("OPTIONS", "/tools/invoke"), default_pairs)
        self.assertIn(("GET", "/socket.io/?EIO=4&transport=polling&t=scanner"), default_pairs)
        self.assertIn(("GET", "/vnc.html"), default_pairs)
        self.assertIn(("GET", "/websockify"), default_pairs)
        self.assertIn(("GET", "/v1/chat/completions"), config_pairs)
        self.assertIn(("GET", "/v1/responses"), config_pairs)
        self.assertIn(("GET", "/v1/embeddings"), config_pairs)
        self.assertIn(("GET", "/browser-tools"), config_pairs)
        self.assertIn(("GET", "/api/canvas"), config_pairs)
        self.assertNotIn(("POST", "/api/doesnotexist"), default_pairs)
        self.assertNotIn(("POST", "/v1/embeddings"), default_pairs)
        self.assertNotIn(("POST", "/v1/chat/completions"), default_pairs)
        self.assertNotIn(("POST", "/v1/responses"), default_pairs)
        self.assertNotIn(("POST", "/tools/invoke"), default_pairs)
        self.assertIn(("POST", "/api/doesnotexist"), config_pairs)
        self.assertIn(("POST", "/v1/embeddings"), config_pairs)
        self.assertIn(("POST", "/v1/chat/completions"), config_pairs)
        self.assertIn(("POST", "/v1/responses"), config_pairs)
        self.assertIn(("POST", "/tools/invoke"), config_pairs)

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

    def test_cdp_version_probe_stores_sanitized_facts_only(self):
        class JsonResponse:
            headers = {"Content-Type": "application/json"}

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def getcode(self):
                return 200

            def geturl(self):
                return "http://example.test/json/version"

            def read(self, *_args):
                return (
                    b'{"Browser":"HeadlessChrome/120.0.6099.109",'
                    b'"Protocol-Version":"1.3",'
                    b'"V8-Version":"12.0.267.17",'
                    b'"webSocketDebuggerUrl":"ws://127.0.0.1:9222/devtools/browser/abc"}'
                )

        with patch("openclaw_scanner.probe.urlopen", return_value=JsonResponse()):
            observation = _fetch(
                base_url="http://example.test",
                config=ProbeConfig(path="/json/version", probe_name="cdp-version"),
                timeout=1.0,
                verify_tls=False,
                user_agent="openclaw-scanner/test",
                max_bytes=4096,
            )

        self.assertEqual(observation.cdp["present"], "true")
        self.assertEqual(observation.cdp["browser_family"], "Chromium")
        self.assertEqual(observation.cdp["engine"], "HeadlessChrome")
        self.assertEqual(observation.cdp["chromium_version"], "120.0.6099.109")
        self.assertEqual(observation.cdp["headless"], "true")
        self.assertEqual(observation.cdp["protocol_version"], "1.3")
        self.assertEqual(observation.cdp["v8_version"], "12.0.267.17")
        self.assertEqual(observation.cdp["debugger_url_present"], "true")
        self.assertNotIn("webSocketDebuggerUrl", observation.cdp)
        self.assertNotIn("127.0.0.1", repr(observation.cdp))

    def test_cors_options_probe_sends_no_body_and_captures_allow_headers(self):
        captured_requests = []

        class OptionsResponse:
            headers = {
                "Access-Control-Allow-Origin": "https://scanner.invalid",
                "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
                "Access-Control-Allow-Headers": "authorization,content-type",
                "Allow": "GET, POST, OPTIONS",
            }

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def getcode(self):
                return 204

            def geturl(self):
                return "http://example.test/tools/invoke"

            def read(self, *_args):
                return b""

        def fake_urlopen(request, **_kwargs):
            captured_requests.append(request)
            return OptionsResponse()

        with patch("openclaw_scanner.probe.urlopen", side_effect=fake_urlopen):
            observation = _fetch(
                base_url="http://example.test",
                config=ProbeConfig(
                    path="/tools/invoke",
                    method="OPTIONS",
                    probe_name="cors-preflight",
                    headers={
                        "Origin": "https://scanner.invalid",
                        "Access-Control-Request-Method": "POST",
                        "Access-Control-Request-Headers": "authorization,content-type",
                    },
                ),
                timeout=1.0,
                verify_tls=False,
                user_agent="openclaw-scanner/test",
                max_bytes=1024,
            )

        request = captured_requests[0]
        self.assertEqual(request.get_method(), "OPTIONS")
        self.assertIsNone(request.data)
        self.assertEqual(request.get_header("Origin"), "https://scanner.invalid")
        self.assertEqual(observation.status, 204)
        self.assertEqual(
            observation.headers["access-control-allow-origin"],
            "https://scanner.invalid",
        )
        self.assertEqual(observation.headers["allow"], "GET, POST, OPTIONS")

    def test_socketio_polling_handshake_shape_is_recorded(self):
        class PollingResponse:
            headers = {"Content-Type": "text/plain; charset=UTF-8"}

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def getcode(self):
                return 200

            def geturl(self):
                return "http://example.test/socket.io/?EIO=4&transport=polling&t=scanner"

            def read(self, *_args):
                return (
                    b'0{"sid":"test-session","upgrades":["websocket"],'
                    b'"pingInterval":25000,"pingTimeout":20000}'
                )

        with patch("openclaw_scanner.probe.urlopen", return_value=PollingResponse()):
            observation = _fetch(
                base_url="http://example.test",
                config=ProbeConfig(path="/socket.io/?EIO=4&transport=polling&t=scanner"),
                timeout=1.0,
                verify_tls=False,
                user_agent="openclaw-scanner/test",
                max_bytes=4096,
            )

        self.assertEqual(observation.status, 200)
        self.assertIn("socketio_polling_handshake", observation.body_markers)
        self.assertIn("sid", observation.json_keys)
        self.assertIn("upgrades", observation.json_keys)

    def test_murmurhash3_matches_known_vector(self):
        self.assertEqual(_murmurhash3_32(b"hello"), 613153351)


if __name__ == "__main__":
    unittest.main()
