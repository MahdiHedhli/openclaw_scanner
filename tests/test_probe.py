import unittest

from openclaw_scanner.probe import _murmurhash3_32, build_probe_configs


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

    def test_murmurhash3_matches_known_vector(self):
        self.assertEqual(_murmurhash3_32(b"hello"), 613153351)


if __name__ == "__main__":
    unittest.main()
