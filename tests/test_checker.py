import unittest
from pathlib import Path

from openclaw_scanner.checker import (
    AUTHORIZATION_ACK_TEXT,
    CheckerValidationError,
    RateLimitBucket,
    check_rate_limit,
    checker_api_contract,
    checker_probe_configs,
    normalize_checker_target,
    validate_public_ip_address,
    validate_checker_request,
)


class CheckerTests(unittest.TestCase):
    def test_normalize_checker_target_defaults_to_https(self):
        self.assertEqual(
            normalize_checker_target("gateway.example.com:18789"),
            "https://gateway.example.com:18789/",
        )

    def test_normalize_checker_target_blocks_ssrf_addresses(self):
        blocked = [
            "http://localhost:18789",
            "http://127.0.0.1:18789",
            "http://10.0.0.1:18789",
            "http://172.16.0.1:18789",
            "http://192.168.1.10:18789",
            "http://169.254.169.254/",
            "http://169.254.10.20/",
            "http://224.0.0.1/",
            "http://service.internal/",
            "http://gateway.local/",
            "http://intranet/",
        ]
        for target in blocked:
            with self.subTest(target=target):
                with self.assertRaises(CheckerValidationError):
                    normalize_checker_target(target)

    def test_validate_checker_request_requires_acknowledgement_and_captcha(self):
        with self.assertRaises(CheckerValidationError):
            validate_checker_request(
                {
                    "target": "https://gateway.example.com",
                    "authorization_acknowledged": False,
                    "captcha_token": "token",
                }
            )
        with self.assertRaises(CheckerValidationError):
            validate_checker_request(
                {
                    "target": "https://gateway.example.com",
                    "authorization_acknowledged": True,
                    "captcha_token": "",
                }
            )

        validated = validate_checker_request(
            {
                "target": "https://gateway.example.com",
                "authorization_acknowledged": True,
                "captcha_token": "token",
            }
        )
        self.assertTrue(validated["authorization_acknowledged"])

    def test_checker_api_contract_shape(self):
        contract = checker_api_contract()

        self.assertEqual(contract["request"]["method"], "POST")
        self.assertEqual(
            contract["request"]["body"]["authorization_text"],
            AUTHORIZATION_ACK_TEXT,
        )
        self.assertIn("possible_openclaw", contract["response"])
        self.assertIn("family_match", contract["response"])
        self.assertIn("risk_context", contract["response"])
        self.assertFalse(contract["limits"]["post_probes"])
        self.assertFalse(contract["limits"]["debugger_socket_connections"])

    def test_validate_public_ip_address_rejects_non_public_ranges(self):
        for value in ("10.0.0.1", "172.16.0.1", "192.168.1.10", "169.254.169.254"):
            with self.subTest(value=value):
                with self.assertRaises(CheckerValidationError):
                    validate_public_ip_address(value)

    def test_rate_limit_helper_limits_by_client_and_target(self):
        bucket = RateLimitBucket()
        first = check_rate_limit(bucket, "client-a", "target-a", limit=2, now=100.0)
        second = check_rate_limit(bucket, "client-a", "target-a", limit=2, now=101.0)
        third = check_rate_limit(bucket, "client-a", "target-a", limit=2, now=102.0)

        self.assertTrue(first["allowed"])
        self.assertTrue(second["allowed"])
        self.assertFalse(third["allowed"])

    def test_checker_probe_configs_do_not_include_post_or_socket_probes(self):
        configs = checker_probe_configs()

        self.assertTrue(configs)
        self.assertTrue(all(config.method == "GET" for config in configs))
        self.assertFalse(any(config.websocket_upgrade for config in configs))
        self.assertFalse(any(config.method == "POST" for config in configs))

    def test_static_frontend_requires_authorization_and_configurable_api(self):
        root = Path(__file__).resolve().parents[1]
        for html_path in (
            root / "docs" / "checker" / "index.html",
            root / "site" / "checker" / "index.html",
        ):
            with self.subTest(html_path=html_path):
                html = html_path.read_text(encoding="utf-8")

                self.assertIn(AUTHORIZATION_ACK_TEXT, html)
                self.assertIn("apiEndpoint", html)
                self.assertIn("Do not scan IPs or services you are not authorized", html)
                self.assertIn("Authorization", html)


if __name__ == "__main__":
    unittest.main()
