import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from openclaw_scanner.shodan_api import resolve_shodan_api_key, search_shodan
from openclaw_scanner.sources import load_targets


class ShodanAPITests(unittest.TestCase):
    def test_resolve_shodan_api_key_from_dotenv(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            env_path = Path(tmpdir) / ".env"
            env_path.write_text(
                "\n".join(
                    [
                        "GITHUB_PAT=github-token",
                        "RAW_TOKEN_WITHOUT_EQUALS",
                        "SHODAN_API_KEY=shodan-secret",
                    ]
                ),
                encoding="utf-8",
            )
            key = resolve_shodan_api_key(
                explicit_key=None,
                env={},
                dotenv_paths=[env_path],
            )

        self.assertEqual(key, "shodan-secret")

    def test_search_shodan_paginates_and_annotates_matches(self):
        first_page = {
            "total": 101,
            "matches": [
                {"ip_str": f"198.51.100.{index}", "port": 443}
                for index in range(1, 101)
            ],
        }
        second_page = {
            "total": 101,
            "matches": [{"ip_str": "203.0.113.10", "port": 18789}],
        }

        with patch(
            "openclaw_scanner.shodan_api._request_json",
            side_effect=[first_page, second_page],
        ) as request_json:
            result = search_shodan(
                query='product:"mDNS" "clawdbot-gw"',
                api_key="api-key",
                pages=3,
                fields="ip_str,port,data",
                minify=True,
                timeout=12.5,
                user_agent="openclaw-scanner/test",
            )

        self.assertEqual(result["pages_fetched"], 2)
        self.assertEqual(len(result["matches"]), 101)
        self.assertEqual(
            result["matches"][0]["_openclaw_scanner"]["query"],
            'product:"mDNS" "clawdbot-gw"',
        )
        self.assertEqual(
            result["matches"][-1]["_openclaw_scanner"]["page"],
            2,
        )
        self.assertEqual(request_json.call_count, 2)
        first_params = request_json.call_args_list[0].kwargs["params"]
        second_params = request_json.call_args_list[1].kwargs["params"]
        self.assertEqual(first_params["page"], 1)
        self.assertEqual(second_params["page"], 2)
        self.assertEqual(first_params["minify"], "true")
        self.assertEqual(first_params["fields"], "ip_str,port,data")

    def test_load_targets_accepts_live_shodan_records(self):
        targets = load_targets(
            shodan_records=[
                {
                    "ip_str": "203.0.113.44",
                    "port": 443,
                    "_openclaw_scanner": {
                        "query": 'http.title:"OpenClaw"',
                        "page": 1,
                    },
                }
            ]
        )

        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0].source, "shodan_api")
        self.assertEqual(targets[0].metadata["shodan_query"], 'http.title:"OpenClaw"')
        self.assertEqual(targets[0].metadata["shodan_page"], 1)


if __name__ == "__main__":
    unittest.main()
