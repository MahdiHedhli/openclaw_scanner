import unittest

from openclaw_scanner.cli import _apply_inferences
from openclaw_scanner.discovery import (
    discovery_queries,
    render_discovery_queries,
    score_passive_record,
    select_discovery_queries,
)
from openclaw_scanner.inference import load_rules
from openclaw_scanner.models import ScanResult


class DiscoveryTests(unittest.TestCase):
    def test_discovery_queries_include_control_titles(self):
        queries = discovery_queries(engine="shodan")
        query_map = {query.id: query for query in queries}

        self.assertEqual(
            query_map["shodan-title-openclaw-control"].query,
            'http.title:"OpenClaw Control"',
        )
        self.assertEqual(
            query_map["shodan-title-clawdbot-control"].query,
            'http.title:"Clawdbot Control"',
        )
        self.assertEqual(
            query_map["shodan-title-moltbot-control"].query,
            'http.title:"Moltbot Control"',
        )

    def test_discovery_queries_generate_favicon_queries_from_rules(self):
        rules = {
            "fingerprint_rules": [
                {"all": [{"type": "favicon_hash", "value": "-1205140012"}]}
            ]
        }

        queries = discovery_queries(rules=rules, engine="shodan")

        self.assertTrue(
            any(query.query == "http.favicon.hash:-1205140012" for query in queries)
        )

    def test_select_discovery_queries_rejects_unknown_ids(self):
        queries = discovery_queries(engine="shodan")

        with self.assertRaises(ValueError):
            select_discovery_queries(["not-a-query"], queries)

    def test_render_discovery_queries_json(self):
        rendered = render_discovery_queries(
            select_discovery_queries(["shodan-title-openclaw-control"], discovery_queries()),
            "json",
        )

        self.assertIn('"id": "shodan-title-openclaw-control"', rendered)
        self.assertIn('"description": "Exact control UI title', rendered)
        self.assertIn('"confidence_weight": 0.82', rendered)
        self.assertIn('"query": "http.title:\\"OpenClaw Control\\""', rendered)

    def test_discovery_query_dict_exposes_contract_fields(self):
        query = discovery_queries(engine="shodan")[0].to_dict()

        self.assertEqual(query["source_engine"], "shodan")
        self.assertEqual(query["description"], query["notes"])
        self.assertEqual(query["confidence_weight"], query["confidence"])

    def test_score_passive_record_weights_title_tls_and_mdns_sources(self):
        score = score_passive_record(
            {
                "http": {"title": "OpenClaw Control"},
                "ssl": {"cert": {"subject": {"CN": "openclaw-gw.local"}}},
                "mdns": {"services": {"18789/tcp openclaw-gw": {}}},
            }
        )

        self.assertGreaterEqual(score["discovery_confidence"], 0.82)
        self.assertIn("http_title:OpenClaw Control", score["discovery_sources"])
        self.assertTrue(
            any(source.startswith("passive_tls_name") for source in score["discovery_sources"])
        )

    def test_discovery_confidence_does_not_identify_or_correlate(self):
        result = _apply_inferences(
            ScanResult(
                input_target="203.0.113.90:18789",
                source="censys",
                probed_base=None,
                metadata={
                    "discovery_confidence": 0.99,
                    "discovery_sources": ["http_title:OpenClaw Control"],
                },
            ),
            load_rules(None),
        )

        self.assertEqual(result.product_confidence, 0.0)
        self.assertEqual(result.fingerprint_matches, [])
        self.assertEqual(result.matched_versions, [])
        self.assertEqual(result.vulnerability_matches, [])


if __name__ == "__main__":
    unittest.main()
