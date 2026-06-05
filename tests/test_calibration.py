import csv
import io
import tempfile
import unittest
from pathlib import Path

from openclaw_scanner.calibration import (
    load_calibration_candidates,
    render_calibration_candidates,
    select_calibration_candidates,
)


class CalibrationCandidateTests(unittest.TestCase):
    def test_selects_high_signal_no_family_no_exact_candidates(self):
        rows = [
            {
                "anon_id": "OCS-ACT-001",
                "has_signal": "true",
                "product_confidence": "0.4",
                "family_match_count": "0",
                "exact_version_count": "0",
                "top_version": "",
                "status_distribution_signature": "200:35;400:2;404:1",
                "observation_count": "38",
                "error_count": "0",
            },
            {
                "anon_id": "OCS-ACT-002",
                "has_signal": "true",
                "product_confidence": "0.9",
                "family_match_count": "1",
                "exact_version_count": "0",
                "status_distribution_signature": "200:35;400:2;404:1",
            },
            {
                "anon_id": "OCS-ACT-003",
                "has_signal": "false",
                "product_confidence": "0.9",
                "family_match_count": "0",
                "exact_version_count": "0",
                "status_distribution_signature": "200:35;400:2;404:1",
            },
        ]

        candidates = select_calibration_candidates(rows)

        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["anon_id"], "OCS-ACT-001")
        self.assertIn(
            "signature_200_35_400_2_404_1",
            candidates[0]["reason_tags"],
        )
        self.assertNotIn("input_target", candidates[0])
        self.assertNotIn("probed_base", candidates[0])

    def test_auth_challenge_variant_is_interesting(self):
        candidates = select_calibration_candidates(
            [
                {
                    "anon_id": "OCS-ACT-004",
                    "has_signal": True,
                    "product_confidence": 0.4,
                    "family_matches": 0,
                    "exact_versions": 0,
                    "status_distribution_signature": "200:28;400:2;401:7;404:1",
                }
            ]
        )

        self.assertEqual(len(candidates), 1)
        self.assertIn("auth_challenge_variant", candidates[0]["reason_tags"])

    def test_csv_render_emits_public_safe_fields(self):
        rendered = render_calibration_candidates(
            [
                {
                    "anon_id": "OCS-ACT-001",
                    "confidence": 0.4,
                    "status_distribution_signature": "200:35;400:2;404:1",
                    "observed_paths_summary": "/=200; /api=400",
                    "reason_tags": ["has_signal"],
                }
            ],
            "csv",
        )
        rows = list(csv.DictReader(io.StringIO(rendered)))

        self.assertEqual(rows[0]["anon_id"], "OCS-ACT-001")
        self.assertEqual(rows[0]["reason_tags"], "has_signal")
        self.assertNotIn("input_target", rows[0])

    def test_cli_loader_reads_anonymized_csv(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "active"
            path.write_text(
                "\n".join(
                    [
                        "anon_id,has_signal,product_confidence,family_match_count,exact_version_count,top_version,status_distribution_signature,observation_count,error_count",
                        "OCS-ACT-001,true,0.3,0,0,,200:35;400:2;404:1,38,0",
                    ]
                ),
                encoding="utf-8",
            )
            rendered = load_calibration_candidates(str(path), "json")

        self.assertIn('"anon_id": "OCS-ACT-001"', rendered)
        self.assertNotIn("203.0.113.", rendered)


if __name__ == "__main__":
    unittest.main()
