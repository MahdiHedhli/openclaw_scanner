import unittest

from openclaw_scanner.honeypot import assess_honeypot
from openclaw_scanner.models import ProbeObservation


class HoneypotTests(unittest.TestCase):
    def test_known_honeypot_signature_is_flagged(self):
        observations = {
            "/": ProbeObservation(
                path="/",
                url="http://example.test/",
                status=200,
                title="Cowrie SSH honeypot",
                response_time_ms=12.0,
            )
        }

        assessment = assess_honeypot(observations)

        self.assertTrue(assessment.probable)
        self.assertEqual(assessment.known_signature, "cowrie")
        self.assertGreaterEqual(assessment.probability, 0.9)

    def test_uniform_timing_without_other_signals_stays_below_probable_threshold(self):
        observations = {
            f"/path-{index}": ProbeObservation(
                path=f"/path-{index}",
                url=f"http://example.test/path-{index}",
                status=200,
                title="OpenClaw Control",
                body_sha256="abc123",
                response_time_ms=20.0 + (index * 0.05),
            )
            for index in range(6)
        }

        assessment = assess_honeypot(observations)

        self.assertFalse(assessment.probable)
        self.assertTrue(assessment.uniform_timing)
        self.assertLess(assessment.probability, 0.7)


if __name__ == "__main__":
    unittest.main()
