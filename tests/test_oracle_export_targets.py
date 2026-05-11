import importlib.util
import unittest
from pathlib import Path


def _load_export_targets_module():
    module_path = (
        Path(__file__).resolve().parents[1]
        / "deploy"
        / "oracle_free_tier"
        / "export_targets.py"
    )
    spec = importlib.util.spec_from_file_location("export_targets", module_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class OracleExportTargetsTests(unittest.TestCase):
    def test_extract_nodes_handles_terraform_output_shape(self):
        module = _load_export_targets_module()
        payload = {
            "calibration_nodes": {
                "value": {
                    "openclaw-2026-2-13": {
                        "public_ip": "203.0.113.10",
                        "openclaw_version": "2026.2.13",
                        "gateway_port": 18789,
                        "scanner_target": "203.0.113.10:18789",
                    },
                    "openclaw-2026-2-14": {
                        "public_ip": "203.0.113.11",
                        "openclaw_version": "2026.2.14",
                        "gateway_port": 18789,
                        "scanner_target": "203.0.113.11:18789",
                    },
                }
            }
        }

        nodes = module._extract_nodes(payload)

        self.assertEqual(len(nodes), 2)
        self.assertEqual(nodes[0]["name"], "openclaw-2026-2-13")
        self.assertEqual(nodes[0]["scanner_target"], "203.0.113.10:18789")


if __name__ == "__main__":
    unittest.main()
