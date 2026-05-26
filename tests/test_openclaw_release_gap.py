import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "check_openclaw_release_gap.py"
SPEC = importlib.util.spec_from_file_location("check_openclaw_release_gap", MODULE_PATH)
release_gap = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release_gap)


class OpenClawReleaseGapTests(unittest.TestCase):
    def write_capture(self, root, name, version, capture_count=1):
        path = root / name
        path.mkdir()
        captures = [{"observations": {"/": {"path": "/", "status": 200}}}]
        if capture_count > 1:
            captures = captures * capture_count
        (path / "capture.json").write_text(
            json.dumps({
                "bundle_type": "openclaw_blackbox_capture",
                "declared_version": version,
                "captures": captures,
            }),
            encoding="utf-8",
        )

    def write_rules(self, path, versions):
        path.write_text(
            json.dumps({
                "version_rules": [
                    {
                        "id": f"lab-capture-{version}",
                        "version": version,
                        "exact": True,
                        "all": [],
                    }
                    for version in versions
                ]
            }),
            encoding="utf-8",
        )

    def test_version_key_orders_newer_prerelease_after_older_stable(self):
        versions = [
            "2026.5.22",
            "2026.5.23-beta.1",
            "2026.5.23-alpha.1",
        ]

        self.assertEqual(release_gap.latest_version(versions), "2026.5.23-beta.1")

    def test_report_needs_no_vm_when_latest_stable_is_captured_and_promoted(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            captures = root / "captures"
            captures.mkdir()
            rules = root / "rules.json"
            self.write_capture(captures, "openclaw-2026.5.20-a", "2026.5.20")
            self.write_capture(captures, "openclaw-2026.5.22-a", "2026.5.22")
            self.write_rules(rules, ["2026.5.20", "2026.5.22"])

            report = release_gap.build_report(
                published_versions=["2026.5.20", "2026.5.22"],
                capture_root=captures,
                rules_file=rules,
                include_prereleases=False,
            )

        self.assertFalse(report["capture_needed"])
        self.assertEqual(report["decision"], "no_vm_needed")
        self.assertEqual(report["latest_published_version"], "2026.5.22")
        self.assertEqual(report["stable_uncaptured_versions_after_latest_capture"], [])

    def test_report_requests_single_vm_when_new_stable_is_uncaptured(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            captures = root / "captures"
            captures.mkdir()
            rules = root / "rules.json"
            self.write_capture(captures, "openclaw-2026.5.22-a", "2026.5.22", 2)
            self.write_rules(rules, ["2026.5.22"])

            report = release_gap.build_report(
                published_versions=["2026.5.22", "2026.5.23"],
                capture_root=captures,
                rules_file=rules,
                include_prereleases=False,
            )

        self.assertTrue(report["capture_needed"])
        self.assertEqual(report["decision"], "launch_single_vm_capture")
        self.assertEqual(report["capture_needed_versions"], ["2026.5.23"])
        self.assertEqual(
            report["captured_versions"],
            [{"capture_count": 2, "version": "2026.5.22"}],
        )

    def test_report_keeps_uncaptured_prerelease_out_by_default(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            captures = root / "captures"
            captures.mkdir()
            rules = root / "rules.json"
            self.write_capture(captures, "openclaw-2026.5.22-a", "2026.5.22")
            self.write_rules(rules, ["2026.5.22"])

            report = release_gap.build_report(
                published_versions=["2026.5.22", "2026.5.23-beta.1"],
                capture_root=captures,
                rules_file=rules,
                include_prereleases=False,
            )
            prerelease_report = release_gap.build_report(
                published_versions=["2026.5.22", "2026.5.23-beta.1"],
                capture_root=captures,
                rules_file=rules,
                include_prereleases=True,
            )

        self.assertFalse(report["capture_needed"])
        self.assertEqual(
            report["prerelease_uncaptured_versions_after_latest_capture"],
            ["2026.5.23-beta.1"],
        )
        self.assertTrue(prerelease_report["capture_needed"])
        self.assertEqual(prerelease_report["capture_needed_versions"], ["2026.5.23-beta.1"])

    def test_main_can_update_manifest_with_release_gap_summary(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            captures = root / "captures"
            captures.mkdir()
            rules = root / "rules.json"
            output = root / "release-gap.json"
            manifest = root / "manifest.json"
            manifest.write_text(json.dumps({"run_id": "test-run"}), encoding="utf-8")
            self.write_capture(captures, "openclaw-2026.5.22-a", "2026.5.22")
            self.write_rules(rules, ["2026.5.22"])

            exit_code = release_gap.main([
                "--versions-json",
                json.dumps(["2026.5.22"]),
                "--capture-root",
                str(captures),
                "--rules-file",
                str(rules),
                "--output",
                str(output),
                "--manifest",
                str(manifest),
            ])

            updated = json.loads(manifest.read_text(encoding="utf-8"))

        self.assertEqual(exit_code, 0)
        self.assertEqual(updated["release_gap"]["decision"], "no_vm_needed")
        self.assertFalse(updated["release_gap"]["capture_needed"])
        self.assertEqual(updated["release_gap"]["latest_published_version"], "2026.5.22")
        self.assertEqual(updated["release_gap"]["captured_version_count"], 1)
        self.assertIn("--manifest", updated["release_gap"]["command"])
        self.assertIn("<versions-json>", updated["release_gap"]["command"])
        self.assertNotIn("2026.5.22", updated["release_gap"]["command"])


if __name__ == "__main__":
    unittest.main()
