"""Regression checks for read-only diagnosis of zero-yield research runs."""
import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
scripts = ROOT / "skills" / "bounty-pilot" / "scripts"
spec = importlib.util.spec_from_file_location("lab_discovery_doctor", scripts / "discovery_doctor.py")
doctor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(doctor)


class DiscoveryDoctorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.run = base / "private-run"
        self.run.mkdir()
        (self.run / "run.json").write_text('{"run_id": "fixture"}', encoding="utf-8")
        (self.run / "findings.json").write_text("[]", encoding="utf-8")
        (self.run / "readings").mkdir()

    def test_diagnoses_valid_candidate_without_import(self):
        (self.run / "readings" / "accounting-claude.md").write_text(
            "LEAD | lens: accounting | surface: src/Vault.sol:Vault.withdraw "
            "| bug_class: missing-accounting-check\n"
            "mechanism: nonce accounting is inconsistent in an edge state.\n"
            "proof: src/Vault.sol:25 if guard\n"
            "next_experiment: native candidate and control test.\n")
        report = doctor.diagnose(self.run)
        self.assertEqual(report["reading_counts"]["candidate_or_lead_blocks"], 1)
        self.assertEqual(report["recorded_hypotheses"], 0)
        self.assertTrue(any("import-findings" in x for x in report["warnings"]))

    def test_warns_on_unparsed_model_output_and_large_bundle(self):
        (self.run / "readings" / "semantic-mismatch-deepseek.md").write_text(
            "CANDIDATE | mystery no fields\n")
        folder = self.run / "bundles"
        folder.mkdir()
        (folder / "manifest.json").write_text(json.dumps({
            "dispatches": [{"bundles": [{
                "lens": "semantic-mismatch",
                "bundle": "bundles/semantic-mismatch-bundle.md",
                "bytes": 750000
            }]}]
        }))
        report = doctor.diagnose(self.run)
        self.assertEqual(report["oversized_bundles"][0]["bytes"], 750000)
        self.assertGreater(report["reading_counts"]["unparsed_candidate_headers"], 0)

    def test_old_opus_json_does_not_disappear_without_diagnosis(self):
        opus = Path(self.tmp.name) / "opus"
        opus.mkdir()
        (opus / "manifest.json").write_text(json.dumps({
            "status": "COMPLETE_UNVERIFIED_HYPOTHESES",
            "api_responses_received": 1, "passes_completed": 1
        }))
        (opus / "partial-exit-and-auth.json").write_text(json.dumps({
            "hypotheses_markdown": "source-only hypothesis"
        }))
        report = doctor.diagnose(self.run, opus)
        self.assertEqual(report["opus_api_responses"], 1)
        self.assertTrue(any("Opus produced no importable" in x for x in report["warnings"]))

    def test_missing_run_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "run.json"):
            doctor.diagnose(Path(self.tmp.name) / "does-not-exist")


if __name__ == "__main__":
    unittest.main()
