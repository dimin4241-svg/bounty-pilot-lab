"""Read-only historical scanner comparator: local, synthetic tests only."""
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills/bounty-pilot/scripts"


def load():
    spec = importlib.util.spec_from_file_location("historical_probe_test", SCRIPTS / "historical_probe.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


probe = load()


class PinnedLocalFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "historical-target"
        self.root.mkdir()
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        subprocess.run(["git", "-C", str(self.root), "config", "user.email", "fixture@example.invalid"],
                       check=True)
        subprocess.run(["git", "-C", str(self.root), "config", "user.name", "Fixture"],
                       check=True)
        (self.root / "source").mkdir()
        (self.root / "source" / "Contract.sol").write_text(
            "contract C { function id(bytes memory a, bytes memory b) public pure "
            "returns(bytes memory) { return abi.encodePacked(a,b); } }\n",
            encoding="utf-8")
        subprocess.run(["git", "-C", str(self.root), "add", "source"], check=True)
        subprocess.run(["git", "-C", str(self.root), "commit", "-qm", "toy snapshot"], check=True)
        self.pin = subprocess.check_output(
            ["git", "-C", str(self.root), "rev-parse", "HEAD"], text=True).strip()
        self.scanner = SCRIPTS / "research_diff.py"

    def test_identical_scanners_produce_only_identical_lexical_leads(self):
        r = probe.compare_probe(self.root, self.pin, self.scanner,
                                self.scanner, ["source"])
        self.assertEqual(r["kind"], "NONBLIND_TOOL_ONLY_DIAGNOSTIC")
        self.assertEqual(r["target_revision"], self.pin)
        self.assertFalse(r["model_used"])
        self.assertFalse(r["blind_ai_comparison"])
        self.assertIsNone(r["verified_rediscoveries"])
        self.assertEqual(r["finding_quality_conclusion"], "NOT_MEASURED")
        self.assertGreater(r["baseline"]["unique"], 0)
        self.assertEqual(r["new_lexical_leads"], 0)
        self.assertEqual(r["lost_lexical_leads"], 0)
        self.assertEqual(r["baseline"]["source_sha256"], r["candidate"]["source_sha256"])

    def test_rejects_wrong_head_and_dirty_tracked_files(self):
        with self.assertRaisesRegex(ValueError, "does not match"):
            probe.compare_probe(self.root, "0" * 40, self.scanner, self.scanner,
                                ["source"])
        (self.root / "source" / "Contract.sol").write_text("contract Changed {}\n")
        with self.assertRaisesRegex(ValueError, "modified tracked"):
            probe.compare_probe(self.root, self.pin, self.scanner, self.scanner,
                                ["source"])

    def test_scopes_only_explicit_top_level_dirs(self):
        for scope in ("../source", "/source", ".", "", "source/subfolder", "source\\escape"):
            with self.subTest(scope=scope):
                with self.assertRaises(ValueError):
                    probe._validate_scope([scope])
        with self.assertRaisesRegex(ValueError, "duplicate"):
            probe._validate_scope(["source", "source"])

    def test_rejects_fabricated_confirmed_target_bug(self):
        fake = Path(self.temp.name) / "fabricated.py"
        fake.write_text("import json\nprint(json.dumps({\"mode\": \"source-scan\", "
                        "\"classification\": \"RESEARCH_LEADS\", "
                        "\"confirmed_vulnerabilities\": 1, \"leads\": []}))\n")
        with self.assertRaisesRegex(ValueError, "passive, unverified"):
            probe.compare_probe(self.root, self.pin, fake, self.scanner, ["source"])

    def test_cli_writes_only_new_results_and_prohibits_overwrite(self):
        report = Path(self.temp.name) / "report.json"
        cmd = [sys.executable, str(SCRIPTS / "historical_probe.py"),
               "--repo", str(self.root), "--pinned", self.pin,
               "--baseline-script", str(self.scanner),
               "--candidate-script", str(self.scanner),
               "--scope", "source", "--out", str(report)]
        first = subprocess.run(cmd, text=True, capture_output=True)
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(json.loads(report.read_text())["verified_rediscoveries"], None)
        second = subprocess.run(cmd, text=True, capture_output=True)
        self.assertNotEqual(second.returncode, 0)
        self.assertIn("refuse overwriting", second.stderr)


if __name__ == "__main__":
    unittest.main()
