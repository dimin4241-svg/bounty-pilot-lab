import json
import tempfile
import unittest
from pathlib import Path
from release_check import evaluate, private_paths

class ReleaseCheckTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / ".claude-plugin").mkdir()
        (self.root / "VERSION").write_text("1.2.3\n",encoding="utf-8")
        self.plugin = {"name":"bounty-pilot-lab","version":"1.2.3"}
        self.market = {"plugins":[{"name":"bounty-pilot-lab","source":"./"}]}
        self.write_metadata()

    def write_metadata(self):
        (self.root / ".claude-plugin/plugin.json").write_text(
            json.dumps(self.plugin),encoding="utf-8")
        (self.root / ".claude-plugin/marketplace.json").write_text(
            json.dumps(self.market),encoding="utf-8")

    def test_consistent_metadata(self):
        result=evaluate(self.root,["README.md","VERSION","tests/test_example.py"])
        self.assertTrue(result["ok"])
        self.assertEqual(result["flagged_count"],0)

    def test_version_mismatch(self):
        self.plugin["version"]="9.9.9"
        self.write_metadata()
        self.assertFalse(evaluate(self.root,[])["ok"])

    def test_duplicate_marketplace(self):
        self.market["plugins"]*=2
        self.write_metadata()
        self.assertFalse(evaluate(self.root,[])["ok"])

    def test_private_path_detection(self):
        paths=["notes/.env.local","data/report.DB","private/a.json",
               "runs/1/a.txt","test.pem","data/db.sqlite3-wal",
               "private-review-1.json","research-status.html","README.md"]
        self.assertEqual(len(private_paths(paths)),8)
        result=evaluate(self.root,paths)
        self.assertFalse(result["ok"])
        self.assertEqual(result["flagged_count"],8)
        self.assertNotIn("test.pem",json.dumps(result))

    def test_normal_paths(self):
        self.assertEqual(private_paths(["docs/keys.md","tests/test_db.py",
                                        "scripts/private_helpers.py"]),[])

    def test_malformed_plugin_metadata(self):
        for malformed in ([], None, "invalid"):
            self.plugin = malformed
            self.write_metadata()
            with self.assertRaisesRegex(ValueError, "Plugin metadata"):
                evaluate(self.root, [])

    def test_malformed_marketplace_metadata(self):
        for malformed in ([], None, {"plugins": None}, {"plugins": ["bad"]}):
            self.market = malformed
            self.write_metadata()
            with self.assertRaisesRegex(ValueError, "Marketplace"):
                evaluate(self.root, [])

if __name__=="__main__":
    unittest.main()
