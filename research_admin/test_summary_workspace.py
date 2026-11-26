import json
import tempfile
import unittest
from pathlib import Path

from summary_workspace import workspace, store, inventory

class WorkspaceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.root = workspace(self.base / "summaries", create=True)
        self.report = self.base / "input.sarif"
        self.report.write_text(json.dumps({"version":"2.1.0","runs":[]}), encoding="utf-8")

    def test_create_and_store(self):
        self.assertEqual(self.root.stat().st_mode & 0o777, 0o700)
        result = store(self.root, self.report)
        self.assertEqual(result["status"], "stored")
        self.assertEqual(store(self.root, self.report)["status"], "already_stored")
        self.assertEqual(inventory(self.root)["summary_files"], 1)
        self.assertEqual(len(list(self.root.iterdir())), 1)

    def test_corrupt_summary_not_overwritten(self):
        result = store(self.root, self.report)
        path = self.root / (result["sha256"] + ".json")
        path.write_text("{}", encoding="utf-8")
        self.assertEqual(inventory(self.root)["invalid_files"], 1)
        with self.assertRaises(ValueError):
            store(self.root, self.report)
        self.assertEqual(path.read_text(encoding="utf-8"), "{}")

    def test_public_directory_rejected(self):
        self.root.chmod(0o755)
        with self.assertRaises(ValueError):
            inventory(self.root)

    def test_symlink_workspace_rejected(self):
        alias = self.base / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ValueError):
            workspace(alias)

    def test_symlink_summary_rejected(self):
        result = store(self.root, self.report)
        path = self.root / (result["sha256"] + ".json")
        path.unlink()
        path.symlink_to(self.report)
        self.assertEqual(inventory(self.root)["invalid_files"], 1)
        with self.assertRaises(ValueError):
            store(self.root, self.report)

    def test_inconsistent_summary_counts(self):
        result = store(self.root, self.report)
        path = self.root / (result["sha256"] + ".json")
        original = json.loads(path.read_text(encoding="utf-8"))
        for change in ({"result_count": 1}, {"runs": True}, {"bytes": -1},
                       {"reported_levels": {"error": 0}}, {"unexpected": "data"},
                       {"review_status": "approved"}):
            with self.subTest(change=change):
                path.write_text(json.dumps(dict(original, **change)), encoding="utf-8")
                self.assertEqual(inventory(self.root)["invalid_files"], 1)
                with self.assertRaises(ValueError):
                    store(self.root, self.report)
        path.write_text(json.dumps(original), encoding="utf-8")
        self.assertEqual(inventory(self.root)["summary_files"], 1)

if __name__ == "__main__":
    unittest.main()
