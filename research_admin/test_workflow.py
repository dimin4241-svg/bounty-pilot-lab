import tempfile
import unittest
from pathlib import Path

from ledger import Ledger
from workflow import Workflow, REQUIRED, render

class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "db.sqlite3"
        legacy = Ledger(self.path)
        legacy.project("demo",100)
        legacy.close()
        self.db = Workflow(self.path)

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def approve(self):
        for name in REQUIRED:
            self.db.checkpoint("demo",name,"approved","operator","Reviewed manually")

    def test_legacy_migration_and_pending(self):
        p = self.db.snapshot()["projects"][0]
        self.assertEqual(p["status"],"review")
        self.assertEqual(set(p["checkpoints"].values()),{"pending"})
        self.assertEqual(p["remaining_micro"],100)

    def test_missing_approval_does_not_change_state(self):
        with self.assertRaises(ValueError):
            self.db.transition("demo","active","operator","Start")
        self.assertEqual(self.db.snapshot()["projects"][0]["status"],"review")
        self.assertEqual(self.db.history("demo"),[])

    def test_pause_on_block_and_resume(self):
        self.approve()
        self.db.transition("demo","active","operator","Approved")
        self.db.checkpoint("demo","authorization","blocked","operator","Review expired")
        self.assertEqual(self.db.snapshot()["projects"][0]["status"],"paused")
        with self.assertRaises(ValueError):
            self.db.transition("demo","active","operator","Resume")
        self.db.checkpoint("demo","authorization","approved","operator","Renewed")
        self.db.transition("demo","active","operator","Resume")
        self.assertEqual(len(self.db.history("demo")),8)
        self.assertEqual(self.db.snapshot()["projects"][0]["status"],"active")

    def test_archive_requires_settlement(self):
        self.db.reserve("demo","a","mock",50)
        with self.assertRaises(ValueError):
            self.db.transition("demo","archived","operator","Close")
        self.db.settle("a",10)
        self.db.transition("demo","archived","operator","Close")
        self.assertEqual(self.db.snapshot()["projects"][0]["status"],"archived")
        with self.assertRaises(ValueError):
            self.db.transition("demo","active","operator","Restart")
        with self.assertRaises(ValueError):
            self.db.checkpoint("demo","review","approved","operator","Change")

    def test_history_persistence(self):
        self.approve()
        other = Workflow(self.path)
        try:
            self.assertEqual(len(other.history("demo")),3)
            self.assertEqual(other.snapshot()["projects"][0]["checkpoints"]["review"],"approved")
        finally:
            other.close()

    def test_dashboard_escapes_untrusted_labels(self):
        self.db.project("<script>alert(1)</script>",1000000)
        markup = render(self.db.snapshot())
        self.assertNotIn("<script>",markup)
        self.assertIn("&lt;script&gt;",markup)
        self.assertIn("$1.000000",markup)
        self.assertIn("Content-Security-Policy",markup)

    def test_invalid_review_and_state(self):
        with self.assertRaises(ValueError):
            self.db.checkpoint("demo","review","approved","","note")
        with self.assertRaises(ValueError):
            self.db.transition("demo","paused","operator","Invalid")
        self.assertEqual(self.db.history("demo"),[])

if __name__ == "__main__":
    unittest.main()
