import sqlite3
import tempfile
import unittest
from pathlib import Path
from journal import Journal

class JournalTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.path=Path(self.tmp.name)/"journal.db"
        self.db=Journal(self.path)
        self.db.project("demo",100)

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def test_empty_not_complete(self):
        self.assertFalse(self.db.handoff("demo")["review_complete"])

    def test_review_and_reopening(self):
        self.db.add("demo","1","question","Documentation question","Local notes")
        self.assertFalse(self.db.handoff("demo")["review_complete"])
        self.db.decide("demo","1","deferred","reviewer","Missing documentation")
        self.assertFalse(self.db.handoff("demo")["review_complete"])
        self.db.decide("demo","1","supported","reviewer","Documentation received")
        self.assertTrue(self.db.handoff("demo")["review_complete"])
        self.db.decide("demo","1","open","reviewer","Needs renewed review")
        report=self.db.handoff("demo")
        self.assertFalse(report["review_complete"])
        self.assertEqual(len(report["history"]),3)

    def test_persistence_and_project_isolation(self):
        self.db.add("demo","1","control","Manual quality check","Local reference")
        self.db.project("other",100)
        other=Journal(self.path)
        try:
            self.assertEqual(other.handoff("demo")["counts"]["open"],1)
            self.assertEqual(other.handoff("other")["entries"],[])
        finally:
            other.close()

    def test_invalid_entries_and_review(self):
        with self.assertRaises(ValueError):
            self.db.add("demo","1","unknown","note","source")
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.decide("demo","missing","supported","reviewer","Reason")
        with self.assertRaises(ValueError):
            self.db.handoff("missing")

    def test_missing_reason_rejected(self):
        self.db.add("demo","1","observation","Generic note","Local reference")
        with self.assertRaises(ValueError):
            self.db.decide("demo","1","supported","reviewer"," ")
        self.assertEqual(self.db.handoff("demo")["counts"]["open"],1)

if __name__=="__main__":
    unittest.main()
