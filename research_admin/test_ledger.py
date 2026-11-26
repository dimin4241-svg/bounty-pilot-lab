import sqlite3
import tempfile
import unittest
from pathlib import Path
from ledger import Ledger

class LedgerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.ledger = Ledger(self.root / "test.db")
        self.ledger.project("demo",100)

    def tearDown(self):
        self.ledger.close()
        self.tmp.cleanup()

    def test_budget_and_resume(self):
        self.ledger.reserve("demo","a","mock",80)
        other = Ledger(self.root / "test.db")
        try:
            with self.assertRaises(ValueError):
                other.reserve("demo","b","mock",21)
            other.settle("a",40)
            other.reserve("demo","b","mock",60)
            with self.assertRaises(ValueError):
                other.settle("b",61)
            with self.assertRaises(ValueError):
                other.settle("a",10)
            self.assertEqual(other.summary()["projects"][0]["reserved_micro"],60)
            self.assertEqual(other.summary()["projects"][0]["spent_micro"],40)
        finally:
            other.close()

    def test_artifact_integrity(self):
        path = self.root / "sample.txt"
        path.write_text("original")
        self.ledger.register("demo",self.root,"sample.txt")
        self.assertTrue(self.ledger.verify("demo",self.root,"sample.txt"))
        path.write_text("changed")
        self.assertFalse(self.ledger.verify("demo",self.root,"sample.txt"))
        with self.assertRaises(ValueError):
            self.ledger.register("demo",self.root,"/etc/hosts")

    def test_manual_review(self):
        self.ledger.review("demo","downgraded","Manual assessment")
        with self.assertRaises(ValueError):
            self.ledger.review("demo","automatic","")
        self.assertEqual(self.ledger.summary()["projects"][0]["reviews"],1)

    def test_metrics(self):
        for i,(expected,observed) in enumerate([(0,1),(1,0),(1,1),(0,0)]):
            self.ledger.evaluate("synthetic","v1",str(i),"mock",expected,observed,2)
        row = self.ledger.metrics()[0]
        self.assertEqual((row["cases"],row["correct"],row["false_positive"],row["false_negative"],row["cost_micro"]),(4,2,1,1,8))
        with self.assertRaises(sqlite3.IntegrityError):
            self.ledger.evaluate("synthetic","v1","0","mock",0,0,2)

if __name__ == "__main__":
    unittest.main()
