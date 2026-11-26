import sqlite3
import tempfile
import unittest
from pathlib import Path
from quality import Quality

class QualityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Quality(Path(self.tmp.name)/"test.db")
    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()
    def test_catalog(self):
        self.db.record("1","process","Example","Manual note","Local review")
        self.assertEqual(len(self.db.catalog()),1)
        self.assertEqual(self.db.catalog("cost"),[])
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.record("1","process","Example","Manual note","Local review")
        with self.assertRaises(ValueError):
            self.db.record("2","process","Example","","Local review")
    def test_matched_comparison(self):
        for i,(e,a,b) in enumerate([(0,1,0),(1,0,1),(1,1,0),(0,0,0)]):
            self.db.evaluate("generic","v1",str(i),"a",e,a,10)
            self.db.evaluate("generic","v2",str(i),"b",e,b,5)
        data = self.db.compare("generic","v1","a","v2","b")
        self.assertEqual(data["baseline"]["accuracy"],0.5)
        self.assertEqual(data["candidate"]["accuracy"],0.75)
        self.assertEqual(data["improved_cases"],2)
        self.assertEqual(data["regressed_cases"],1)
        self.assertEqual(data["delta"]["cost_micro"],-20)
    def test_unmatched_case_sets(self):
        self.db.evaluate("generic","v1","a","x",1,1,0)
        self.db.evaluate("generic","v2","b","x",1,1,0)
        with self.assertRaises(ValueError):
            self.db.compare("generic","v1","x","v2","x")
    def test_inconsistent_reference(self):
        self.db.evaluate("generic","v1","a","x",1,1,0)
        self.db.evaluate("generic","v2","a","x",0,1,0)
        with self.assertRaises(ValueError):
            self.db.compare("generic","v1","x","v2","x")
    def test_undefined_precision_and_recall(self):
        self.db.evaluate("generic","v1","a","x",0,0,0)
        self.db.evaluate("generic","v2","a","x",0,0,0)
        result = self.db.compare("generic","v1","x","v2","x")
        self.assertIsNone(result["candidate"]["precision"])
        self.assertIsNone(result["candidate"]["recall"])

if __name__ == "__main__":
    unittest.main()
