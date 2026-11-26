import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

from ledger import Ledger
from maintenance import doctor, backup
from workflow import Workflow

class MaintenanceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.path = self.root / "ledger.db"
        self.db = Workflow(self.path)
        self.db.project("demo",1000)

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def test_backup_and_restore(self):
        self.db.reserve("demo","a","mock",500)
        self.db.settle("a",123)
        self.db.checkpoint("demo","review","approved","operator","Test")
        dest = self.root / "backup.db"
        self.assertTrue(doctor(self.path)["ok"])
        self.assertTrue(backup(self.path,dest)["ok"])
        copy = Workflow(dest)
        try:
            self.assertEqual(copy.snapshot(),self.db.snapshot())
            self.assertEqual(copy.history("demo"),self.db.history("demo"))
        finally:
            copy.close()
        self.assertEqual(dest.stat().st_mode & 0o777,0o600)
        with self.assertRaises(FileExistsError):
            backup(self.path,dest)
        self.assertTrue(doctor(dest)["ok"])

    def test_missing_and_invalid_source(self):
        with self.assertRaises(FileNotFoundError):
            doctor(self.root/"missing.db")
        p = self.root/"other.db"
        with sqlite3.connect(p) as conn:
            conn.execute("CREATE TABLE unrelated(id)")
        self.assertFalse(doctor(p)["ok"])
        with self.assertRaises(ValueError):
            backup(p,self.root/"no.db")
        self.assertFalse((self.root/"no.db").exists())

    def test_new_database_is_private_and_links_refused(self):
        self.assertEqual(self.path.stat().st_mode & 0o777,0o600)
        alias = self.root/"link.db"
        alias.symlink_to(self.path)
        with self.assertRaises(ValueError):
            Ledger(alias)

    def test_archived_budget_closed(self):
        self.db.transition("demo","archived","operator","End")
        with self.assertRaises(ValueError):
            self.db.reserve("demo","x","mock",1)

    def test_budget_type_limits(self):
        for invalid in (True,-1,2**63,1.5):
            with self.assertRaises(ValueError):
                self.db.project("x",invalid)
            with self.assertRaises(ValueError):
                self.db.reserve("demo","x","mock",invalid)

    def test_doctor_rejects_overcommitted_budget(self):
        self.db.reserve("demo","a","mock",800)
        with sqlite3.connect(self.path) as conn:
            conn.execute("UPDATE projects SET limit_micro=700 WHERE id='demo'")
        result = doctor(self.path)
        self.assertFalse(result["ok"])
        self.assertEqual(result["budget_violations"], [
            {"project":"demo","limit_micro":700,"committed_micro":800}
        ])
        with self.assertRaises(ValueError):
            backup(self.path,self.root/"invalid-backup.db")
        self.assertFalse((self.root/"invalid-backup.db").exists())

    def test_doctor_detects_missing_columns_without_repairing(self):
        p = self.root/"incomplete.db"
        with sqlite3.connect(p) as conn:
            for name in ("projects","charges","artifacts","reviews","evaluations"):
                conn.execute("CREATE TABLE "+name+"(id TEXT)")
        result = doctor(p)
        self.assertFalse(result["ok"])
        self.assertEqual(result["missing_tables"],[])
        self.assertIn("limit_micro",result["missing_columns"]["projects"])
        self.assertIsNone(result["budget_violations"])
        with sqlite3.connect(p) as conn:
            self.assertEqual([r[1] for r in conn.execute("PRAGMA table_info(projects)")],["id"])

if __name__ == "__main__":
    unittest.main()
