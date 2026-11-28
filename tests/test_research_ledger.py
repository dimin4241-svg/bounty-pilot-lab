import sys
import tempfile
import unittest
import sqlite3
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "skills/bounty-pilot/scripts"))
import research_ledger as ledger


class ResearchLedgerTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.scope = self.root / "scope.txt"
        self.scope.write_text("owned synthetic fixtures")
        self.db = self.root / "ledger.sqlite"
        self.rev = "a" * 40
        ledger.initialize(self.db, self.rev, self.scope, 100, True)

    def open(self):
        return ledger.opened(self.db, self.scope, self.rev)

    def test_resume_and_budget(self):
        with self.open() as (con, budget):
            ledger.reserve(con, budget, "one", "model-a", 70)
        with self.open() as (con, budget):
            self.assertEqual(ledger.status(con, budget)["available_micro_usd"], 30)
            self.assertEqual(ledger.status(con, budget)["pending_reservations"][0]["id"], "one")
            with self.assertRaises(ValueError):
                ledger.reserve(con, budget, "two", "model-b", 31)
            ledger.settle(con, "one", 40)
            ledger.reserve(con, budget, "two", "model-b", 60)
            self.assertEqual(ledger.status(con, budget)["available_micro_usd"], 0)

    def test_overrun_is_recorded_and_blocks(self):
        with self.open() as (con, budget):
            ledger.reserve(con, budget, "one", "m", 50)
            ledger.settle(con, "one", 101)
            self.assertTrue(ledger.status(con, budget)["over_budget"])
            with self.assertRaises(ValueError):
                ledger.reserve(con, budget, "two", "m", 1)

    def test_no_duplicate_charge(self):
        with self.open() as (con, budget):
            ledger.reserve(con, budget, "one", "m", 20)
            with self.assertRaises(sqlite3.IntegrityError):
                ledger.reserve(con, budget, "one", "m", 20)
            ledger.settle(con, "one", 0)
            with self.assertRaises(ValueError):
                ledger.settle(con, "one", 10)

    def test_scope_change(self):
        self.scope.write_text("different scope")
        with self.assertRaises(ValueError):
            with self.open():
                pass

    def test_revision_change(self):
        with self.assertRaises(ValueError):
            with ledger.opened(self.db, self.scope, "b"*40):
                pass

    def test_private_and_no_overwrite(self):
        self.assertEqual(self.db.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(FileExistsError):
            ledger.initialize(self.db, self.rev, self.scope, 100, True)

    def test_reviews_never_claim_verification(self):
        c = self.root / "candidate"
        n = self.root / "control"
        c.write_text("candidate")
        n.write_text("control")
        with self.open() as (con, budget):
            with self.assertRaises(ValueError):
                ledger.review(con, "case", "same", "same", c, n, "supports")
            with self.assertRaises(ValueError):
                ledger.review(con, "case", "a", "b", c, c, "supports")
            ledger.review(con, "case", "a", "b", c, n, "supports")
            ledger.feedback(con, "case", "pending", c)
            report = ledger.status(con, budget)
            self.assertEqual(report["reviews"], {"supports": 1})
            self.assertEqual(report["feedback"], {"pending": 1})
            ledger.feedback(con, "case", "accepted", n)
            self.assertEqual(ledger.status(con, budget)["feedback"], {"accepted": 1})
            self.assertEqual(ledger.status(con, budget)["feedback_events"], 2)
            with self.assertRaises(sqlite3.IntegrityError):
                ledger.feedback(con, "case", "accepted", n)
            self.assertEqual(report["independently_verified_by_ledger"], 0)

    def test_rollback(self):
        with self.assertRaises(RuntimeError):
            with self.open() as (con, budget):
                ledger.reserve(con, budget, "one", "m", 20)
                raise RuntimeError("abort")
        with self.open() as (con, budget):
            self.assertEqual(ledger.status(con, budget)["reserved_micro_usd"], 0)

    def test_confirm_and_exact_amount(self):
        with self.assertRaises(ValueError):
            ledger.initialize(self.root / "other", self.rev, self.scope, 100)
        with self.open() as (con, budget):
            for bad in (-1, 1.2, True, 0):
                with self.assertRaises(ValueError):
                    ledger.reserve(con, budget, "one", "m", bad)
