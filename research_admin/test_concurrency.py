"""Offline concurrency and deterministic accounting regression tests."""
import random
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from ledger import Ledger
from maintenance import doctor

class AccountingRegressionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name)/"ledger.db"
        self.db = Ledger(self.path)
        self.db.project("demo",1000)

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def test_parallel_reservations_never_exceed_limit(self):
        barrier = threading.Barrier(12)
        def attempt(i):
            db = Ledger(self.path)
            try:
                barrier.wait(timeout=10)
                try:
                    db.reserve("demo",str(i),"mock",100)
                    return True
                except ValueError:
                    return False
            finally:
                db.close()
        with ThreadPoolExecutor(max_workers=12) as pool:
            accepted = list(pool.map(attempt,range(12)))
        self.assertEqual(sum(accepted),10)
        row = self.db.summary()["projects"][0]
        self.assertEqual(row["reserved_micro"],1000)
        self.assertTrue(doctor(self.path)["ok"])

    def test_deterministic_budget_sequence(self):
        rng = random.Random(20261126)
        expected_spent = 0
        outstanding = {}
        for i in range(200):
            if outstanding and rng.random() < .5:
                charge = rng.choice(list(outstanding))
                value = rng.randint(0,outstanding.pop(charge))
                self.db.settle(charge,value)
                expected_spent += value
            else:
                charge = str(i)
                value = rng.randint(0,150)
                if expected_spent+sum(outstanding.values())+value <= 1000:
                    self.db.reserve("demo",charge,"mock",value)
                    outstanding[charge] = value
                else:
                    with self.assertRaises(ValueError):
                        self.db.reserve("demo",charge,"mock",value)
            row = self.db.summary()["projects"][0]
            self.assertEqual(row["spent_micro"],expected_spent)
            self.assertEqual(row["reserved_micro"],sum(outstanding.values()))
            self.assertLessEqual(row["spent_micro"]+row["reserved_micro"],1000)
        self.assertTrue(doctor(self.path)["ok"])

if __name__ == "__main__":
    unittest.main()
