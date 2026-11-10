"""Paired blinded-source A/B benchmark integrity and cost accounting tests.

No external repo fetch, model invocation or payout-performance claims.
"""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "skills" / "bounty-pilot" / "scripts"
sys.path.insert(0, str(SCRIPTS))
SPEC = importlib.util.spec_from_file_location("web_bench_ab_for_tests",
                                              SCRIPTS / "web_bench_ab.py")
bench = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bench)


def catalog():
    return {"schema_version": 1, "cases": [
        {"id": "CASE-A", "repository_url": "https://github.com/example/repoA",
         "vulnerable_commit": "a" * 40, "fixed_commit": "b" * 40,
         "paths": ["src/api.ts"], "family": "authorization",
         "advisory_url": "https://github.com/advisories/GHSA-aaaa-bbbb-cccc",
         "published_at": "2026-08-05",
         "source_revisions": "Synthetic snapshot pair, never used for scored benchmark"},
        {"id": "CASE-B", "repository_url": "https://github.com/example/repoB",
         "vulnerable_commit": "c" * 40, "fixed_commit": "d" * 40,
         "paths": ["src/route.ts"], "family": "signed-intent",
         "advisory_url": "https://github.com/advisories/GHSA-dddd-eeee-ffff",
         "published_at": "2026-09-01",
         "source_revisions": "Synthetic snapshot pair, never used for scored benchmark"},
    ]}


def config():
    return {"schema_version": 1, "model_id": "synthetic-bounded-model",
            "baseline_skill_revision": "1" * 40,
            "candidate_skill_revision": "2" * 40,
            "max_usd_per_task": 0.5, "max_seconds_per_task": 600}


def spend(queue):
    return {"schema_version": 1, "model_id": config()["model_id"],
            "tasks": [{"task_id": row["task_id"], "spent_usd": 0.1,
                       "elapsed_seconds": 30, "input_tokens": 200,
                       "output_tokens": 150} for row in queue["tasks"]]}


def empty_prediction(queue):
    return {"schema_version": 1, "tasks": [
        {"task_id": x["task_id"], "source_revision": x["source_revision"],
         "findings": []} for x in queue["tasks"]]}


def empty_judgments():
    return {"schema_version": 1, "reviewer": "independent-fixture-reviewer",
            "judgments": []}


class PairedBenchmarkTests(unittest.TestCase):
    def test_prepare_equal_opaque_tasks_and_no_truth_leak(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "study"
            result = bench.prepare(config(), catalog(), root)
            self.assertEqual(result["state"], "PREPARED_NOT_EXECUTED")
            bq = bench._read(root / "baseline" / "hunter" / "blind-queue.json")
            cq = bench._read(root / "candidate" / "hunter" / "blind-queue.json")
            self.assertEqual(bq, cq)
            raw = json.dumps(bq)
            self.assertNotIn("vulnerable", raw)
            self.assertNotIn("patched", raw)
            self.assertNotIn("advisory_url", raw)
            self.assertNotIn("source_revisions", raw)
            self.assertEqual(len(bq["tasks"]), 4)
            self.assertEqual((root / "study.json").stat().st_mode & 0o777, 0o600)
            with self.assertRaises(ValueError):
                bench.prepare(config(), catalog(), root)

    def test_sealed_empty_arms_do_not_fake_success_or_uplift(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "study"
            bench.prepare(config(), catalog(), root)
            for arm in ("baseline", "candidate"):
                q = bench._read(root / arm / "hunter" / "blind-queue.json")
                bench.historical.seal(q, empty_prediction(q), root / arm / "evaluator")
            queue = bench._read(root / "baseline" / "hunter" / "blind-queue.json")
            result = bench.evaluate(root, empty_judgments(), empty_judgments(),
                                    spend(queue), spend(queue))
            self.assertEqual(result["delta_true_positives"], 0)
            self.assertEqual(result["candidate"]["scores"]["false_negatives"], 2)
            self.assertEqual(result["baseline"]["scores"]["false_negatives"], 2)
            self.assertFalse(result["minimum_case_diversity_for_exploratory_analysis"])
            self.assertFalse(result["public_uplift_claim_allowed"])
            self.assertIsNone(result["baseline_usd_per_true_positive"])
            self.assertEqual(result["candidate"]["recorded_usage"]["usd"], 0.4)
            self.assertEqual(result["model_runs_executed_by_this_tool"], 0)

    def test_missing_seal_or_tampered_hunter_queue_blocks_scoring(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "study"
            bench.prepare(config(), catalog(), root)
            q = bench._read(root / "baseline" / "hunter" / "blind-queue.json")
            with self.assertRaises((ValueError, OSError)):
                bench.evaluate(root, empty_judgments(), empty_judgments(),
                               spend(q), spend(q))
            a = root / "candidate" / "hunter" / "blind-queue.json"
            damaged = bench._read(a)
            damaged["tasks"].pop()
            a.write_text(json.dumps(damaged))
            with self.assertRaises(ValueError):
                bench.evaluate(root, empty_judgments(), empty_judgments(),
                               spend(q), spend(q))

    def test_cost_budget_and_missing_task_fail_closed(self):
        q = {"tasks": [{"task_id": "WB-" + "0" * 16}]}
        good = {"schema_version": 1, "model_id": config()["model_id"],
                "tasks": [{"task_id": q["tasks"][0]["task_id"],
                           "spent_usd": 0.25, "elapsed_seconds": 15,
                           "input_tokens": 5, "output_tokens": 3}]}
        self.assertEqual(bench._spent(good, q, config())["usd"], 0.25)
        good["tasks"][0]["spent_usd"] = 1.0
        with self.assertRaises(ValueError):
            bench._spent(good, q, config())
        good["tasks"] = []
        with self.assertRaises(ValueError):
            bench._spent(good, q, config())

    def test_invalid_config_and_same_arm_rejected(self):
        cfg = config()
        cfg["candidate_skill_revision"] = cfg["baseline_skill_revision"]
        with self.assertRaises(ValueError):
            bench._config(cfg)
        cfg = config()
        cfg["max_seconds_per_task"] = 0
        with self.assertRaises(ValueError):
            bench._config(cfg)


if __name__ == "__main__":
    unittest.main()
