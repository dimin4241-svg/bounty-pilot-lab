import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "skills/bounty-pilot/scripts"))
from quality_scorecard import summarize


def fixture():
    doc = {"schema_version": 1, "model": "synthetic-model",
           "baseline_revision": "a" * 40, "candidate_revision": "b" * 40,
           "budget": {"usd": 1, "seconds": 60, "input_tokens": 100, "output_tokens": 100},
           "tasks": [{"id": "p", "kind": "positive"}, {"id": "n", "kind": "negative"}],
           "receipts": []}
    for arm in ("baseline", "candidate"):
        for task in doc["tasks"]:
            positive = task["kind"] == "positive"
            solved = positive and arm == "candidate"
            doc["receipts"].append({
                "arm": arm, "task_id": task["id"], "status": "completed",
                "oracle_solved": solved if positive else None,
                "confirmed": int(solved), "rejected": int(not positive and arm == "baseline"),
                "unresolved": 0,
                "usage": {"usd": 0.1, "seconds": 5, "input_tokens": 50,
                          "output_tokens": 10, "context_tokens": 20}})
    return doc


class QualityScorecardTest(unittest.TestCase):
    def test_paired_scores(self):
        r = summarize(fixture())
        self.assertEqual(r["candidate_only_solves"], 1)
        self.assertEqual(r["baseline_only_solves"], 0)
        self.assertEqual(r["arms"]["baseline"]["clean_negative_rate"], 0)
        self.assertEqual(r["arms"]["candidate"]["clean_negative_rate"], 1)
        self.assertEqual(r["arms"]["candidate"]["usd_per_confirmed_claim"], 0.2)
        self.assertEqual(r["arms"]["candidate"]["context_share"], 0.4)
        self.assertFalse(r["public_uplift_claim_allowed"])

    def test_missing_usage_unknown(self):
        d = fixture()
        d["receipts"][2]["usage"] = None
        c = summarize(d)["arms"]["candidate"]
        self.assertIsNone(c["usage_totals"])
        self.assertIsNone(c["usd_per_confirmed_claim"])

    def test_failed_run_retained(self):
        d = fixture()
        d["receipts"][0]["status"] = "timeout"
        d["receipts"][0]["usage"]["seconds"] = 80
        a = summarize(d)["arms"]["baseline"]
        self.assertEqual(a["failed_runs"], 1)
        self.assertEqual(a["known_budget_exceedances"], 1)

    def test_invalid_receipts(self):
        for mutate in (
            lambda d: d["receipts"].pop(),
            lambda d: d["receipts"].__setitem__(1, copy.deepcopy(d["receipts"][0])),
            lambda d: d["receipts"][0].update(oracle_solved=True),
            lambda d: d["receipts"][0]["usage"].update(usd=float("nan")),
            lambda d: d["receipts"][0]["usage"].update(context_tokens=51),
            lambda d: d["receipts"][1].update(confirmed=1),
            lambda d: d["receipts"][2].update(status="error"),
        ):
            d = fixture()
            mutate(d)
            with self.assertRaises(ValueError):
                summarize(d)

    def test_unresolved_not_clean(self):
        d = fixture()
        d["receipts"][3]["unresolved"] = 1
        c = summarize(d)["arms"]["candidate"]
        self.assertEqual(c["clean_negative_rate"], 0)
        self.assertEqual(c["unresolved_claims"], 1)

    def test_no_positive_or_negative_denominator(self):
        d = fixture()
        d["tasks"] = d["tasks"][:1]
        d["receipts"] = [r for r in d["receipts"] if r["task_id"] == "p"]
        self.assertIsNone(summarize(d)["arms"]["candidate"]["clean_negative_rate"])


if __name__ == "__main__":
    unittest.main()
