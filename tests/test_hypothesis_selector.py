"""AVRE's cap must never make a late high-scoring lead unsearchable."""
import importlib.util
import unittest
from pathlib import Path

FILE = Path(__file__).resolve().parents[1] / "skills/bounty-pilot/scripts/hypothesis_selector.py"
spec = importlib.util.spec_from_file_location("hypothesis_selector", FILE)
selector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(selector)


def candidate(id_, module, priority, surface="src/Pool.sol", bug="state"):
    return {"id": id_, "module": module, "scores": {"priority": priority},
            "affected_paths": [surface], "bug_class": bug}


class HypothesisSelectorTests(unittest.TestCase):
    def test_late_high_ranked_lead_is_not_silently_dropped(self):
        original = [candidate("a", "first", 0.1),
                    candidate("b", "first", 0.2),
                    candidate("c", "second", 0.99)]
        kept, deferred, stats = selector.select(original, 2)
        self.assertIn("c", [x["id"] for x in kept])
        self.assertIn("a", [x["id"] for x in deferred])
        self.assertEqual(stats["evaluated"], 3)
        self.assertEqual(stats["deferred"], 1)
        self.assertEqual(deferred[0]["deferred_reason"], "bounded-research-budget-not-refuted")

    def test_deterministic_module_diversity_and_conservation(self):
        cases = [candidate(str(i), "a", 0.8 - i / 100) for i in range(6)]
        cases += [candidate("last", "b", 0.01, bug="auth")]
        first = selector.select(cases, 3)
        self.assertEqual(first, selector.select(cases, 3))
        self.assertIn("last", [x["id"] for x in first[0]])
        self.assertEqual(len(first[0]) + len(first[1]), len(cases))
        self.assertEqual(set(x["id"] for x in first[0] + first[1]),
                         set(x["id"] for x in cases))

    def test_more_modules_than_budget_prioritizes_best_head(self):
        cases = [candidate("a", "a", 0.2), candidate("b", "b", 0.9),
                 candidate("c", "c", 0.7)]
        kept, _, _ = selector.select(cases, 2)
        self.assertEqual({x["id"] for x in kept}, {"b", "c"})

    def test_feedback_is_revision_bound_and_never_confirms_findings(self):
        rows = [candidate("late", "b", 0.55), candidate("top", "a", 0.6)]
        feed = {"schema_version": 1, "source_revision": "a"*40,
                "execution": "local-native", "experiments": [{
                    "hypothesis_id": "late",
                    "status": "local-witness-needs-independent-review",
                    "observations": [{}, {}]}]}
        ranked, stats = selector.apply_feedback(rows, feed, "a"*40)
        self.assertEqual(ranked[0]["id"], "late")
        self.assertEqual(stats["witness_leads"], 1)
        self.assertEqual(ranked[0]["native_feedback"]["status"], "witness-unverified")
        with self.assertRaisesRegex(ValueError, "revision"):
            selector.apply_feedback(rows, feed, "b"*40)

    def test_invalid_ids_and_budgets_fail_closed(self):
        with self.assertRaises(ValueError):
            selector.select([candidate("a", "a", 1), candidate("a", "a", 2)], 2)
        with self.assertRaises(ValueError):
            selector.select([], 0)


if __name__ == "__main__":
    unittest.main()
