"""Tests of the evaluator, not results of an AI participant."""
import unittest
from collections import Counter
from pathlib import Path
from report_benchmark import load, score, compare

FIXTURES = Path(__file__).resolve().parent / "fixtures"

class DocumentationFixturesTests(unittest.TestCase):
    def setUp(self):
        self.tasks = load(FIXTURES / "documentation_tasks.json")
        self.refs = load(FIXTURES / "documentation_references.json")
        self.control = [
            dict(ref, reason="Synthetic scoring control, copied from answer key.")
            for ref in self.refs
        ]

    def test_balanced_public_corpus(self):
        self.assertEqual(len(self.tasks), 12)
        self.assertEqual(Counter(ref["label"] for ref in self.refs),
                         {"supported": 4, "refuted": 4, "unresolved": 4})
        self.assertEqual(score(self.tasks, self.refs, self.control)["passed"], 12)

    def test_all_supported_is_not_success(self):
        answers = [dict(row, label="supported") for row in self.control]
        result = score(self.tasks, self.refs, answers)
        self.assertEqual(result["passed"], 4)

    def test_missing_answers_count(self):
        result = score(self.tasks, self.refs, self.control[:6])
        self.assertEqual(result["passed"], 6)
        self.assertEqual(result["cases"], 12)

    def test_paired_regression_detected(self):
        answers = self.control.copy()
        answers[0] = dict(answers[0], source_ids=[])
        result = compare(self.tasks, self.refs, self.control, answers)
        self.assertFalse(result["no_regression"])
        self.assertEqual(result["regressed"], 1)

if __name__ == "__main__":
    unittest.main()
