"""Gate a purported 30–50 case historical benchmark without inventing evidence."""
import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "skills" / "bounty-pilot" / "scripts"
SPEC = importlib.util.spec_from_file_location("web_benchmark_readiness_test",
                                              SCRIPTS / "web_benchmark_readiness.py")
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)


def synthetic_catalog(n=30):
    cases = []
    for i in range(n):
        repo = "https://github.com/example/repo" + str(i % 6)
        a = hashlib.sha1(("revision-vulnerable-%d" % i).encode()).hexdigest()
        b = hashlib.sha1(("revision-patched-%d" % i).encode()).hexdigest()
        cases.append({
            "id": "SYNTHETIC-" + str(i).zfill(3),
            "repository_url": repo,
            "vulnerable_commit": a, "fixed_commit": b,
            "paths": ["src/file-%d.js" % i],
            "family": ["authorization", "business-state", "cache",
                       "session", "browser-trust"][i % 5],
            "advisory_url": "https://github.com/advisories/GHSA-synthetic-" + str(i),
            "published_at": "2026-01-01",
            "source_revisions": "SYNTHETIC placeholder, NOT historically verified"
        })
    return {"schema_version": 1, "cases": cases,
            "notice": "Synthetic shape fixture only, not real published cases"}


def evaluator(catalog, complete=True):
    return {"schema_version": 1, "reviewer_role": "external_independent_reviewer",
            "cases": [
                {"id": row["id"], "reproduced_vulnerable_sha256": (
                    hashlib.sha256(("vulnerable%d" % i).encode()).hexdigest()
                    if complete else None),
                 "reproduced_patched_sha256": (
                    hashlib.sha256(("patched%d" % i).encode()).hexdigest()
                    if complete else None),
                 "revision_chain_checked": complete,
                 "distinct_negative_control": complete,
                 "reviewer_id": "operator-asserted-reviewer",
                 "independent_review_asserted": complete}
                for i, row in enumerate(catalog["cases"])]}


class HistoricalReadinessTests(unittest.TestCase):
    def test_builtin_three_cases_are_blocked_not_reported_as_40(self):
        path = SCRIPTS.parent / "references" / "web-historical-seeds.json"
        catalog = json.loads(path.read_text())
        result = mod.assess(catalog, {"schema_version": 1,
            "reviewer_role": "external_independent_reviewer", "cases": []})
        self.assertEqual(result["case_count"], 3)
        self.assertFalse(result["can_prepare_private_operator_replay"])
        self.assertIn("NEED_30_TO_50_INDEPENDENT_HISTORICAL_CASES",
                      result["blocking_reasons"])
        self.assertFalse(result["public_uplift_claim_allowed"])

    def test_synthetic_shape_30_asserted_reviews_still_not_attested(self):
        catalog = synthetic_catalog()
        result = mod.assess(catalog, evaluator(catalog))
        self.assertEqual(result["case_count"], 30)
        self.assertEqual(result["repository_count"], 6)
        self.assertEqual(result["mechanism_families"], 5)
        self.assertEqual(result["status"],
                         "BLOCKED_INSUFFICIENT_HISTORICAL_EVIDENCE")
        self.assertFalse(result["can_prepare_private_operator_replay"])
        self.assertIn("SYNTHETIC_OR_PLACEHOLDER_CASES_NOT_HISTORICAL",
                      result["blocking_reasons"])
        self.assertFalse(result["ground_truth_independently_verified_by_tool"])
        self.assertFalse(result["public_uplift_claim_allowed"])
        self.assertEqual(result["real_model_runs"], 0)

    def test_missing_controls_blocks(self):
        catalog = synthetic_catalog(40)
        result = mod.assess(catalog, evaluator(catalog, False))
        self.assertEqual(result["case_count"], 40)
        self.assertEqual(result["cases_with_operator_attested_controls"], 0)
        self.assertFalse(result["can_prepare_private_operator_replay"])
        self.assertIn("MISSING_SEPARATELY_REVIEWED_VULNERABLE_AND_PATCHED_CONTROLS",
                      result["blocking_reasons"])

    def test_different_repos_and_families_are_required(self):
        catalog = synthetic_catalog(30)
        for row in catalog["cases"]:
            row["repository_url"] = "https://github.com/example/same"
            row["family"] = "authorization"
        result = mod.assess(catalog, evaluator(catalog))
        self.assertFalse(result["can_prepare_private_operator_replay"])
        self.assertIn("INSUFFICIENT_REPOSITORY_DIVERSITY", result["blocking_reasons"])
        self.assertIn("INSUFFICIENT_MECHANISM_DIVERSITY", result["blocking_reasons"])

    def test_duplicate_or_unknown_reviewer_invalidates(self):
        catalog = synthetic_catalog()
        reviews = evaluator(catalog)
        reviews["cases"].append(dict(reviews["cases"][0]))
        with self.assertRaises(ValueError):
            mod.assess(catalog, reviews)
        reviews = evaluator(catalog)
        reviews["cases"][0]["id"] = "UNKNOWN"
        with self.assertRaises(ValueError):
            mod.assess(catalog, reviews)

    def test_reused_evidence_digest_blocks_even_asserted_reviews(self):
        catalog = synthetic_catalog(30)
        reviews = evaluator(catalog)
        reviews["cases"][1]["reproduced_patched_sha256"] = (
            reviews["cases"][0]["reproduced_patched_sha256"])
        result = mod.assess(catalog, reviews)
        self.assertIn("EVIDENCE_DIGEST_REUSED_ACROSS_DISTINCT_CASES",
                      result["blocking_reasons"])
        self.assertFalse(result["public_uplift_claim_allowed"])

    def test_private_immutable_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "result.json"
            report = mod.assess(synthetic_catalog(30), evaluator(synthetic_catalog(30)))
            mod._write(out, report)
            self.assertEqual(out.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(ValueError):
                mod._write(out, report)


if __name__ == "__main__":
    unittest.main()
