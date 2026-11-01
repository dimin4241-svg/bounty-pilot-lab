"""Offline native test-output capture and independent web historical benchmark gates."""
import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "skills/bounty-pilot/scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))
import web_native_capture as native
import web_historical_bench as history

REV = "b" * 40


class Checkout(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "target"
        self.root.mkdir()
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        subprocess.run(["git", "-C", str(self.root), "config", "user.email",
                        "fixture@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(self.root), "config", "user.name", "Fixture"], check=True)

    def commit(self, text, path="README.md"):
        f = self.root / path
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text, encoding="utf-8")
        subprocess.run(["git", "-C", str(self.root), "add", "-A"], check=True)
        subprocess.run(["git", "-C", str(self.root), "commit", "-qm", "fixture"], check=True)
        return subprocess.run(["git", "-C", str(self.root), "rev-parse", "HEAD"],
                              check=True, text=True, capture_output=True).stdout.strip()


def marker(role, observation):
    return (native.PREFIX + json.dumps({"schema_version": 1, "pair_id": "BP-501",
                                         "role": role, "observation": observation}))


class NativeCaptureTests(Checkout):
    def configuration(self, candidate, control, marker_on=True):
        script = ("import unittest\nclass Case(unittest.TestCase):\n"
                  "    def test_case(self):\n"
                  "        self.assertEqual(2+2,4)\n"
                  "        print(%r)\n")
        for role, observation, f in (("candidate", candidate, "candidate_test.py"),
                                     ("negative-control", control, "control_test.py")):
            payload = marker(role, observation) if marker_on else "just a normal passing test"
            (self.root / f).write_text(script % payload, encoding="utf-8")
        revision = self.commit("Native fixtures with local printed observations\n")
        return {"schema_version": 1, "finding_id": "BP-501", "source_revision": revision,
                "environment": "native-local", "operation": "business-invariants",
                "scenario": "fee-sign", "invariant": "fee cannot be negative",
                "equivalence_basis": "same fixture, negative fee toggled",
                "runner_plan": {"finding_id": "BP-501", "cases": [
                    {"id": "native-candidate", "pair_id": "BP-501", "role": "candidate",
                     "cwd": ".", "argv": [sys.executable, "-m", "unittest", "-v",
                                          "candidate_test.Case.test_case"]},
                    {"id": "native-control", "pair_id": "BP-501", "role": "negative-control",
                     "cwd": ".", "argv": [sys.executable, "-m", "unittest", "-v",
                                          "control_test.Case.test_case"]}
                ]}}

    @staticmethod
    def observations():
        return ({"order_id": "invoice-1", "actor": "alice",
                 "fee_atomic": "-10", "status": "accepted"},
                {"order_id": "invoice-1", "actor": "alice",
                 "fee_atomic": "10", "status": "accepted"})

    def test_dry_run_is_not_evidence_and_does_not_execute(self):
        c = self.configuration(*self.observations())
        o = native.collect(c, self.root, None)
        self.assertEqual(o["status"], "DRY_RUN_ONLY")
        self.assertEqual(o["confirmed_vulnerabilities"], 0)

    def test_execution_needs_external_sandbox_confirmation(self):
        c = self.configuration(*self.observations())
        with self.assertRaisesRegex(ValueError, "network-isolation"):
            native.collect(c, self.root, Path(self.tmp.name) / "evidence",
                           execute=True, isolated=True)
        self.assertFalse((Path(self.tmp.name) / "evidence").exists())

    def test_two_real_native_rounds_are_bound_and_reusable_in_web3(self):
        c = self.configuration(*self.observations())
        out = Path(self.tmp.name) / "native-evidence"
        result = native.collect(c, self.root, out, execute=True, isolated=True,
                                network_isolated=True)
        self.assertEqual(result["status"], "CAPTURED_NATIVE_TEST_OUTPUT")
        self.assertEqual(result["differential_leads"], 1)
        self.assertEqual(result["confirmed_vulnerabilities"], 0)
        doc = json.loads((out / "native-observations.json").read_text())
        for field in ("candidate", "negative_control"):
            self.assertRegex(doc["cases"][0][field]["trace_sha256"], r"^[0-9a-f]{64}$")
        report = json.loads((out / "differential.json").read_text())
        self.assertEqual(report["leads"], 1)
        self.assertEqual(len(result["rounds"]), 2)
        self.assertEqual(result["pinned_revision"], c["source_revision"])
        self.assertEqual(result["observation_file_sha256"], native._hash(doc))
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE((out / "native-observations.json").stat().st_mode),
                             0o600)

    def test_missing_marker_is_not_evidence(self):
        c = self.configuration(*self.observations(), marker_on=False)
        with self.assertRaisesRegex(ValueError, "one native observation marker"):
            native.collect(c, self.root, Path(self.tmp.name) / "out",
                           execute=True, isolated=True, network_isolated=True)

    def test_dirty_checkout_and_wrong_revision_refused(self):
        c = self.configuration(*self.observations())
        c["source_revision"] = REV
        with self.assertRaisesRegex(ValueError, "HEAD differs"):
            native.collect(c, self.root, None)
        c["source_revision"] = self.commit("changed source\n")
        (self.root / "README.md").write_text("uncommitted change\n")
        with self.assertRaisesRegex(ValueError, "tracked changes"):
            native.collect(c, self.root, Path(self.tmp.name) / "out", execute=True,
                           isolated=True, network_isolated=True)

    def test_duplicate_role_and_unsafe_env_rejected(self):
        c = self.configuration(*self.observations())
        c["runner_plan"]["cases"][1]["role"] = "candidate"
        with self.assertRaisesRegex(ValueError, "roles"):
            native.collect(c, self.root, None)
        c["runner_plan"]["cases"][1]["role"] = "negative-control"
        c["runner_plan"]["cases"][0]["pass_env"] = ["API_KEY"]
        with self.assertRaisesRegex(ValueError, "pass_env"):
            native.collect(c, self.root, None)

    def test_marker_duplicate_keys_and_mismatched_pair_rejected(self):
        base = {"executed": True, "status": "ran", "matched_expected_exit": True,
                "tests_ran": True, "stdout": native.PREFIX +
                '{"schema_version":1,"schema_version":1,"pair_id":"BP-501",'
                '"role":"candidate","observation":{}}', "stderr": ""}
        with self.assertRaisesRegex(ValueError, "duplicate"):
            native._marker(base, "BP-501", "candidate")
        base["stdout"] = marker("negative-control", {"foo": "bar"})
        with self.assertRaisesRegex(ValueError, "marker fields"):
            native._marker(base, "BP-501", "candidate")

    def test_no_stdout_marker_in_missing_or_truncated_test(self):
        data = {"executed": True, "status": "ran", "matched_expected_exit": True,
                "tests_ran": True, "truncated": True, "stdout":
                marker("candidate", self.observations()[0]), "stderr": ""}
        with self.assertRaisesRegex(ValueError, "complete output"):
            native._marker(data, "BP-501", "candidate")


class HistoricBenchmarkTests(Checkout):
    def seed(self):
        c1 = self.commit("affected source", "app/middleware.ts")
        c2 = self.commit("patched source", "app/middleware.ts")
        return {"schema_version": 1, "cases": [{
            "id": "HIST-CHECK", "repository_url": "https://github.com/example/project",
            "vulnerable_commit": c1, "fixed_commit": c2,
            "paths": ["app/middleware.ts"], "family": "authz",
            "advisory_url": "https://github.com/advisories/GHSA-example",
            "published_at": "2025-01-01",
            "source_revisions": "synthetic pinned demo only"}]}

    def setup_benchmark(self):
        hunter = Path(self.tmp.name) / "hunter"
        evaluator = Path(self.tmp.name) / "evaluator"
        res = history.prepare(self.seed(), hunter, evaluator)
        queue = json.loads((hunter / "blind-queue.json").read_text())
        mapping = json.loads((evaluator / "answer-map.json").read_text())
        return res, queue, mapping, evaluator

    def predictions(self, queue, mapping, with_claims=True):
        roles = {t["task_id"]: t["role"] for t in mapping["key"]}
        return {"schema_version": 1, "tasks": [{
            "task_id": t["task_id"], "source_revision": t["source_revision"],
            "findings": ([{"id": "BP-501", "source_path": "app/middleware.ts",
                           "mechanism": "bypass of protected route"}]
                         if with_claims and roles[t["task_id"]] == "vulnerable" else [])
        } for t in queue["tasks"]]}

    def test_immutable_public_historical_seeds_are_pinned(self):
        seed = history.json_file(history.SEED)
        self.assertEqual(len(history._catalog(seed)), 3)
        self.assertEqual(len({x["repository_url"] for x in seed["cases"]}), 2)
        self.assertEqual(len({c["vulnerable_commit"] for c in seed["cases"]}), 3)

    def test_prepare_separates_evaluator_truth_and_shuffles_tasks(self):
        res, queue, mapping, evaluator = self.setup_benchmark()
        self.assertEqual(res["status"], "PREPARED_NOT_MEASURED")
        self.assertEqual(len(queue["tasks"]), 2)
        self.assertNotIn("vulnerable", json.dumps(queue))
        self.assertNotIn("patched", json.dumps(queue))
        self.assertNotIn("advisory", json.dumps(queue))
        self.assertIn("role", json.dumps(mapping))
        self.assertEqual(mapping["hunter_queue_sha256"], history._sha(queue))
        self.assertIsNone(res["measured_rediscoveries"])

    def test_verify_pinned_checkout_required(self):
        _, queue, mapping, _ = self.setup_benchmark()
        vuln = next(t for t in mapping["key"] if t["role"] == "vulnerable")
        from_queue = next(t for t in queue["tasks"] if t["task_id"] == vuln["task_id"])
        with self.assertRaisesRegex(ValueError, "pinned"):
            history.verify_checkout(queue, from_queue["task_id"], self.root)
        subprocess.run(["git", "-C", str(self.root), "checkout", "-q",
                        vuln["source_revision"]], check=True)
        ok = history.verify_checkout(queue, vuln["task_id"], self.root)
        self.assertEqual(ok["pinned_git_revision_verified"], vuln["source_revision"])

    def test_seal_then_independently_judged_score(self):
        _, queue, mapping, evaluator = self.setup_benchmark()
        predictions = self.predictions(queue, mapping)
        sealed = history.seal(queue, predictions, evaluator)
        self.assertEqual(sealed["findings_count"], 1)
        with self.assertRaisesRegex(ValueError, "already sealed"):
            history.seal(queue, predictions, evaluator)
        positive = next(t for t in mapping["key"] if t["role"] == "vulnerable")
        review = {"schema_version": 1, "reviewer": "independent-human-fixture",
                  "judgments": [{"task_id": positive["task_id"], "finding_id": "BP-501",
                                 "valid_match": True, "basis": "line and effect matched"}]}
        scored = history.score(evaluator, review)
        self.assertEqual((scored["true_positives"], scored["false_negatives"]), (1, 0))
        self.assertEqual(scored["patched_controls_without_claim"], 1)
        self.assertFalse(scored["independent_model_run_verified"])

    def test_no_findings_is_zero_recall_not_fake_success(self):
        _, queue, mapping, evaluator = self.setup_benchmark()
        history.seal(queue, self.predictions(queue, mapping, with_claims=False), evaluator)
        scored = history.score(evaluator, {"schema_version": 1, "reviewer": "reviewer",
                                           "judgments": []})
        self.assertEqual(scored["recall"], 0)
        self.assertIsNone(scored["precision"])

    def test_unreviewed_claims_refuse_score(self):
        _, queue, mapping, evaluator = self.setup_benchmark()
        history.seal(queue, self.predictions(queue, mapping), evaluator)
        with self.assertRaisesRegex(ValueError, "each and every"):
            history.score(evaluator, {"schema_version": 1, "reviewer": "reviewer",
                                      "judgments": []})

    def test_tampered_sealed_prediction_is_void(self):
        _, queue, mapping, evaluator = self.setup_benchmark()
        history.seal(queue, self.predictions(queue, mapping), evaluator)
        p = evaluator / "sealed-predictions.json"
        d = json.loads(p.read_text())
        d["tasks"][0]["source_revision"] = REV  # guaranteed to change the sealed bytes
        p.write_text(json.dumps(d))
        with self.assertRaisesRegex(ValueError, "edited"):
            history.score(evaluator, {"schema_version": 1, "reviewer": "reviewer",
                                      "judgments": []})

    def test_patched_snapshot_cannot_get_positive_credit(self):
        _, queue, mapping, evaluator = self.setup_benchmark()
        predictions = self.predictions(queue, mapping, with_claims=False)
        patched = next(t for t in mapping["key"] if t["role"] == "patched")
        for row in predictions["tasks"]:
            if row["task_id"] == patched["task_id"]:
                row["findings"] = [{"id": "BP-501", "source_path": "app/middleware.ts",
                                    "mechanism": "false assertion"}]
        history.seal(queue, predictions, evaluator)
        with self.assertRaisesRegex(ValueError, "patched"):
            history.score(evaluator, {"schema_version": 1, "reviewer": "reviewer",
                                      "judgments": [{"task_id": patched["task_id"],
                                                     "finding_id": "BP-501",
                                                     "valid_match": True, "basis": "invalid"}]})

    def test_prediction_missing_or_changed_revision_rejected(self):
        _, queue, mapping, evaluator = self.setup_benchmark()
        incomplete = self.predictions(queue, mapping)
        incomplete["tasks"].pop()
        with self.assertRaisesRegex(ValueError, "cover all"):
            history.seal(queue, incomplete, evaluator)
        wrong = self.predictions(queue, mapping)
        wrong["tasks"][0]["source_revision"] = REV
        with self.assertRaisesRegex(ValueError, "mismatched"):
            history.seal(queue, wrong, evaluator)

    def test_duplicate_catalog_case_and_snapshot_refused(self):
        seed = self.seed()
        seed["cases"].append(seed["cases"][0])
        with self.assertRaisesRegex(ValueError, "duplicate case"):
            history._catalog(seed)

    def test_separation_guard(self):
        seed = self.seed()
        folder = Path(self.tmp.name) / "shared"
        with self.assertRaisesRegex(ValueError, "separate"):
            history.prepare(seed, folder, folder)


if __name__ == "__main__":
    unittest.main()
