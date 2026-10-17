"""Evidence-first and mixed-stack coverage regression tests (stdlib only)."""
import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "skills" / "bounty-pilot" / "scripts"


def load(name):
    spec = importlib.util.spec_from_file_location("test_" + name, SCRIPTS / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


EXPERIMENT = load("experiment_gate")
COVERAGE = load("scope_coverage")
SHA = "a" * 40


def paired():
    def case(role):
        return {"pair_id": "witness", "role": role, "executed": True, "tests_ran": True,
                "timed_out": False, "status": "ran", "exit_code": 0,
                "matched_expected_exit": True,
                "argv": ["forge", "test", "--match-test", "test_" + role]}
    return {"source_revision": SHA, "source_status": "clean", "mode": "executed", "result": "experiments-conformed",
            "finding_id": "BP-001", "cases": [case("candidate"), case("negative-control")]}


class EvidenceFirstTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.run = Path(self.temp.name)
        (self.run / "run.json").write_text(json.dumps({"commit": SHA}))
        self.findings = [{"id": "BP-001", "revision": SHA,
                          "status": "needs-evidence", "severity": "high"}]
        self.ledger = {"version": 1, "experiments": []}
        self.write()

    def write(self):
        (self.run / "findings.json").write_text(json.dumps(self.findings))
        (self.run / "experiments.json").write_text(json.dumps(self.ledger))

    def recorded(self, data=None):
        (self.run / "native-results.json").write_text(json.dumps(data or paired()))
        self.ledger["experiments"] = [{
            "finding_id": "BP-001", "status": "executed", "revision": SHA,
            "result_path": "native-results.json",
            "observation": "Candidate and protected control both ran locally."
        }]
        self.write()

    def test_missing_experiment_fails(self):
        self.assertEqual(EXPERIMENT.review(self.run)["result"], "failed")

    def test_paired_experiment_passes(self):
        self.recorded()
        self.assertEqual(EXPERIMENT.review(self.run)["result"], "passed")

    def test_dry_run_is_not_execution(self):
        evidence = paired()
        evidence["mode"] = "dry-run"
        self.recorded(evidence)
        self.assertEqual(EXPERIMENT.review(self.run)["selected"][0]["state"], "incomplete")

    def test_zero_tests_cannot_pass(self):
        evidence = paired()
        evidence["cases"][0]["tests_ran"] = False
        self.recorded(evidence)
        self.assertEqual(EXPERIMENT.review(self.run)["result"], "failed")

    def test_missing_control_cannot_pass(self):
        evidence = paired()
        evidence["cases"] = evidence["cases"][:1]
        self.recorded(evidence)
        self.assertEqual(EXPERIMENT.review(self.run)["result"], "failed")

    def test_runner_observed_commit_must_match(self):
        evidence = paired()
        evidence["source_revision"] = "b" * 40
        self.recorded(evidence)
        self.assertEqual(EXPERIMENT.review(self.run)["result"], "failed")

    def test_stale_revision_cannot_pass(self):
        self.recorded()
        self.ledger["experiments"][0]["revision"] = "b" * 40
        self.write()
        self.assertEqual(EXPERIMENT.review(self.run)["result"], "failed")

    def test_pair_result_cannot_escape_private_run(self):
        self.recorded()
        self.ledger["experiments"][0]["result_path"] = "../outside.json"
        self.write()
        self.assertEqual(EXPERIMENT.review(self.run)["result"], "failed")

    def test_blocker_requires_alternative_attempt(self):
        self.ledger["experiments"] = [{
            "finding_id": "BP-001", "status": "blocked",
            "reason": "Cargo dependencies could not be fetched in offline environment.",
            "attempted_alternative": "Tried cargo test --offline in a disposable checkout."
        }]
        self.write()
        # A blocker carries what the shell printed, not only a sentence about it.
        self.assertEqual(EXPERIMENT.review(self.run)["result"], "failed")
        self.ledger["experiments"][0].update(
            command="cargo test --offline", exit_code=101,
            output_excerpt="error: no matching package named `anchor-lang` found")
        self.write()
        self.assertEqual(EXPERIMENT.review(self.run)["result"], "passed")
        del self.ledger["experiments"][0]["attempted_alternative"]
        self.write()
        self.assertEqual(EXPERIMENT.review(self.run)["result"], "failed")

    def test_only_top_three_block_followup(self):
        for i in range(2, 6):
            self.findings.append({"id": "BP-%03d" % i, "revision": SHA,
                                  "status": "hypothesis", "severity": "medium"})
        self.recorded()
        report = EXPERIMENT.review(self.run, limit=1)
        self.assertEqual(report["result"], "passed")
        self.assertEqual(len(report["deferred"]), 4)

    def test_unexecuted_runner_cannot_claim_conformance(self):
        evidence = paired()
        evidence["cases"][0]["executed"] = False
        self.recorded(evidence)
        self.assertEqual(EXPERIMENT.review(self.run)["result"], "failed")


class CrossStackTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name) / "project"
        self.repo.mkdir()
        self.run = Path(self.temp.name) / "private-run"
        (self.run / "bundles").mkdir(parents=True)
        for name in ("contracts/src/Bridge.sol", "relayer/src/main.rs"):
            path = self.repo / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("// placeholder\n")
        subprocess.check_call(["git", "init", "-q", str(self.repo)])
        subprocess.check_call(["git", "-C", str(self.repo), "add", "."])

    def test_mixed_project_fails_if_rust_is_excluded(self):
        (self.run / "bundles" / "source.md").write_text(
            "# In-scope source\n\n### contracts/src/Bridge.sol\n\n")
        report = COVERAGE.audit(self.repo, self.run, ["contracts"])
        self.assertIn("rust", report["missing_stacks"])
        self.assertIn("relayer/src/main.rs", report["excluded_by_scope"])

    def test_both_stacks_pass_inventory(self):
        (self.run / "bundles" / "source.md").write_text(
            "### contracts/src/Bridge.sol\n\n### relayer/src/main.rs\n")
        report = COVERAGE.audit(self.repo, self.run)
        self.assertEqual(report["missing_stacks"], [])
        self.assertEqual(report["bundled_source_files"], 2)


if __name__ == "__main__":
    unittest.main()
