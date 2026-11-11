"""Phase 6: deterministic sealed mutants, independently cited intent, strict effect review.

Unit tests never run Forge/Docker on a GitHub-hosted runner and never send
requests to any user target. Native subprocesses are tested with fake output.
"""
import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills/bounty-pilot/scripts"


def load(name):
    spec = importlib.util.spec_from_file_location("test_phase6_" + name,
                                                  SCRIPTS / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


harness = load("harness_gen")
fuzz = load("scenario_fuzz")
experiment = load("experimenter")
sandbox = load("sandbox_run")

SOL = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Vault {
    mapping(address => uint256) public balances;
    uint256 public totalAssets;
    uint256 public liabilities;
    address public owner;
    function deposit(uint256 amount) external {
        balances[msg.sender] += amount;
        totalAssets += amount;
    }
    function withdraw(uint256 amount) external {
        require(msg.sender == owner, "denied");
        balances[msg.sender] -= amount;
    }
    function unlock(uint256 at) external {
        require(block.timestamp >= at, "locked");
    }
}
"""

ABI = {"contractName": "Vault", "abi": [
    {"type": "function", "name": "deposit", "stateMutability": "nonpayable",
     "inputs": [{"name": "amount", "type": "uint256"}], "outputs": []},
    {"type": "function", "name": "totalAssets", "stateMutability": "view",
     "inputs": [], "outputs": [{"name": "", "type": "uint256"}]},
    {"type": "function", "name": "liabilities", "stateMutability": "view",
     "inputs": [], "outputs": [{"name": "", "type": "uint256"}]}
]}


def git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args], check=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)


class Fixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        self.repo = self.home / "repo"
        (self.repo / "src").mkdir(parents=True)
        (self.repo / "docs").mkdir()
        (self.repo / "src/Vault.sol").write_text(SOL)
        (self.repo / "docs/intent.md").write_text(
            "The protocol must never report liabilities above total assets.\n"
            "A user should never withdraw funds belonging to another user.\n")
        git(self.repo, "init", "-q")
        git(self.repo, "add", ".")
        git(self.repo, "-c", "user.name=Fixture",
            "-c", "user.email=fixture@example.invalid", "-c",
            "commit.gpgsign=false", "commit", "-qm", "before-property-generation")
        self.revision = subprocess.check_output(
            ["git", "-C", str(self.repo), "rev-parse", "HEAD"],
            text=True).strip()
        self.mutants = self.home / "sealed" / "mutation-plan.json"
        self.intent = self.home / "agent" / "intent-task.json"

    def make_catalog(self, limit=32):
        return harness.prepare_mutants(
            self.repo, ["src/Vault.sol"], self.mutants, max_mutants=limit)

    def make_task(self):
        self.make_catalog()
        return harness.prepare_intent_task(
            self.repo, self.mutants, ["docs/intent.md"], self.intent)

    def proposals(self, approve=True):
        return {"schema_version": 1, "source_revision": self.revision,
                "properties": [{
                    "name": "assetsCoverLiabilities",
                    "text": "Available assets must cover all recorded liabilities",
                    "kind": "getter_compare",
                    "left_getter": "totalAssets",
                    "right_getter": "liabilities",
                    "op": "ge",
                    "evidence_id": "ref-0001", "tier": "confirmed_requirement",
                    "reviewer_approved": approve,
                    "assumptions": ["No approved off-balance-sheet obligations"]
                }]}


class SealedMutationTests(Fixture):
    def test_fixed_operators_and_reproducible_ids(self):
        a = self.make_catalog()
        self.assertEqual(a["source_revision"], self.revision)
        kinds = {m["operator"] for m in a["mutants"]}
        self.assertIn("skip-state-update", kinds)
        self.assertIn("reverse-accounting-sign", kinds)
        self.assertIn("tighten-time-boundary", kinds)
        self.assertIn("flip-sender-auth", kinds)
        self.assertIn("skip-require-guard", kinds)
        self.assertEqual(a["model_calls"], 0)
        self.assertFalse(a["properties_visible_during_mutation"])
        self.assertEqual((self.repo / "src/Vault.sol").read_text(), SOL)
        self.assertEqual(self.mutants.stat().st_mode & 0o777, 0o600)
        b = harness.prepare_mutants(
            self.repo, ["src/Vault.sol"], self.home / "sealed2" / "mutants.json")
        self.assertEqual([x["id"] for x in a["mutants"]],
                         [x["id"] for x in b["mutants"]])

    def test_duplicate_source_and_mutating_checkout_fail_closed(self):
        with self.assertRaises(ValueError):
            harness.prepare_mutants(
                self.repo, ["src/Vault.sol", "src/Vault.sol"], self.mutants)
        (self.repo / "src/Vault.sol").write_text(SOL + "// changed\n")
        with self.assertRaisesRegex(ValueError, "clean"):
            self.make_catalog()

    def test_symlinks_and_untracked_source_denied(self):
        (self.repo / "src/link.sol").symlink_to(self.repo / "src/Vault.sol")
        with self.assertRaises(ValueError):
            harness.prepare_mutants(self.repo, ["src/link.sol"], self.mutants)
        (self.repo / "src/new.sol").write_text(SOL)
        with self.assertRaisesRegex(ValueError, "committed"):
            harness.prepare_mutants(self.repo, ["src/new.sol"], self.mutants)

    def test_fixed_generator_rejects_unsafe_custom_arbitrary_patch(self):
        plan = self.make_catalog()
        mutant = dict(plan["mutants"][0])
        mutant["after_line"] = "selfdestruct(payable(msg.sender));\n"
        with self.assertRaisesRegex(ValueError, "fixed operator"):
            sandbox._validate_source_mutant(plan, mutant, self.repo)

    def test_no_overwrite_sealed_plan(self):
        self.make_catalog()
        with self.assertRaises(ValueError):
            self.make_catalog()


class IntentSeparationTests(Fixture):
    def test_no_sealed_mutant_data_reaches_model_task(self):
        task = self.make_task()
        rendered = json.dumps(task)
        self.assertIn("liabilities", rendered)
        self.assertNotIn("skip-state-update", rendered)
        self.assertNotIn("after_line", rendered)
        self.assertNotIn("before_sha256", rendered)
        self.assertNotIn(self.mutants.name, rendered)
        self.assertFalse(task["mutants_in_bundle"])
        self.assertEqual(self.intent.stat().st_mode & 0o777, 0o600)

    def test_mutations_must_exist_before_separate_task(self):
        with self.assertRaises(ValueError):
            harness.prepare_intent_task(
                self.repo, self.mutants, ["docs/intent.md"], self.intent)
        self.make_catalog()
        with self.assertRaisesRegex(ValueError, "separate"):
            harness.prepare_intent_task(
                self.repo, self.mutants, ["docs/intent.md"],
                self.home / "sealed" / "agent-task.json")

    def test_exact_revision_mismatch_rejected(self):
        self.make_catalog()
        (self.repo / "docs/intent.md").write_text(
            "Changed docs that must not be silently used.\n")
        with self.assertRaises(ValueError):
            harness.prepare_intent_task(
                self.repo, self.mutants, ["docs/intent.md"], self.intent)

    def test_reviewed_and_unreviewed_properties_are_separated(self):
        self.make_task()
        proposals = self.home / "agent" / "proposals.json"
        proposals.write_text(json.dumps(self.proposals(False)))
        result = harness.validate_property_proposals(
            self.intent, proposals, self.home / "review" / "property-catalog.json")
        self.assertEqual(result["approved_rules"], [])
        self.assertEqual(len(result["needs_review"]), 1)
        self.assertEqual(result["native_runs"], 0)

    def test_approved_property_compiles_to_real_assertion_not_todo(self):
        self.make_task()
        p = self.home / "agent" / "proposals.json"
        p.write_text(json.dumps(self.proposals()))
        result = harness.validate_property_proposals(
            self.intent, p, self.home / "review" / "rules.json")
        self.assertEqual(len(result["approved_rules"]), 1)
        self.assertEqual(result["approved_rules"][0]["evidence"]["source_path"],
                         "docs/intent.md")
        abi = self.home / "Vault.json"
        abi.write_text(json.dumps(ABI))
        out = self.home / "generated"
        plan = harness.generate(
            [str(abi)], out, repo=self.repo, approved_properties=result)
        text = (out / "VaultInvariants.t.sol").read_text()
        self.assertEqual(plan["intent_property_count"], 1)
        self.assertIn("function invariant_assetsCoverLiabilities()", text)
        self.assertIn('abi.encodeWithSignature("totalAssets()")', text)
        self.assertIn('abi.encodeWithSignature("liabilities()")', text)
        self.assertIn('assertGe(a, b, "documented getter invariant")', text)
        self.assertNotIn('assertTrue(false, "TODO: write the property', text)

    def test_nonexistent_view_getter_rejected(self):
        self.make_task()
        payload = self.proposals()
        payload["properties"][0]["right_getter"] = "steal"
        path = self.home / "agent" / "p.json"
        path.write_text(json.dumps(payload))
        reviewed = harness.validate_property_proposals(
            self.intent, path, self.home / "review" / "props.json")
        abi = self.home / "Vault.json"
        abi.write_text(json.dumps(ABI))
        with self.assertRaisesRegex(ValueError, "view getter"):
            harness.generate(
                [str(abi)], self.home / "generated", repo=self.repo,
                approved_properties=reviewed)

    def test_invalid_source_reference_and_false_reviewer_block(self):
        self.make_task()
        payload = self.proposals()
        payload["properties"][0]["evidence_id"] = "not-in-citations"
        path = self.home / "agent" / "p.json"
        path.write_text(json.dumps(payload))
        with self.assertRaises(ValueError):
            harness.validate_property_proposals(
                self.intent, path, self.home / "review" / "props.json")


class MutationAssessmentTests(Fixture):
    def receipt(self, catalog):
        return {"schema_version": 1,
                "source_revision": catalog["source_revision"],
                "catalog_sha256": catalog["catalog_sha256"],
                "baseline": {"compiled": True, "property_tests_passed": True,
                             "test_count": 2},
                "results": []}

    @staticmethod
    def row(mid, **fields):
        d = {"mutant_id": mid, "compiled": True,
             "line_reached": True, "state_diverged": True,
             "property_failed": True, "negative_control_passed": True,
             "evidence_sha256": "a" * 64}
        d.update(fields)
        return d

    def test_reached_infected_killed_and_survived_are_separate(self):
        plan = self.make_catalog()
        obs = self.receipt(plan)
        ids = [m["id"] for m in plan["mutants"]]
        obs["results"] = [
            self.row(ids[0]),
            self.row(ids[1], property_failed=False),
            self.row(ids[2], line_reached=False),
            self.row(ids[3], state_diverged=False)]
        result = experiment.assess_mutations(plan, obs)
        self.assertEqual(result["reached_infected_observed"], 2)
        self.assertEqual(result["mutation_detection_fraction"], 0.5)
        self.assertIn("UNREACHED_BY_CAMPAIGN", result["classifications"])
        self.assertIn("POSSIBLY_EQUIVALENT_OR_WEAK_STATE_ORACLE",
                      result["classifications"])
        self.assertFalse(result["native_execution_verified_by_tool"])

    def test_baseline_and_unbound_catalog_fail_closed(self):
        plan = self.make_catalog()
        obs = self.receipt(plan)
        obs["baseline"]["property_tests_passed"] = False
        with self.assertRaises(ValueError):
            experiment.assess_mutations(plan, obs)
        obs = self.receipt(plan)
        obs["catalog_sha256"] = "f" * 64
        with self.assertRaises(ValueError):
            experiment.assess_mutations(plan, obs)

    def test_no_reached_infected_returns_unknown_score_not_zero(self):
        plan = self.make_catalog()
        obs = self.receipt(plan)
        obs["results"] = [self.row(plan["mutants"][0]["id"],
                                   line_reached=None, state_diverged=None)]
        result = experiment.assess_mutations(plan, obs)
        self.assertIsNone(result["mutation_detection_fraction"])
        self.assertEqual(result["classifications"]["REACHABILITY_UNKNOWN"], 1)


def model(buggy=True):
    return {
        "actors": ["alice"],
        "state": {"backing": "10", "claims": "10", "unlocked": 0},
        "invariants": [{"id": "backing", "kind": "compare",
                        "left": {"path": "backing"},
                        "op": "ge", "right": {"path": "claims"}}],
        "actions": [
            {"name": "unlock", "actor": "alice", "effects": [
                {"op": "set", "path": "unlocked", "value": 1}]},
            {"name": "withdraw", "actor": "alice",
             "guards": [{"path": "unlocked", "op": "eq", "value": 1}],
             "effects": ([{"op": "sub", "path": "backing", "value": 1}]
                         if buggy else
                         [{"op": "sub", "path": "backing", "value": 1},
                          {"op": "sub", "path": "claims", "value": 1}])}
        ]
    }


class CounterfactualTests(unittest.TestCase):
    def test_first_violating_transition_and_patched_same_trace(self):
        outcome = fuzz.explore(model(), depth=3)
        self.assertEqual(outcome["status"], "model-counterexample")
        counter = outcome["counterexamples"][0]
        self.assertEqual(counter["depth"], 2)
        trace = counter["stepwise_causal_trace"]
        self.assertEqual(trace["first_violating_step"], 2)
        self.assertIn("backing", {x["path"] for x in trace["steps"][1]["changed_fields"]})
        reviewer = experiment.evaluate_model_counterfactual(
            model(), model(False), counter["trace"])
        self.assertTrue(reviewer["same_trace_passes_on_model"])
        self.assertFalse(reviewer["root_cause_verified"])
        self.assertFalse(reviewer["native_patch_executed"])

    def test_unreplayable_control_not_described_as_fix(self):
        original = fuzz.explore(model(), depth=3)["counterexamples"][0]["trace"]
        changed = model(False)
        changed["actions"][1]["name"] = "different"
        outcome = experiment.evaluate_model_counterfactual(
            model(), changed, original)
        self.assertFalse(outcome["same_trace_passes_on_model"])
        self.assertEqual(outcome["proposed_fix"]["status"], "TRACE_NOT_REPLAYABLE")


class SandboxNativeGateTests(Fixture):
    def test_only_immutable_network_disabled_docker_command(self):
        self.make_catalog()
        out = self.home / "out" / "receipt.json"
        out.parent.mkdir()
        cmd = sandbox.build_mutation_command(
            self.repo, self.mutants, out, "myorg/foundry@sha256:" + "a" * 64,
            "VaultInvariants", max_mutants=5, uid=1001, gid=1001)
        self.assertIn("--network=none", cmd)
        self.assertIn("--pull=never", cmd)
        self.assertIn("--read-only", cmd)
        self.assertIn("--env=BPL_MUTATION_SANDBOX=1", cmd)
        self.assertIn("--mount=type=bind,src=" + str(self.repo.resolve()) +
                      ",dst=/target,readonly", cmd)
        self.assertIn("__inside_mutation", cmd)
        self.assertFalse(out.exists())

    def test_mutant_native_mode_fails_on_host(self):
        self.make_catalog()
        with patch.dict(os.environ, {"BPL_MUTATION_SANDBOX": "0"}):
            with self.assertRaises(ValueError):
                sandbox.run_inside_mutations(
                    "/target", "/input/catalog.json", "/evidence/out.json",
                    "VaultInvariants", 1)

    def test_missing_image_or_insecure_target_denied(self):
        self.make_catalog()
        out = self.home / "report.json"
        with self.assertRaises(ValueError):
            sandbox.build_mutation_command(
                self.repo, self.mutants, out, "foundry:latest", "VaultInvariants",
                uid=1001, gid=1001)
        with self.assertRaises(ValueError):
            sandbox.build_mutation_command(
                self.repo, self.mutants, out, "foundry@sha256:" + "a"*64,
                "../external", uid=1001, gid=1001)

    def test_forge_output_parses_nonzero_test_count_and_reverts(self):
        class Completed:
            returncode = 0
            stdout = ("Suite result: ok. 2 passed; 0 failed;\n"
                      "deposit(uint256) 100 91\n")
            stderr = ""
        with patch.object(sandbox.shutil, "which", return_value="/trusted/forge"), \
             patch.object(sandbox.subprocess, "run", return_value=Completed()):
            result = sandbox._forge(["test", "--offline"], self.repo)
        self.assertEqual(result["test_count"], 2)
        self.assertEqual(result["handler_metrics"][0]["reverts"], 91)
        self.assertEqual(result["handler_metrics"][0]["revert_fraction"], 0.91)


if __name__ == "__main__":
    unittest.main()
