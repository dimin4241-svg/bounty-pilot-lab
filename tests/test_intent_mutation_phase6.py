"""Phase 6: blind deterministic mutants, source-pinned intent and honest scores."""
import copy
import hashlib
import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "skills/bounty-pilot/scripts"


def load(name):
    spec = importlib.util.spec_from_file_location("phase6_" + name, SCRIPTS / (name+".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


harness = load("harness_gen")
fuzzer = load("scenario_fuzz")
experiment = load("experimenter")


class Phase6Test(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.repo = self.base / "target"
        self.repo.mkdir()
        (self.repo / "src").mkdir()
        (self.repo / "docs").mkdir()
        self.source = self.repo / "src" / "Vault.sol"
        self.source.write_text(
            "pragma solidity ^0.8.13;\ncontract Vault {\n"
            "  uint256 public totalAssets;\n  uint256 public totalDebt;\n"
            "  function deposit(uint256 amount) external {\n"
            "    require(totalAssets >= totalDebt);\n"
            "    totalAssets += amount;\n  }\n}\n")
        self.doc = self.repo / "docs" / "spec.md"
        self.doc.write_text("# Owned fixture\nTotal assets must cover total debt.\n")
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True,
                       stdout=subprocess.DEVNULL)
        subprocess.run(["git", "-C", str(self.repo), "add", "."], check=True,
                       stdout=subprocess.DEVNULL)
        subprocess.run(["git", "-C", str(self.repo), "-c", "user.name=Fixture",
                        "-c", "user.email=fixture@example.invalid", "commit",
                        "-qm", "pinned"], check=True, stdout=subprocess.DEVNULL)
        self.sha = subprocess.check_output(
            ["git", "-C", str(self.repo), "rev-parse", "HEAD"]).decode().strip()
        self.abi = {
            "contractName": "Vault", "abi": [
                {"type": "function", "name": "deposit",
                 "stateMutability": "nonpayable",
                 "inputs": [{"name":"amount","type":"uint256"}],
                 "outputs": []},
                {"type": "function", "name": "totalAssets",
                 "stateMutability": "view", "inputs": [],
                 "outputs": [{"type":"uint256"}]},
                {"type": "function", "name": "totalDebt",
                 "stateMutability": "view", "inputs": [],
                 "outputs": [{"type":"uint256"}]}]}
        self.prop = {
            "name": "backing", "text": "Assets cover debt",
            "contract": "Vault", "left": "totalAssets", "op": "ge",
            "right": "totalDebt", "basis_class": "documented_requirement",
            "basis_file": "docs/spec.md",
            "basis_sha256": hashlib.sha256(self.doc.read_bytes()).hexdigest(),
            "operator_reviewed": True}

    def proposal(self):
        return {"schema_version": 1, "source_revision": self.sha,
                "mutation_catalog_seen": False, "properties": [dict(self.prop)]}

    def mutants(self):
        return harness.mutation_plan(
            str(self.repo), self.sha, ["src/Vault.sol"], self.base / "mutants")

    def receipt(self, plan):
        return {
            "schema_version": 1, "source_revision": self.sha,
            "mutants": [{
                "id": r["id"], "mutant_file_sha256": r["mutant_file_sha256"],
                "baseline_pass": True, "compile_result": "pass",
                "mutation_reached": True, "property_failed": True,
                "negative_control_pass": True,
                "equivalence_review": "not-reviewed",
                "equivalence_evidence_sha256": None}
                for r in plan["mutants"]]}

    def test_deterministic_source_mutants_are_generated_before_properties(self):
        plan = self.mutants()
        self.assertEqual(plan["operator_set"], "fixed-v1")
        self.assertFalse(plan["property_material_read"])
        self.assertGreaterEqual(len(plan["mutants"]), 2)
        self.assertFalse(plan["target_code_executed"])
        self.assertTrue((self.base / "mutants" / "mutation-plan.json").is_file())
        self.assertEqual(self.source.read_text().count("totalAssets += amount"), 1)
        for row in plan["mutants"]:
            self.assertTrue((self.base/"mutants"/row["mutant_copy"]).is_file())
            self.assertIn(row["operator"], (
                "guard-strict-ge", "accounting-update-flip"))

    def test_same_source_same_mutation_operators_and_digests(self):
        p1 = self.mutants()
        p2 = harness.mutation_plan(str(self.repo), self.sha, ["src/Vault.sol"],
                                   self.base/"again")
        for a,b in zip(p1["mutants"],p2["mutants"]):
            for key in ("id", "operator", "source_path", "line",
                        "original_file_sha256", "mutant_file_sha256"):
                self.assertEqual(a[key], b[key])

    def test_mutation_can_only_be_staged_in_marked_pristine_disposable_clone(self):
        plan = self.mutants()
        checkout = self.base / "ephemeral"
        subprocess.run(["git", "clone", "-q", str(self.repo),
                        str(checkout)], check=True)
        with self.assertRaises(ValueError):
            harness.stage_mutation(plan, self.base / "mutants",
                                   "mutant-0001", checkout, True)
        marker = checkout / ".bounty-pilot-disposable-mutation"
        marker.write_text("I_CONTROL_THIS_DISPOSABLE_CHECKOUT\n")
        with self.assertRaises(ValueError):
            harness.stage_mutation(plan, self.base / "mutants",
                                   "mutant-0001", checkout, False)
        original = self.source.read_bytes()
        report = harness.stage_mutation(
            plan, self.base / "mutants", "mutant-0001", checkout, True)
        self.assertTrue(report["target_checkout_modified"])
        self.assertFalse(report["native_test_executed"])
        self.assertEqual(self.source.read_bytes(), original)
        self.assertEqual(hashlib.sha256(
            (checkout / "src" / "Vault.sol").read_bytes()).hexdigest(),
            plan["mutants"][0]["mutant_file_sha256"])
        with self.assertRaises(ValueError):
            harness.stage_mutation(plan, self.base / "mutants",
                                   "mutant-0001", checkout, True)

    def test_mutation_does_not_accept_untracked_or_modified_sources(self):
        bad = self.repo/"src"/"other.sol"
        bad.write_text("pragma solidity ^0.8.13;\n")
        with self.assertRaises(ValueError):
            harness.mutation_plan(str(self.repo), self.sha, ["src/other.sol"],
                                  self.base/"bad")
        with self.assertRaises(ValueError):
            harness.mutation_plan(str(self.repo), "0"*40, ["src/Vault.sol"],
                                  self.base/"bad2")
        self.source.write_text(self.source.read_text() + "\n// dirty\n")
        with self.assertRaises(ValueError):
            harness.mutation_plan(str(self.repo), self.sha, ["src/Vault.sol"],
                                  self.base/"bad3")

    def test_no_supported_mutation_returns_inconclusive_not_success(self):
        self.assertEqual(harness._mutate_line("// require(a >= b);"), [])
        self.assertEqual(harness._mutate_line('require(a >= b, "x");'), [])
        self.assertEqual(harness._mutate_line("uint256 x = 10;"), [])

    def test_intent_only_bundle_contains_no_mutants(self):
        path = self.base/"intent.json"
        data = harness.intent_bundle(str(self.repo), self.sha,
                                     ["docs/spec.md"], path)
        self.assertFalse(data["mutation_catalog_read"])
        self.assertFalse(data["source_code_read"])
        self.assertEqual(data["documentation"][0]["sha256"], self.prop["basis_sha256"])
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_reviewed_intent_getter_property_is_real_assert_not_todo(self):
        props = harness.intent_properties(str(self.repo), self.sha,
                                          self.proposal(), [self.abi])
        self.assertEqual(len(props), 1)
        out = self.base/"harness"
        result = harness.generate([self.abi], str(out), contracts=["Vault"],
                                  properties=props, repo=str(self.repo))
        content = (out/"VaultInvariants.t.sol").read_text()
        self.assertIn('abi.encodeWithSignature("totalAssets()")', content)
        self.assertIn("assertGe(a, b", content)
        self.assertNotIn("TODO: write the property:", content)
        self.assertEqual(result["properties"][0]["basis_class"],
                         "documented_requirement")

    def test_unreviewed_and_unpinned_intent_proposals_are_rejected(self):
        doc = self.proposal()
        doc["properties"][0]["operator_reviewed"] = False
        with self.assertRaises(ValueError):
            harness.intent_properties(str(self.repo), self.sha, doc, [self.abi])
        doc = self.proposal()
        doc["properties"][0]["basis_sha256"] = "a"*64
        with self.assertRaises(ValueError):
            harness.intent_properties(str(self.repo), self.sha, doc, [self.abi])
        doc = self.proposal()
        doc["mutation_catalog_seen"] = True
        with self.assertRaises(ValueError):
            harness.intent_properties(str(self.repo), self.sha, doc, [self.abi])

    def test_missing_getter_and_wrong_return_type_rejected(self):
        doc = self.proposal()
        doc["properties"][0]["right"] = "withdraw"
        with self.assertRaises(ValueError):
            harness.intent_properties(str(self.repo), self.sha, doc, [self.abi])

    def test_modified_document_does_not_count_as_pinned_intent(self):
        self.doc.write_text("Modified docs")
        with self.assertRaises(ValueError):
            harness.intent_bundle(str(self.repo), self.sha, ["docs/spec.md"],
                                  self.base/"intent.json")

    def test_mutation_scoring_never_calls_unreached_mutant_weak(self):
        plan = self.mutants()
        receipts = self.receipt(plan)
        first = receipts["mutants"][0]
        first["mutation_reached"] = False
        first["property_failed"] = False
        scored = harness.mutation_score(plan, receipts)
        self.assertEqual(scored["results"][0]["status"], "UNREACHED_COVERAGE_GAP")
        self.assertEqual(scored["independent_equivalence_verified_by_tool"], False)

    def test_killed_and_reached_survived_are_separate(self):
        plan = self.mutants()
        receipts = self.receipt(plan)
        receipts["mutants"][0]["property_failed"] = False
        result = harness.mutation_score(plan, receipts)
        self.assertEqual(result["results"][0]["status"],
                         "REACHED_SURVIVED_EQUIVALENCE_UNKNOWN")
        self.assertGreater(result["reached_non_equivalent_or_unknown"], 0)
        self.assertEqual(result["real_vulnerabilities_confirmed"], 0)

    def test_compilation_failure_and_equivalent_attestation_excluded(self):
        plan = self.mutants()
        receipts = self.receipt(plan)
        receipts["mutants"][0]["compile_result"] = "fail"
        receipts["mutants"][1]["equivalence_review"] = "independent-equivalent"
        receipts["mutants"][1]["equivalence_evidence_sha256"] = "9"*64
        result = harness.mutation_score(plan, receipts)
        self.assertEqual(result["results"][0]["status"],
                         "INVALID_NONCOMPILING_MUTANT")
        self.assertEqual(result["results"][1]["status"],
                         "OPERATOR_ATTESTED_EQUIVALENT_EXCLUDED")
        self.assertFalse(result["independent_equivalence_verified_by_tool"])

    def test_mutant_receipt_source_revisions_and_digests_bound(self):
        plan = self.mutants()
        receipts = self.receipt(plan)
        receipts["source_revision"] = "0"*40
        with self.assertRaises(ValueError):
            harness.mutation_score(plan, receipts)
        receipts = self.receipt(plan)
        receipts["mutants"][0]["mutant_file_sha256"] = "0"*64
        with self.assertRaises(ValueError):
            harness.mutation_score(plan, receipts)

    def test_fuzz_handler_revert_rate_identifies_useless_campaigns(self):
        report = harness.coverage_review({
            "schema_version": 1, "source_revision": self.sha,
            "handlers": [
                {"selector": "0x00000001", "calls": 100, "reverts": 95},
                {"selector": "0x00000002", "calls": 0, "reverts": 0},
                {"selector": "0x00000003", "calls": 60, "reverts": 2}]})
        self.assertEqual([r["status"] for r in report["handlers"]],
                         ["MOSTLY_REVERTING_FIX_SETUP", "NOT_CALLED",
                          "REACHED_WITH_CALLS_NOT_PATH_PROOF"])
        self.assertEqual(report["total_calls"], 160)
        self.assertFalse(report["mutated_line_reachability_proven"])

    def test_fuzz_counters_refuse_invalid_or_duplicated_selectors(self):
        example = {"schema_version": 1, "source_revision": self.sha,
                   "handlers": [{"selector": "0x00000001", "calls": 2,
                                 "reverts": 3}]}
        with self.assertRaises(ValueError):
            harness.coverage_review(example)
        example["handlers"][0]["reverts"] = 1
        example["handlers"].append(dict(example["handlers"][0]))
        with self.assertRaises(ValueError):
            harness.coverage_review(example)

    def test_first_violation_delta_is_observation_not_root_cause(self):
        before = {"reserve": {"cash": "10", "secret": "private"}}
        after = {"reserve": {"cash": "11", "secret": "private"}}
        delta = fuzzer._changed_scalar_fields(before, after)
        self.assertEqual(delta, [{"field": "reserve.cash", "kind": "changed"}])
        self.assertNotIn("10", json.dumps(delta))
        self.assertNotIn("private", json.dumps(delta))

    def test_counterfactual_patch_review_with_controls(self):
        receipt = {
            "schema_version": 1, "source_revision": self.sha,
            "candidate_id": "lead-synthetic", "operator_reviewed": True,
            "original": {"source_sha256":"1"*64,
                         "native_trace_sha256":"2"*64, "repetitions":2,
                         "violation_reproduced":True,
                         "negative_control_passed":True,
                         "ordinary_tests_passed":True},
            "patched": {"source_sha256":"3"*64,
                        "native_trace_sha256":"4"*64, "repetitions":2,
                        "violation_reproduced":False,
                        "negative_control_passed":True,
                        "ordinary_tests_passed":True}}
        result = experiment.counterfactual_review(receipt)
        self.assertEqual(result["status"],
                         "OPERATOR_ATTESTED_CAUSAL_SUPPORT_NOT_INDEPENDENTLY_VERIFIED")
        self.assertFalse(result["patch_safety_verified"])
        receipt["patched"]["negative_control_passed"] = False
        blocked = experiment.counterfactual_review(receipt)
        self.assertEqual(blocked["status"], "BLOCKED_FAILED_CONTROL_OR_REGRESSION")
        receipt["original"]["source_sha256"] = receipt["patched"]["source_sha256"]
        with self.assertRaises(ValueError):
            experiment.counterfactual_review(receipt)


if __name__ == "__main__":
    unittest.main()
