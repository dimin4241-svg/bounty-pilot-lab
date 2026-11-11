"""Independent intent-backed property authoring and property-blind mutation tests."""
import copy
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills/bounty-pilot/scripts"


def module(name):
    spec = importlib.util.spec_from_file_location("mutation_test_" + name,
                                                  SCRIPTS / (name + ".py"))
    obj = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)
    return obj


lab = module("mutation_lab")
harness = module("harness_gen")

MODEL = {
    "state": {"assets": "10", "liabilities": "10", "counter": "0"},
    "actors": ["alice"],
    "actions": [
        {"name": "accrue", "actor": "alice",
         "guards": [{"path": "assets", "op": "ge", "value": "0"}],
         "effects": [
             {"path": "assets", "op": "add", "value": 2},
             {"path": "liabilities", "op": "add", "value": 2}]},
        {"name": "noop", "actor": "alice",
         "guards": [{"path": "counter", "op": "lt", "value": "0"}],
         "effects": [{"path": "counter", "op": "add", "value": 1}]}
    ]
}


def props(rule=None):
    if rule is None:
        rule = {"id": "balanced", "kind": "compare",
                "left": {"path": "assets"}, "op": "eq",
                "right": {"path": "liabilities"}}
    return {"schema_version": 1, "author_role": "separate_property_author",
            "bank_visible_to_author": False,
            "rules": [{"id": rule["id"], "invariant": rule,
                       "provenance": {
                           "tier": "confirmed_requirement",
                           "source_kind": "protocol_specification",
                           "source_ref": "spec_balanced",
                           "source_sha256": "a"*64,
                           "supporting_excerpt": "Assets must equal liabilities on each completed operation.",
                           "reviewer_confirmed": True}}]}


class MutationBankTests(unittest.TestCase):
    def test_fixed_deterministic_bank_no_property_dependency(self):
        a = lab.bank(MODEL)
        b = lab.bank(copy.deepcopy(MODEL))
        self.assertEqual(a, b)
        self.assertEqual(a["bank_sha256"], b["bank_sha256"])
        self.assertFalse(a["properties_seen_during_generation"])
        self.assertNotIn("invariants", json.dumps(a))
        self.assertTrue(len(a["mutants"]) > 4)
        self.assertEqual(len({x["mutant_sha256"] for x in a["mutants"]}),
                         len(a["mutants"]))

    def test_bank_refuses_properties_and_nonfinite_floats(self):
        data = copy.deepcopy(MODEL)
        data["invariants"] = [props()["rules"][0]["invariant"]]
        with self.assertRaisesRegex(ValueError, "no properties"):
            lab.bank(data)
        data = copy.deepcopy(MODEL)
        data["state"]["assets"] = 10.25
        with self.assertRaisesRegex(ValueError, "floats"):
            lab.bank(data)

    def test_bank_integrity_catches_edited_mutant_and_operator(self):
        sealed = lab.bank(MODEL)
        sealed["mutants"][0]["mutant_model"]["state"]["assets"] = "777"
        with self.assertRaisesRegex(ValueError, "seal"):
            lab.score(sealed, props())
        sealed = lab.bank(MODEL)
        sealed["bank_sha256"] = "0"*64
        with self.assertRaisesRegex(ValueError, "seal"):
            lab.score(sealed, props())

    def test_mutant_cannot_rely_on_authored_property(self):
        original = lab.bank(MODEL)
        mutated_property = props({
            "id": "unrelated", "kind": "compare",
            "left": {"const": "1"}, "op": "eq",
            "right": {"const": "1"}})
        result = lab.score(original, mutated_property)
        self.assertEqual(result["bank_sha256"], original["bank_sha256"])
        self.assertEqual(result["metrics"]["caught"], 0)
        self.assertGreater(result["metrics"]["reached_changed_behavior"], 0)

    def test_source_protocol_property_kills_reachable_change(self):
        bank = lab.bank(MODEL)
        result = lab.score(bank, props())
        self.assertEqual(result["status"], "LOCAL_STATE_MODEL_MUTATION_EVALUATION")
        self.assertGreater(result["metrics"]["caught"], 0)
        self.assertGreater(result["metrics"]["reached_changed_behavior"], 0)
        self.assertEqual(result["denominator_validated"],
                         result["metrics"]["reached_changed_behavior"])
        self.assertEqual(result["confirmed_vulnerabilities"], 0)
        self.assertFalse(result["target_executed"])
        self.assertGreater(result["metrics"]["not_reached"], 0)
        killed = [r for r in result["mutation_results"]
                  if r["status"] == "KILLED_BY_PROPERTY"]
        self.assertTrue(killed)
        self.assertIn("balanced", killed[0]["property_ids_that_killed"])
        first = killed[0]["first_divergence"]
        self.assertGreaterEqual(first["first_divergent_step"], 1)
        self.assertTrue(first["trace"])
        self.assertTrue(first["changed_fields"])
        self.assertEqual(first["first_divergent_step"], len(first["trace"]))
        self.assertLessEqual(first["first_divergent_step"],
                             first["property_violation_at_step"])

    def test_reached_semantically_equivalent_not_penalized(self):
        simple = {
            "state": {"x": "1"}, "actors": ["a"],
            "actions": [{"name": "add", "actor": "a",
                         "effects": [{"op": "add", "path": "x", "value": 0}]}]}
        saved = lab.bank(simple)
        const = props({"id": "nonnegative", "kind": "compare",
                       "left": {"path": "x"}, "op": "ge",
                       "right": {"const": 0}})
        report = lab.score(saved, const, depth=2)
        self.assertGreater(report["metrics"]["observationally_equivalent_within_bounds"], 0)
        self.assertEqual(
            report["denominator_validated"],
            report["metrics"]["reached_changed_behavior"])
        self.assertEqual(report["metrics"]["caught"], 0)

    def test_baseline_invalid_property_blocks_score(self):
        broken = props({"id": "bad", "kind": "compare",
                        "left": {"path": "assets"}, "op": "lt",
                        "right": {"const": 0}})
        result = lab.score(lab.bank(MODEL), broken)
        self.assertEqual(result["status"], "INVALID_BASELINE_PROPERTY_OR_MODEL")
        self.assertIsNone(result["kill_rate"])

    def test_budget_exhaustion_disables_score_claim(self):
        result = lab.score(lab.bank(MODEL), props(), depth=5, max_states=1)
        self.assertEqual(result["status"], "BOUNDED_EXPLORATION_INCOMPLETE")
        self.assertIsNone(result["kill_rate"])
        self.assertTrue(result["bounded_search_truncated"])


class ProvenanceTests(unittest.TestCase):
    def test_external_intent_only_author_brief(self):
        info = {"schema_version": 1, "target_label": "owned_vault",
                "observable_state_fields": ["assets", "liabilities"],
                "independent_sources": [{
                    "source_ref": "spec_balanced", "source_kind": "protocol_specification",
                    "text": "Every transaction must preserve exact balance of assets and liabilities.",
                    "reviewer_confirmed": True
                }]}
        result = lab.author_brief(info)
        self.assertFalse(result["mutant_bank_visible"])
        self.assertFalse(result["source_code_visible"])
        self.assertEqual(result["llm_calls"], 0)
        self.assertIn("NOT see", result["instructions"][0])
        self.assertEqual(len(result["independent_sources"]), 1)

    def test_author_brief_rejects_token_leaks(self):
        data = {"schema_version":1, "target_label":"vault",
                "observable_state_fields":["a"], "independent_sources":[{
                    "source_ref":"doc1", "source_kind":"external_documentation",
                    "text":"The app requires bearer ABCDEFGHIJKLM1234567890 for login",
                    "reviewer_confirmed":False}]}
        with self.assertRaises(ValueError):
            lab.author_brief(data)

    def test_rule_source_tier_and_independent_author(self):
        invalid = props()
        invalid["rules"][0]["provenance"]["tier"] = "confirmed_requirement"
        invalid["rules"][0]["provenance"]["source_kind"] = "research_hypothesis"
        with self.assertRaisesRegex(ValueError, "external evidence"):
            lab.score(lab.bank(MODEL), invalid)
        invalid = props()
        invalid["bank_visible_to_author"] = True
        with self.assertRaisesRegex(ValueError, "separate property"):
            lab.score(lab.bank(MODEL), invalid)

    def test_harness_generated_stubs_preserve_source_basis_and_cannot_pass_by_default(self):
        candidate = props()
        property_rows = harness.source_backed_properties(candidate)
        self.assertEqual(len(property_rows), 1)
        self.assertEqual(property_rows[0]["name"], "balanced")
        self.assertIn("confirmed_requirement", property_rows[0]["text"])
        text = harness.render_invariants("Vault", [], property_rows, "foundry")
        self.assertIn("assertTrue(false", text)
        self.assertIn("invariant_balanced", text)

    def test_artifacts_are_private_and_create_only(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "bank.json"
            lab._save_new(path, lab.bank(MODEL))
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(ValueError):
                lab._save_new(path, {})
            self.assertEqual(lab._read(path)["mode"],
                             "private-property-blind-state-model-bank")

    def test_audit_model_outputs_are_not_production_proof(self):
        output = lab.score(lab.bank(MODEL), props())
        self.assertEqual(output["confirmed_vulnerabilities"], 0)
        self.assertFalse(output["target_executed"])
        self.assertEqual(output["real_model_calls"], 0)


if __name__ == "__main__":
    unittest.main()
