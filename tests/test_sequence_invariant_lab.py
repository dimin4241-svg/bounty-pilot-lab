"""Offline fixtures and negative controls for sequence_invariant_lab.py."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("sequence_invariant_lab", Path(__file__).resolve().parents[1] / "skills/bounty-pilot/scripts/sequence_invariant_lab.py")
lab = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lab)
SHA = "a" * 40


def doc(kind, step, options=None):
    return {"source_revision": SHA, "checks": [{"id": "case", "kind": kind, **(options or {})}], "steps": [step]}


class InvariantReviewTest(unittest.TestCase):
    def check(self, kind, step, count=1, options=None):
        result = lab.review(doc(kind, step, options))
        self.assertEqual(result["witness_count"], count, result)
        self.assertEqual(result["classification"], "OFFLINE_MODEL_REVIEW_NOT_A_DEPLOYED_FINDING")
        return result

    def test_cross_context_transfer(self):
        self.check("transfer_isolation", {"transfers": [{"fund_owner": "alice", "recipient": "mallory", "amount": "100", "authorized_by_owner": False}]})

    def test_self_and_authorized_transfers(self):
        self.check("transfer_isolation", {"transfers": [{"fund_owner": "alice", "recipient": "alice", "amount": "100"},
            {"fund_owner": "alice", "recipient": "bob", "amount": "2", "authorized_by_owner": True}]}, 0)

    def test_backing_deficit(self):
        self.check("obligation_coverage", {"accounting": {"USDC": {"held_assets": "90", "claims_by_owner": {"alice": "80", "bob": "20"}}}})

    def test_backing_control(self):
        self.check("obligation_coverage", {"accounting": {"USDC": {"held_assets": "90", "collectible_receivables": "10", "claims_by_owner": {"alice": "80", "bob": "20"}}}}, 0)

    def test_callback_interleaving(self):
        d = {"source_revision": SHA, "checks": [{"id": "nested", "kind": "callback_stack", "disallow_cross_actor_nested": True}],
             "steps": [{"event": "enter", "actor": "alice", "operation": "collect"},
                       {"event": "enter", "actor": "mallory", "operation": "withdraw"},
                       {"event": "exit", "actor": "mallory", "operation": "withdraw"},
                       {"event": "exit", "actor": "alice", "operation": "collect"}]}
        self.assertEqual(lab.review(d)["witnesses"][0]["status"], "REVIEW_NEEDED")

    def test_callback_nested_normal_legal(self):
        d = {"source_revision": SHA, "checks": [{"id": "nested", "kind": "callback_stack"}],
             "steps": [{"event": "enter", "actor": "alice", "operation": "collect"},
                       {"event": "enter", "actor": "mallory", "operation": "withdraw"},
                       {"event": "exit", "actor": "mallory", "operation": "withdraw"},
                       {"event": "exit", "actor": "alice", "operation": "collect"}]}
        self.assertEqual(lab.review(d)["witness_count"], 0)

    def test_unbalanced_callback_invalid(self):
        with self.assertRaises(ValueError):
            self.check("callback_stack", {"event": "exit", "actor": "alice", "operation": "collect"})

    def test_trigger_overwrite_and_disable(self):
        self.check("trigger_integrity", {"trigger": {"active": True, "required": ["range_upper"],
            "armed": ["lend_upper", "range_lower"], "disabled": ["range_lower"],
            "allowed_actions": ["range", "lend"], "executed_mode": "exit"}}, 3)

    def test_trigger_failure_not_rearmed(self):
        self.check("trigger_integrity", {"trigger": {"active": True, "required": [], "armed": [],
            "action_failed": True, "consumed": ["stop_loss"], "rearmed": False, "must_survive_failure": True}})

    def test_trigger_intended_burn_not_flagged(self):
        self.check("trigger_integrity", {"trigger": {"active": True, "required": [], "armed": [],
            "action_failed": True, "consumed": ["notification"], "rearmed": False, "must_survive_failure": False}}, 0)

    def test_migration_approval_missing(self):
        self.check("lifecycle_authority", {"migration": {"old_id": 1, "new_id": 2,
            "automation_active": True, "required_capabilities": ["erc721_token_approval"], "successor_capabilities": []}})

    def test_migration_approval_control(self):
        self.check("lifecycle_authority", {"migration": {"old_id": 1, "new_id": 2,
            "automation_active": True, "required_capabilities": ["operator_for_all"], "successor_capabilities": ["operator_for_all"]}}, 0)

    def test_lazy_interest_checkpoint_drift(self):
        self.check("temporal_accrual", {"accrual": {"intervals": [{"start": "0", "end": "10", "rate_per_unit": "4"},
            {"start": "10", "end": "20", "rate_per_unit": "2"}], "observed_accrual": "40"}})

    def test_lazy_interest_control(self):
        self.check("temporal_accrual", {"accrual": {"intervals": [{"start": "0", "end": "10", "rate_per_unit": "4"},
            {"start": "10", "end": "20", "rate_per_unit": "2"}], "observed_accrual": "60"}}, 0)

    def test_asset_alias_mismatch(self):
        self.check("asset_identity", {"asset_links": [{"left": "native", "right": "wrapped", "admitted_as_same": False}]}, 1,
                   {"canonical_assets": {"native": "ETH", "wrapped": "ETH"}})

    def test_asset_identity_control(self):
        self.check("asset_identity", {"asset_links": [{"left": "native", "right": "wrapped", "admitted_as_same": True}]}, 0,
                   {"canonical_assets": {"native": "ETH", "wrapped": "ETH"}})

    def test_asset_identity_never_infer_aliases(self):
        with self.assertRaises(ValueError):
            self.check("asset_identity", {"asset_links": [{"left": "native", "right": "wrapped", "admitted_as_same": True}]}, 0)

    def test_no_model_from_float(self):
        with self.assertRaises(ValueError):
            self.check("transfer_isolation", {"transfers": [{"fund_owner": "a", "recipient": "b", "amount": 0.1}]})

    def test_no_model_from_nan(self):
        with self.assertRaises(ValueError):
            self.check("transfer_isolation", {"transfers": [{"fund_owner": "a", "recipient": "b", "amount": "NaN"}]})

    def test_digest_mismatch_fails_gate(self):
        pair = self.native_pair()
        pair["control"]["starting_state_digest"] = "d"*64
        r = lab.review({**doc("transfer_isolation", {"transfers": []}), "native_pair": pair})
        self.assertEqual(r["native_evidence"]["status"], "NATIVE_PAIR_INSUFFICIENT")

    def test_pair_still_not_verified_even_when_contrasting(self):
        r = lab.review({**doc("transfer_isolation", {"transfers": []}), "native_pair": self.native_pair()})
        self.assertEqual(r["native_evidence"]["status"], "NATIVE_PAIR_RECEIPTS_NEED_INDEPENDENT_VERIFICATION")

    def test_unpinned_native_receipt_fails_gate(self):
        pair = self.native_pair()
        pair["candidate"]["source_revision"] = "b"*40
        r = lab.review({**doc("transfer_isolation", {"transfers": []}), "native_pair": pair})
        self.assertEqual(r["native_evidence"]["status"], "NATIVE_PAIR_INSUFFICIENT")

    @staticmethod
    def native_pair():
        core = {"source_revision": SHA, "starting_state_digest": "b"*64, "command": "forge test --offline", "log_sha256": "c"*64, "exit_code": 0}
        return {"candidate": {**core, "invariant_holds": False}, "control": {**core, "invariant_holds": True}}

    def test_proof_plan_has_no_fake_execution(self):
        p = lab.proof_plan(doc("transfer_isolation", {"transfers": [{"fund_owner": "a", "recipient": "b", "amount": 10}]}))
        self.assertEqual(p["candidate_count"], 1)
        self.assertEqual(p["classification"], "NATIVE_POC_TASKS_NOT_EXECUTED")

    def test_scan_source_cues_and_negative(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "Vault.sol").write_text("contract V { function f() public { x = currencyDelta(address(this)); TAKE_PAIR(); }}")
            (root / "Quiet.sol").write_text("contract Q {function f() public {value += 1; }}")
            result = lab.scan(d, SHA)
            self.assertEqual(result["files_inspected"], 2)
            self.assertTrue(any(x["pattern"] == "shared-context-accounting" for x in result["findings"]))
            self.assertFalse(any(x["file"] == "Quiet.sol" for x in result["findings"]))
            self.assertFalse(result["revision_verified_by_tool"])

    def test_output_never_overwrite(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "out.json"
            lab._write_new(path, {"test": "ok"})
            with self.assertRaises(ValueError):
                lab._write_new(path, {"test": "overwritten"})
            self.assertEqual(json.loads(path.read_text()), {"test": "ok"})
            if os.name == "posix":
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_caseforge_scoring_not_blind(self):
        with tempfile.TemporaryDirectory() as d:
            c, p = Path(d)/"c.json", Path(d)/"p.json"
            c.write_text(json.dumps({"cases": [{"id": "c1", "status": "Confirmed", "severity": "Medium", "pattern": "trigger", "url": "https://example.org"}]}))
            p.write_text(json.dumps({"predictions": [{"case_id": "c1", "pattern": "trigger", "status": "Confirmed", "native_pair_evidence_supplied": True}]}))
            x = lab._caseforge(c, "score", p)
            self.assertEqual(x["pattern_matches"], 1)
            self.assertIn("NOT_BLIND", x["classification"])


if __name__ == "__main__":
    unittest.main()
