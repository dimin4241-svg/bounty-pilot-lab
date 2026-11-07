"""Evidence-first extensions: offline deterministic tests, native execution mocked.

Native target tests and integration suites are run only by the Mac self-hosted
GitHub Actions workflow; no live RPC, transactions or network requests here.
"""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills/bounty-pilot/scripts"


def load(name):
    spec = importlib.util.spec_from_file_location("bp_test_" + name, SCRIPTS / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


oracle = load("exploit_oracle")
loop = load("exploit_loop")
metrics = load("campaign_metrics")
radar = load("target_radar")
deep = load("deep_audit")
harness = load("harness_gen")


def measured_side(delta="2000000", victim="1", violated=True):
    return {
        "assets": [{"id": "USDC", "decimals": 6, "price_usd": "1",
                    "before_raw": "10000000", "after_raw": str(10000000 + int(delta))}],
        "liabilities": [],
        "unreflected_costs_usd": {key: "0" for key in oracle.COSTS},
        "victim_loss_usd": victim, "invariant": {"id": "p", "violated": violated},
    }


def measured():
    return {"schema_version": 1, "source_revision": "a" * 40, "chain_id": 1,
            "fork_block": 100, "initial_state_digest": "b" * 64,
            "experiments": [{"id": "one",
                             "candidate": measured_side(),
                             "negative_control": measured_side("0", "0", False),
                             "attestations": {
                                 "native_execution": True, "paired_same_initial_state": True,
                                 "unmodified_target": True, "realistic_capital": True,
                                 "no_balance_cheatcodes": True, "all_positions_enumerated": True,
                                 "flash_loans_fully_repaid": True, "prices_pinned": True,
                                 "receipts_preserved": True,
                             }}]}


class OracleTests(unittest.TestCase):
    def test_paired_victim_profit_invariant(self):
        o = oracle.evaluate(measured())
        self.assertEqual(o["candidates"], 1)
        r = o["results"][0]
        self.assertEqual(r["candidate_net_usd"], "2")
        self.assertEqual(r["control_net_usd"], "0")
        self.assertEqual(r["status"], "local-candidate-needs-independent-review")

    def test_control_profit_blocks_promotion(self):
        o = measured()
        o["experiments"][0]["negative_control"] = measured_side("1000000", "0", False)
        self.assertEqual(oracle.evaluate(o)["candidates"], 0)

    def test_unattested_claims_do_not_pass(self):
        o = measured()
        o["experiments"][0]["attestations"]["receipts_preserved"] = False
        self.assertEqual(oracle.evaluate(o)["candidates"], 0)

    def test_mismatched_prices_and_forged_raw_units_rejected(self):
        o = measured()
        o["experiments"][0]["negative_control"]["assets"][0]["price_usd"] = "5"
        with self.assertRaisesRegex(ValueError, "valuations"):
            oracle.evaluate(o)
        o = measured()
        o["experiments"][0]["candidate"]["assets"][0]["after_raw"] = "0.5"
        with self.assertRaisesRegex(ValueError, "integer"):
            oracle.evaluate(o)

    def test_liabilities_and_unreflected_costs(self):
        o = measured()
        c = o["experiments"][0]["candidate"]
        c["liabilities"] = [{"id": "debt", "decimals": 6, "price_usd": "1",
                             "before_raw": "0", "after_raw": "3000000"}]
        o["experiments"][0]["negative_control"]["liabilities"] = [
            {"id": "debt", "decimals": 6, "price_usd": "1",
             "before_raw": "0", "after_raw": "0"}]
        c["unreflected_costs_usd"]["gas"] = "0.01"
        outcome = oracle.evaluate(o)["results"][0]
        self.assertEqual(outcome["candidate_net_usd"], "-1.01")
        self.assertTrue(outcome["candidate_invariant_violated"])


class LoopTests(unittest.TestCase):
    def native(self):
        obs = {"candidate": {"property_id": "p", "initial_state_digest": "b" * 64},
               "negative-control": {"property_id": "p", "initial_state_digest": "b" * 64}}
        return {"source_revision": "a" * 40, "execution": "local-native",
                "witness_count": 1, "experiments": [{
                    "id": "one", "status": "local-witness-needs-independent-review",
                    "observations": [obs, obs]}], "notice": "Review required."}

    def test_no_execution_no_oracle_witness(self):
        native = self.native()
        native["execution"] = "dry-run"
        with patch.object(loop.research, "run", return_value=native):
            result = loop.run(".", {}, measured(), execute=False)
        self.assertEqual(result["oracle_matched_witnesses"], 0)
        self.assertIn("native-tests-not-executed", result["oracle_blockers"])

    def test_exact_native_property_and_digest_binding(self):
        with patch.object(loop.research, "run", return_value=self.native()):
            result = loop.run(".", {}, measured(), execute=True)
        self.assertEqual(result["oracle_matched_witnesses"], 1)

    def test_estranged_state_digest_blocks_binding(self):
        bad = measured()
        bad["initial_state_digest"] = "c" * 64
        with patch.object(loop.research, "run", return_value=self.native()):
            result = loop.run(".", {}, bad, execute=True)
        self.assertEqual(result["oracle_matched_witnesses"], 0)
        self.assertTrue(any("binding-mismatch" in s for s in result["oracle_blockers"]))


class RadarTests(unittest.TestCase):
    def test_tracks_implementation_and_config(self):
        a = {"schema_version": 1, "chain_id": 1, "block": 100,
             "targets": [{"address": "0x" + "1" * 40, "implementation": "0x" + "2" * 40,
                          "reads": {"minDelay": 100}, "errors": []}]}
        b = {"schema_version": 1, "chain_id": 1, "block": 101,
             "targets": [{"address": "0x" + "1" * 40, "implementation": "0x" + "3" * 40,
                          "reads": {"minDelay": 0}, "errors": []},
                         {"address": "0x" + "4" * 40, "errors": []}]}
        result = radar.compare(a, b)
        self.assertEqual(result["implementation_changes"], 1)
        self.assertEqual(result["new_inventory_addresses"], 1)
        self.assertIn("deployed-config-changed", {lead["kind"] for lead in result["leads"]})
        with self.assertRaisesRegex(ValueError, "ascending"):
            radar.compare(b, a)

    def test_errors_are_not_change_evidence(self):
        a = {"schema_version": 1, "chain_id": 1, "block": 1,
             "targets": [{"address": "0x" + "1" * 40, "reads": {"k": "a"}, "errors": []}]}
        b = {"schema_version": 1, "chain_id": 1, "block": 2,
             "targets": [{"address": "0x" + "1" * 40, "reads": {"k": "b"},
                          "errors": ["timeout"]}]}
        self.assertEqual(radar.compare(a, b)["leads"][0]["kind"], "comparison-blocked")


class DeepAuditTests(unittest.TestCase):
    def test_ranks_in_scope_fresh_flows_without_claiming_execution(self):
        model = {"schema_version": 1, "source_revision": "a" * 40,
                 "flows": [
                     {"id": "old", "kind": "vault", "in_scope": True,
                      "value_at_risk_usd": "100000000", "known_duplicate": True},
                     {"id": "fresh", "kind": "bridge", "in_scope": True,
                      "value_at_risk_usd": "20000000", "unprivileged_reachable": True,
                      "changed_since_audit": True},
                     {"id": "excluded", "kind": "wallet", "in_scope": False,
                      "value_at_risk_usd": "999999999"},
                 ]}
        output = deep.plan(model, flows_limit=1)
        self.assertEqual(output["flows_selected"][0]["id"], "fresh")
        self.assertEqual(len(output["flows_selected"][0]["lenses"]), 4)
        self.assertEqual(output["execution"], "planning-only")


class MetricsTests(unittest.TestCase):
    def test_paired_scored_campaign_without_fake_precision(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            a = {"state": "scored", "pinned_commit": "a" * 40, "case": "one",
                 "sealed_at": "2026-01-01T00:00:00Z",
                 "rediscovered": [], "missed": [{"id": "H-1", "severity": "high"}],
                 "published_findings": 1}
            b = dict(a, rediscovered=[{"id": "H-1", "severity": "high"}], missed=[])
            (root / "base.json").write_text(json.dumps([a]), encoding="utf-8")
            (root / "experiment.json").write_text(json.dumps([b]), encoding="utf-8")
            m = {"schema_version": 1, "baseline": "base", "arms": {
                "base": {"scored": "base.json"},
                "without-lens": {"scored": "experiment.json",
                                 "disabled_lenses": ["rounding-map"]}}}
            result = metrics.score(m, root)
            self.assertEqual(result["cases"], 1)
            self.assertEqual(result["comparisons"]["without-lens"]["delta"], 1)
            self.assertFalse(result["reportable_advantage"])
            self.assertFalse(result["precision_measured"])

    def test_reject_mismatched_truth(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            a = {"state": "scored", "pinned_commit": "a" * 40, "case": "one",
                 "sealed_at": "2026-01-01", "rediscovered": [],
                 "missed": [{"id": "H-1", "severity": "high"}], "published_findings": 1}
            (root / "a.json").write_text(json.dumps([a]))
            b = dict(a, missed=[{"id": "H-2", "severity": "high"}])
            (root / "b.json").write_text(json.dumps([b]))
            manifest = {"schema_version": 1, "baseline": "a",
                        "arms": {"a": {"scored": "a.json"}, "b": {"scored": "b.json"}}}
            with self.assertRaisesRegex(ValueError, "ground truth"):
                metrics.score(manifest, root)


class HarnessPresetTests(unittest.TestCase):
    def test_custody_preset_requires_operator_acknowledgment_and_real_getters(self):
        abi = {"contractName": "Vault", "abi": [
            {"type": "function", "name": "deposit", "stateMutability": "nonpayable",
             "inputs": [{"type": "uint256"}]},
            {"type": "function", "name": "asset", "stateMutability": "view",
             "inputs": [], "outputs": [{"type": "address"}]},
            {"type": "function", "name": "totalAssets", "stateMutability": "view",
             "inputs": [], "outputs": [{"type": "uint256"}]},
        ]}
        fork = {"address": "0x" + "1" * 40, "block": 123, "rpc_env": "BP_RPC_URL"}
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "generated"
            with self.assertRaisesRegex(ValueError, "confirm-direct-custody"):
                harness.generate([abi], out, preset="erc4626-direct-custody", fork=fork)
            generated = harness.generate([abi], out, preset="erc4626-direct-custody",
                                         fork=fork, confirm_direct_custody=True)
            source = (out / "VaultInvariants.t.sol").read_text()
            self.assertEqual(generated["property_preset"], "erc4626-direct-custody")
            self.assertIn("invariant_directCustodyBacking()", source)
            self.assertIn("vm.createSelectFork", source)
            self.assertNotIn('assertTrue(false, "TODO', source)


if __name__ == "__main__":
    unittest.main()
