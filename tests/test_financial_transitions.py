"""Concrete offline differential regressions; never contact a live target."""
import importlib.util
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "skills/bounty-pilot/scripts/financial_transitions.py"
spec = importlib.util.spec_from_file_location("bp_financial_transitions", PATH)
lab = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lab)
REV = "a" * 40
DIG = "b" * 64


def observed(**values):
    return dict(source_revision=REV, initial_state_digest=DIG, **values)


def case(domain, bad, good, label=None):
    return {"id": label or domain, "domain": domain, "source_revision": REV,
            "initial_state_digest": DIG,
            "candidate": observed(**bad), "negative_control": observed(**good)}


def base_cex():
    return dict(available_before=100, held_before=0, available_after=90,
                held_after=0, settled_inflow=0, settled_outflow=10,
                settlement_count=1, same_operation_id=True,
                deposit_finalized=True, deposit_credit=0,
                reviewed_destination="wallet-A", authorized_destination="wallet-A")


def domain_examples():
    cgood = base_cex()
    cbad = dict(cgood, available_after=100, settlement_count=2,
                authorized_destination="wallet-B")
    rgood = dict(execution_count=1, source_finalized=True, proof_verified=True,
                 challenge_window_closed=True, origin_and_alias_bound=True,
                 payload_bound=True, message_invalidated=False)
    rbad = dict(rgood, source_finalized=False, proof_verified=False,
                execution_count=2, origin_and_alias_bound=False)
    sgood = dict(total_shares_including_exit_queue=100, queued_shares=50,
                 assets_after_slash=90, observed_exit_payout=45,
                 burned_exit_shares=50, no_other_asset_flows=True)
    sbad = dict(sgood, observed_exit_payout=50, burned_exit_shares=0)
    pgood = dict(margin_collateral=100, signed_base_position=1, entry_price=100,
                 mark_price=100, maintenance_bps=1000, funding_paid=0,
                 funding_is_closed_system=True,
                 net_funding_across_all_participants=0,
                 liquidation_executed=False)
    pbad = dict(pgood, liquidation_executed=True,
                net_funding_across_all_participants=1)
    lgood = dict(actual_tokens_out=100, minimum_tokens_out=100,
                 purchase_succeeded=True)
    lbad = dict(lgood, actual_tokens_out=90)
    mgood = dict(settlement_collateral=100, total_redeemed=90,
                 outcome_finalized=True)
    mbad = dict(mgood, total_redeemed=120, outcome_finalized=False)
    agood = dict(leaf_allocation=100, cumulative_claimed=100,
                 claim_count=1, single_use_leaf=True,
                 campaign_and_chain_bound=True)
    abad = dict(agood, cumulative_claimed=110, claim_count=2,
                campaign_and_chain_bound=False)
    dgood = dict(settlement_accepted=True, commitment_verified=True,
                 data_availability_verified=True, origin_domain_verified=True)
    dbad = dict(dgood, commitment_verified=False, data_availability_verified=False)
    vgood = dict(prize_paid=True, vrf_proof_verified=True,
                 randomness_request_bound=True,
                 claim_count_for_single_prize=1)
    vbad = dict(vgood, vrf_proof_verified=False,
                claim_count_for_single_prize=2)
    return [
        case("cex-custody", cbad, cgood),
        case("rollup-l2", rbad, rgood),
        case("restaking-lst", sbad, sgood),
        case("perps", pbad, pgood),
        case("launchpad", lbad, lgood),
        case("prediction-market", mbad, mgood),
        case("airdrop", abad, agood),
        case("data-availability", dbad, dgood),
        case("lottery-vrf", vbad, vgood),
    ]


class FinancialTransitionsTests(unittest.TestCase):
    def test_all_nine_domains_differential(self):
        examples = domain_examples()
        self.assertEqual({x["domain"] for x in examples}, set(lab.DOMAINS))
        out = lab.evaluate({"schema_version": 1, "cases": examples})
        self.assertEqual(out["case_count"], 9)
        self.assertEqual(out["differential_leads"], 9)
        for item in out["results"]:
            self.assertEqual(item["status"], "differential-lead-needs-native-verification")
            self.assertTrue(item["candidate_violations"], item["domain"])
            self.assertEqual(item["control_violations"], [])
            self.assertEqual(item["evidence_level"], "unverified-researcher-supplied")

    def test_controls_are_not_reported_as_bugs(self):
        items = domain_examples()
        for row in items:
            row["candidate"] = dict(row["negative_control"])
        out = lab.evaluate({"schema_version": 1, "cases": items})
        self.assertEqual(out["differential_leads"], 0)
        self.assertEqual({r["status"] for r in out["results"]},
                         {"no-differential-violation"})

    def test_bad_control_must_not_be_promoted(self):
        row = domain_examples()[0]
        row["negative_control"] = dict(row["candidate"])
        out = lab.evaluate({"schema_version": 1, "cases": [row]})
        self.assertEqual(out["differential_leads"], 0)
        self.assertEqual(out["results"][0]["status"], "not-isolated-control-also-violates")

    def test_inconsistent_revision_is_inconclusive(self):
        row = domain_examples()[0]
        row["candidate"]["source_revision"] = "c" * 40
        out = lab.evaluate({"schema_version": 1, "cases": [row]})
        self.assertEqual(out["differential_leads"], 0)
        self.assertEqual(out["results"][0]["status"], "inconclusive-binding")

    def test_invalid_inputs_fail_closed(self):
        bad = domain_examples()[0]
        bad["candidate"]["settlement_count"] = True
        with self.assertRaises(ValueError):
            lab.evaluate({"schema_version": 1, "cases": [bad]})
        with self.assertRaises(ValueError):
            lab.evaluate({"schema_version": 1, "cases": []})
        good = domain_examples()[0]
        with self.assertRaises(ValueError):
            lab.evaluate({"schema_version": 1, "cases": [good, dict(good)]})
        unknown = dict(good, domain="unknown")
        with self.assertRaises(ValueError):
            lab.evaluate({"schema_version": 1, "cases": [unknown]})
        noflow = domain_examples()[2]
        noflow["candidate"]["no_other_asset_flows"] = False
        with self.assertRaises(ValueError):
            lab.evaluate({"schema_version": 1, "cases": [noflow]})

    def test_cex_unfinalized_deposit_and_value_conservation(self):
        control = base_cex()
        candidate = dict(control, deposit_finalized=False, deposit_credit=5,
                         available_after=95)
        result = lab.evaluate({"schema_version": 1,
                               "cases": [case("cex-custody", candidate, control)]})
        self.assertIn("unfinalized-deposit-credit",
                      result["results"][0]["candidate_violations"])
        self.assertIn("funds-conservation",
                      result["results"][0]["candidate_violations"])

    def test_rollup_challenge_and_domain_checks(self):
        control = domain_examples()[1]["negative_control"].copy()
        attack = dict(control, message_invalidated=True, payload_bound=False)
        out = lab.evaluate({"schema_version": 1,
                            "cases": [case("rollup-l2", attack, control)]})
        self.assertIn("challenged-message-executed",
                      out["results"][0]["candidate_violations"])

    def test_negative_perp_funding_credit_is_signed(self):
        control = dict(domain_examples()[3]["negative_control"],
                       signed_base_position=-2, mark_price=140,
                       funding_paid=-5, liquidation_executed=False)
        bad = dict(control, liquidation_executed=True)
        out = lab.evaluate({"schema_version": 1,
                            "cases": [case("perps", bad, control)]})
        self.assertEqual(out["differential_leads"], 0)  # underwater => may liquidate

    def test_cli_writes_private_json_and_rejects_duplicate_input_keys(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            inp = root / "cases.json"
            dest = root / "result.json"
            inp.write_text(json.dumps({"schema_version": 1,
                                       "cases": domain_examples()}), encoding="utf-8")
            command = [sys.executable, str(PATH), "--input", str(inp), "--out", str(dest)]
            p = subprocess.run(command, capture_output=True, text=True, timeout=15)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertEqual(json.loads(dest.read_text())["differential_leads"], 9)
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(dest.stat().st_mode), 0o600)
            again = subprocess.run(command, capture_output=True, text=True, timeout=15)
            self.assertNotEqual(again.returncode, 0)
            inp.write_text('{"schema_version":1,"schema_version":1,"cases":[]}')
            with self.assertRaises(ValueError):
                lab.load(inp)


if __name__ == "__main__":
    unittest.main()
