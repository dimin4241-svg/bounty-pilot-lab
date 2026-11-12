"""Paired synthetic SQLite account/payment business-logic tests (no network)."""
import copy
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills" / "bounty-pilot" / "scripts"


def load(name):
    spec = importlib.util.spec_from_file_location("business_test_" + name, SCRIPTS / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


lab = load("web_business_lab")
fixture = load("web_business_fixture")


class BusinessLabTests(unittest.TestCase):
    def test_all_14_vulnerable_sqlite_scenarios_have_repeatable_candidate_and_clean_control(self):
        report = lab.analyze(fixture.generate(defective=True))
        self.assertEqual(set(lab.RULES), {row["rule"] for row in report["cases"]})
        self.assertEqual(report["candidate_count"], len(lab.RULES))
        self.assertEqual(report["confirmed_production_vulnerabilities"], 0)
        self.assertFalse(report["ready_to_submit"])
        for row in report["cases"]:
            self.assertEqual(row["classification"], "REPEATED_LOCAL_TRACE_LEAD")
            self.assertEqual(len(row["candidate_hit_steps"]), 2)
            self.assertTrue(all(row["candidate_hit_steps"]))
            self.assertEqual(row["control_hit_steps"], [[], []])

    def test_all_patched_sqlite_scenarios_reject_bad_transition(self):
        report = lab.analyze(fixture.generate(defective=False))
        self.assertEqual(report["candidate_count"], 0)
        self.assertTrue(all(row["classification"] == "NO_OBSERVED_VIOLATION"
                            for row in report["cases"]))

    def test_fake_psp_signature_finality_and_ledger_are_independent(self):
        app = fixture.LocalApp(defective=False)
        try:
            initial = app.snapshot()
            app.credit("pending-1", confirmed=False)
            self.assertEqual(app.snapshot(), initial)
            app.credit("tampered-1", confirmed=True, bound=False)
            self.assertEqual(app.snapshot(), initial)
            app.credit("paid-1", confirmed=True)
            self.assertEqual(app.snapshot()["available_cents"], 10500)
            self.assertEqual(app.snapshot()["ledger_credited_cents"], 500)
            app.credit("paid-1", confirmed=True)
            self.assertEqual(app.snapshot()["available_cents"], 10500)
            self.assertEqual(app.snapshot()["ledger_credited_cents"], 500)
            self.assertFalse(app.psp.callback("tampered-1",
                                            tampered=True)["signature_valid"])
        finally:
            app.close()
        buggy = fixture.LocalApp(defective=True)
        try:
            facts = buggy.credit("unpaid-1", confirmed=False)
            self.assertIs(facts["psp_confirmed"], False)
            self.assertEqual(buggy.snapshot()["ledger_credited_cents"], 500)
        finally:
            buggy.close()


    def test_scenarios_are_deterministic_and_use_actual_database_snapshots(self):
        a = fixture.generate(defective=True)
        b = fixture.generate(defective=True)
        self.assertEqual(a, b)
        self.assertTrue(all(run["initial_state_digest"] == control["initial_state_digest"]
            for c in a["cases"]
            for run, control in zip(c["candidate_runs"], c["control_runs"])))
        self.assertTrue(any(e["after"]["available_cents"] > e["before"]["available_cents"]
            for c in a["cases"] if c["rule"] == "unpaid-credit"
            for run in c["candidate_runs"] for e in run["events"]))

    def test_missing_authorization_fact_cannot_prove_cross_actor_violation(self):
        d = fixture.generate(defective=True, rules=["account-owner"])
        for run in d["cases"][0]["candidate_runs"]:
            del run["events"][0]["facts"]["actor_authorized"]
        out = lab.analyze(d)
        self.assertEqual(out["candidate_count"], 0)

    def test_missing_explicit_no_grants_cannot_claim_unpaid_balance(self):
        d = fixture.generate(defective=True, rules=["unpaid-credit"])
        for run in d["cases"][0]["candidate_runs"]:
            del run["events"][0]["facts"]["non_payment_credit_allowed"]
        self.assertEqual(lab.analyze(d)["candidate_count"], 0)

    def test_same_actor_read_is_never_a_disclosure_violation(self):
        d = fixture.generate(defective=True, rules=["cross-actor-disclosure"])
        for run in d["cases"][0]["candidate_runs"]:
            run["events"][0]["actor"] = run["events"][0]["subject"]
        self.assertEqual(lab.analyze(d)["candidate_count"], 0)

    def test_missing_disclosure_fact_cannot_prove_cross_actor_violation(self):
        d = fixture.generate(defective=True, rules=["cross-actor-disclosure"])
        for run in d["cases"][0]["candidate_runs"]:
            del run["events"][0]["facts"]["sensitive_fields_returned"]
        self.assertEqual(lab.analyze(d)["candidate_count"], 0)

    def test_tampered_control_violation_disqualifies_lead(self):
        d = fixture.generate(defective=True, rules=["account-owner"])
        for run in d["cases"][0]["control_runs"]:
            run["events"][0] = copy.deepcopy(d["cases"][0]["candidate_runs"][0]["events"][0])
        result = lab.analyze(d)
        self.assertEqual(result["candidate_count"], 0)
        self.assertEqual(result["cases"][0]["classification"], "CONTROL_VIOLATION_INCONCLUSIVE")

    def test_repetition_and_same_initial_state_are_mandatory(self):
        d = fixture.generate(defective=True, rules=["refund-replay"])
        d["cases"][0]["control_runs"][0]["initial_state_digest"] = "b" * 64
        with self.assertRaisesRegex(ValueError, "equivalent"):
            lab.analyze(d)
        d = fixture.generate(defective=True, rules=["refund-replay"])
        d["cases"][0]["candidate_runs"] = d["cases"][0]["candidate_runs"][:1]
        d["cases"][0]["control_runs"] = d["cases"][0]["control_runs"][:1]
        with self.assertRaisesRegex(ValueError, "repetitions"):
            lab.analyze(d)

    def test_duplicate_or_unsupported_schema_fails_closed(self):
        d = fixture.generate(defective=True, rules=["oauth-binding"])
        d["environment"] = "production"
        with self.assertRaises(ValueError):
            lab.analyze(d)
        d = fixture.generate(defective=True, rules=["oauth-binding"])
        d["cases"][0]["control_runs"][0]["evidence_sha256"] = (
            d["cases"][0]["candidate_runs"][0]["evidence_sha256"])
        with self.assertRaisesRegex(ValueError, "digest"):
            lab.analyze(d)
        d = fixture.generate(defective=True, rules=["oauth-binding"])
        d["cases"][0]["rule"] = "free-money"
        with self.assertRaises(ValueError):
            lab.analyze(d)

    def test_rules_are_in_review_plan_not_executed(self):
        p = {"schema_version": 1, "environment": "researcher_owned_lab",
             "source_revision": "e" * 40,
             "rules": ["account-owner", "unpaid-credit", "event-replay"]}
        out = lab.plan(p)
        self.assertEqual(len(out["jobs"]), 3)
        self.assertEqual(out["external_network_requests"], 0)
        self.assertEqual(out["classification"], "OFFLINE_TEST_DESCRIPTIONS_NOT_EXECUTED")

    def test_source_anchored_bridge_is_accepted_by_existing_dedup(self):
        root_dedup = load("web_root_cause_dedup")
        review = lab.analyze(fixture.generate(defective=True, rules=["unpaid-credit"]))
        case_id = review["cases"][0]["id"]
        anchors = {
            "schema_version": 1,
            "project": "owned-sqlite-lab",
            "source_revision": review["source_revision"],
            "entries": [{
                "case_id": case_id,
                "source_file": "src/payments.py",
                "code_anchor": "credit_balance",
                "trust_boundary_id": "psp_to_ledger",
                "claimed_effect_id": "balance_delta"
            }]
        }
        queue = lab.bridge(review, anchors)
        self.assertEqual(queue["candidates"][0]["evidence_digest"], None)
        self.assertEqual(queue["candidates"][0]["disposition"], "unreviewed")
        ranked = root_dedup.analyze(queue)
        self.assertEqual(ranked["candidates"], 1)
        self.assertEqual(len(ranked["groups"]), 1)
        self.assertEqual(ranked["confirmed_vulnerabilities"], 0)

    def test_bridge_refuses_revision_mismatch_and_unanchored_leads(self):
        review = lab.analyze(fixture.generate(defective=True, rules=["mfa-gate"]))
        anchors = {"schema_version": 1, "project": "owned-lab",
                   "source_revision": "a" * 40, "entries": [{
                       "case_id": "sqlite-mfa-gate",
                       "source_file": "src/auth.py", "code_anchor": "verify",
                       "trust_boundary_id": "session", "claimed_effect_id": "credential"
                   }]}
        with self.assertRaisesRegex(ValueError, "revision"):
            lab.bridge(review, anchors)
        anchors["source_revision"] = review["source_revision"]
        anchors["entries"][0]["source_file"] = "../outside.py"
        with self.assertRaisesRegex(ValueError, "relative"):
            lab.bridge(review, anchors)
        anchors["entries"][0]["source_file"] = "src/auth.py"
        anchors["entries"][0]["case_id"] = "not-this-case"
        with self.assertRaisesRegex(ValueError, "no repeated"):
            lab.bridge(review, anchors)


    def test_write_private_create_only_and_duplicate_json_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "result.json"
            lab._write(p, {"dummy": True})
            self.assertEqual(p.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(ValueError):
                lab._write(p, {"dummy": False})
            inp = Path(tmp) / "duplicate.json"
            inp.write_text('{"schema_version":1,"schema_version":2}', encoding="utf8")
            with self.assertRaisesRegex(ValueError, "duplicate"):
                lab._read(inp)

    def test_main_dispatches_demo_without_any_target_access(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "business-result.json"
            command = [sys.executable, str(SCRIPTS / "bounty.py"),
                       "web-business-lab", "demo", "--out", str(out)]
            proc = subprocess.run(command, capture_output=True, text=True, timeout=30)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            res = json.loads(out.read_text())
            self.assertTrue(res["synthetic_fixture"])
            self.assertEqual(res["candidate_count"], len(lab.RULES))
            self.assertFalse(res["ready_to_submit"])
            self.assertEqual(res["external_network_requests"], 0)


if __name__ == "__main__":
    unittest.main()
