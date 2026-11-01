"""Web3 advanced research: paired synthetic truths and local source provenance.

Never connects to an RPC or web target. Fixture results are not security proofs.
"""
import hashlib
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
SCRIPTS = ROOT / "skills/bounty-pilot/scripts"
S = importlib.util.spec_from_file_location("test_web3_advanced", SCRIPTS / "web3_advanced.py")
engine = importlib.util.module_from_spec(S)
S.loader.exec_module(engine)
SHA = "a" * 64
REV = "b" * 40


def envelope(case):
    return {"schema_version": 1, "source_revision": REV,
            "environment": "mock-local", "cases": [case]}


def case(scenario, candidate, control):
    return {"id": "BP-501", "invariant": "bounded, source-cited security invariant",
            "equivalence_basis": "identical native fixture except the controlled variant",
            "scenario": scenario, "candidate": candidate, "negative_control": control}


def trade(debit="BTC", state="completed", order="BTC", actor="alice"):
    return {"order_id": "order-17", "actor": actor, "order_asset": order,
            "debit_asset": debit, "status": state, "trace_sha256": SHA}


def fee(value, state="accepted", order="order-17"):
    return {"order_id": order, "actor": "alice", "fee_atomic": str(value),
            "status": state, "trace_sha256": SHA}


def deposit(status="finalized", credit="finalized", received="100", credited="100"):
    return {"order_id": "invoice-1", "actor": "alice", "deposit_status": status,
            "credit_status": credit, "received_atomic": str(received),
            "credited_atomic": str(credited), "trace_sha256": SHA}


def leg(value="A"):
    return {"recipient": value, "asset": "USDC", "amount_atomic": "10",
            "chain_id": "1", "calldata_sha256": SHA}


def intent(display=None, signed=None, executed=None, coverage="complete",
           approval="approved", status="success", decoder="independent-local"):
    return {"displayed_legs": [leg(x) for x in (display or ["A"])],
            "decoded_signed_legs": [leg(x) for x in (signed or ["A"])],
            "executed_legs": [leg(x) for x in (executed or ["A"])],
            "display_coverage": coverage, "approval_status": approval,
            "execution_status": status, "decoder": decoder,
            "trace_sha256": SHA}


def intent_case(candidate, control, fields=None):
    item = case(None, candidate, control)
    del item["scenario"]
    item["bound_fields"] = fields if fields is not None else ["recipient", "asset", "amount_atomic"]
    return envelope(item)


def policy():
    return {"schema_version": 1, "network_mode": "offline",
            "production_requests": False,
            "scope_evidence": "investigator-supplied published source reference",
            "in_scope_origins": ["https://app.example.org"],
            "excluded_origins": [],
            "allowed_source_prefixes": ["app", "api"]}


class BusinessTests(unittest.TestCase):
    def test_completed_trade_uses_different_debit_asset(self):
        result = engine.compare_business(envelope(case("trade-asset", trade("SHIB"), trade())))
        self.assertEqual(result["leads"], 1)
        self.assertEqual(result["confirmed_vulnerabilities"], 0)
        self.assertEqual(result["cases"][0]["decision"], "DIFFERENTIAL_LEAD")

    def test_rejected_mismatched_trade_is_not_exploit(self):
        result = engine.compare_business(envelope(case("trade-asset",
                                                        trade("SHIB", state="rejected"), trade())))
        self.assertEqual(result["cases"][0]["decision"], "NO_DIFFERENTIAL")

    def test_pending_trade_inconclusive(self):
        result = engine.compare_business(envelope(case("trade-asset",
                                                        trade("SHIB", state="pending"), trade())))
        self.assertEqual(result["cases"][0]["decision"], "INCONCLUSIVE")

    def test_different_order_asset_or_actor_inconclusive(self):
        for candidate in (trade("SHIB", order="ETH"), trade("SHIB", actor="bob")):
            with self.subTest(candidate=candidate):
                result = engine.compare_business(envelope(case("trade-asset", candidate, trade())))
                self.assertEqual(result["cases"][0]["decision"], "INCONCLUSIVE")

    def test_fee_negative_accepted(self):
        r = engine.compare_business(envelope(case("fee-sign", fee("-1"), fee("1"))))
        self.assertEqual(r["leads"], 1)
        self.assertTrue(r["cases"][0]["candidate_signals"]["fee_negative"])

    def test_fee_negative_rejected_not_flagged(self):
        r = engine.compare_business(envelope(case("fee-sign", fee("-1", "rejected"), fee("1"))))
        self.assertEqual(r["leads"], 0)

    def test_invalid_control_for_fee(self):
        r = engine.compare_business(envelope(case("fee-sign", fee("-1"), fee("-2"))))
        self.assertEqual(r["cases"][0]["decision"], "CONTROL_ALSO_VIOLATES")

    def test_deposit_before_finality_and_unbacked_credit(self):
        for candidate in (deposit(status="pending"),
                          deposit(status="finalized", received="80"),
                          deposit(status="failed")):
            with self.subTest(candidate=candidate):
                r = engine.compare_business(envelope(case("deposit-finality", candidate, deposit())))
                self.assertEqual(r["leads"], 1)

    def test_deposit_credit_pending_is_not_positive(self):
        r = engine.compare_business(envelope(case("deposit-finality",
                                                    deposit(status="pending", credit="pending"), deposit())))
        self.assertEqual(r["leads"], 0)

    def test_unknown_deposit_is_inconclusive(self):
        r = engine.compare_business(envelope(case("deposit-finality",
                                                    deposit(status="unknown"), deposit())))
        self.assertEqual(r["cases"][0]["decision"], "INCONCLUSIVE")

    def test_invalid_negative_float_scientific_and_bool_rejected(self):
        for value in ("01", "1e7", 3.0, True, "-2"):
            with self.subTest(value=value):
                candidate = deposit(status="finalized", received="80")
                candidate["received_atomic"] = value
                with self.assertRaises(ValueError):
                    engine.compare_business(envelope(case("deposit-finality", candidate, deposit())))

    def test_preexisting_bad_control_not_positive(self):
        r = engine.compare_business(envelope(case("deposit-finality",
                                                    deposit(received="80"), deposit(received="90"))))
        self.assertEqual(r["cases"][0]["decision"], "CONTROL_ALSO_VIOLATES")

    def test_big_atomic_amounts_not_float_rounded(self):
        huge = 10**60
        r = engine.compare_business(envelope(case("deposit-finality",
                                                    deposit(received=str(huge), credited=str(huge+1)),
                                                    deposit(received=str(huge+1), credited=str(huge+1)))))
        self.assertEqual(r["leads"], 1)


class IntentTests(unittest.TestCase):
    def test_user_display_vs_decoded_signed_difference(self):
        r = engine.compare_intent(intent_case(intent(signed=["B"], executed=["B"]), intent()))
        self.assertEqual(r["leads"], 1)

    def test_signed_vs_executed_difference(self):
        r = engine.compare_intent(intent_case(intent(executed=["B"]), intent()))
        self.assertEqual(r["leads"], 1)

    def test_hidden_batch_leg(self):
        r = engine.compare_intent(intent_case(
            intent(display=["A"], signed=["A", "B"], executed=["A", "B"]), intent()))
        self.assertEqual(r["leads"], 1)
        self.assertEqual(r["cases"][0]["candidate_signals"]["leg_counts"], [1, 2, 2])

    def test_incomplete_display_not_claimed(self):
        r = engine.compare_intent(intent_case(
            intent(coverage="partial", signed=["A", "B"], executed=["A", "B"]), intent()))
        self.assertEqual(r["cases"][0]["decision"], "INCONCLUSIVE")

    def test_rejected_execution_not_claimed(self):
        r = engine.compare_intent(intent_case(
            intent(signed=["B"], executed=["B"], status="rejected"), intent()))
        self.assertEqual(r["cases"][0]["decision"], "INCONCLUSIVE")

    def test_invalid_control_not_positive(self):
        r = engine.compare_intent(intent_case(
            intent(signed=["B"], executed=["B"]), intent(signed=["C"], executed=["C"])))
        self.assertEqual(r["cases"][0]["decision"], "CONTROL_ALSO_VIOLATES")

    def test_missing_bound_field_inconclusive(self):
        c = intent(signed=["B"], executed=["B"])
        del c["decoded_signed_legs"][0]["recipient"]
        r = engine.compare_intent(intent_case(c, intent()))
        self.assertEqual(r["cases"][0]["decision"], "INCONCLUSIVE")

    def test_unknown_execution_inconclusive(self):
        r = engine.compare_intent(intent_case(intent(status="unknown"), intent()))
        self.assertEqual(r["cases"][0]["decision"], "INCONCLUSIVE")

    def test_bad_decoder_disallowed(self):
        with self.assertRaises(ValueError):
            engine.compare_intent(intent_case(intent(decoder="not-real"), intent()))

    def test_duplicate_fields_refused(self):
        with self.assertRaises(ValueError):
            engine.compare_intent(intent_case(intent(signed=["B"]), intent(),
                                                   fields=["recipient", "recipient"]))

    def test_identical_pair_refused(self):
        with self.assertRaisesRegex(ValueError, "identical"):
            engine.compare_intent(intent_case(intent(), intent()))

    def test_null_or_wrong_field_types_fail(self):
        a = intent(signed=["B"], executed=["B"])
        a["signed"] = "unauthorized"
        with self.assertRaises(ValueError):
            engine.compare_intent(intent_case(a, intent()))


class ProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name) / "repo"
        (self.repo / "app").mkdir(parents=True)

    def file(self, rel, body):
        p = self.repo / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")

    def git(self):
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        subprocess.run(["git", "-C", str(self.repo), "add", "-A"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "-c", "user.name=Test",
                        "-c", "user.email=fixture@example.invalid",
                        "-c", "commit.gpgsign=false", "commit", "-qm", "fixture"], check=True)

    def manifest(self, path="app/bundle.js", digest=SHA, **rest):
        return {"schema_version": 1, "baseline_id": "reviewed-lab-artifact",
                "baseline_revision": REV, "artifacts": [{
                    "path": path, "expected_sha256": digest,
                    "origin": "first-party", "role": "script", **rest}]}

    def test_identical_local_digest(self):
        data = 'console.log("hello");\n'
        self.file("app/bundle.js", data)
        self.git()
        r = engine.runtime_provenance(self.repo, policy(), self.manifest(
            digest=hashlib.sha256(data.encode()).hexdigest()))
        self.assertEqual(r["drift_count"], 0)
        self.assertEqual(r["artifacts"][0]["decision"], "BASELINE_MATCH")
        self.assertEqual(r["network_requests"], 0)

    def test_modified_js_detected_and_hunt_cue_line(self):
        self.file("app/bundle.js", 'const z=wallet.signTypedData(payload);\n')
        self.git()
        r = engine.runtime_provenance(self.repo, policy(), self.manifest())
        self.assertEqual(r["drift_count"], 1)
        self.assertEqual(r["confirmed_vulnerabilities"], 0)
        self.assertEqual(r["artifacts"][0]["source_cues_not_vulnerabilities"][0]["kind"],
                         "wallet-request")

    def test_wrong_source_scope_rejected(self):
        self.file("other/bundle.js", "x")
        self.git()
        with self.assertRaisesRegex(ValueError, "outside policy"):
            engine.runtime_provenance(self.repo, policy(), self.manifest("other/bundle.js"))

    def test_untracked_artifact_rejected(self):
        self.file("app/known.js", "x")
        self.git()
        self.file("app/untracked.js", "x")
        with self.assertRaisesRegex(ValueError, "not tracked"):
            engine.runtime_provenance(self.repo, policy(), self.manifest("app/untracked.js"))

    def test_symlinked_artifact_not_followed(self):
        self.file("app/real.js", "x")
        (self.repo / "app/link.js").symlink_to(self.repo / "app/real.js")
        self.git()
        with self.assertRaisesRegex(ValueError, "symlink"):
            engine.runtime_provenance(self.repo, policy(), self.manifest("app/link.js"))

    def test_path_traversal_and_abs_paths_rejected(self):
        self.file("app/main.js", "x")
        self.git()
        for path in ("app/../api/private.js", "/tmp/data.js", "app\\x.js",
                     "app//../main.js", "app/./main.js"):
            with self.subTest(path=path):
                with self.assertRaises(ValueError):
                    engine.runtime_provenance(self.repo, policy(), self.manifest(path))

    def test_multiple_manifest_duplicates_refused(self):
        self.file("app/main.js", "x")
        self.git()
        one = self.manifest("app/main.js")
        one["artifacts"].append(one["artifacts"][0])
        with self.assertRaisesRegex(ValueError, "duplicate"):
            engine.runtime_provenance(self.repo, policy(), one)

    def test_oversized_source_rejected(self):
        self.file("app/huge.js", "x" * 2_000_001)
        self.git()
        with self.assertRaisesRegex(ValueError, "under 2MB"):
            engine.runtime_provenance(self.repo, policy(), self.manifest("app/huge.js"))

    def test_online_policy_rejected(self):
        self.file("app/main.js", "x")
        self.git()
        pol = policy()
        pol["network_mode"] = "online"
        with self.assertRaises(ValueError):
            engine.runtime_provenance(self.repo, pol, self.manifest("app/main.js"))


class CliSafetyTests(unittest.TestCase):
    def test_two_clis_and_three_modes(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            d = tmp / "business.json"
            d.write_text(json.dumps(envelope(case("fee-sign", fee("-2"), fee("2")))))
            i = tmp / "intent.json"
            i.write_text(json.dumps(intent_case(intent(executed=["B"]), intent())))
            repo = tmp / "target"
            (repo / "app").mkdir(parents=True)
            js = repo / "app/file.js"
            js.write_text("wallet.signTypedData(x)\n")
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
            subprocess.run(["git", "-C", str(repo), "-c", "user.name=Test",
                            "-c", "user.email=test@example.invalid", "-c", "commit",
                            "-qm", "fixture"], check=True)
            manifest = tmp / "manifest.json"
            manifest.write_text(json.dumps({"schema_version": 1, "baseline_id": "review",
                                            "baseline_revision": REV, "artifacts": [{
                                                "path": "app/file.js", "origin": "first-party",
                                                "role": "script", "expected_sha256": SHA}]}))
            p = tmp / "policy.json"
            p.write_text(json.dumps(policy()))
            commands = [
                ["business-invariants", "--input", str(d)],
                ["signed-intent-mirror", "--input", str(i)],
                ["runtime-provenance", "--repo", str(repo), "--policy", str(p),
                 "--input", str(manifest)],
            ]
            for entry in ([sys.executable, str(SCRIPTS / "web3_advanced.py")],
                          [sys.executable, str(SCRIPTS / "bounty.py"), "web3-advanced"]):
                for args in commands:
                    done = subprocess.run(entry + args, capture_output=True,
                                          text=True, timeout=30)
                    self.assertEqual(done.returncode, 0, done.stderr)
                    result = json.loads(done.stdout)
                    self.assertEqual(result["confirmed_vulnerabilities"], 0)

    def test_private_file_never_overwrites(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "evidence.json"
            engine.private_write(p, {"test": True})
            self.assertEqual(json.loads(p.read_text()), {"test": True})
            if os.name == "posix":
                self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o600)
            with self.assertRaises(FileExistsError):
                engine.private_write(p, {"test": False})

    def test_duplicate_json_keys_and_symlinks_denied(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "data.json"
            p.write_text('{"schema_version":1,"schema_version":1}')
            with self.assertRaisesRegex(ValueError, "duplicate"):
                engine.json_file(p)
            link = Path(tmp) / "link.json"
            link.symlink_to(p)
            with self.assertRaisesRegex(ValueError, "non-symlink"):
                engine.json_file(link)

    def test_duplicate_ids_and_bool_schema(self):
        d = envelope(case("trade-asset", trade("SHIB"), trade()))
        d["cases"] *= 2
        with self.assertRaisesRegex(ValueError, "duplicate"):
            engine.compare_business(d)
        d["cases"] = d["cases"][:1]
        d["schema_version"] = True
        with self.assertRaises(ValueError):
            engine.compare_business(d)


if __name__ == "__main__":
    unittest.main()
