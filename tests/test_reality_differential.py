"""Synthetic candidate/control tests for bounded offline differential research."""
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
SPEC = importlib.util.spec_from_file_location("test_reality", SCRIPTS / "reality_differential.py")
reality = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(reality)
SHA = "a" * 64
REV = "b" * 40


def document(case, env="mock-local"):
    return {"schema_version": 1, "source_revision": REV, "environment": env, "cases": [case]}


def pair(candidate, control, **extras):
    return {"id": "BP-501", "invariant": "Finalize only backed or successful operations",
            "equivalence_basis": "same native source, controlled failure variant",
            "candidate": candidate, "negative_control": control, **extras}


def balances(before_h, before_o, after_h, after_o, finality="finalized"):
    return {"before": {"held_atomic": str(before_h), "owed_atomic": str(before_o)},
            "after": {"held_atomic": str(after_h), "owed_atomic": str(after_o)},
            "finality": finality, "trace_sha256": SHA}


def outcome(items, recorded="success", outer="success", policy="all_required", finality="finalized"):
    return {"outer_status": outer, "recorded_status": recorded, "item_statuses": items,
            "success_policy": policy, "finality": finality, "trace_sha256": SHA}


def context(a="first", v="first", e="first", entries=None):
    return {"authorized": {"operation_digest": a, "chain_id": "1"},
            "verified": {"operation_digest": v, "chain_id": "1"},
            "executed": {"operation_digest": e, "chain_id": "1"},
            "cache_entries": [] if entries is None else entries, "trace_sha256": SHA}


class SettlementTests(unittest.TestCase):
    def test_unbacked_finalized_liability_has_control(self):
        item = pair(balances(100, 100, 100, 115), balances(100, 100, 115, 115),
                    asset="USDC:atomic")
        r = reality.analyze(document(item), "settlement")
        self.assertEqual(r["leads"], 1)
        self.assertEqual(r["confirmed_vulnerabilities"], 0)
        self.assertEqual(r["cases"][0]["signals"], ["UNBACKED_FINALIZED_LIABILITY"])
        self.assertEqual(r["cases"][0]["candidate_observation"]["after_deficit_atomic"], "15")

    def test_preexisting_insolvency_not_called_new(self):
        item = pair(balances(100, 110, 100, 130), balances(100, 110, 100, 111), asset="DAI")
        self.assertEqual(reality.analyze(document(item), "settlement")["leads"], 0)

    def test_control_deficit_prevents_promotion(self):
        item = pair(balances(50, 50, 45, 50), balances(50, 50, 40, 50), asset="ETH")
        r = reality.analyze(document(item), "settlement")
        self.assertEqual(r["cases"][0]["decision"], "CONTROL_ALSO_VIOLATES")

    def test_pending_is_not_finalized(self):
        item = pair(balances(10, 10, 10, 20, "pending"), balances(10, 10, 20, 20), asset="BTC")
        self.assertEqual(reality.analyze(document(item), "settlement")["cases"][0]["decision"],
                         "INCONCLUSIVE")

    def test_large_integer_exactness(self):
        huge = 10**60
        item = pair(balances(huge, huge, huge, huge+1),
                    balances(huge, huge, huge+1, huge+1), asset="BTC")
        self.assertEqual(reality.analyze(document(item), "settlement")["leads"], 1)

    def test_reject_float_negative_and_leading_zero(self):
        item = pair(balances(10, 10, 10, 20), balances(10, 10, 20, 20), asset="BTC")
        for bad in (1.0, -1, True, "01", "1e5"):
            with self.subTest(bad=bad):
                item["candidate"]["after"]["held_atomic"] = bad
                with self.assertRaises(ValueError):
                    reality.analyze(document(item), "settlement")


class OutcomeTests(unittest.TestCase):
    def test_force_batch_success_with_inner_failure(self):
        item = pair(outcome(["failed", "success"]), outcome(["success", "success"]))
        r = reality.analyze(document(item), "outcome")
        self.assertEqual(r["cases"][0]["decision"], "DIFFERENTIAL_LEAD")
        self.assertEqual(r["cases"][0]["signals"], ["RECORDED_SUCCESS_CONTRADICTS_INNER_OUTCOME"])

    def test_all_failed_in_any_required(self):
        item = pair(outcome(["failed", "failed"], policy="any_required"),
                    outcome(["failed", "success"], policy="any_required"))
        self.assertEqual(reality.analyze(document(item), "outcome")["leads"], 1)

    def test_one_success_in_any_required_is_not_a_bug(self):
        item = pair(outcome(["failed", "success"], policy="any_required"),
                    outcome(["success", "success"], policy="any_required"))
        self.assertEqual(reality.analyze(document(item), "outcome")["leads"], 0)

    def test_failed_outer_but_recorded_success(self):
        item = pair(outcome(["success"], outer="failed"), outcome(["success"]))
        self.assertEqual(reality.analyze(document(item), "outcome")["leads"], 1)

    def test_control_failure_cannot_be_positive(self):
        item = pair(outcome(["failed"]), outcome(["failed", "success"]))
        self.assertEqual(reality.analyze(document(item), "outcome")["cases"][0]["decision"],
                         "CONTROL_ALSO_VIOLATES")

    def test_pending_item_cannot_be_called_delivered(self):
        item = pair(outcome(["pending", "failed"]), outcome(["success", "success"]))
        self.assertEqual(reality.analyze(document(item), "outcome")["cases"][0]["decision"],
                         "INCONCLUSIVE")

    def test_different_success_policies_incomparable(self):
        item = pair(outcome(["failed"], policy="all_required"),
                    outcome(["success"], policy="any_required"))
        self.assertEqual(reality.analyze(document(item), "outcome")["cases"][0]["decision"],
                         "INCONCLUSIVE")

    def test_reject_invalid_result_status(self):
        item = pair(outcome(["failed"]), outcome(["success"]))
        item["candidate"]["item_statuses"] = ["succcess"]
        with self.assertRaises(ValueError):
            reality.analyze(document(item), "outcome")


class ContextTests(unittest.TestCase):
    def test_signed_verified_executed_mismatch(self):
        item = pair(context("operation-A", "operation-A", "operation-B"),
                    context("operation-A", "operation-A", "operation-A"),
                    bound_fields=["operation_digest", "chain_id"])
        r = reality.analyze(document(item), "context")
        self.assertEqual(r["leads"], 1)
        self.assertIn("AUTHORIZED_VERIFIED_EXECUTED_MISMATCH", r["cases"][0]["signals"])
        self.assertNotIn("operation-B", json.dumps(r))

    def test_cache_key_collision_across_verified_context(self):
        collision = [{"key": "same", "verified_context_digest": "proof-one"},
                     {"key": "same", "verified_context_digest": "proof-two"}]
        safe = [{"key": "one", "verified_context_digest": "proof-one"},
                {"key": "two", "verified_context_digest": "proof-two"}]
        item = pair(context(entries=collision), context(entries=safe),
                    bound_fields=["operation_digest"])
        r = reality.analyze(document(item), "context")
        self.assertEqual(r["cases"][0]["signals"], ["VERIFICATION_CACHE_CONTEXT_COLLISION"])

    def test_missing_bound_field_inconclusive(self):
        candidate = context("A", "A", "B")
        del candidate["verified"]["chain_id"]
        item = pair(candidate, context("A", "A", "A"),
                    bound_fields=["operation_digest", "chain_id"])
        self.assertEqual(reality.analyze(document(item), "context")["cases"][0]["decision"],
                         "INCONCLUSIVE")

    def test_control_failure_rejected(self):
        item = pair(context("A", "A", "B"), context("A", "A", "C"),
                    bound_fields=["operation_digest"])
        self.assertEqual(reality.analyze(document(item), "context")["cases"][0]["decision"],
                         "CONTROL_ALSO_VIOLATES")

    def test_reject_unrecognized_binding_and_duplicate(self):
        item = pair(context("A", "A", "B"), context(), bound_fields=["operation_digest"])
        for fields in (["made_up"], ["chain_id", "chain_id"], [], [1]):
            with self.subTest(fields=fields):
                item["bound_fields"] = fields
                with self.assertRaises(ValueError):
                    reality.analyze(document(item), "context")


class InputGateTests(unittest.TestCase):
    def test_duplicate_ids_and_bool_schema_rejected(self):
        item = pair(outcome(["failed"]), outcome(["success"]))
        d = document(item)
        for invalid in (dict(d, schema_version=True), dict(d, cases=[item, item])):
            with self.assertRaises(ValueError):
                reality.analyze(invalid, "outcome")

    def test_identical_candidate_control_refused(self):
        item = pair(outcome(["success"]), outcome(["success"]))
        with self.assertRaises(ValueError):
            reality.analyze(document(item), "outcome")

    def test_duplicate_object_keys_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / "pairs.json"
            file.write_text('{"schema_version":1,"schema_version":1}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate"):
                reality.load_input(file)

    def test_symlink_input_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / "pairs.json"
            file.write_text("{}", encoding="utf-8")
            link = Path(tmp) / "link.json"
            link.symlink_to(file)
            with self.assertRaisesRegex(ValueError, "non-symlink"):
                reality.load_input(link)

    def test_private_output_never_overwrites(self):
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / "result.json"
            reality._write_private(file, {"result": "lead"})
            self.assertEqual(json.loads(file.read_text())["result"], "lead")
            if os.name == "posix":
                self.assertEqual(stat.S_IMODE(file.stat().st_mode), 0o600)
            with self.assertRaises(FileExistsError):
                reality._write_private(file, {"result": "overwrite"})

    def test_direct_cli_and_bounty_dispatch(self):
        item = pair(balances(50, 50, 50, 60), balances(50, 50, 60, 60), asset="USDC")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "input.json"
            path.write_text(json.dumps(document(item)), encoding="utf-8")
            for command in (
                [sys.executable, str(SCRIPTS / "reality_differential.py")],
                [sys.executable, str(SCRIPTS / "bounty.py"), "reality-diff"],
            ):
                done = subprocess.run(command + ["settlement", "--input", str(path)],
                                      capture_output=True, text=True, timeout=30)
                self.assertEqual(done.returncode, 0, done.stderr)
                self.assertEqual(json.loads(done.stdout)["leads"], 1)


if __name__ == "__main__":
    unittest.main()
