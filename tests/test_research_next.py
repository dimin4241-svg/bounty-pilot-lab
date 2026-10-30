"""Research-next guards: synthetic local fixtures, never live targets or chain broadcasts."""
import importlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills/bounty-pilot/scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

spec_mapper = importlib.import_module("spec_mapper")
belief = importlib.import_module("belief_ledger")
native = importlib.import_module("native_cycle")
ecosystem = importlib.import_module("ecosystem_intelligence")


class CheckoutFixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "checkout"
        self.root.mkdir()
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        subprocess.run(["git", "-C", str(self.root), "config", "user.email",
                        "research@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(self.root), "config", "user.name",
                        "Research Fixture"], check=True)
        (self.root / "README.md").write_text(
            "Every withdrawal must check the caller.\n", encoding="utf-8")
        (self.root / "src").mkdir()
        (self.root / "src/Vault.sol").write_text(
            "contract Vault { function withdraw() public { require(msg.sender == owner); } }\n",
            encoding="utf-8")
        subprocess.run(["git", "-C", str(self.root), "add", "-A"], check=True)
        subprocess.run(["git", "-C", str(self.root), "commit", "-qm", "fixture"], check=True)
        self.sha = subprocess.run(["git", "-C", str(self.root), "rev-parse", "HEAD"],
                                  capture_output=True, text=True, check=True).stdout.strip()

    def spec(self, symbol="withdraw", scope="src"):
        return {"schema_version": 1, "requirements": [{
            "id": "REQ-001", "source_path": "README.md", "source_line": 1,
            "quote": "Every withdrawal must check the caller.",
            "symbols": [symbol], "code_scope": [scope]}]}


class SpecMappingTests(CheckoutFixture):
    def test_spec_uses_a_real_doc_anchor_and_returns_source_only_lead(self):
        res = spec_mapper.map_spec(self.spec(), self.root)
        self.assertEqual(res["confirmed_vulnerabilities"], 0)
        item = res["requirements"][0]
        self.assertEqual(item["classification"], "LEXICAL_MAPPING_LEAD")
        self.assertEqual(item["symbol_hits"][0]["path"], "src/Vault.sol")
        self.assertEqual(item["scoped_code_files"], 1)
        self.assertNotIn("contract Vault", json.dumps(res))

    def test_absent_symbol_is_not_a_security_verdict(self):
        item = spec_mapper.map_spec(self.spec("missing_guard"), self.root)["requirements"][0]
        self.assertEqual(item["classification"], "UNMAPPED_LEAD")
        self.assertIn("does not establish", item["notice"])

    def test_spec_quote_must_match_tracked_doc_and_reject_escape(self):
        wrong = self.spec()
        wrong["requirements"][0]["quote"] = "Not actually stated in the doc."
        with self.assertRaisesRegex(ValueError, "quoted specification"):
            spec_mapper.map_spec(wrong, self.root)
        with self.assertRaisesRegex(ValueError, "path traversal"):
            spec_mapper.map_spec(self.spec(scope="../outside"), self.root)
        with self.assertRaisesRegex(ValueError, "path traversal"):
            spec_mapper.map_spec(self.spec(scope="."), self.root)

    def test_untracked_or_symlink_source_cannot_be_treated_as_coverage(self):
        (self.root / "README.md").unlink()
        (self.root / "README.md").symlink_to(self.root / "src/Vault.sol")
        with self.assertRaisesRegex(ValueError, "safe regular"):
            spec_mapper.map_spec(self.spec(), self.root)


class MemoryTests(CheckoutFixture):
    def observation(self, state="refuted", artifact="f" * 64):
        return {"target": "synthetic local fixture", "mechanism": "cached replay",
                "revision": self.sha, "status": state, "evidence_kind": "native-pair",
                "artifact_sha256": artifact}

    def test_revision_bound_evidence_does_not_auto_suppress(self):
        ledger = Path(self.tmp.name) / "private" / "ledger.jsonl"
        belief.record(self.observation(), ledger)
        exact = belief.lookup("synthetic local fixture", "cached replay", self.sha, ledger)
        self.assertEqual(exact["match"]["status"], "refuted")
        self.assertEqual(exact["recommendation"], "REVIEW_PRIOR_EVIDENCE")
        changed = belief.lookup("synthetic local fixture", "cached replay", "e" * 40, ledger)
        self.assertIsNone(changed["match"])
        self.assertEqual(changed["stale_other_revisions"], 1)
        raw = ledger.read_text()
        self.assertNotIn("synthetic local fixture", raw)
        self.assertNotIn("cached replay", raw)

    def test_unproven_refutation_rejected(self):
        with self.assertRaisesRegex(ValueError, "requires a reviewable"):
            belief.record(self.observation(artifact=None), Path(self.tmp.name) / "none.jsonl")
        with self.assertRaisesRegex(ValueError, "environment-blocker"):
            belief.record(self.observation(state="blocked"), Path(self.tmp.name) / "none.jsonl")

    def test_symlink_ledger_rejected(self):
        destination = Path(self.tmp.name) / "target.jsonl"
        destination.write_text("")
        link = Path(self.tmp.name) / "link.jsonl"
        link.symlink_to(destination)
        with self.assertRaisesRegex(ValueError, "non-symlink"):
            belief.record(self.observation(), link)


class NativeCycleTests(CheckoutFixture):
    def pair_spec(self):
        return {"finding_id": "BP-123", "source_revision": self.sha,
                "invariant": "An unauthorized withdrawal does not transfer balance",
                "equivalence_basis": "README.md:1",
                "cases": [{"id": "withdraw-pair", "candidate": "test_candidate",
                           "control": "test_control"}]}

    def test_dry_run_does_not_execute_target_tests(self):
        result = native.cycle(self.pair_spec(), "pytest", self.root)
        self.assertEqual(result["mode"], "dry-run")
        self.assertEqual(result["confirmed_vulnerabilities"], 0)
        self.assertEqual(result["status"], "INCOMPLETE_OR_NOT_EXECUTED")

    def test_exec_needs_confirmed_isolated_workspace_and_pinned_revision(self):
        with self.assertRaisesRegex(ValueError, "isolated-workspace-confirmed"):
            native.cycle(self.pair_spec(), "pytest", self.root, allow_exec=True)
        bad = self.pair_spec()
        bad["source_revision"] = "0" * 40
        with self.assertRaisesRegex(ValueError, "HEAD differs"):
            native.cycle(bad, "pytest", self.root)

    def test_execution_refuses_missing_private_evidence_destination(self):
        with self.assertRaisesRegex(ValueError, "NEW private"):
            native.cycle(self.pair_spec(), "pytest", self.root,
                         allow_exec=True, isolated_confirmed=True)
        with self.assertRaisesRegex(ValueError, "outside the target checkout"):
            native.cycle(self.pair_spec(), "pytest", self.root,
                         allow_exec=True, isolated_confirmed=True,
                         evidence_dir=self.root / "results")

    def test_two_independent_synthetic_runs_are_only_harness_evidence(self):
        pairs = [{"pair_id": "withdraw-pair", "role": role, "executed": True,
                  "tests_ran": True, "status": "ran", "matched_expected_exit": True,
                  "stdout": "1 passed", "stderr": ""}
                 for role in ("candidate", "negative-control")]
        evidence = Path(self.tmp.name) / "evidence"
        with mock.patch.object(native.scenario_runner, "execute",
                               return_value={"result": "experiments-conformed",
                                             "cases": pairs}) as execute:
            report = native.cycle(self.pair_spec(), "pytest", self.root,
                                  allow_exec=True, isolated_confirmed=True,
                                  evidence_dir=evidence)
        self.assertTrue((evidence / "round-1.json").exists())
        self.assertTrue((evidence / "round-2.json").exists())
        self.assertEqual(execute.call_count, 2)
        self.assertEqual(report["status"], "NATIVE_PAIR_RAN_NEEDS_INDEPENDENT_REVIEW")
        self.assertEqual(report["confirmed_vulnerabilities"], 0)
        self.assertTrue(report["tracked_files_unchanged"])


class PatchVariantTests(unittest.TestCase):
    def test_patch_lead_has_provenance_and_falsification_recipe(self):
        result = ecosystem._patch_variant_analysis([
            {"commit": "b" * 40, "parent_commit": "a" * 40,
             "subject": "fix replay domain", "changes": [
                 {"path": "src/Signer.sol", "invariants_added": ["signature_domain"]}]}],
            {"src/Other.sol": "contract S { function check() public { ecrecover(x,y,z); } }"})
        self.assertGreaterEqual(len(result["candidates"]), 1)
        lead = result["candidates"][0]
        self.assertEqual(lead["pre_patch_commit"], "a" * 40)
        self.assertEqual(lead["recommended_verification"]["after_revision"], "b" * 40)
        self.assertEqual(lead["recommended_verification"]["evidence_status"], "commands-not-run")
        self.assertEqual(lead["status"], "hypothesis")
        self.assertEqual(len(lead["candidate_fingerprint_sha256"]), 64)


if __name__ == "__main__":
    unittest.main()
