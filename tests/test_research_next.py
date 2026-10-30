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


class SpecMappingBudgetTests(unittest.TestCase):
    """The hit budget must not be spent on fixtures, and a bounded sample must say so."""

    @staticmethod
    def _commit(repo):
        for key, value in (("user.email", "fixture@example.invalid"),
                           ("user.name", "Fixture")):
            subprocess.run(["git", "-C", str(repo), "config", key, value], check=True)
        subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
        subprocess.run(["git", "-C", str(repo), "commit", "-qm", "fixture"], check=True)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "checkout"
        (self.root / "src").mkdir(parents=True)
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        (self.root / "README.md").write_text(
            "Every withdrawal must check the caller.\n", encoding="utf-8")
        # A fixture mentioning the same symbol, named so it sorts BEFORE the code it
        # exercises -- the real case was cluster/cluster_internal_test.go preceding
        # cluster/definition.go, which spent the whole budget on the fixture.
        (self.root / "src/agent_internal_test.go").write_text(
            "package src\n" + "var withdraw = 1\n" * 60, encoding="utf-8")
        (self.root / "src/vault.go").write_text(
            "package src\n" + "func withdraw() {}\n" * 60, encoding="utf-8")
        self._commit(self.root)

    def spec(self):
        return {"schema_version": 1, "requirements": [{
            "id": "REQ-001", "source_path": "README.md", "source_line": 1,
            "quote": "Every withdrawal must check the caller.",
            "symbols": ["withdraw"], "code_scope": ["src"]}]}

    def test_production_code_is_read_before_test_fixtures(self):
        item = spec_mapper.map_spec(self.spec(), self.root)["requirements"][0]
        paths = [hit["path"] for hit in item["symbol_hits"]]
        self.assertEqual(paths[0], "src/vault.go",
                         "the budget must not be spent on a fixture first")
        self.assertNotIn("src/agent_internal_test.go", paths)

    def test_a_capped_map_declares_itself_a_bounded_sample(self):
        item = spec_mapper.map_spec(self.spec(), self.root)["requirements"][0]
        self.assertTrue(item["truncated"])
        self.assertEqual(len(item["symbol_hits"]), item["symbol_hit_cap"])
        self.assertEqual(item["scoped_code_files"], 2)
        self.assertEqual(item["readable_code_files"], 1)
        self.assertEqual(item["unread_code_files"], 1)
        self.assertIn("bounded sample and not", item["notice"])
        self.assertIn("were never opened", item["notice"])

    def test_an_uncapped_map_is_not_marked_truncated(self):
        small = Path(self.tmp.name) / "small"
        (small / "src").mkdir(parents=True)
        subprocess.run(["git", "init", "-q", str(small)], check=True)
        (small / "README.md").write_text(
            "Every withdrawal must check the caller.\n", encoding="utf-8")
        (small / "src/vault.go").write_text("func withdraw() {}\n", encoding="utf-8")
        self._commit(small)
        item = spec_mapper.map_spec(self.spec(), small)["requirements"][0]
        self.assertFalse(item["truncated"])
        self.assertEqual(item["unread_code_files"], 0)
        self.assertNotIn("bounded sample", item["notice"])


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

    def test_native_runner_detects_tracked_source_mutation(self):
        def mutate(plan, root, allow_exec=False):
            (self.root / "src/Vault.sol").write_text("contract Changed {}\n")
            return {"result": "experiments-conformed", "cases": []}
        with mock.patch.object(native.scenario_runner, "execute", side_effect=mutate):
            with self.assertRaisesRegex(ValueError, "tracked source changed"):
                native.cycle(self.pair_spec(), "pytest", self.root,
                             allow_exec=True, isolated_confirmed=True,
                             evidence_dir=Path(self.tmp.name) / "modified")

    def test_dirty_checkout_is_rejected_before_any_native_execution(self):
        (self.root / "src/Vault.sol").write_text("contract V { function changed() external {} }\\n")
        evidence = Path(self.tmp.name) / "dirty-should-not-create"
        with mock.patch.object(native.scenario_runner, "execute") as execute:
            with self.assertRaisesRegex(ValueError, "pre-existing tracked changes"):
                native.cycle(self.pair_spec(), "pytest", self.root,
                             allow_exec=True, isolated_confirmed=True,
                             evidence_dir=evidence)
            execute.assert_not_called()
        self.assertFalse(evidence.exists())

    def test_actual_native_unittest_pair_runs_twice_in_disposable_fixture(self):
        # Real local subprocesses rather than mocked scenario_runner output.
        # Each case asserts a simple generic property; this is NOT a target PoC.
        fixture = self.root / "test_local_native.py"
        fixture.write_text(
            "import unittest\n"
            "class LocalNative(unittest.TestCase):\n"
            "    def test_candidate(self):\n"
            "        self.assertEqual(2 * 3, 6)\n"
            "    def test_control(self):\n"
            "        self.assertNotEqual(2 * 3, 7)\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.root), "add",
                        "test_local_native.py"], check=True)
        subprocess.run(["git", "-C", str(self.root), "commit", "-qm",
                        "add synthetic native fixture"], check=True)
        self.sha = subprocess.run(["git", "-C", str(self.root),
                                   "rev-parse", "HEAD"], check=True,
                                  capture_output=True, text=True).stdout.strip()
        spec = self.pair_spec()
        spec["cases"][0]["candidate"] = "test_local_native.LocalNative.test_candidate"
        spec["cases"][0]["control"] = "test_local_native.LocalNative.test_control"
        report = native.cycle(spec, "unittest", self.root,
                              allow_exec=True, isolated_confirmed=True,
                              evidence_dir=Path(self.tmp.name) / "native-real")
        self.assertEqual(report["status"], "NATIVE_PAIR_RAN_NEEDS_INDEPENDENT_REVIEW")
        self.assertEqual(len(report["rounds"]), 2)
        self.assertTrue(all(len(r["cases"]) == 2 for r in report["rounds"]))
        self.assertTrue(all(c["tests_ran"] for r in report["rounds"]
                            for c in r["cases"]))
        self.assertEqual(report["confirmed_vulnerabilities"], 0)

    def test_missing_control_or_zero_executed_cases_cannot_claim_conformance(self):
        only_candidate = [{"id": "withdraw-pair-candidate", "pair_id": "withdraw-pair", "role": "candidate",
                           "executed": True, "tests_ran": True, "status": "ran",
                           "matched_expected_exit": True, "stdout": "1 passed",
                           "stderr": ""}]
        with mock.patch.object(native.scenario_runner, "execute",
                               return_value={"result": "experiments-conformed",
                                             "cases": only_candidate}):
            report = native.cycle(self.pair_spec(), "pytest", self.root,
                                  allow_exec=True, isolated_confirmed=True,
                                  evidence_dir=Path(self.tmp.name) / "missing-control")
        self.assertEqual(report["status"], "INCOMPLETE_OR_NOT_EXECUTED")

    def test_empty_mocked_native_result_cannot_claim_conformance(self):
        with mock.patch.object(native.scenario_runner, "execute",
                               return_value={"result": "experiments-conformed",
                                             "cases": []}):
            report = native.cycle(self.pair_spec(), "pytest", self.root,
                                  allow_exec=True, isolated_confirmed=True,
                                  evidence_dir=Path(self.tmp.name) / "empty-results")
        self.assertEqual(report["status"], "INCOMPLETE_OR_NOT_EXECUTED")

    def test_two_independent_synthetic_runs_are_only_harness_evidence(self):
        pairs = [{"id": "withdraw-pair-" + role, "pair_id": "withdraw-pair", "role": role, "executed": True,
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


class IntegratedCLITests(CheckoutFixture):
    def test_bounty_cli_spec_maps_without_promoting_finding(self):
        spec_file = Path(self.tmp.name) / "spec.json"
        spec_file.write_text(json.dumps(self.spec()), encoding="utf-8")
        r = subprocess.run(
            [sys.executable, str(SCRIPTS / "bounty.py"), "research-next", "spec",
             "--repo", str(self.root), "--spec", str(spec_file)],
            capture_output=True, text=True, check=True)
        self.assertEqual(json.loads(r.stdout)["confirmed_vulnerabilities"], 0)

    def test_bounty_cli_native_defaults_to_dry_run(self):
        spec_file = Path(self.tmp.name) / "native.json"
        spec_file.write_text(json.dumps({
            "finding_id": "BP-123", "source_revision": self.sha,
            "invariant": "Caller authentication required",
            "cases": [{"id": "auth", "candidate": "test_candidate",
                       "control": "test_control"}]}), encoding="utf-8")
        r = subprocess.run(
            [sys.executable, str(SCRIPTS / "bounty.py"), "research-next", "native",
             "--repo", str(self.root), "--spec", str(spec_file), "--stack", "pytest"],
            capture_output=True, text=True, check=True)
        self.assertEqual(json.loads(r.stdout)["mode"], "dry-run")


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
