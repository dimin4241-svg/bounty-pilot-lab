"""Lab 0.55 workflow regressions — offline, no model/RPC/production calls."""
import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills/bounty-pilot/scripts"
sys.path.insert(0, str(SCRIPTS))


def load(name):
    path = SCRIPTS / (name + ".py")
    spec = importlib.util.spec_from_file_location("bp_" + name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


poc = load("poc_builder")
bench = load("blind_campaign")
ir = load("native_ir_flow")
doctor = load("failure_taxonomy")
wizard = load("setup_wizard")
SHA = "a" * 40
SHA2 = "b" * 40


def specimen(name="C-01"):
    return {"schema_version": 1, "id": name, "stack": "solidity",
            "source_revision": SHA,
            "entry_point": "transferTo(address,uint256)",
            "invariant": "Cannot spend reserved collateral",
            "attacker_capabilities": ["unprivileged user with own funded account"],
            "steps": ["locally create two accounts", "execute candidate and control"]}


def campaign():
    return {"schema_version": 1, "baseline_skill_sha": SHA,
            "candidate_skill_sha": SHA2, "model": "same-model",
            "budget_usd": 10, "minutes_per_case": 15,
            "cases": [{"case": "case1", "repo_url": "https://github.com/example/protocol",
                       "pinned_commit": "c" * 40, "scope_paths": ["src"]},
                      {"case": "case2", "repo_url": "https://github.com/example/protocol",
                       "pinned_commit": "d" * 40, "scope_paths": ["src"]}]}


def ledger(**overrides):
    value = {"id": "case-one", "reading": "completed", "candidate": "hypothesis",
             "poc": "not-run", "impact": "not-assessed",
             "eligibility": "not-checked", "disposition": "not-submitted"}
    value.update(overrides)
    return value


class PoCBuilderTests(unittest.TestCase):
    def _make(self, root):
        repo = root / "repo"
        (repo / "src").mkdir(parents=True)
        target = repo / "src/Token.sol"
        target.write_text("contract Token {}\n", encoding="utf-8")
        finding = specimen()
        finding["source_anchors"] = [{"path": "src/Token.sol",
                                      "line": 1,
                                      "sha256": hashlib.sha256(target.read_bytes()).hexdigest()}]
        return repo, finding, target

    def test_plan_source_anchored_and_deliberately_failing(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, f, _ = self._make(Path(tmp))
            dest = Path(tmp) / "private"
            fpath = Path(tmp) / "finding.json"
            fpath.write_text(json.dumps(f), encoding="utf-8")
            receipt = poc.prepare(fpath, repo, dest)
            self.assertEqual(receipt["status"], "incomplete-unexecuted-skeleton")
            self.assertTrue((dest / "authoring-task.md").is_file())
            data = json.loads((dest / "poc-manifest.json").read_text())
            self.assertEqual(data["source_revision"], SHA)
            self.assertIn("revert(", (dest / data["template_name"]).read_text())
            with self.assertRaises(ValueError):
                poc.prepare(fpath, repo, dest)

    def test_source_drift_and_unsafe_paths_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, f, target = self._make(Path(tmp))
            target.write_text("contract Changed {}\n")
            with self.assertRaises(ValueError):
                poc.plan(f, repo)
            f["source_anchors"][0]["path"] = "../secret"
            with self.assertRaises(ValueError):
                poc.plan(f, repo)

    def test_reported_pass_is_not_promoted_to_verified(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo, f, _ = self._make(root)
            manifest, test, _, task = poc.plan(f, repo)
            dest = root / "bundle"
            dest.mkdir()
            (dest / "poc-manifest.json").write_text(json.dumps(manifest))
            t = dest / manifest["template_name"]
            t.write_text(test)
            row = {"status": "passed", "exit_code": 0,
                   "log_sha256": "e" * 64,
                   "test_file_sha256": hashlib.sha256(test.encode()).hexdigest()}
            receipt = {"schema_version": 1, "case_id": f["id"],
                       "source_revision": SHA,
                       "candidate": row.copy(), "negative_control": row.copy()}
            self.assertEqual(poc.check(dest, receipt)["status"],
                             "not-proven-skeleton-unchanged")
            modified = test.replace(
                'revert("fill in: candidate must assert the demonstrated vulnerability");',
                "assertTrue(true);").replace(
                'revert("fill in: negative control must assert the protection holds");',
                "assertTrue(true);")
            t.write_text(modified)
            # Even after edit this remains only researcher-reported, NOT verified.
            self.assertEqual(poc.check(dest, receipt)["status"],
                             "not-proven-skeleton-placeholders")
            for line in poc.STUBS:
                modified = modified.replace(line, "filled")
            t.write_text(modified)
            newhash = hashlib.sha256(modified.encode()).hexdigest()
            for k in ("candidate", "negative_control"):
                receipt[k]["test_file_sha256"] = newhash
            self.assertEqual(poc.check(dest, receipt)["status"],
                             "reported-local-pair-passed-independent-review-needed")
            receipt["negative_control"]["exit_code"] = 1
            self.assertEqual(poc.check(dest, receipt)["status"],
                             "not-proven-missing-passing-negative_control")
            self.assertIn("untrusted", task)

    def test_cli_fails_closed_for_missing_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo, f, target = self._make(root)
            target.unlink()
            fpath = root / "input.json"
            fpath.write_text(json.dumps(f))
            p = subprocess.run([sys.executable, str(SCRIPTS / "poc_builder.py"),
                                "plan", "--finding", str(fpath),
                                "--repo", str(repo), "--out-dir", str(root / "out")],
                               capture_output=True, text=True, timeout=12)
            self.assertNotEqual(p.returncode, 0)
            self.assertFalse((root / "out").exists())


class BlindCampaignTests(unittest.TestCase):
    def test_blind_preparation_keeps_truth_out_of_hunter_jobs(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "campaign"
            result = bench.prepare(campaign(), dest)
            self.assertEqual(result["comparisons"], 4)
            self.assertFalse(result["public_accuracy_claim_allowed"])
            for arm in ("baseline", "candidate"):
                tasks = sorted((dest / "jobs" / arm).glob("*/TASK.json"))
                self.assertEqual(len(tasks), 2)
                for t in tasks:
                    txt = t.read_text()
                    self.assertNotIn("ground_truth", txt)
                    self.assertNotIn("vulnerability_title", txt)
                    self.assertIn("NOT_STARTED_REQUIRES_SEPARATE_APPROVED_MAC", txt)

    def test_ground_truth_in_campaign_and_mismatched_budget_rejected(self):
        bad = campaign()
        bad["cases"][0]["published_bug"] = "High"
        with self.assertRaises(ValueError):
            bench.prepare(bad, Path("/tmp/not-created-campaign"))
        bad = campaign()
        bad["candidate_skill_sha"] = bad["baseline_skill_sha"]
        with self.assertRaises(ValueError):
            bench._validate(bad)

    def test_scored_comparison_rejects_unsealed_or_unknown_cases(self):
        one = {"case": "case1", "pinned_commit": "c" * 40,
               "state": "scored", "sealed_at": "2026-11-08T00:00:00Z",
               "published_findings": 1,
               "rediscovered": [], "missed": [{"id": "H-01", "severity": "high"}]}
        two = dict(one, case="case2", pinned_commit="d" * 40)
        with self.assertRaises(ValueError):
            bench.compare_scored([one], [one], campaign())
        with self.assertRaises(ValueError):
            bench.compare_scored([{**one, "state": "unscored"}, two],
                                 [one, two], campaign())

    def test_scored_summary_is_not_an_automatic_public_accuracy_claim(self):
        one = {"case": "case1", "pinned_commit": "c" * 40,
               "state": "scored", "sealed_at": "2026-11-08T00:00:00Z",
               "published_findings": 1,
               "rediscovered": [], "missed": [{"id": "H-01", "severity": "high"}]}
        two = dict(one, case="case2", pinned_commit="d" * 40)
        win = dict(one, rediscovered=[{"id": "H-01", "severity": "high"}],
                   missed=[])
        summary = bench.compare_scored([one, two], [win, two], campaign())
        self.assertFalse(summary["public_claim_allowed"])
        self.assertEqual(summary["case_count"], 2)


class NativeIRFlowTests(unittest.TestCase):
    def test_rust_mir_defuse_passes_parameter_to_sink(self):
        mir = """fn transfer(_1: u64) -> () {
bb0: {
    _2 = copy _1;
    _3 = invoke_signed(move _2);
}
}"""
        out = ir.scan_rust_mir(mir, SHA)
        self.assertEqual(out["count"], 1)
        self.assertEqual(out["leads"][0]["seed_parameters"], ["_1"])
        self.assertIn("unverified", out["leads"][0]["status"])

    def test_no_input_or_no_sink_is_not_reported_as_safe(self):
        mir = "fn foo(_1: u64) -> () {\n    _2 = const 3;\n}"
        self.assertEqual(ir.scan_rust_mir(mir, SHA)["count"], 0)
        with self.assertRaises(ValueError):
            ir.scan_rust_mir(mir, "not-a-revision")

    def test_move_normalized_graph_multihop(self):
        graph = {"schema_version": 1, "language": "move",
                 "source_revision": SHA,
                 "nodes": [
                     {"id": "n1", "kind": "signer", "file": "sources/market.move",
                      "line": 10},
                     {"id": "n2", "kind": "value", "file": "sources/market.move",
                      "line": 11, "inputs": ["n1"]},
                     {"id": "n3", "kind": "asset-transfer",
                      "file": "sources/market.move", "line": 20,
                      "inputs": ["n2"]}]}
        o = ir.normalize_graph(graph)
        self.assertEqual(o["count"], 1)
        self.assertEqual(o["leads"][0]["nodes"], ["n1", "n2", "n3"])
        self.assertIn("not-authenticated", o["limitations"][0])

    def test_native_graph_dangling_inputs_and_path_traversal_rejected(self):
        graph = {"schema_version": 1, "language": "rust",
                 "source_revision": SHA,
                 "nodes": [{"id": "v1", "kind": "asset-transfer",
                            "file": "src/lib.rs", "line": 4,
                            "inputs": ["missing"]}]}
        with self.assertRaises(ValueError):
            ir.normalize_graph(graph)
        graph["nodes"][0]["inputs"] = []
        graph["nodes"][0]["file"] = "../src/lib.rs"
        with self.assertRaises(ValueError):
            ir.normalize_graph(graph)

    def test_native_graph_cli_honors_no_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "a.mir"
            output = root / "result.json"
            source.write_text("fn moveit(_1: u64) -> () {\n_2 = transfer(move _1);\n}")
            cmd = [sys.executable, str(SCRIPTS / "native_ir_flow.py"),
                   "--rust-mir", str(source), "--source-revision", SHA,
                   "--out", str(output)]
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=12)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertEqual(json.loads(output.read_text())["count"], 1)
            p2 = subprocess.run(cmd, capture_output=True, text=True, timeout=12)
            self.assertNotEqual(p2.returncode, 0)


class FailureTaxonomyTests(unittest.TestCase):
    def test_empty_candidate_is_not_claimed_as_a_missed_real_bug(self):
        out = doctor.evaluate({"schema_version": 1,
                               "cases": [ledger(candidate="none")]})
        self.assertEqual(out["cases"][0]["bottleneck"],
                         "no-candidate-unproven-negative")
        self.assertEqual(out["cases"][0]["status"], "operator-ledger-unverified")

    def test_evidence_steps_have_distinct_bottlenecks(self):
        cases = [
            ledger(id="a", reading="failed"),
            ledger(id="b", poc="setup-failed"),
            ledger(id="c", poc="candidate-failed"),
            ledger(id="d", poc="reported-paired-pass",
                   impact="capital-unrealistic"),
            ledger(id="e", poc="reported-paired-pass",
                   impact="measured-researcher-supplied",
                   eligibility="duplicate"),
        ]
        out = doctor.evaluate({"schema_version": 1, "cases": cases},
                              {"schema_version": 1, "agent_jobs": {"failed": 1},
                               "reading_counts": {"unparsed_candidate_headers": 1}})
        self.assertEqual(out["case_count"], 5)
        self.assertIn("agent-dispatch-incomplete", out["pipeline_warnings"])
        self.assertEqual(out["cases"][-1]["bottleneck"],
                         "already-known-duplicate")

    def test_impossible_paid_without_poc_is_rejected(self):
        row = ledger(disposition="rewarded-researcher-supplied")
        with self.assertRaises(ValueError):
            doctor.evaluate({"schema_version": 1, "cases": [row]})

    def test_duplicate_ledger_case_ids_rejected(self):
        with self.assertRaises(ValueError):
            doctor.evaluate({"schema_version": 1, "cases": [ledger(), ledger()]})


class SetupWizardTests(unittest.TestCase):
    def test_offline_wizard_detects_available_local_tools(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "target"
            (repo / "contracts").mkdir(parents=True)
            data = {"schema_version": 1, "repo": str(repo),
                    "stack": "solidity-evm", "scope_paths": ["contracts"],
                    "program_url": "https://example.test/security",
                    "rpc_env_var": "BP_TEST_RPC_URL"}
            o = wizard.build(data, which=lambda n: "/usr/bin/" + n if n == "python3" else None)
            self.assertEqual(o["status"], "preflight-ready-for-offline-planning")
            self.assertFalse(o["native_harness_ready"])
            self.assertEqual(o["scope_eligibility"], "NOT_VERIFIED")
            self.assertNotIn("rpc_url", o)

    def test_path_traversal_and_rpc_secret_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "target"
            repo.mkdir()
            good = {"schema_version": 1, "repo": str(repo),
                    "stack": "rust-solana", "scope_paths": [".."]}
            with self.assertRaises(ValueError):
                wizard.build(good)
            good["scope_paths"] = ["."]
            good["rpc_env_var"] = "https://secret-endpoint"
            with self.assertRaises(ValueError):
                wizard.build(good)

    def test_wizard_cli_writes_private_plan(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "repo" / "src").mkdir(parents=True)
            data = {"schema_version": 1, "repo": str(root / "repo"),
                    "stack": "rust-native", "scope_paths": ["src"]}
            inp = root / "answers.json"
            inp.write_text(json.dumps(data))
            out = root / "plan.json"
            cmd = [sys.executable, str(SCRIPTS / "setup_wizard.py"),
                   "--answers", str(inp), "--out", str(out)]
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=12)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertIn("offline-configuration-only", out.read_text())
            # Main bounty.py entrypoint must expose the same safe wizard.
            from_main = root / "plan-from-bounty.json"
            main_cmd = [sys.executable, str(SCRIPTS / "bounty.py"),
                        "wizard", "--answers", str(inp), "--out", str(from_main)]
            q = subprocess.run(main_cmd, capture_output=True, text=True, timeout=15)
            self.assertEqual(q.returncode, 0, q.stderr)
            self.assertEqual(json.loads(from_main.read_text())["execution"],
                             "offline-configuration-only")
            repeat = subprocess.run(cmd, capture_output=True, text=True, timeout=12)
            self.assertNotEqual(repeat.returncode, 0)


if __name__ == "__main__":
    unittest.main()
