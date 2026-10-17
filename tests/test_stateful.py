"""Regression tests for bounded, non-proving cross-stack hunt helpers."""
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT_DIR = ROOT / "skills/bounty-pilot/scripts"

def load(name):
    path = SCRIPT_DIR / (name + ".py")
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

graph = load("state_graph")
coverage = load("coverage_graph")
invariants = load("invariant_check")
runner = load("scenario_runner")
bounty = load("bounty")

class GraphTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        (self.repo / "src").mkdir()
        (self.repo / "tests").mkdir()
        (self.repo / "src/vault.rs").write_text(
            "impl Vault {\n"
            "fn deposit(&mut self, amount: u64) { self.balance = amount; }\n"
            "fn withdraw(&self) { let old = self.balance; }\n"
            "}\n", encoding="utf-8")
        (self.repo / "src/worker.ts").write_text(
            "async function retry() { state.queue = 4; }\n"
            "function process() { return state.queue; }\n", encoding="utf-8")
        (self.repo / "tests/test_vault.rs").write_text("fn fake() {}\n")
        (self.repo / "src/.env").write_text("SECRET=should-not-be-captured")
        subprocess.run(["git", "-C", str(self.repo), "add", "-A"], check=True)

    def test_graph_invents_no_high_confidence_edges(self):
        g = graph.scan(self.repo)
        self.assertEqual(g["method"], "regex-lexical-heuristic")
        self.assertFalse(g["sound"])
        self.assertTrue(g["scenario_seeds"])
        self.assertTrue(all(e["confidence"] == "low" for e in g["edges"]))
        self.assertTrue(any(s["language"] == "rust" for s in g["symbols"]))
        self.assertTrue(any(s["language"] == "typescript" for s in g["symbols"]))
        self.assertFalse(any("tests/" in s["path"] for s in g["symbols"]))
        self.assertNotIn("should-not-be-captured", json.dumps(g))

    def test_gap_rank_tracks_reviewed_paths(self):
        g = graph.scan(self.repo)
        report = coverage.gaps(g, {"src/vault.rs"})
        self.assertTrue(report["unreviewed"])
        self.assertTrue(all(x["path"] != "src/vault.rs" for x in report["unreviewed"]))
        self.assertIn("heuristic", report["method"])
        self.assertEqual(report["unreviewed_symbols"],
                         len([x for x in g["symbols"] if x["path"] != "src/vault.rs"]))

    def test_empty_symbol_limit_is_refused(self):
        with self.assertRaises(ValueError):
            # A repo with no source should return empty, without inventing symbols.
            graph.scan(self.repo, 0)
        
class InvariantTests(unittest.TestCase):
    def test_exact_large_integer_conservation_and_comparison(self):
        big = 9007199254740993
        spec = {"invariants": [
            {"id": "solvency", "kind": "compare",
             "left": {"path": "vault.assets"}, "op": "ge",
             "right": {"path": "vault.liabilities"}, "basis": "inferred"},
            {"id": "supply", "kind": "conservation",
             "terms": [{"value": {"path": "balances.0"}},
                       {"value": {"path": "balances.1"}}],
             "expected": {"path": "vault.assets"}},
            {"id": "once", "kind": "unique", "values": {"path": "claims"}}
        ]}
        snapshot = {"vault": {"assets": str(big), "liabilities": str(big - 1)},
                    "balances": [big - 2, "2"], "claims": ["a", "b"]}
        res = invariants.evaluate(spec, snapshot)
        self.assertEqual(res["summary"], {"pass": 3, "fail": 0, "unknown": 0})
        self.assertEqual(res["evidence_level"], "snapshot-consistency-only")

    def test_fail_and_unknown_not_silently_passed(self):
        spec = {"invariants": [
            {"id": "duplicate", "kind": "unique", "values": {"path": "claims"}},
            {"id": "unavailable", "kind": "compare",
             "left": {"path": "missing"}, "op": "eq", "right": 0}
        ]}
        report = invariants.evaluate(spec, {"claims": [1, 1]})
        self.assertEqual(report["summary"], {"pass": 0, "fail": 1, "unknown": 1})

    def test_no_expressions_or_bool_numeric(self):
        with self.assertRaises(ValueError):
            invariants.resolve({}, {"eval": "__import__('os').system('echo bad')"})
        with self.assertRaises(ValueError):
            invariants.number(True)

class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        # Inline `-c` is rejected as a shell/interpreter wrapper, so run a real file.
        self.ok = self.repo / "exit0.py"
        self.ok.write_text("print('ok 1 - check')\nraise SystemExit(0)\n")
        argv = [sys.executable, "exit0.py"]
        # A plain script is not a recognised test runner; the marker is what shows it ran.
        self.plan = {"cases": [
            {"id": "poc", "pair_id": "one", "role": "candidate", "argv": list(argv),
             "expect_tests_marker": "^ok 1 "},
            {"id": "control", "pair_id": "one", "role": "negative-control", "argv": list(argv),
             "expect_tests_marker": "^ok 1 "}
        ]}

    def test_dry_run_never_executes(self):
        output = runner.execute(self.plan, self.repo)
        self.assertEqual(output["result"], "not-executed")
        self.assertFalse(any(c["executed"] for c in output["cases"]))

    def test_explicit_local_execution_with_controls(self):
        output = runner.execute(self.plan, self.repo, True)
        self.assertEqual(output["result"], "experiments-conformed")
        self.assertTrue(all(c["matched_expected_exit"] for c in output["cases"]))
        self.assertIn("only show", output["notice"])

    def test_missing_control_and_cwd_escape_are_rejected(self):
        with self.assertRaises(ValueError):
            runner.execute({"cases": self.plan["cases"][:1]}, self.repo, True)
        self.plan["cases"][0]["cwd"] = "../"
        with self.assertRaises(ValueError):
            runner.execute(self.plan, self.repo, True)

    def test_failure_keeps_runner_in_incomplete_status(self):
        self.plan["cases"][0]["expected_exit"] = 1
        output = runner.execute(self.plan, self.repo, True)
        self.assertEqual(output["result"], "incomplete")

class BundleRegistrationTests(unittest.TestCase):
    def test_new_lenses_registered_with_matching_files(self):
        all_lenses = set(bounty.LENSES)
        self.assertTrue(set(bounty.LOGIC_LENSES).issubset(all_lenses))
        self.assertTrue(set(bounty.CROSS_STACK_LENSES).issubset(all_lenses))
        self.assertEqual(bounty.ATTACK_LENSES[0], "privileged-path")
        for lens in all_lenses:
            self.assertTrue((ROOT / "skills/bounty-pilot/references/hunt-agents"
                             / (lens + "-agent.md")).is_file(), lens)

class NativeRoutingAndScaffoldTests(unittest.TestCase):
    def test_router_separates_native_rust_and_solana_from_manifests(self):
        routing = load("stack_route")
        with tempfile.TemporaryDirectory() as temp:
            repo = Path(temp)
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            (repo / "worker").mkdir()
            (repo / "program").mkdir()
            (repo / "worker/Cargo.toml").write_text(
                '[package]\nname = "worker"\nversion = "0.1.0"\n')
            (repo / "program/Cargo.toml").write_text(
                '[dependencies]\nanchor-lang = "0.30"\n')
            # A bare helper script is NOT a backend: it must not acquire a web-backend tag.
            (repo / "api.py").write_text("def main(): pass\n")
            subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
            summary = routing.route(repo)
            stacks = {x["stack"] for x in summary["stacks"]}
            self.assertIn("rust-native", stacks)
            self.assertIn("rust-solana", stacks)
            self.assertNotIn("web-backend", stacks)
            self.assertIn("semantic-mismatch", summary["suggested_cross_stack_lenses"])
            self.assertEqual(len(summary["prioritization"]["selected"]), 6)
            limited = routing.prioritize(summary, budget=3)
            self.assertEqual(len(limited["selected"]), 3)
            self.assertNotIn("anchor-account", routing.prioritize({"stacks": []})["selected"])
            with self.assertRaises(ValueError):
                routing.prioritize(summary, 0)

    def test_hardhat_defi_repo_keeps_accounting_and_avoids_web_backend(self):
        routing = load("stack_route")
        with tempfile.TemporaryDirectory() as temp:
            repo = Path(temp)
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            (repo / "contracts").mkdir()
            (repo / "contracts/Vault.sol").write_text(
                "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\ncontract Vault {}\n")
            (repo / "hardhat.config.js").write_text("module.exports = {};\n")
            (repo / "package.json").write_text(
                '{"name":"defi","devDependencies":{"hardhat":"^2.0.0",'
                '"@openzeppelin/contracts":"^5.0.0"}}\n')
            (repo / "scripts").mkdir()
            (repo / "scripts/deploy.js").write_text("async function main(){}\n")
            subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
            summary = routing.route(repo)
            stacks = {x["stack"] for x in summary["stacks"]}
            self.assertEqual(stacks, {"solidity-evm"})
            self.assertNotIn("web-backend", stacks)
            self.assertIn("accounting", summary["prioritization"]["selected"])

    def test_express_backend_is_routed_as_web_backend(self):
        routing = load("stack_route")
        with tempfile.TemporaryDirectory() as temp:
            repo = Path(temp)
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            (repo / "package.json").write_text(
                '{"name":"svc","dependencies":{"express":"^4.19.0"}}\n')
            (repo / "server.js").write_text("const app = require('express')();\n")
            subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
            stacks = {x["stack"] for x in routing.route(repo)["stacks"]}
            self.assertIn("web-backend", stacks)

    def test_anchor_workspace_routes_to_solana_and_selects_anchor_account(self):
        routing = load("stack_route")
        with tempfile.TemporaryDirectory() as temp:
            repo = Path(temp)
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            (repo / "Anchor.toml").write_text('[programs.localnet]\nmy = "11111111111111111111111111111111"\n')
            (repo / "Cargo.toml").write_text('[workspace]\nmembers = ["programs/*"]\n')
            (repo / "programs/my/src").mkdir(parents=True)
            (repo / "programs/my/Cargo.toml").write_text(
                '[package]\nname = "my"\nversion = "0.1.0"\n[dependencies]\nanchor-lang = "0.30"\n')
            (repo / "tests").mkdir()
            (repo / "tests/my.ts").write_text("describe('my', () => {});\n")
            subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
            summary = routing.route(repo)
            stacks = {x["stack"] for x in summary["stacks"]}
            self.assertIn("rust-solana", stacks)
            # A workspace-only root Cargo.toml must not be tagged plain rust-native.
            self.assertNotIn("rust-native", stacks)
            self.assertIn("anchor-account", summary["prioritization"]["selected"])

    def test_scaffold_is_explicitly_incomplete_and_rejects_empty_findings(self):
        scaffold = load("poc_scaffold")
        finding = {"id": "BP-42", "invariant": "one payout per claim",
                   "entry_point": "deposit", "attacker_capabilities": "public user",
                   "steps": ["deposit", "cancel", "retry"]}
        for stack in ("solidity", "rust", "python", "go"):
            ident, code, data = scaffold.scaffold(finding, stack)
            self.assertIn("todo", code.lower())
            self.assertEqual(data["verification"], "not-run-not-proven")
            self.assertTrue(ident.startswith("bp_"))
        with self.assertRaises(ValueError):
            scaffold.scaffold({"id": "../escape"}, "python")

    def test_logic_bundle_includes_native_adapter(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repo = root / "repo"
            repo.mkdir()
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            (repo / "Cargo.toml").write_text(
                '[package]\nname = "keeper"\nversion = "0.1.0"\n')
            (repo / "lib.rs").write_text("fn process() { }\n")
            subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
            subprocess.run(["git", "-C", str(repo),
                            "-c", "user.name=Test", "-c", "user.email=a@example.invalid",
                            "commit", "-qm", "baseline"], check=True)
            run = root / "private-run"
            result = bounty.bundle(repo, run, ["business-logic"])
            text = (run / "bundles/business-logic-bundle.md").read_text()
            self.assertIn("Native Rust adapter", text)
            self.assertIn("Stateful, cross-stack search protocol", text)
            self.assertIn("rust-native", result["detected_stacks_heuristic"])
            targeted = bounty.bundle(repo, run, ["recommended"])
            self.assertEqual(len(targeted["bundles"]), 6)
            self.assertTrue(any(x["lens"] == "business-logic" for x in targeted["bundles"]))

if __name__ == "__main__":
    unittest.main()
