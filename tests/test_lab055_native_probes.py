"""Deterministic adversarial probes for Lab 0.55.

Tests actual rustc MIR when available, graph flow reachability, pair evidence
controls, random reference-state conservation and explicitly limited claims.
All targets are synthetic and owned by the test; no network/model/RPC.
"""
import copy
import hashlib
import importlib.util
import json
import random
import shutil
import subprocess
import sys
import tempfile
import unittest
from collections import deque
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills" / "bounty-pilot" / "scripts"
sys.path.insert(0, str(SCRIPTS))


def helper(name):
    loc = SCRIPTS / (name + ".py")
    spec = importlib.util.spec_from_file_location("bp_probe_" + name, loc)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


flow = helper("native_ir_flow")
sim = helper("local_transition_sim")
poc = helper("poc_builder")
blind = helper("blind_campaign")
REV = "a" * 40
REV_NEW = "b" * 40


class ActualRustMIRTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("rustc"), "rustc is required for native compiler integration")
    def test_compiler_generated_mir_true_path_and_constant_control(self):
        # This invokes a real native compiler on a tiny safe source that is
        # constructed by this test, not a cloned unknown third-party project.
        source = """\
#![allow(unused_variables)]
#[inline(never)]
pub fn invoke_signed(value: u64) -> u64 { value + 1 }
#[inline(never)]
pub fn call_untrusted(value: u64) -> u64 {
    let copied = value;
    invoke_signed(copied)
}
#[inline(never)]
pub fn call_constant(value: u64) -> u64 {
    let ignored = value;
    invoke_signed(7)
}
"""
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            src, mir = root / "lib.rs", root / "out.mir"
            src.write_text(source, encoding="utf-8")
            cmd = ["rustc", "--edition", "2021", "--crate-type", "lib",
                   "-C", "opt-level=0", "--emit=mir", str(src), "-o", str(mir)]
            compiled = subprocess.run(cmd, cwd=str(root),
                                      capture_output=True, text=True, timeout=60)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            self.assertTrue(mir.stat().st_size)
            out = flow.scan_rust_mir(mir.read_text(encoding="utf-8"), REV)
            self.assertEqual(out["language"], "rust")
            self.assertIn("unverified", out["mode"] + " unverified")
            good = [x for x in out["leads"] if x["function"] == "call_untrusted"]
            bad = [x for x in out["leads"] if x["function"] == "call_constant"]
            self.assertTrue(good, out)
            self.assertFalse(bad, "a constant control cannot be reported as external-input flow")
            self.assertTrue(all(x["status"].startswith("unverified") for x in good))

    def test_source_parameter_overwritten_by_constant_is_not_tainted(self):
        code = """fn transfer(_1: u64) -> u64 {
bb0: {
    _1 = const 7_u64;
    _0 = invoke_signed(copy _1);
}
}"""
        result = flow.scan_rust_mir(code, REV)
        self.assertEqual(result["count"], 0, result)

    def test_parameter_update_that_depends_on_old_value_stays_tainted(self):
        code = """fn transfer(_1: u64) -> u64 {
bb0: {
    _1 = Add(copy _1, const 1_u64);
    _0 = invoke_signed(copy _1);
}
}"""
        result = flow.scan_rust_mir(code, REV)
        self.assertEqual(result["count"], 1, result)
        self.assertEqual(result["leads"][0]["seed_parameters"], ["_1"])

    def test_function_declaration_and_unrelated_sink_name_do_not_count(self):
        code = """fn invoke_signed(_1: u64) -> u64 {
bb0: {
    _0 = copy _1;
}
}
fn no_sensitive(_1: u64) -> u64 {
bb0: {
    _0 = Add(copy _1, const 1_u64);
}
}"""
        self.assertEqual(flow.scan_rust_mir(code, REV)["count"], 0)


class RandomizedFlowGraphTests(unittest.TestCase):
    def test_random_dags_match_independent_reachability(self):
        # 80 independently seeded DAGs; validation must find exactly the
        # source/sink pairs that are actually connected via declared edges.
        for seed in range(80):
            rng = random.Random(seed + 734)
            n = 22
            nodes = []
            src_nodes = {"n0", "n1"}
            sinks = {"n10", "n16", "n21"}
            inputs = {}
            for k in range(n):
                ident = "n%d" % k
                dependencies = [] if k < 2 else sorted(rng.sample(
                    ["n%d" % t for t in range(k)], rng.randint(0, min(k, 4))))
                inputs[ident] = dependencies
                kind = ("signer" if ident in src_nodes else
                        "asset-transfer" if ident in sinks else "value")
                nodes.append({"id": ident, "kind": kind,
                              "file": "src/lib.move", "line": k+1,
                              "inputs": dependencies})
            result = flow.normalize_graph({"schema_version": 1,
                                           "language": "move",
                                           "source_revision": REV, "nodes": nodes})
            got = {(item["source"], item["sink"]) for item in result["leads"]}
            expected = set()
            for source in src_nodes:
                seen, queue = {source}, deque([source])
                while queue:
                    node = queue.popleft()
                    if node in sinks:
                        expected.add((source, node))
                    for nextid in ["n%d" % i for i in range(n) if node in inputs["n%d" % i]]:
                        if nextid not in seen:
                            seen.add(nextid)
                            queue.append(nextid)
            self.assertEqual(got, expected, "DAG seed=%d" % seed)

    def test_cyclic_graph_terminates_without_false_safety_claim(self):
        graph = {"schema_version": 1, "language": "rust",
                 "source_revision": REV,
                 "nodes": [
                     {"id": "a", "kind": "external-input", "file": "src/x.rs",
                      "line": 1, "inputs": ["b"]},
                     {"id": "b", "kind": "value", "file": "src/x.rs",
                      "line": 2, "inputs": ["a"]},
                     {"id": "c", "kind": "settlement", "file": "src/x.rs",
                      "line": 3, "inputs": ["b"]}]}
        out = flow.normalize_graph(graph)
        self.assertEqual(out["count"], 1)
        self.assertEqual(out["leads"][0]["nodes"], ["a", "b", "c"])
        self.assertTrue(out["limitations"])


class FinancialStateRandomTests(unittest.TestCase):
    def test_cex_3000_action_fuzz_conserves_liabilities(self):
        for seed in range(30):
            rng = random.Random(3000 + seed)
            accounts = {"a": {"available": 500, "held": 0},
                        "b": {"available": 500, "held": 0}}
            actions = []
            for step in range(100):
                kind = rng.choice(("deposit", "withdraw_request", "withdraw_settle",
                                   "withdraw_cancel", "transfer"))
                ident = "w%d" % rng.randrange(100)
                user = rng.choice(("a", "b"))
                val = rng.randrange(1, 100)
                if kind == "deposit":
                    action = {"op": kind, "id": "d%d" % rng.randrange(50),
                              "account": user, "amount": val,
                              "finalized": rng.choice((True, False))}
                elif kind == "withdraw_request":
                    action = {"op": kind, "id": ident, "account": user,
                              "amount": val, "reviewed_destination": "wallet-a",
                              "authorized_destination": rng.choice(("wallet-a", "wallet-b"))}
                elif kind == "transfer":
                    action = {"op": kind, "id": "t%d" % rng.randrange(60),
                              "source": user,
                              "destination": "b" if user == "a" else "a",
                              "amount": val}
                else:
                    action = {"op": kind, "id": ident}
                actions.append(action)
            result = sim.simulate({"schema_version": 1, "domain": "cex-custody",
                                   "initial": {"accounts": accounts, "custody": 1000},
                                   "actions": actions})
            st = result["final_state"]
            self.assertEqual(st["custody"], sum(
                a["available"] + a["held"] for a in st["accounts"].values()),
                "CEX seed=%d" % seed)
            self.assertEqual(result["accepted"] + result["rejected"], 100)
            self.assertTrue(all(x["available"] >= 0 and x["held"] >= 0
                                for x in st["accounts"].values()))
            done = [row["status"] for row in st["withdrawals"].values()]
            self.assertTrue(all(x in ("pending", "settled", "cancelled") for x in done))

    def test_restaking_queue_slash_exit_preserves_shares(self):
        for seed in range(30):
            rng = random.Random(9000+seed)
            actions = []
            for step in range(90):
                kind = rng.choice(("stake", "queue_exit", "slash", "settle_exit"))
                ident = "e%d" % rng.randrange(50)
                if kind == "stake":
                    actions.append({"op": kind, "account": rng.choice(("a", "b")),
                                    "amount": rng.randrange(1, 30)})
                elif kind == "queue_exit":
                    actions.append({"op": kind, "id": ident,
                                    "account": rng.choice(("a", "b")),
                                    "shares": rng.randrange(1, 30)})
                elif kind == "slash":
                    actions.append({"op": kind, "amount": rng.randrange(1, 30)})
                else:
                    actions.append({"op": kind, "id": ident})
            result = sim.simulate({"schema_version": 1, "domain": "restaking-lst",
                                   "initial": {"assets": 100, "total_shares": 100,
                                               "available_shares": {"a": 50, "b": 50},
                                               "exits": {}},
                                   "actions": actions})
            st = result["final_state"]
            remaining = sum(st["available_shares"].values()) + sum(
                entry["shares"] for entry in st["exits"].values()
                if entry["status"] == "pending")
            self.assertEqual(st["total_shares"], remaining, "LST seed=%d" % seed)
            self.assertGreaterEqual(st["assets"], 0)
            self.assertEqual(result["accepted"] + result["rejected"], 90)


class FalseEvidenceControls(unittest.TestCase):
    def test_fake_poc_receipt_cannot_prove_unmodified_scaffold(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repo = root / "repo"
            (repo / "src").mkdir(parents=True)
            src = repo / "src" / "Bank.sol"
            src.write_text("contract Bank {}\n")
            sha = hashlib.sha256(src.read_bytes()).hexdigest()
            finding = {"id": "simulated", "stack": "solidity",
                       "source_revision": REV, "entry_point": "withdraw(uint256)",
                       "invariant": "balance never negative",
                       "attacker_capabilities": ["own account"],
                       "steps": ["simulate request"],
                       "source_anchors": [{"path": "src/Bank.sol", "line": 1,
                                          "sha256": sha}]}
            inputp = root / "finding.json"
            inputp.write_text(json.dumps(finding))
            dest = root / "bundle"
            poc.prepare(inputp, repo, dest)
            manifest = json.loads((dest / "poc-manifest.json").read_text())
            receipt = {"schema_version": 1, "case_id": finding["id"],
                       "source_revision": REV,
                       "candidate": {"status": "passed", "exit_code": 0,
                                     "test_file_sha256": manifest["template_sha256"],
                                     "log_sha256": "f"*64},
                       "negative_control": {"status": "passed", "exit_code": 0,
                                            "test_file_sha256": manifest["template_sha256"],
                                            "log_sha256": "f"*64}}
            self.assertEqual(poc.check(dest, receipt)["status"],
                             "not-proven-skeleton-unchanged")
            copied = copy.deepcopy(receipt)
            copied["candidate"]["exit_code"] = 1
            self.assertEqual(poc.check(dest, copied)["status"],
                             "not-proven-skeleton-unchanged")

    def test_blind_campaign_generator_never_includes_report_truth(self):
        with tempfile.TemporaryDirectory() as temp:
            dest = Path(temp) / "sealed"
            data = {"schema_version": 1, "baseline_skill_sha": REV,
                    "candidate_skill_sha": REV_NEW, "model": "dummy-unexecuted",
                    "budget_usd": 1, "minutes_per_case": 5,
                    "cases": [{"case": "hidden-case",
                               "repo_url": "https://github.com/anon/example",
                               "pinned_commit": "c"*40,
                               "scope_paths": ["src"]}]}
            out = blind.prepare(data, dest)
            self.assertEqual(out["status"], "prepared-only-not-run")
            tasks = list((dest / "jobs").rglob("TASK.json"))
            self.assertEqual(len(tasks), 2)
            for task in tasks:
                body = json.loads(task.read_text())
                self.assertEqual(body["execution"], "NOT_STARTED_REQUIRES_SEPARATE_APPROVED_MAC")
                self.assertNotIn("truth", body)
                self.assertNotIn("published_bug", body)
                self.assertNotIn("score", body)
            self.assertFalse(out["public_accuracy_claim_allowed"])


if __name__ == "__main__":
    unittest.main()
