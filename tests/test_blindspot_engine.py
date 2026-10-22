import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from contextlib import nullcontext

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills/bounty-pilot/scripts"


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


engine = load("lab_blindspot_engine", "blindspot_engine.py")


def git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args], check=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def commit(repo, message="fixture"):
    git(repo, "add", "-A")
    git(repo, "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
        "-c", "commit.gpgsign=false", "commit", "-qm", message)


class BlindSpotEngineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()

    def test_lcov_reports_uncovered_branch_outcomes_only(self):
        path = self.base / "coverage.info"
        path.write_text("TN:\nSF:src/Vault.sol\nBRDA:41,0,0,1\nBRDA:41,0,1,0\nBRDA:42,0,0,-\nend_of_record\n")
        report = engine.parse_lcov(path)
        self.assertEqual(report["branch_outcomes_total"], 3)
        self.assertEqual(report["branch_outcomes_observed"], 1)
        self.assertEqual([(row["line"], row["branch"]) for row in report["uncovered"]],
                         [(41, "1"), (42, "0")])

    def test_mutation_survivors_are_review_leads_not_vulnerabilities(self):
        report = engine.summarize_mutations({"mutants": [
            {"id": "m1", "status": "survived", "path": "src/Vault.sol", "line": 8},
            {"id": "m2", "status": "killed"}]})
        self.assertEqual(report["counts"], {"survived": 1, "killed": 1})
        self.assertEqual(report["survivors_and_unresolved"][0]["id"], "m1")
        self.assertIn("do not establish", report["notice"])

    def test_live_config_missing_rpc_values_remain_unverified(self):
        report = engine.live_config_diff({"expected": {"owner": "0x01", "paused": False},
                                          "instances": [{"id": "chain-a", "values": {"owner": "0x01"}},
                                                        {"id": "chain-b", "values": {"owner": "0x02", "paused": False}}]})
        self.assertEqual(report["unverified"][0]["state"], "LIVE_STATE_UNVERIFIED")
        self.assertEqual(report["differences"][0]["key"], "owner")
        self.assertEqual(report["open_tasks"], [{"instance": "chain-a", "key": "paused",
                                                 "state": "LIVE_STATE_UNVERIFIED"}])

    def test_live_rpc_queries_only_read_methods_and_never_records_endpoint(self):
        responses = ["0x1", "0x10", "0x" + "0" * 24 + "11" * 20, "0x" + "0" * 63 + "1"]
        methods = []

        class Response:
            def __init__(self, body):
                self.body = body
            def read(self):
                return json.dumps({"jsonrpc": "2.0", "id": 1, "result": self.body}).encode()

        def opener(request, timeout):
            payload = json.loads(request.data)
            methods.append(payload["method"])
            return nullcontext(Response(responses.pop(0)))

        snapshot = {"expected": {"owner": "0x" + "11" * 20, "paused": True},
                    "instances": [{"id": "mainnet", "expected_chain_id": 1,
                                   "rpc_env": "RPC_MAINNET", "block": "latest",
                                   "calls": [{"key": "owner", "to": "0x" + "22" * 20,
                                              "data": "0x8da5cb5b", "decoder": "address"},
                                             {"key": "paused", "to": "0x" + "22" * 20,
                                              "data": "0x5c975abb", "decoder": "bool"}]}]}
        queried = engine.query_live_config(snapshot, env={"RPC_MAINNET": "https://secret.example/key"},
                                           opener=opener)
        report = engine.live_config_diff(queried)
        self.assertEqual(methods, ["eth_chainId", "eth_blockNumber", "eth_call", "eth_call"])
        self.assertEqual(queried["instances"][0]["block"], 16)
        self.assertEqual(report["differences"], [])
        self.assertNotIn("secret.example", json.dumps(report))
        self.assertEqual(queried["instances"][0]["read_status"], "read-complete")

    def test_live_rpc_without_environment_keeps_live_state_unverified(self):
        snapshot = {"expected": {"owner": "0x" + "00" * 20},
                    "instances": [{"id": "mainnet", "rpc_env": "RPC_MAINNET",
                                   "calls": [{"key": "owner", "to": "0x" + "22" * 20,
                                              "data": "0x8da5cb5b", "decoder": "address"}]}]}
        queried = engine.query_live_config(snapshot, env={})
        report = engine.live_config_diff(queried)
        self.assertEqual(queried["instances"][0]["read_status"], "LIVE_STATE_UNVERIFIED")
        self.assertTrue(report["open_tasks"])

    def test_capacity_cliff_uses_first_load_failure_and_checks_recovery_separately(self):
        report = engine.capacity_review({"metric": "gas", "samples": [
            {"load": 1, "gas": 50, "outcome": "ok"},
            {"load": 2, "gas": 101, "outcome": "reverted", "recovery": "unknown"},
            {"load": 3, "gas": 110, "outcome": "blocked", "recovery": "failed"}]}, budget=100)
        self.assertEqual(report["first_observed_cliff"]["load"], 2)
        self.assertEqual(report["self_recovery"], "failed")

    def test_trust_inventory_keeps_unavailable_dependency_source_visible(self):
        report = engine.trust_boundary_review({
            "components": [{"id": "frontend", "kind": "app"},
                           {"id": "validator", "kind": "external-dependency", "source_status": "unavailable"}],
            "flows": [{"source": "frontend", "destination": "validator",
                       "checks": {"parameter_origin": "user input"}}]})
        self.assertEqual(report["unavailable_dependency_sources"], ["validator"])
        self.assertIn("validation", report["unverified_flows"][0]["missing"])

    def test_legacy_risk_uses_age_as_context_and_other_signals_for_score(self):
        repo = self.base / "repo"
        (repo / "src").mkdir(parents=True)
        (repo / "test").mkdir()
        git(repo, "init", "-q")
        (repo / "src/Vault.sol").write_text("contract Vault {\n function withdraw() external onlyOwner { token.transfer(msg.sender, amount); }\n}\n")
        (repo / "test/Vault.t.sol").write_text("function testOther() public { withdraw(); }\n")
        commit(repo)
        old = 1_500_000_000
        with mock.patch.object(engine, "_git_history", return_value={"src/Vault.sol": old,
                                                                       "test/Vault.t.sol": old}):
            report = engine.legacy_inventory(repo)
        row = next(item for item in report["candidates"] if item["symbol"] == "withdraw")
        self.assertGreaterEqual(row["score_components"]["authority"], 7)
        self.assertGreaterEqual(row["score_components"]["asset_operations"], 5)
        self.assertTrue(row["test_symbol_reference_found"])
        self.assertGreater(row["age_days_context_only"], 1000)

    def test_state_invalidation_requires_a_lexical_state_write_read_edge(self):
        repo = self.base / "repo"
        (repo / "src").mkdir(parents=True)
        git(repo, "init", "-q")
        (repo / "src/Authority.sol").write_text(
            "contract Authority {\n"
            "address public owner;\n"
            "function transferOwnership(address next) external { owner = next; }\n"
            "function execute() external { require(msg.sender == owner); }\n"
            "}\n")
        commit(repo)
        report = engine.state_invalidation(repo)
        candidates = [row for row in report["candidates"]
                      if row["scenario"] == "transfer-then-old-authority"]
        self.assertTrue(candidates)
        self.assertEqual(candidates[0]["confidence"], "low-lexical-link")
        self.assertIn("confirm actual state identity and call graph", candidates[0]["required_next_evidence"])

    def test_patch_propagation_suggests_same_name_sibling(self):
        repo = self.base / "repo"
        (repo / "src").mkdir(parents=True)
        git(repo, "init", "-q")
        (repo / "src/A.sol").write_text("contract A { function withdraw() external { require(msg.sender == owner); } }\n")
        (repo / "src/B.sol").write_text("contract B { function withdraw() external { token.transfer(msg.sender, amount); } }\n")
        commit(repo, "initial")
        (repo / "src/A.sol").write_text("contract A { function withdraw() external onlyOwner { require(msg.sender == owner); } }\n")
        commit(repo, "fix authorization")
        head = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
        report = engine.patch_propagation(repo, head)
        self.assertEqual(report["changed_paths"], ["src/A.sol"])
        self.assertTrue(any(row["path"] == "src/B.sol" and row["symbol"] == "withdraw"
                            for row in report["candidate_paths"]))

    def test_reopen_only_queues_new_source_evidence_and_never_changes_status(self):
        repo = self.base / "repo"
        (repo / "src").mkdir(parents=True)
        git(repo, "init", "-q")
        file = repo / "src/Vault.sol"
        file.write_text("contract Vault { function withdraw() external {} }\n")
        commit(repo, "initial")
        old = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
        file.write_text("contract Vault { function withdraw() external onlyOwner {} }\n")
        commit(repo, "new guard")
        report = engine.reopen_review(repo, [{"id": "BP-001", "status": "refuted",
                                              "revision": old, "affected_paths": ["src/Vault.sol"]},
                                             {"id": "BP-002", "status": "parked",
                                              "revision": old, "affected_paths": ["docs/other.md"]}])
        states = {row["finding_id"]: row["state"] for row in report["findings"]}
        self.assertEqual(states["BP-001"], "reopen-review-required-new-evidence")
        self.assertEqual(states["BP-002"], "remains-closed-no-new-evidence")


if __name__ == "__main__":
    unittest.main()
