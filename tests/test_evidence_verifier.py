import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills/bounty-pilot/scripts"


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


verifier = load("lab_evidence_verifier", "evidence_verifier.py")
bounty = load("lab_ev_bounty", "bounty.py")


def git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args], check=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def commit(repo):
    git(repo, "add", "-A")
    git(repo, "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
        "-c", "commit.gpgsign=false", "commit", "-qm", "fixture")


class EvidenceVerifierTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()

    def test_source_anchor_requires_exact_nearby_quote(self):
        repo = self.base / "repo"
        (repo / "src").mkdir(parents=True)
        file = repo / "src/Vault.sol"
        file.write_text("contract Vault {\n    function withdraw() external {\n        balances[msg.sender] -= amount;\n    }\n}\n")
        valid, _ = verifier._target_anchor(repo, {"path": "src/Vault.sol", "line": 3,
                                                  "quote": "balances[msg.sender] -= amount;"})
        invalid, reason = verifier._target_anchor(repo, {"path": "src/Vault.sol", "line": 3,
                                                          "quote": "require(false);"})
        self.assertTrue(valid)
        self.assertFalse(invalid)
        self.assertIn("not present", reason)

    def test_machine_result_keeps_three_stages_separate_and_does_not_promote(self):
        repo = self.base / "repo"
        (repo / "src").mkdir(parents=True)
        (repo / "test").mkdir()
        git(repo, "init", "-q")
        source = "contract Vault {\n    function withdraw() external {\n        balances[msg.sender] -= amount;\n    }\n}\n"
        (repo / "src/Vault.sol").write_text(source)
        (repo / "test/Vault.t.sol").write_text("contract VaultTest {}\n")
        commit(repo)
        revision = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
        run = self.base / "run"
        bounty.initialize(repo, run, strict_evidence_review=True)
        rows = [{"id": "BP-001", "status": "hypothesis", "revision": revision,
                 "affected_paths": ["src/Vault.sol"], "evidence": {"assertion": "balances conserve"}}]
        (run / "findings.json").write_text(json.dumps(rows))
        (run / "candidate.sol").write_text("assert(balancesAfter < balancesBefore);\n")
        (run / "control.sol").write_text("assert(balancesAfter == balancesBefore);\n")
        review = self.base / "independent-review.json"
        review.write_text(json.dumps({
            "schema": 1, "producer_id": "agent-a", "reviewer_id": "reviewer-b", "independent": True,
            "source_review": {"decision": "confirmed", "anchors": [
                {"path": "src/Vault.sol", "line": 3, "quote": "balances[msg.sender] -= amount;"}]},
            "reachability": {"decision": "confirmed", "anchors": [
                {"path": "src/Vault.sol", "line": 2, "quote": "function withdraw() external {"}]},
            "ordered_steps": ["attacker calls withdraw", "balance decreases incorrectly"],
            "assertions": {"candidate": {"poc_path": "candidate.sol", "quote": "assert(balancesAfter < balancesBefore);",
                                           "property": "balances conserve"},
                           "negative-control": {"poc_path": "control.sol", "quote": "assert(balancesAfter == balancesBefore);",
                                                "property": "balances conserve", "expected": "protected state conserves"}},
            "impact": {"decision": "confirmed", "kind": "economic", "victim_loss": 1,
                       "attacker_cost": 0, "unit": "token", "artifact_path": "candidate.sol",
                       "quote": "assert(balancesAfter < balancesBefore);"},
            "scope": {"decision": "in-scope"},
            "scope_anchor": {"path": "src/Vault.sol", "line": 2, "quote": "function withdraw() external {"},
            "deployment": {"decision": "matched", "artifact_path": "candidate.sol",
                           "quote": "assert(balancesAfter < balancesBefore);"}}))
        result = verifier.verify(run, "BP-001", review)
        self.assertEqual(result["status"]["SOURCE_CONFIRMED"], "passed")
        self.assertEqual(result["status"]["POC_REPRODUCED"], "not-confirmed")
        self.assertEqual(result["status"]["IMPACT_VERIFIED"], "not-confirmed")
        self.assertFalse(result["can_mark_verified"])
        self.assertEqual(rows[0]["status"], "hypothesis")
        structural_errors = []
        bounty._check_verified_evidence({"id": "BP-001", "revision": revision, "evidence": {}},
                                        "finding", run, structural_errors)
        self.assertTrue(any("strict evidence review requires" in error for error in structural_errors))


if __name__ == "__main__":
    unittest.main()
