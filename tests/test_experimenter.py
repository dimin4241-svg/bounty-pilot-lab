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


experimenter = load("lab_experimenter", "experimenter.py")
bounty = load("lab_experimenter_bounty", "bounty.py")


def git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args], check=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def commit(repo):
    git(repo, "add", "-A")
    git(repo, "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
        "-c", "commit.gpgsign=false", "commit", "-qm", "fixture")


class ExperimenterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()

    def test_draft_creates_deliberately_incomplete_poc_and_brief(self):
        repo = self.base / "repo"
        (repo / "src").mkdir(parents=True)
        git(repo, "init", "-q")
        (repo / "src/Vault.sol").write_text("contract Vault { function withdraw() external {} }\n")
        commit(repo)
        revision = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
        run = self.base / "run"
        bounty.initialize(repo, run)
        finding = {"id": "BP-001", "status": "hypothesis", "revision": revision,
                   "affected_paths": ["src/Vault.sol"], "attacker_capabilities": "unprivileged user",
                   "preconditions": "vault has balance", "impact": "balance loss",
                   "next_experiment": {"question": "does withdraw alter other balance?",
                                       "method": "two actors and native test",
                                       "expected_evidence": "measured balance delta"},
                   "steps": ["deposit as victim", "withdraw as attacker"], "evidence": {"assertion": "balance conservation"}}
        (run / "findings.json").write_text(json.dumps([finding]))
        out = self.base / "experiments"
        report = experimenter.draft(run, "BP-001", "solidity", out)
        self.assertEqual(report["status"], "draft-incomplete-not-executed")
        source = Path(report["test_skeleton"]).read_text()
        self.assertIn('revert("fill in:', source)
        self.assertIn('"status": "incomplete-test-skeleton"', Path(report["metadata"]).read_text())
        self.assertEqual(json.loads(Path(report["brief"]).read_text())["status"], "draft-incomplete-not-executed")

    def test_differential_plan_requires_documented_equivalence_basis(self):
        spec = {"finding_id": "BP-001", "source_revision": "a" * 40,
                "invariant": "equal output after allowed fee", "kind": "differential",
                "cases": [{"id": "batch-vs-single", "candidate": "testBatch", "control": "testSingle"}]}
        with self.assertRaisesRegex(ValueError, "equivalence_basis"):
            experimenter.plan(spec, "foundry")
        spec["equivalence_basis"] = "docs/accounting.md: batching preserves net shares"
        result = experimenter.plan(spec, "foundry")
        self.assertEqual(result["generation_status"], "commands-not-run")
        self.assertEqual(len(result["cases"]), 2)


if __name__ == "__main__":
    unittest.main()
