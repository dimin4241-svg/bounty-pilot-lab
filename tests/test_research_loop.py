"""Research loop uses pinned, repeated paired native evidence and fails closed."""
import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

FILE = Path(__file__).resolve().parents[1] / "skills/bounty-pilot/scripts/research_loop.py"
spec = importlib.util.spec_from_file_location("research_loop", FILE)
loop = importlib.util.module_from_spec(spec)
spec.loader.exec_module(loop)


class ResearchLoopTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        (self.repo / "README.txt").write_text("demo", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.repo), "add", "README.txt"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "-c", "user.name=fixture",
                        "-c", "user.email=fixture@example.invalid", "commit", "-qm", "base"], check=True)
        revision, _ = loop.runner._checkout_identity(self.repo)
        self.manifest = {
            "schema_version": 1, "source_revision": revision, "variants": [{
                "id": "one", "family": "identity", "priority": 2,
                "cases": [
                    {"id": "c", "pair_id": "p", "role": "candidate",
                     "argv": ["python3", "-m", "unittest", "tests.test_a"]},
                    {"id": "n", "pair_id": "p", "role": "negative-control",
                     "argv": ["python3", "-m", "unittest", "tests.test_b"]},
                ],
            }]
        }

    def fake_native(self, plan, root, allow_exec=False, allow_dotenv=False):
        return {"source_revision": self.manifest["source_revision"], "cases": [
            {"role": role, "executed": True, "status": "ran",
             "matched_expected_exit": True,
             "stdout": "BP_LAB_OBSERVATION=" + json.dumps({
                 "variant": "one", "role": role, "property_id": "account-isolation",
                 "violated": role == "candidate", "victim_loss": "1.5",
                 "attacker_delta": "0.5", "state_digest": "a" * 64,
                 "initial_state_digest": "b" * 64})}
            for role in ("candidate", "negative-control")]}

    def test_dry_run_never_counts_witness(self):
        output = loop.run(self.manifest, self.repo)
        self.assertEqual(output["execution"], "dry-run")
        self.assertEqual(output["witness_count"], 0)
        self.assertEqual(output["experiments"][0]["status"], "not-executed")

    def test_live_execution_requires_external_isolation_attestation(self):
        with self.assertRaisesRegex(ValueError, "isolation"):
            loop.run(self.manifest, self.repo, execute=True)
        with patch.object(loop.runner, "execute", side_effect=self.fake_native) as action:
            output = loop.run(self.manifest, self.repo, execute=True,
                              isolation_attested=True, no_network_attested=True)
        self.assertEqual(action.call_count, 2)
        self.assertEqual(output["witness_count"], 1)
        self.assertEqual(len(output["experiments"][0]["observations"]), 2)

    def test_no_observation_is_not_evidence(self):
        def no_marker(plan, root, allow_exec=False, allow_dotenv=False):
            result = self.fake_native(plan, root, allow_exec, allow_dotenv)
            for case in result["cases"]:
                case["stdout"] = "Ran 1 test"
            return result
        with patch.object(loop.runner, "execute", side_effect=no_marker):
            output = loop.run(self.manifest, self.repo, execute=True,
                              isolation_attested=True, no_network_attested=True)
        self.assertEqual(output["witness_count"], 0)
        self.assertTrue(output["experiments"][0]["errors"])

    def test_unpinned_revision_and_forged_negative_control_rejected(self):
        self.manifest["source_revision"] = "0" * 40
        with self.assertRaisesRegex(ValueError, "HEAD"):
            loop.run(self.manifest, self.repo)
        self.manifest["source_revision"], _ = loop.runner._checkout_identity(self.repo)
        forged = self.fake_native(None, None)
        forged["cases"][1]["stdout"] = forged["cases"][0]["stdout"]
        with patch.object(loop.runner, "execute", return_value=forged):
            result = loop.run(self.manifest, self.repo, execute=True,
                              isolation_attested=True, no_network_attested=True)
        self.assertEqual(result["witness_count"], 0)


if __name__ == "__main__":
    unittest.main()
