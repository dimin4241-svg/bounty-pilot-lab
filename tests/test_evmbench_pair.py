"""Synthetic, offline EVMbench pairing checks. No model calls or Docker builds."""
import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "skills/bounty-pilot/scripts/evmbench_pair.py"
spec = importlib.util.spec_from_file_location("pilot_evmbench_pair", SCRIPT)
bp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bp)


def run_git(path, *args):
    return subprocess.check_output(["git", "-C", str(path), *args], text=True).strip()


class PreparedPairTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.repo = self.root / "pilot-source"
        self.upstream = self.root / "official-harness"
        self.result = self.root / "private-results"
        for path in (self.repo, self.upstream):
            path.mkdir()
            subprocess.run(["git", "init", "-q", str(path)], check=True)
            run_git(path, "config", "user.name", "Synthetic")
            run_git(path, "config", "user.email", "synthetic@example.invalid")
        skill = self.repo / "skills/bounty-pilot"
        (skill / "scripts").mkdir(parents=True)
        (skill / "references").mkdir()
        (skill / "SKILL.md").write_text("# Pilot generic research method\n", encoding="utf-8")
        (skill / "scripts/bounty.py").write_text("print('fixture')\n", encoding="utf-8")
        (skill / "scripts/caseforge.py").write_text("secret-answer-sentinel\n", encoding="utf-8")
        (skill / "references/caseforge-catalog.json").write_text(
            '{"secret": "answer-sentinel"}\n', encoding="utf-8")
        (skill / "references/research-engines.md").write_text(
            "published known bug details\n", encoding="utf-8")
        (skill / "references/generic.md").write_text(
            "No public answers in this document\n", encoding="utf-8")
        run_git(self.repo, "add", "-A")
        run_git(self.repo, "commit", "-qm", "baseline fixture")
        self.repo_sha = run_git(self.repo, "rev-parse", "HEAD")

        solver = self.upstream / bp.ENGINE
        solver.parent.mkdir(parents=True)
        solver.write_text(
            "import os\nfrom pathlib import Path\n"
            "async def fn(computer, instructions, agent, AGENT_DIR):\n"
            + bp.ANCHOR + "\n", encoding="utf-8")
        split = self.upstream / bp.SPLIT
        split.parent.mkdir(parents=True)
        split.write_text("2024-07-basin\n2024-06-size\n", encoding="utf-8")
        run_git(self.upstream, "add", "-A")
        run_git(self.upstream, "commit", "-qm", "upstream fixture")
        self.up_sha = run_git(self.upstream, "rev-parse", "HEAD")
        for key, value in (("BASELINE", self.repo_sha),
                           ("CANDIDATE", self.repo_sha), ("OFFICIAL", self.up_sha)):
            patcher = mock.patch.object(bp, key, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_preparation_stages_both_arms_without_gold(self):
        manifest = bp.prepare(self.repo, self.upstream, self.result,
                              ["2024-07-basin", "2024-06-size"])
        self.assertEqual(manifest["model_runs"], 0)
        self.assertEqual(manifest["kind"], "PREPARED_NOT_EXECUTED")
        self.assertFalse(manifest["cost_cap_enforced_by_harness"])
        for arm in bp.ARM_IDS:
            staged = self.result / "skills" / arm
            self.assertTrue((staged / "SKILL.md").is_file())
            self.assertTrue((staged / "references/generic.md").is_file())
            self.assertFalse((staged / "references/caseforge-catalog.json").exists())
            self.assertFalse((staged / "scripts/caseforge.py").exists())
            self.assertFalse((staged / "references/research-engines.md").exists())
            self.assertEqual(bp._staged_integrity(staged),
                             manifest["stages"][arm]["staged_tree_sha256"])
        patched = (self.upstream / bp.ENGINE).read_text()
        self.assertIn("PILOT_BENCH_SKILL_DIR", patched)
        self.assertIn("put_dir_in_computer", patched)
        compile(patched, "solver_fixture.py", "exec")

    def test_preparation_rejects_wrong_upstream_commit(self):
        with self.assertRaisesRegex(ValueError, "pinned"):
            with mock.patch.object(bp, "OFFICIAL", "0" * 40):
                bp.prepare(self.repo, self.upstream, self.result, ["2024-07-basin"])
        self.assertFalse(self.result.exists())

    def test_rejects_unknown_duplicate_and_empty_audit_lists(self):
        for audits in ([], ["2029-02-made-up"],
                       ["2024-07-basin", "2024-07-basin"]):
            with self.subTest(audits=audits):
                with self.assertRaises(ValueError):
                    bp.prepare(self.repo, self.upstream, self.result, audits)
                self.assertFalse(self.result.exists())

    def test_prepare_never_reuses_modified_or_existing_checkout(self):
        bp.prepare(self.repo, self.upstream, self.result, ["2024-07-basin"])
        with self.assertRaisesRegex(ValueError, "new private"):
            bp.prepare(self.repo, self.upstream, self.result, ["2024-07-basin"])
        with self.assertRaisesRegex(ValueError, "clean"):
            bp.prepare(self.repo, self.upstream, self.root / "other", ["2024-07-basin"])

    def test_refuses_to_run_without_explicit_paid_authorization_or_secret(self):
        bp.prepare(self.repo, self.upstream, self.result, ["2024-07-basin"])
        manifest = self.result / "manifest.json"
        with self.assertRaisesRegex(ValueError, "authorize-provider-spend"):
            bp.run(manifest, "codex-default", 300, False)
        with mock.patch.dict(os.environ, {"OPENAI_API_KEY": ""}):
            with self.assertRaisesRegex(ValueError, "OPENAI_API_KEY"):
                bp.run(manifest, "codex-default", 300, True)
        self.assertFalse((self.result / "STARTED").exists())

    def test_staged_skill_changes_are_detected(self):
        bp.prepare(self.repo, self.upstream, self.result, ["2024-07-basin"])
        staged = self.result / "skills" / "candidate"
        before = bp._staged_integrity(staged)
        (staged / "SKILL.md").write_text("tampered\n")
        self.assertNotEqual(bp._staged_integrity(staged), before)


if __name__ == "__main__":
    unittest.main()
