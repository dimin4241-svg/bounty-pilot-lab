"""Opus5 audit launcher: offline tests, no keys, no Anthropic API calls."""
import importlib.util
import json
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "opus_charon_mock", ROOT / "skills/bounty-pilot/scripts/opus5_charon_audit.py")
opus = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(opus)


class SecureOpusRunnerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.repo = Path(self.tmp.name) / "charon"
        self.repo.mkdir()
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        subprocess.run(["git", "-C", str(self.repo), "config", "user.name",
                        "Fixture"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "config", "user.email",
                        "fixture@example.invalid"], check=True)
        for _, paths in opus.PLAN:
            for name in paths:
                f = self.repo / name
                f.parent.mkdir(parents=True, exist_ok=True)
                f.write_text('package test\nfunc sample() { /* local proof */ }\n',
                             encoding="utf-8")
        subprocess.run(["git", "-C", str(self.repo), "add", "."], check=True)
        subprocess.run(["git", "-C", str(self.repo), "commit", "-qm", "fixture"], check=True)
        self.sha = opus.git(self.repo, "rev-parse", "HEAD")
        self.pin = mock.patch.object(opus, "PIN", self.sha)
        self.pin.start()
        self.addCleanup(self.pin.stop)

    def test_model_is_exact_opus_5_not_sonnet(self):
        self.assertEqual(opus.MODEL, "claude-opus-5")
        self.assertEqual(opus.TARGET, "https://github.com/ObolNetwork/charon")

    def test_safely_validates_clean_pinned_checkout(self):
        self.assertEqual(opus.verify_target(self.repo), self.repo)

    def test_fails_on_wrong_git_revision(self):
        with mock.patch.object(opus, "PIN", "a"*40):
            with self.assertRaisesRegex(ValueError, "HEAD mismatch"):
                opus.verify_target(self.repo)

    def test_fails_on_untracked_source(self):
        (self.repo / "test-leak.tmp").write_text("a")
        with self.assertRaisesRegex(ValueError, "clean"):
            opus.verify_target(self.repo)

    def test_dry_run_never_calls_provider_or_reads_key(self):
        out = Path(self.tmp.name) / "private"
        with mock.patch.dict(os.environ, {}, clear=True):
            res = opus.run(self.repo, out, passes=2, dry_run=True,
                           requester=lambda *a: self.fail("unexpected API call"))
        self.assertEqual(res["status"], "DRY_RUN")
        self.assertEqual(res["confirmed_findings"], 0)
        self.assertEqual(len(res["source"]), 2)
        self.assertFalse(out.exists())

    def test_request_spends_budget_and_writes_private_results(self):
        output = Path(self.tmp.name) / "evidence"
        calls = []
        def fake(key, question):
            calls.append((key, question))
            return {"text": "HYPOTHESIS ONLY, source line needs proof",
                    "usage": {"input_tokens": 330, "output_tokens": 230,
                              "estimated_usd": 0.01}, "stop_reason": "end_turn"}
        with mock.patch.dict(os.environ, {"ANTHROPIC_API_KEY": "mock-key-not-real-"+"q"*30}):
            res = opus.run(self.repo, output, passes=2,
                           max_usd=2.0, requester=fake)
        self.assertEqual(res["passes_completed"], 2)
        self.assertEqual(len(calls), 2)
        self.assertEqual(res["estimated_usd_spent"], 0.02)
        self.assertEqual(res["confirmed_findings"], 0)
        self.assertTrue((output / "manifest.json").exists())
        report = json.loads((output / "partial-exit-and-auth.json").read_text())
        self.assertEqual(report["classification"], "UNVERIFIED_MODEL_HYPOTHESES")
        self.assertNotIn("mock-key-not-real", (output / "manifest.json").read_text())
        self.assertNotIn("mock-key-not-real", (output / "partial-exit-and-auth.json").read_text())
        self.assertIn("file:line", calls[0][1])
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE((output / "manifest.json").stat().st_mode), 0o600)

    def test_without_key_provider_is_not_called(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(ValueError, "NEW ANTHROPIC_API_KEY"):
                opus.run(self.repo, Path(self.tmp.name) / "result", passes=1,
                         max_usd=2.0, requester=lambda *a: self.fail("called"))

    def test_budget_blocks_api_request_before_creating_output(self):
        out = Path(self.tmp.name) / "result"
        with mock.patch.dict(os.environ, {"ANTHROPIC_API_KEY": "mock-key-"+"q"*40}):
            with mock.patch.object(opus, "upper_bound_usd", return_value=4.0):
                with self.assertRaisesRegex(ValueError, "budget"):
                    opus.run(self.repo, out, passes=1,
                             max_usd=1.0, requester=lambda *a: self.fail("called"))
        self.assertFalse(out.exists())

    def test_no_overwrite_of_previous_results(self):
        out = Path(self.tmp.name) / "result"
        out.mkdir()
        with self.assertRaisesRegex(ValueError, "refusing overwrite"):
            opus.run(self.repo, out, dry_run=True)

    def test_no_output_in_source_checkout(self):
        with self.assertRaisesRegex(ValueError, "outside source"):
            opus.run(self.repo, self.repo / "private-output", dry_run=True)

    def test_symlinked_source_fails(self):
        name = opus.PLAN[0][1][0]
        f = self.repo / name
        target = self.repo / "app/obolapi/real.go"
        target.write_text(f.read_text())
        f.unlink()
        f.symlink_to(target)
        with self.assertRaisesRegex(ValueError, "symlink"):
            opus._source(self.repo, [name])

    def test_budget_source_file_limit(self):
        name = opus.PLAN[0][1][0]
        f = self.repo / name
        f.write_text("x" * (opus.MAX_FILE_BYTES + 1))
        with self.assertRaisesRegex(ValueError, "per-file budget"):
            opus._source(self.repo, [name])

    def test_request_error_does_not_echo_provider_secret(self):
        with mock.patch.object(opus.urllib.request, "urlopen",
                               side_effect=opus.urllib.error.HTTPError(
                                   opus.API_URL, 401, "dummy", {}, None)):
            with self.assertRaisesRegex(ValueError, "HTTP 401") as ctx:
                opus.request_opus("secret-key-not-to-echo", "test")
        self.assertNotIn("secret-key-not-to-echo", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
