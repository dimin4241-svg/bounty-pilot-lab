"""Opus5 audit launcher: offline tests, no keys, no Anthropic API calls."""
import importlib.util
import io
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
        self.assertEqual(res["readings_saved"], 2)
        reading = output / "readings" / "partial-exit-and-auth.md"
        self.assertTrue(reading.is_file())
        self.assertIn("HYPOTHESIS ONLY", reading.read_text())
        self.assertIn("LEAD blocks", calls[0][1])
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

    def test_http400_shows_safe_provider_reason_and_request_id(self):
        response = json.dumps({
            "type": "error",
            "error": {"type": "invalid_request_error",
                      "message": "You have reached your specified API usage limits"},
            "request_id": "req_0123456789"
        }).encode()
        err = opus.urllib.error.HTTPError(opus.API_URL, 400, "Bad request",
                                           {}, io.BytesIO(response))
        with mock.patch.object(opus.urllib.request, "urlopen", side_effect=err):
            with self.assertRaisesRegex(ValueError, "usage limits") as ctx:
                opus.request_opus("secret-key-not-to-echo", "test")
        self.assertIn("invalid_request_error", str(ctx.exception))
        self.assertIn("req_0123456789", str(ctx.exception))
        self.assertNotIn("secret-key-not-to-echo", str(ctx.exception))

    def test_error_body_redacts_keys_and_control_chars(self):
        secret = "sk-ant-api03-ABCD1234SECRET_DO_NOT_LOG"
        response = json.dumps({
            "error": {"type": "invalid_request_error",
                      "message": "Invalid header " + secret +
                                 "\\nBearer abc123secret\\r broken"}
        }).encode()
        err = opus.urllib.error.HTTPError(opus.API_URL, 400, "Bad request",
                                           {}, io.BytesIO(response))
        text = str(opus._http_error(err, secret))
        self.assertNotIn(secret, text)
        self.assertNotIn("abc123secret", text)
        self.assertNotIn("\\n", text)
        self.assertNotIn("\\r", text)
        self.assertIn("[REDACTED", text)

    def test_provider_payload_overlimit_is_ignored(self):
        data = b"x" * 9000
        err = opus.urllib.error.HTTPError(opus.API_URL, 400, "Bad request",
                                           {}, io.BytesIO(data))
        text = str(opus._http_error(err, "secret-not-for-logs"))
        self.assertIn("HTTP 400", text)
        self.assertLess(len(text), 500)

    def test_check_model_uses_read_only_model_metadata(self):
        response = io.BytesIO(json.dumps({
            "id": opus.MODEL, "type": "model"
        }).encode())
        with mock.patch.object(opus.urllib.request, "urlopen",
                               return_value=response) as run:
            result = opus.check_model("new-key-" + "x"*30)
        self.assertEqual(result["status"], "MODEL_AVAILABLE")
        request = run.call_args[0][0]
        self.assertEqual(request.get_method(), "GET")
        self.assertTrue(request.full_url.endswith("/v1/models/" + opus.MODEL))

    def test_messages_request_medium_effort_leaves_room_for_text(self):
        response = io.BytesIO(json.dumps({
            "model": opus.MODEL,
            "content": [{"type": "text", "text": "Only tentative analysis"}],
            "usage": {"input_tokens": 520, "output_tokens": 310},
            "stop_reason": "end_turn"
        }).encode())
        with mock.patch.object(opus.urllib.request, "urlopen", return_value=response) as call:
            reply = opus.request_opus("safe-local-fixture-" + "k"*40, "test")
        sent = json.loads(call.call_args[0][0].data)
        self.assertEqual(sent["output_config"]["effort"], "medium")
        self.assertEqual(sent["max_tokens"], 8192)
        self.assertEqual(reply["text"], "Only tentative analysis")

    def test_thinking_only_success_counts_tokens_and_hides_thinking(self):
        # Simulate paid 200 response with only private reasoning, no final text.
        response = io.BytesIO(json.dumps({
            "model": opus.MODEL,
            "content": [{"type": "thinking",
                         "thinking": "CONFIDENTIAL INTERNAL THINKING MUST NOT BE SAVED",
                         "signature": "opaque-signature"}],
            "usage": {"input_tokens": 310, "output_tokens": 8192},
            "stop_reason": "max_tokens"
        }).encode())
        with mock.patch.object(opus.urllib.request, "urlopen", return_value=response):
            reply = opus.request_opus("safe-local-fixture-" + "k"*40, "test")
        self.assertEqual(reply["text"], "")
        self.assertEqual(reply["content_types"], ["thinking"])
        self.assertEqual(reply["stop_reason"], "max_tokens")
        self.assertEqual(reply["usage"]["output_tokens"], 8192)
        self.assertGreater(reply["usage"]["estimated_usd"], 0)
        self.assertNotIn("INTERNAL THINKING", json.dumps(reply))
        self.assertNotIn("opaque-signature", json.dumps(reply))

    def test_source_trial_records_cost_of_no_text_response(self):
        out = Path(self.tmp.name) / "no-text-evidence"
        def fake(key, question):
            return {"text": "", "content_types": ["thinking"],
                    "stop_reason": "max_tokens",
                    "usage": {"input_tokens": 350, "output_tokens": 8192,
                              "estimated_usd": 0.20655}}
        with mock.patch.dict(os.environ, {"ANTHROPIC_API_KEY": "local-mock-" + "x"*30}):
            result = opus.run(self.repo, out, passes=2,
                              max_usd=2.0, requester=fake)
        self.assertEqual(result["status"], "PARTIAL_NO_TEXT_RESPONSE")
        self.assertEqual(result["passes_completed"], 0)
        self.assertEqual(result["api_responses_received"], 1)
        self.assertEqual(result["estimated_usd_spent"], 0.20655)
        content = (out / "partial-exit-and-auth.json").read_text()
        self.assertIn("NO_TEXT_NO_FINDING", content)
        self.assertNotIn("hypotheses_markdown", content)
        self.assertIn("thinking", content)
        self.assertFalse((out / "beacon-cross-client-boundary.json").exists())
        self.assertIn("0.20655", (out / "manifest.json").read_text())

    def test_incomplete_text_is_not_marked_as_completed_pass(self):
        out = Path(self.tmp.name) / "incomplete-evidence"
        def fake(key, question):
            return {"text": "unfinished draft", "content_types": ["text"],
                    "stop_reason": "max_tokens",
                    "usage": {"input_tokens": 350, "output_tokens": 8192,
                              "estimated_usd": 0.20655}}
        with mock.patch.dict(os.environ, {"ANTHROPIC_API_KEY": "local-mock-" + "x"*30}):
            result = opus.run(self.repo, out, passes=2,
                              max_usd=2.0, requester=fake)
        self.assertEqual(result["status"], "PARTIAL_INCOMPLETE_RESPONSE")
        self.assertEqual(result["passes_completed"], 0)
        report = json.loads((out / "partial-exit-and-auth.json").read_text())
        self.assertEqual(report["classification"], "UNVERIFIED_INCOMPLETE_RESPONSE")
        self.assertEqual(report["stop_reason"], "max_tokens")

    def test_workspace_unscoped_key_injects_header_for_model_lookup(self):
        workspace = "wrkspc_01JwQvzr7rXLA5AGx3HKfFUJ"
        response = io.BytesIO(json.dumps({"id": opus.MODEL}).encode())
        with mock.patch.dict(os.environ, {"ANTHROPIC_WORKSPACE_ID": workspace}):
            with mock.patch.object(opus.urllib.request, "urlopen", return_value=response) as call:
                result = opus.check_model("local-rotated-key-" + "x"*30)
        req = call.call_args[0][0]
        headers = dict((k.lower(), v) for k, v in req.header_items())
        self.assertEqual(req.get_method(), "GET")
        self.assertEqual(headers.get("anthropic-workspace-id"), workspace)
        self.assertEqual(result["status"], "MODEL_AVAILABLE")
        self.assertNotIn(workspace, json.dumps(result))

    def test_workspace_header_applies_to_paid_messages_request(self):
        workspace = "wrkspc_01JwQvzr7rXLA5AGx3HKfFUJ"
        response = io.BytesIO(json.dumps({
            "model": opus.MODEL,
            "content": [{"type": "text", "text": "No supported hypothesis"}],
            "usage": {"input_tokens": 100, "output_tokens": 25},
            "stop_reason": "end_turn"
        }).encode())
        with mock.patch.dict(os.environ, {"ANTHROPIC_WORKSPACE_ID": workspace}):
            with mock.patch.object(opus.urllib.request, "urlopen", return_value=response) as call:
                result = opus.request_opus("local-rotated-key-" + "x"*30, "audit test")
        req = call.call_args[0][0]
        headers = dict((k.lower(), v) for k, v in req.header_items())
        self.assertEqual(req.get_method(), "POST")
        self.assertEqual(headers.get("anthropic-workspace-id"), workspace)
        self.assertEqual(result["text"], "No supported hypothesis")

    def test_workspace_scoped_key_omits_optional_header(self):
        with mock.patch.dict(os.environ, {"ANTHROPIC_WORKSPACE_ID": ""}):
            headers = opus._anthropic_headers("local-rotated-key-" + "x"*30)
        self.assertNotIn("anthropic-workspace-id", headers)

    def test_invalid_workspace_id_rejected_without_network_calls(self):
        invalid = ("ws_123456", "wrkspc_bad\\r\\nx-injected: yes",
                   "wrkspc_", " wrkspc_0123456789A", "wrkspc_1234567890/")
        for workspace in invalid:
            with self.subTest(workspace=repr(workspace)):
                with mock.patch.dict(os.environ, {"ANTHROPIC_WORKSPACE_ID": workspace}):
                    with mock.patch.object(opus.urllib.request, "urlopen") as call:
                        with self.assertRaisesRegex(ValueError, "ANTHROPIC_WORKSPACE_ID"):
                            opus.check_model("local-rotated-key-" + "x"*30)
                        call.assert_not_called()

    def test_check_model_does_not_need_source_paths(self):
        with mock.patch.object(opus, "check_model",
                               return_value={"status": "MODEL_AVAILABLE",
                                             "model": opus.MODEL}) as checker:
            with mock.patch.dict(os.environ, {"ANTHROPIC_API_KEY": "secret"+"0"*30}):
                with mock.patch("sys.stdout", new_callable=io.StringIO) as sink:
                    exit_code = opus.main(["--check-model"])
        self.assertEqual(exit_code, 0)
        checker.assert_called_once()
        self.assertNotIn("secret", sink.getvalue())

    def test_request_error_does_not_echo_provider_secret(self):
        with mock.patch.object(opus.urllib.request, "urlopen",
                               side_effect=opus.urllib.error.HTTPError(
                                   opus.API_URL, 401, "dummy", {}, None)):
            with self.assertRaisesRegex(ValueError, "HTTP 401") as ctx:
                opus.request_opus("secret-key-not-to-echo", "test")
        self.assertNotIn("secret-key-not-to-echo", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
