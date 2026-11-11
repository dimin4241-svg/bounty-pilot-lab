"""Native Web integration: offline gates, mock tool executions and real 40-pair synthetic regression."""
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1] / "skills" / "bounty-pilot" / "scripts"


def load(name):
    spec = importlib.util.spec_from_file_location("bp_test_" + name, ROOT / (name + ".py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


native = load("web_native_toolchain")
benchmark = load("web_benchmark_regression")


def openapi():
    return {"openapi": "3.0.3", "info": {"title": "Owned Lab", "version": "1"},
            "servers": [], "paths": {"/state": {
                "get": {"responses": {"200": {"description": "ok"}}}}}}


def fixture(tmp, mode):
    root = Path(tmp)
    plan = {"schema_version": 1, "mode": mode,
            "attestation": "I_CONTROL_THIS_LOCAL_FIXTURE", "max_seconds": 30}
    if mode == "schemathesis":
        source = root / "owned"
        source.mkdir()
        spec = source / "openapi.json"
        spec.write_text(json.dumps(openapi()))
        plan.update({"origin": "http://127.0.0.1:8082",
                     "fixture_dir": str(source), "openapi_file": str(spec),
                     "seed": 7, "max_examples": 3, "phases": "stateful"})
    elif mode == "playwright":
        mod = root / "trusted" / "node_modules"
        (mod / "playwright").mkdir(parents=True)
        plan.update({"origin": "http://127.0.0.1:8084",
                     "owner_path": "/owner", "outsider_path": "/outsider",
                     "scalar_selector": "#value", "browser_module": str(mod)})
    elif mode == "codeql":
        repo = root / "source"
        repo.mkdir()
        (repo / "index.js").write_text("export const n = 1;")
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        subprocess.run(["git", "-C", str(repo), "add", "index.js"], check=True)
        subprocess.run(["git", "-C", str(repo), "-c", "user.name=Owned",
                        "-c", "user.email=owned@fixture.invalid",
                        "commit", "-qm", "fixture"], check=True)
        commit = subprocess.check_output(["git", "-C", str(repo),
                                          "rev-parse", "HEAD"]).decode().strip()
        query = root / "trusted.ql"
        query.write_text("/* local vetted query */")
        plan.update({"repo": str(repo), "source_commit": commit,
                     "local_query": str(query)})
    return plan


class NativeBridgeTests(unittest.TestCase):
    def test_macos_style_symlink_above_fixture_root_is_allowed(self):
        # Reproduce /var -> /private/var on Linux and macOS without
        # relying on the host having that exact alias.
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            real = base / "private-storage"
            (real / "owned").mkdir(parents=True)
            alias = base / "var-alias"
            alias.symlink_to(real, target_is_directory=True)
            fixture = alias / "owned"
            spec = fixture / "api.json"
            spec.write_text(json.dumps(openapi()))
            canonical = native._local_dir(str(fixture))
            self.assertEqual(canonical, (real / "owned").resolve())
            self.assertEqual(native._file(str(spec), root=canonical), spec.resolve())
            self.assertEqual(native._file(str(spec), root=fixture), spec.resolve())

    def test_symlink_directory_below_canonical_fixture_root_remains_denied(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            real = base / "private-storage"
            owned = real / "owned"
            inside = owned / "inside"
            inside.mkdir(parents=True)
            (inside / "api.json").write_text(json.dumps(openapi()))
            (owned / "alias-inside").symlink_to(
                inside, target_is_directory=True)
            top_alias = base / "var-alias"
            top_alias.symlink_to(real, target_is_directory=True)
            canonical = native._local_dir(str(top_alias / "owned"))
            with self.assertRaisesRegex(ValueError, "symlink directory"):
                native._file(str(top_alias / "owned" / "alias-inside" / "api.json"),
                             root=canonical)
            # And a link to an external directory cannot circumvent containment.
            external = base / "elsewhere"
            external.mkdir()
            (external / "api.json").write_text(json.dumps(openapi()))
            (owned / "outside-link").symlink_to(
                external, target_is_directory=True)
            with self.assertRaises(ValueError):
                native._file(str(top_alias / "owned" / "outside-link" / "api.json"),
                             root=canonical)

    def test_schemathesis_dry_run_and_strict_schema(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = fixture(tmp, "schemathesis")
            out = native.run_native(p, str(Path(tmp) / "out.json"))
            self.assertEqual(out["native_calls"], 0)
            self.assertEqual(out["status"], "PLAN_VALIDATED_NOT_EXECUTED")
            p["origin"] = "http://somewhere.example.com"
            with self.assertRaises(ValueError):
                native.check(p)
            p["origin"] = "http://127.0.0.1:8082"
            data = openapi()
            data["paths"]["/state"]["get"]["responses"]["200"]["content"] = {
                "application/json": {"schema": {"$ref": "https://outside.invalid/x"}}}
            Path(p["openapi_file"]).write_text(json.dumps(data))
            with self.assertRaises(ValueError):
                native.check(p)

    def test_schemathesis_calls_only_bounded_loopback(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = fixture(tmp, "schemathesis")
            seen = []
            def fake(cmd, timeout, cwd, scratch):
                seen.append(cmd)
                Path(cmd[cmd.index("--report-json-path") + 1]).write_text(
                    json.dumps({"private_data": "never retained"}))
                return {"exit_code": 0, "stdout_sha256": "a"*64, "stdout_bytes": 5}
            with patch.object(native.shutil, "which", return_value="/trusted/st"), \
                 patch.object(native, "_execute", side_effect=fake):
                out = native.run_native(p, str(Path(tmp) / "out.json"), execute=True)
            self.assertIn("--max-redirects", seen[0])
            self.assertIn("--max-examples", seen[0])
            self.assertIn(p["origin"], seen[0])
            self.assertEqual(out["native_calls"], 1)
            self.assertNotIn("never retained", json.dumps(out))

    def test_codeql_pinned_commit_and_sarif_redaction(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = fixture(tmp, "codeql")
            self.assertEqual(native.check(p)["source_commit"], p["source_commit"])
            changed = dict(p, source_commit="0"*40)
            with self.assertRaises(ValueError):
                native.run_native(changed, str(Path(tmp)/"out.json"), execute=True)
            calls = []
            def fake(cmd, timeout, cwd, scratch):
                calls.append(cmd)
                if cmd[1:3] == ["database", "analyze"]:
                    report = next(x.split("=", 1)[1] for x in cmd
                                  if x.startswith("--output="))
                    Path(report).write_text(json.dumps({"runs": [{"results": [
                        {"ruleId": "js/synthetic", "message": {"text": "SECRET"},
                         "locations": [{"physicalLocation": {
                             "artifactLocation": {"uri": "index.js"},
                             "region": {"startLine": 1}}}]},
                        {"ruleId": "bad", "locations": [{"physicalLocation": {
                            "artifactLocation": {"uri": "../outside"},
                            "region": {"startLine": 1}}}]}
                    ]}]}))
                return {"exit_code": 0, "stdout_sha256": "a"*64, "stdout_bytes": 0}
            with patch.object(native.shutil, "which", return_value="/trusted/codeql"), \
                 patch.object(native, "_execute", side_effect=fake):
                out = native.run_native(p, str(Path(tmp) / "out.json"), execute=True)
            self.assertIn("--build-mode=none", calls[0])
            self.assertEqual(out["observations"]["count"], 1)
            self.assertNotIn("SECRET", json.dumps(out))
            self.assertEqual(out["confirmed_vulnerabilities"], 0)

    def test_playwright_requires_trusted_module_and_browser_snapshots(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = fixture(tmp, "playwright")
            self.assertEqual(native.check(p)["scalar_selector"], "#value")
            p["scalar_selector"] = "script"
            with self.assertRaises(ValueError):
                native.check(p)
            p["scalar_selector"] = "#value"
            commands = []
            def fake(cmd, timeout, cwd, scratch):
                commands.append(cmd)
                Path(cmd[-1]).write_text(json.dumps({
                    "schema_version":1, "mode":"local-browser-isolated-contexts",
                    "owner":{"present":True,"scalar":2,"http_status":200},
                    "outsider":{"present":True,"scalar":1,"http_status":200},
                    "blocked_external_requests":1}))
                return {"exit_code":0,"stdout_sha256":"a"*64,"stdout_bytes":0}
            with patch.object(native.shutil, "which", return_value="/trusted/node"), \
                 patch.object(native, "_execute", side_effect=fake):
                result = native.run_native(p, str(Path(tmp)/"out.json"), execute=True)
            self.assertTrue(commands[0][1].endswith("web_playwright_local.cjs"))
            self.assertEqual(result["observations"]["owner"]["scalar"], 2)

    def test_garden_import_is_not_fabricated_native_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            checkout = root / "garden"
            checkout.mkdir()
            def cap(name, digest):
                return {"parser_id": name, "parser_build": name + "-v1",
                        "input_sha256": digest, "request_count":0,
                        "consumed_bytes":0, "requests":[]}
            sample = {"schema_version":1,"environment":"researcher_owned_isolated_lab",
                      "pairs":[{"pair_id":"p1",
                                "candidate":{"front":cap("front","a"*64),
                                             "back":cap("back","a"*64)},
                                "negative_control":{"front":cap("front","b"*64),
                                                    "back":cap("back","b"*64)}}]}
            src = root / "obs.json"
            src.write_text(json.dumps(sample))
            p = {"schema_version":1, "mode":"http-garden-import",
                 "attestation":"I_CONTROL_THIS_LOCAL_FIXTURE", "max_seconds":30,
                 "garden_commit":"1"*40, "garden_checkout":str(checkout),
                 "observation_file":str(src)}
            with patch.object(native, "_git_head", return_value="1"*40):
                result = native.run_native(p, str(root/"out.json"), execute=True)
            self.assertEqual(result["native_calls"], 0)
            self.assertEqual(result["comparison"]["pairs_reviewed"], 1)
            self.assertEqual(result["confirmed_vulnerabilities"], 0)

    def test_no_inherited_tokens_and_private_outputs(self):
        with patch.dict(os.environ, {"GITHUB_TOKEN":"secret",
                                     "OPENAI_API_KEY":"private"}):
            env = native._env("/tmp/owned")
        self.assertNotIn("GITHUB_TOKEN", env)
        self.assertNotIn("OPENAI_API_KEY", env)
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "out.json"
            native._write_new(p, {"ok":True})
            self.assertEqual(p.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(ValueError):
                native._write_new(p, {})


class SyntheticFortyTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("node"), "Node URL parser required")
    def test_40_positive_control_case_pairs(self):
        report = benchmark.run()
        self.assertEqual(report["case_pairs"], 40)
        self.assertEqual(report["snapshots"], 80)
        self.assertEqual(report["passed_pairs"], 40)
        self.assertEqual(report["missed_fixture_leads"], 0)
        self.assertEqual(report["control_false_positives"], 0)
        self.assertFalse(report["public_uplift_claim_allowed"])
        self.assertEqual(report["real_model_runs"], 0)


if __name__ == "__main__":
    unittest.main()
