"""Fast Hunt regression tests: candidate queue, shared anomaly ledger, exact-target HTTP."""
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SCRIPT = Path(__file__).resolve().parents[1] / "skills" / "bounty-pilot" / "scripts" / "fast_hunt.py"
spec = importlib.util.spec_from_file_location("test_fast_hunt_module", SCRIPT)
fh = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fh)


class Server(ThreadingHTTPServer):
    daemon_threads = True


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.calls.append(("GET", self.path, dict(self.headers)))
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "http://outside.invalid/secrets")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"secret":"NEVER_LOG_THIS","ok":true}')

    def do_HEAD(self):
        self.server.calls.append(("HEAD", self.path, dict(self.headers)))
        self.send_response(204)
        self.end_headers()

    def log_message(self, *args):
        return


def local_manifest(port):
    origin = "http://127.0.0.1:" + str(port)
    return {
        "schema_version": 1, "environment": "owned-loopback",
        "acknowledgement": "I_CONTROL_THIS_LOCAL_FIXTURE",
        "origin": origin, "pinned_ip": "127.0.0.1",
        "program_policy": None,
        "requests": [
            {"id": "one", "method": "GET", "url": origin + "/safe", "headers": {}},
            {"id": "two", "method": "GET", "url": origin + "/redirect", "headers": {}},
            {"id": "three", "method": "HEAD", "url": origin + "/head", "headers": {}},
        ],
        "timeout_seconds": 2, "max_response_bytes": 8192
    }


def public_manifest():
    origin = "https://api.example.com"
    d = {
        "schema_version": 1, "environment": "approved-public",
        "acknowledgement": "I_HAVE_REVIEWED_CURRENT_RULES_AND_TARGET_IP",
        "origin": origin, "pinned_ip": "8.8.8.8",
        "program_policy": {
            "schema_version": 1, "platform": "other", "program_id": "example",
            "status": "active", "source_url": "https://example.com/rules",
            "rules_sha256": "c" * 64, "reviewed_at": "2026-11-21T00:00:00Z",
            "expires_at": "2026-11-28T00:00:00Z",
            "operator_reviewed": True,
            "include": [{"origin": origin, "path_prefix": "/api",
                         "actions": ["read-only"]}],
            "exclude": [{"origin": origin, "path_prefix": "/api/admin",
                         "actions": ["read-only"]}],
            "required_headers": ["X-Bug-Bounty"]
        },
        "requests": [{"id": "public", "method": "GET", "url": origin + "/api/health",
                      "headers": {"X-Bug-Bounty": "researcher"}}],
        "timeout_seconds": 3, "max_response_bytes": 1024
    }
    return d


class FastSourceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "repo"
        self.path.mkdir()
        subprocess.run(["git", "-C", str(self.path), "init", "-q"], check=True)
        (self.path / "src").mkdir()
        (self.path / "src" / "account.py").write_text(
            "def withdraw(owner):\n    transfer(owner)\n\n"
            "def admin_guard(request):\n    require(request.owner)\n    delete(request.account)\n")
        (self.path / "src" / "api.ts").write_text(
            "app.post('/api/refund', handler);\n"
            "async function refund() { credit(balance) }\n")
        subprocess.run(["git", "-C", str(self.path), "add", "."], check=True)
        subprocess.run(["git", "-C", str(self.path), "-c", "user.name=Test",
                        "-c", "user.email=test@example.com", "commit", "-qm", "pinned"],
                       check=True)
        self.rev = subprocess.check_output(
            ["git", "-C", str(self.path), "rev-parse", "HEAD"], text=True).strip()

    def tearDown(self):
        self.tmp.cleanup()

    def test_plan_is_bounded_anchored_and_not_a_claim(self):
        out = fh.plan(self.path, "src", 2, 12)
        self.assertEqual(out["revision"], self.rev)
        self.assertEqual(out["tracked_source_files"], 2)
        self.assertTrue(out["candidates"])
        self.assertEqual(out["network_requests"], 0)
        self.assertEqual(out["confirmed_vulnerabilities"], 0)
        self.assertTrue(all(len(x["source_line_sha256"]) == 64 for x in out["candidates"]))
        self.assertTrue(all("UNVERIFIED" in x["classification"] for x in out["candidates"]))
        limited = fh.plan(self.path, "src", 1, 1)
        self.assertEqual(limited["uninspected_source_files"], 1)
        self.assertLessEqual(len(limited["candidates"]), 1)

    def test_one_command_cycle_is_offline_without_manifest(self):
        cycle = fh.run_cycle(self.path, "src")
        self.assertEqual(cycle["network_requests"], 0)
        self.assertIsNone(cycle["http_observations"])
        self.assertTrue(cycle["source_queue"]["candidates"])
        with self.assertRaises(ValueError):
            fh.run_cycle(self.path, "src", execute=True)

    def test_invalid_scopes_and_untracked_or_symlink_files_not_read(self):
        for scope in ("/src", "../src", ".", "src/../x", ""):
            with self.assertRaises(ValueError):
                fh.plan(self.path, scope)
        (self.path / "src" / "link.py").symlink_to("/etc/hosts")
        subprocess.run(["git", "-C", str(self.path), "add", "src/link.py"], check=True)
        subprocess.run(["git", "-C", str(self.path), "-c", "user.name=Test",
                        "-c", "user.email=test@example.com", "commit", "-qm", "symlink"],
                       check=True)
        self.assertEqual(fh.plan(self.path, "src")["tracked_source_files"], 2)
        (self.path / "src" / "account.py").write_text("def changed(): pass\\n")
        with self.assertRaises(ValueError):
            fh.plan(self.path, "src")

    def test_private_output_and_no_overwrite(self):
        out = Path(self.tmp.name) / "queue.json"
        fh.write_new(out, fh.plan(self.path, "src"), repo=self.path)
        self.assertEqual(out.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(ValueError):
            fh.write_new(out, {})
        with self.assertRaises(ValueError):
            fh.write_new(self.path / "queue.json", {}, repo=self.path)


class AnomalyTests(unittest.TestCase):
    def test_merge_keeps_weak_anomalies_across_two_lenses(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "input.json"
            rev = "a" * 40
            items = [
                {"path": "src/token.sol", "line": 17, "kind": "ACCOUNTING",
                 "note": "Balance delta may not be conserved across callbacks",
                 "evidence_sha256": "b" * 64, "observed_by": "accounting"},
                {"path": "src/token.sol", "line": 26, "kind": "AUTHZ",
                 "note": "Reentrant helper may change recipient ownership",
                 "evidence_sha256": "c" * 64, "observed_by": "composition"}
            ]
            p.write_text(json.dumps(items))
            first = fh.merge_anomalies(rev, str(p))
            self.assertEqual(len(first["anomalies"]), 2)
            self.assertEqual(len(first["cross_lens_review"]), 1)
            prior = Path(d) / "previous.json"
            prior.write_text(json.dumps(first))
            second = fh.merge_anomalies(rev, str(p), str(prior))
            self.assertEqual(first, second)
            forged = json.loads(json.dumps(first))
            forged["anomalies"][0]["id"] = "AN-not-the-evidence"
            prior.write_text(json.dumps(forged))
            with self.assertRaises(ValueError):
                fh.merge_anomalies(rev, str(p), str(prior))
            prior.write_text(json.dumps(first))
            with self.assertRaises(ValueError):
                fh.merge_anomalies("f"*40, str(p), str(prior))
            self.assertEqual(second["confirmed_vulnerabilities"], 0)


class BoundedNetworkTests(unittest.TestCase):
    def setUp(self):
        self.server = Server(("127.0.0.1", 0), Handler)
        self.server.calls = []
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)

    def test_dry_run_makes_zero_requests(self):
        result = fh.probe(local_manifest(self.server.server_port))
        self.assertEqual(result["network_requests"], 0)
        self.assertEqual(self.server.calls, [])

    def test_real_reads_and_cross_host_redirect_not_followed(self):
        result = fh.probe(local_manifest(self.server.server_port), execute=True)
        self.assertEqual(result["network_requests"], 3)
        self.assertEqual(len(self.server.calls), 3)
        self.assertEqual([x["status"] for x in result["results"]], [200, 302, 204])
        self.assertTrue(result["results"][1]["redirect_blocked"])
        self.assertEqual(result["confirmed_vulnerabilities"], 0)
        self.assertNotIn("NEVER_LOG_THIS", json.dumps(result))
        self.assertNotIn("outside.invalid", json.dumps(result))

    def test_one_command_cycle_respects_owned_probe_plan(self):
        with tempfile.TemporaryDirectory() as d:
            repo = Path(d) / "repo"
            repo.mkdir()
            subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True)
            (repo / "src").mkdir()
            (repo / "src" / "app.py").write_text("def withdraw():\\n    transfer(balance)\\n")
            subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
            subprocess.run(["git", "-C", str(repo), "-c", "user.name=Test",
                            "-c", "user.email=test@example.com", "commit", "-qm", "pin"],
                           check=True)
            manifest = Path(d) / "manifest.json"
            manifest.write_text(json.dumps(local_manifest(self.server.server_port)))
            cycle = fh.run_cycle(repo, "src", str(manifest), execute=True)
            self.assertEqual(cycle["network_requests"], 3)
            self.assertTrue(cycle["source_queue"]["candidates"])
            self.assertEqual(cycle["confirmed_vulnerabilities"], 0)

    def test_refuses_other_host_methods_query_path_encoding_and_extra_headers(self):
        base = local_manifest(self.server.server_port)
        bad = [
            ("method", "POST"), ("method", "DELETE"),
            ("url", "https://evil.example/api"),
            ("url", "http://127.0.0.1:1/admin"),
            ("url", base["origin"] + "/api?token=secret"),
            ("url", base["origin"] + "/api/%252e%252e/admin"),
            ("url", base["origin"] + "//admin"),
            ("url", base["origin"] + "/../admin"),
            ("headers", {"Authorization": "Bearer secret"}),
            ("headers", {"X-Bug-Bounty": "x\r\nInjected: true"}),
            ("headers", {"Accept": "application/json", "accept": "text/plain"})
        ]
        for key, val in bad:
            m = json.loads(json.dumps(base))
            m["requests"][0][key] = val
            with self.subTest(key=key, value=val):
                with self.assertRaises(ValueError):
                    fh.validate_probe(m)
        self.assertEqual(self.server.calls, [])

    def test_explicit_public_policy_is_fail_closed(self):
        m = public_manifest()
        now = dt.datetime(2026, 11, 22, tzinfo=dt.timezone.utc)
        self.assertEqual(len(fh.validate_probe(m, now=now)), 1)
        for alter in ("paused", "closed"):
            d = json.loads(json.dumps(m))
            d["program_policy"]["status"] = alter
            with self.assertRaises(ValueError):
                fh.validate_probe(d, now=now)
        for key, val in [("pinned_ip", "127.0.0.1"), ("pinned_ip", "10.0.0.1"),
                         ("pinned_ip", "192.0.2.1"),
                         ("acknowledgement", "I_DID_NOT_REVIEW")]:
            d = json.loads(json.dumps(m))
            d[key] = val
            with self.assertRaises(ValueError):
                fh.validate_probe(d, now=now)
        d = json.loads(json.dumps(m))
        d["requests"][0]["url"] = "https://api.example.com/api/admin/stats"
        with self.assertRaises(ValueError):
            fh.validate_probe(d, now=now)
        d = json.loads(json.dumps(m))
        del d["requests"][0]["headers"]["X-Bug-Bounty"]
        with self.assertRaises(ValueError):
            fh.validate_probe(d, now=now)
        d = json.loads(json.dumps(m))
        d["program_policy"]["expires_at"] = "2026-11-21T01:00:00Z"
        with self.assertRaises(ValueError):
            fh.validate_probe(d, now=now)

    def test_bounded_requests_and_safe_create_only_cli(self):
        m = local_manifest(self.server.server_port)
        m["requests"] = m["requests"] * 3
        with self.assertRaises(ValueError):
            fh.validate_probe(m)
        with tempfile.TemporaryDirectory() as d:
            m = local_manifest(self.server.server_port)
            path = Path(d) / "plan.json"
            out = Path(d) / "observation.json"
            path.write_text(json.dumps(m))
            self.assertEqual(fh.main(["probe", "--manifest", str(path),
                                      "--out", str(out)]), 0)
            self.assertEqual(json.loads(out.read_text())["network_requests"], 0)
            self.assertEqual(out.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(SystemExit):
                fh.main(["probe", "--manifest", str(path), "--out", str(out)])


if __name__ == "__main__":
    unittest.main()
