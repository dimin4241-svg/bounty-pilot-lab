"""Actual safe 127.0.0.1-only business effect replay on an owned synthetic server."""
import importlib.util
import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "skills" / "bounty-pilot" / "scripts"
SPEC = importlib.util.spec_from_file_location(
    "web_effect_fixture_replay_test", SCRIPTS / "web_effect_fixture_replay.py")
fixture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture)


def plan(port):
    return {
        "schema_version": 1, "ownership_attestation": "I_CONTROL_THIS_LOCAL_FIXTURE",
        "origin": "http://127.0.0.1:%d" % port,
        "case_id": "subscription-owned", "resource_kind": "subscription",
        "business_effect": "plan_activated",
        "predicate": {"field": "plan_level", "relation": "increased", "value": None},
        "rounds": [{
            "candidate": {"state_path": "/r%d/c/state" % i,
                          "action_path": "/r%d/c/action" % i},
            "negative_control": {"state_path": "/r%d/n/state" % i,
                                 "action_path": "/r%d/n/action" % i}}
            for i in range(2)]
    }


class LocalServer(ThreadingHTTPServer):
    daemon_threads = True


class Handler(BaseHTTPRequestHandler):
    def _reply(self, code=200, body=None, redirect=None):
        self.send_response(code)
        if redirect:
            self.send_header("Location", redirect)
        else:
            self.send_header("Content-Type", "application/json")
        self.end_headers()
        if body is not None:
            self.wfile.write(json.dumps(body).encode("utf-8"))

    def do_GET(self):
        self.server.record.append(("GET", self.path,
                                   self.headers.get("Authorization"),
                                   self.headers.get("Cookie")))
        if not self.path.endswith("/state"):
            return self._reply(404, {})
        level = self.server.levels.get(self.path, 1)
        self._reply(200, {"plan_level": level, "private_secret": "do not save"})

    def do_POST(self):
        self.server.record.append(("POST", self.path,
                                   self.headers.get("Authorization"),
                                   self.headers.get("Cookie")))
        if self.server.redirect:
            return self._reply(302, redirect="https://fixture.invalid/disallowed")
        if not self.path.endswith("/action"):
            return self._reply(404, {})
        path = self.path.rsplit("/", 1)[0] + "/state"
        if "/c/" in self.path or self.server.bad_control:
            self.server.levels[path] = 2
        self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self._reply(200, {"status": "accepted"})

    def log_message(self, *args):
        return


class EffectFixtureReplayTests(unittest.TestCase):
    def setUp(self):
        self.server = LocalServer(("127.0.0.1", 0), Handler)
        self.server.levels = {}
        self.server.record = []
        self.server.bad_control = False
        self.server.redirect = False
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def test_real_two_round_effect_and_no_secret_exfiltration(self):
        res = fixture.replay(plan(self.server.server_port))
        self.assertEqual(res["oracle_review"]["controlled_effect_leads"], 1)
        self.assertEqual(res["network_request_count_local"], 12)
        self.assertEqual(res["network_requests_external"], 0)
        self.assertEqual(res["confirmed_production_vulnerabilities"], 0)
        self.assertEqual(len(self.server.record), 12)
        self.assertTrue(all(auth is None and cookie is None
                            for _, _, auth, cookie in self.server.record))
        text = json.dumps(res)
        self.assertNotIn("do not save", text)
        self.assertNotIn("/r0/c/action", text)
        self.assertIn("plan_level", text)

    def test_negative_control_changed_refutes_promotion(self):
        self.server.bad_control = True
        res = fixture.replay(plan(self.server.server_port))
        self.assertEqual(res["oracle_review"]["controlled_effect_leads"], 0)
        self.assertEqual(res["oracle_review"]["results"][0]["status"],
                         "INCONCLUSIVE_NEGATIVE_CONTROL_CHANGED")

    def test_redirect_to_external_host_is_never_followed(self):
        self.server.redirect = True
        with self.assertRaises(ValueError):
            fixture.replay(plan(self.server.server_port))
        self.assertEqual(len(self.server.record), 3)

    def test_remote_or_dns_origin_denied(self):
        for origin in (
            "https://127.0.0.1:%d" % self.server.server_port,
            "http://localhost:%d" % self.server.server_port,
            "http://127.0.0.1:80",
            "http://127.0.0.1:%d/redirect" % self.server.server_port,
            "http://127.0.0.1:%d#fragment" % self.server.server_port,
            "http://127.0.0.2:%d" % self.server.server_port):
            p = plan(self.server.server_port)
            p["origin"] = origin
            with self.assertRaises(ValueError):
                fixture.validate(p)

    def test_reused_endpoints_or_query_denied(self):
        p = plan(self.server.server_port)
        p["rounds"][1]["candidate"]["state_path"] = p["rounds"][0]["candidate"]["state_path"]
        with self.assertRaises(ValueError):
            fixture.validate(p)
        p = plan(self.server.server_port)
        p["rounds"][0]["candidate"]["action_path"] = "/r0/c/action?next=https://bad.invalid"
        with self.assertRaises(ValueError):
            fixture.validate(p)

    def test_cli_requires_execute_opt_in(self):
        with tempfile.TemporaryDirectory() as tmp:
            planfile = Path(tmp) / "plan.json"
            out = Path(tmp) / "result.json"
            planfile.write_text(json.dumps(plan(self.server.server_port)))
            self.assertEqual(fixture.main(["--plan", str(planfile), "--out", str(out)]), 0)
            self.assertFalse(out.exists())
            self.assertEqual(self.server.record, [])
            self.assertEqual(fixture.main([
                "--plan", str(planfile), "--out", str(out), "--execute"]), 0)
            self.assertTrue(out.exists())
            self.assertEqual(out.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(SystemExit):
                fixture.main(["--plan", str(planfile), "--out", str(out), "--execute"])


if __name__ == "__main__":
    unittest.main()
