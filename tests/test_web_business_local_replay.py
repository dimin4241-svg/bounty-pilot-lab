"""Researcher-owned loopback multi-step account/payment native replay tests."""
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills" / "bounty-pilot" / "scripts"


def load(name):
    spec = importlib.util.spec_from_file_location("bp_local_test_" + name, SCRIPTS / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


replay = load("web_business_local_replay")
engine = load("web_business_lab")
TOKENS = {"BP_LOCAL_OWNER_TOKEN": "owned-test-token-owner-000",
          "BP_LOCAL_OUTSIDER_TOKEN": "owned-test-token-outsider-111"}


def make_plan(port):
    rounds = []
    for n in (1, 2):
        pair = {}
        for role, actor, suffix in (("candidate", "outsider", "c"),
                                    ("control", "owner", "n")):
            ref = "fake-psp-event-" + str(n) + suffix
            pair[role] = {
                "state_path": "/r" + str(n) + "/" + suffix + "/state",
                "state_actor": "owner",
                "steps": [{
                    "path": "/r" + str(n) + "/" + suffix + "/credit",
                    "actor": actor, "subject": "owner", "kind": "credit",
                    "payload": {"operation": "credit", "payment_event_ref": ref},
                    "payment_event_ref": ref, "refund_event_ref": None
                }]
            }
        rounds.append(pair)
    return {
        "schema_version": 1,
        "attestation": "I_CONTROL_THIS_LOCAL_FIXTURE",
        "origin": "http://127.0.0.1:" + str(port),
        "source_revision": "a" * 40,
        "test_actors": {
            "owner": {"bearer_env": "BP_LOCAL_OWNER_TOKEN"},
            "outsider": {"bearer_env": "BP_LOCAL_OUTSIDER_TOKEN"}
        },
        "cases": [{"id": "owned-unpaid-credit", "rule": "unpaid-credit",
                   "invariant_basis": "documented", "rounds": rounds}]
    }


class OwnedHTTPFixture:
    def __init__(self):
        states = {}
        self.calls = []
        calls = self.calls
        class Handler(BaseHTTPRequestHandler):
            def send_json(self, status, body):
                b = json.dumps(body).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)

            def do_GET(self):
                calls.append(("GET", self.path))
                if self.headers.get("Authorization") != (
                        "Bearer " + TOKENS["BP_LOCAL_OWNER_TOKEN"]):
                    return self.send_json(403, {})
                if not self.path.endswith("/state"):
                    return self.send_json(404, {})
                amount = states.setdefault(self.path, 10000)
                return self.send_json(200, {"available_cents": amount,
                                            "ledger_credited_cents": amount - 10000})

            def do_POST(self):
                calls.append(("POST", self.path))
                if self.path.endswith("/credit"):
                    if "/c/" in self.path:
                        expected = "Bearer " + TOKENS["BP_LOCAL_OUTSIDER_TOKEN"]
                    else:
                        expected = "Bearer " + TOKENS["BP_LOCAL_OWNER_TOKEN"]
                    if self.headers.get("Authorization") != expected:
                        return self.send_json(403, {})
                    try:
                        payload = json.loads(self.rfile.read(
                            int(self.headers.get("Content-Length", "0"))))
                    except (ValueError, json.JSONDecodeError):
                        return self.send_json(400, {})
                    if payload.get("operation") != "credit" or not payload.get(
                            "payment_event_ref", "").startswith("fake-psp-event-"):
                        return self.send_json(400, {})
                    state_path = self.path.rsplit("/", 1)[0] + "/state"
                    states[state_path] = states.setdefault(state_path, 10000) + 500
                    return self.send_json(200, {
                        "facts": {"psp_confirmed": "/c/" not in self.path,
                                  "non_payment_credit_allowed": False}})
                return self.send_json(404, {})

            def log_message(self, *_):
                pass
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self.server.server_port

    def __exit__(self, *_):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=4)


class BusinessLocalReplayTests(unittest.TestCase):
    def test_dry_run_does_not_open_sockets(self):
        out = replay.execute(make_plan(18342), run=False)
        self.assertEqual(out["network_requests_local"], 0)
        self.assertEqual(out["classification"], "VALIDATED_LOCAL_PLAN_NOT_EXECUTED")

    def test_real_loopback_sqlite_like_effect_is_consumed_by_offline_oracle(self):
        server = OwnedHTTPFixture()
        with server as port:
            out = replay.execute(make_plan(port), run=True, environment=TOKENS)
        self.assertEqual(out["network_requests_local"], 12)
        self.assertEqual(len(server.calls), 12)
        self.assertEqual(out["external_network_requests"], 0)
        result = engine.analyze(out)
        self.assertEqual(result["candidate_count"], 1)
        self.assertEqual(result["confirmed_production_vulnerabilities"], 0)
        for token in TOKENS.values():
            self.assertNotIn(token, json.dumps(out))

    def test_rejects_external_or_ambiguous_target_hosts(self):
        for url in ("http://localhost:8000", "https://127.0.0.1:8000",
                    "http://127.0.0.2:8000", "http://127.0.0.1:80",
                    "http://127.0.0.1:8000@evil.test:9000",
                    "http://127.0.0.1:8000/path",
                    "http://127.0.0.1:08000"):
            plan = make_plan(18342)
            plan["origin"] = url
            with self.subTest(origin=url), self.assertRaises(ValueError):
                replay.validate(plan)

    def test_rejects_token_fields_and_mismatched_payment_reference(self):
        p = make_plan(18342)
        step = p["cases"][0]["rounds"][0]["candidate"]["steps"][0]
        step["payload"]["password"] = "no-secrets-here"
        with self.assertRaisesRegex(ValueError, "non-secret"):
            replay.validate(p)
        del step["payload"]["password"]
        step["payment_event_ref"] = "forged-id"
        with self.assertRaisesRegex(ValueError, "payment ref"):
            replay.validate(p)

    def test_rejects_shared_fixture_state_routes(self):
        p = make_plan(18342)
        p["cases"][0]["rounds"][0]["control"]["state_path"] = (
            p["cases"][0]["rounds"][0]["candidate"]["state_path"])
        with self.assertRaisesRegex(ValueError, "isolated"):
            replay.validate(p)

    def test_requires_distinct_runtime_test_actor_tokens(self):
        p = make_plan(18342)
        with self.assertRaises(ValueError):
            replay.execute(p, run=True, environment={
                "BP_LOCAL_OWNER_TOKEN": "same-test-token",
                "BP_LOCAL_OUTSIDER_TOKEN": "same-test-token"
            })

    def test_cli_dispatch_and_0600_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            inp = Path(tmp) / "plan.json"
            out = Path(tmp) / "dry.json"
            inp.write_text(json.dumps(make_plan(18342)), encoding="utf8")
            proc = subprocess.run(
                [sys.executable, str(SCRIPTS / "bounty.py"),
                 "web-business-local-replay", "--plan", str(inp), "--out", str(out)],
                text=True, capture_output=True, timeout=20)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            doc = json.loads(out.read_text())
            self.assertEqual(doc["network_requests_local"], 0)
            self.assertEqual(out.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
