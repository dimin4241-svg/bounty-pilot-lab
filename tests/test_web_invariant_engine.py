"""Synthetic regression tests for the offline Web invariant engine and local replay."""
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
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills" / "bounty-pilot" / "scripts"


def load_module(name):
    spec = importlib.util.spec_from_file_location("test_" + name, SCRIPTS / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


engine = load_module("web_invariant_engine")
replay = load_module("web_local_replay")


def api_spec():
    return {
        "openapi": "3.0.3",
        "security": [{"bearerAuth": []}],
        "paths": {
            "/api/v1/docs/{id}": {
                "get": {"operationId": "viewDocument", "x-bp-handler": "Document.handler"},
                "patch": {"operationId": "editDocument", "x-bp-handler": "Document.handler",
                          "x-bp-roles": ["member"]},
            },
            "/api/v2/docs/{documentId}": {
                "get": {"operationId": "viewDocumentLegacy",
                        "x-bp-handler": "Document.handler", "security": []},
            },
            "/api/v1/ping": {"get": {"security": []}}
        },
    }


def credentials():
    return {
        "BP_WEB_REPLAY_OWNER_TOKEN": "synthetic-token-alice",
        "BP_WEB_REPLAY_OUTSIDER_TOKEN": "synthetic-token-bob",
        "BP_WEB_OWNER_MARKER": "ALICE_PRIVATE_FIXTURE_CONTENT",
        "BP_WEB_OUTSIDER_MARKER": "BOB_PRIVATE_FIXTURE_CONTENT",
    }


def plan(port, method="GET"):
    return {
        "schema_version": 1,
        "base_url": "http://127.0.0.1:" + str(port),
        "local_fixture_confirmed": True,
        "test_actors": {
            "alice": {"bearer_env": "BP_WEB_REPLAY_OWNER_TOKEN"},
            "bob": {"bearer_env": "BP_WEB_REPLAY_OUTSIDER_TOKEN"},
        },
        "cases": [{
            "id": "document-1", "private_resource_confirmed": True,
            "owner_marker_env": "BP_WEB_OWNER_MARKER",
            "outsider_marker_env": "BP_WEB_OUTSIDER_MARKER",
            "owner": {"actor": "alice", "method": method, "path": "/api/docs/owned"},
            "cross": {"actor": "bob", "method": method, "path": "/api/docs/owned"},
            "outsider_control": {"actor": "bob", "method": method, "path": "/api/docs/bob"},
        }]
    }


class FakeServer:
    def __init__(self, leaky):
        creds = credentials()
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                user = self.headers.get("Authorization")
                if self.path == "/api/docs/owned":
                    if user == "Bearer " + creds["BP_WEB_REPLAY_OWNER_TOKEN"] or leaky:
                        status, body = 200, creds["BP_WEB_OWNER_MARKER"]
                    else:
                        status, body = 403, "denied"
                elif self.path == "/api/docs/bob" and user == (
                        "Bearer " + creds["BP_WEB_REPLAY_OUTSIDER_TOKEN"]):
                    status, body = 200, creds["BP_WEB_OUTSIDER_MARKER"]
                else:
                    status, body = 404, "not found"
                body = body.encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self.server.server_port

    def __exit__(self, *_):
        self.server.shutdown()
        self.thread.join(timeout=3)
        self.server.server_close()


class OperationGraphTests(unittest.TestCase):
    def test_security_mismatch_is_a_lead_not_proof(self):
        graph = engine.build_operation_graph(api_spec())
        self.assertEqual(len(graph["operations"]), 4)
        self.assertEqual(len(graph["leads"]), 1)
        self.assertEqual(graph["leads"][0]["kind"], "ADVERTISED_AUTH_MISMATCH")
        self.assertEqual(graph["confirmed_vulnerabilities"], 0)
        self.assertEqual(graph["network_requests"], 0)

    def test_deterministic_output(self):
        self.assertEqual(engine.build_operation_graph(api_spec()),
                         engine.build_operation_graph(api_spec()))

    def test_structural_grouping_has_lower_priority(self):
        spec = api_spec()
        for paths in spec["paths"].values():
            for op in paths.values():
                if isinstance(op, dict):
                    op.pop("x-bp-handler", None)
        graph = engine.build_operation_graph(spec)
        leads = graph["leads"]
        self.assertTrue(any(x["basis"] == "structural_heuristic" for x in leads))
        self.assertTrue(all(x["priority"] < 85 for x in leads))

    def test_openapi_invalid_and_secret_path_not_persisted(self):
        with self.assertRaises(ValueError):
            engine.build_operation_graph({"openapi": "2.0", "paths": {}})
        spec = {"openapi": "3.0.3", "paths": {
            "/api/" + "X" * 40: {"get": {"security": []}}}}
        graph = engine.build_operation_graph(spec)
        self.assertIn("{opaque}", graph["operations"][0]["path"])
        self.assertNotIn("X" * 40, json.dumps(graph))

    def test_auth_matrix_only_for_confirmed_owned_resources(self):
        graph = engine.build_operation_graph(api_spec())
        oid = graph["operations"][0]["id"]
        fixtures = {"schema_version": 1, "resources": [{
            "id": "doc-case", "operation_id": oid, "owner": "alice", "outsider": "bob",
            "owner_fixture": "alice-doc", "outsider_fixture": "bob-doc",
            "private_resource_confirmed": True
        }, {
            "id": "not-private", "operation_id": oid, "owner": "alice", "outsider": "bob",
            "owner_fixture": "x", "outsider_fixture": "y",
            "private_resource_confirmed": False
        }]}
        out = engine.build_auth_matrix(graph, fixtures)
        self.assertEqual(out["count"], 1)
        self.assertEqual(len(out["cases"][0]["checks"]), 4)
        self.assertEqual(out["cases"][0]["classification"], "TEST_PLAN_NOT_EXECUTED")

    def test_auth_matrix_rejects_forged_operation(self):
        with self.assertRaises(ValueError):
            engine.build_auth_matrix(engine.build_operation_graph(api_spec()), {
                "schema_version": 1, "resources": [{
                    "id": "case", "operation_id": "unknown", "owner": "a", "outsider": "b",
                    "owner_fixture": "a", "outsider_fixture": "b",
                    "private_resource_confirmed": True}]})


class TraceTests(unittest.TestCase):
    def test_revocation_regrant_and_cross_owner(self):
        events = [
            {"kind": "revoke", "actor": "bob", "resource": "doc-1"},
            {"kind": "access", "actor": "bob", "resource": "doc-1",
             "allowed": True, "confirmed_private": True,
             "owner": "alice", "authorized_delegate": False},
            {"kind": "grant", "actor": "bob", "resource": "doc-1"},
            {"kind": "access", "actor": "bob", "resource": "doc-1", "allowed": True},
        ]
        result = engine.analyze_state_trace({"schema_version": 1, "events": events})
        kinds = {lead["kind"] for lead in result["leads"]}
        self.assertEqual(kinds, {"REVOKED_ACCESS_RESTORED", "CROSS_OWNER_ACCESS"})
        self.assertEqual(result["confirmed_vulnerabilities"], 0)

    def test_payment_binding_and_idempotency(self):
        events = [
            {"kind": "payment_settled", "idempotency_key": "owned-payment",
             "signature_valid": True, "order_bound": True,
             "amount_bound": True, "currency_bound": True,
             "settled": True, "additional_credit": True},
            {"kind": "payment_settled", "idempotency_key": "owned-payment",
             "signature_valid": False, "order_bound": True,
             "amount_bound": True, "currency_bound": True,
             "settled": True, "additional_credit": True},
        ]
        result = engine.analyze_state_trace({"schema_version": 1, "events": events})
        self.assertEqual({x["kind"] for x in result["leads"]},
                         {"PAYMENT_BINDING_BROKEN", "NON_IDEMPOTENT_SETTLEMENT"})

    def test_unknown_is_not_false_positive(self):
        result = engine.analyze_state_trace({"schema_version": 1, "events": [
            {"kind": "payment_settled", "settled": True},
            {"kind": "access", "actor": "bob", "resource": "doc-1",
             "confirmed_private": True, "allowed": None},
        ]})
        self.assertEqual(result["leads"], [])
        self.assertIn(0, result["unknown_event_indices"])

    def test_parser_leads_offline(self):
        result = engine.parser_differential({"schema_version": 1, "cases": [
            {"url": "https://example.test/a%252fb"}, {"url": "https://example.test/normal"},
        ]})
        self.assertEqual(len(result["leads"]), 1)
        self.assertEqual(result["leads"][0]["kind"], "MULTI_STAGE_URL_DECODING")
        self.assertEqual(result["network_requests"], 0)

    def test_load_rejects_duplicate_keys_and_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "dup.json"
            f.write_text('{"schema_version":1,"schema_version":2}')
            with self.assertRaisesRegex(ValueError, "duplicate"):
                engine.load_file(f)
            out = Path(tmp) / "proof.json"
            engine.save_new(out, {"ok": True})
            self.assertEqual(out.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(ValueError):
                engine.save_new(out, {"ok": False})


class ReplayTests(unittest.TestCase):
    def test_dry_run_has_zero_requests(self):
        result = replay.run(plan(12345), {}, execute=False)
        self.assertEqual(result["network_requests"], 0)
        self.assertEqual(result["classification"], "VALIDATED_PLAN_NOT_EXECUTED")

    def test_refuses_non_loopback_destinations(self):
        for url in ("https://127.0.0.1:80", "http://localhost:4000",
                    "http://127.0.0.2:4000", "http://example.com:4000",
                    "http://127.0.0.1:4000/path",
                    "http://127.0.0.1:4000@evil.invalid:80"):
            p = plan(12345)
            p["base_url"] = url
            with self.subTest(url=url), self.assertRaises(ValueError):
                replay.run(p, credentials(), execute=True)

    def test_refuses_shared_actor_creds_and_guessed_objects(self):
        p = plan(12345)
        p["test_actors"]["bob"]["bearer_env"] = "BP_WEB_REPLAY_OWNER_TOKEN"
        with self.assertRaises(ValueError):
            replay.run(p, credentials())
        p = plan(12345)
        p["cases"][0]["private_resource_confirmed"] = False
        with self.assertRaises(ValueError):
            replay.run(p, credentials())

    def test_local_vulnerable_fixture_reproduces(self):
        with FakeServer(leaky=True) as port:
            result = replay.run(plan(port), credentials(), execute=True)
        self.assertEqual(result["network_requests"], 6)
        self.assertEqual(result["results"][0]["status"], "LOCAL_REPRODUCED")
        raw = json.dumps(result)
        for secret in credentials().values():
            self.assertNotIn(secret, raw)
        self.assertEqual(result["confirmed_production_vulnerabilities"], 0)

    def test_local_fixed_fixture_denies(self):
        with FakeServer(leaky=False) as port:
            result = replay.run(plan(port), credentials(), execute=True)
        self.assertEqual(result["results"][0]["status"],
                         "NO_BYPASS_OBSERVED_IN_LOCAL_FIXTURE")
        self.assertTrue(result["results"][0]["control_valid"])
        self.assertEqual(result["results"][0]["rounds"], 2)

    def test_cli_dry_run_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            src, dst = Path(tmp) / "plan.json", Path(tmp) / "result.json"
            src.write_text(json.dumps(plan(12345)))
            proc = subprocess.run([sys.executable, str(SCRIPTS / "web_local_replay.py"),
                                   "--plan", str(src), "--out", str(dst)],
                                  text=True, capture_output=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            data = json.loads(dst.read_text())
            self.assertEqual(data["network_requests"], 0)
            self.assertEqual(dst.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
