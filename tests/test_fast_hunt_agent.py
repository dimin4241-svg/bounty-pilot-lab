"""Local owned-fixture autonomy: bounded actor replay and evidence regression."""
import importlib.util
import json
from pathlib import Path
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

p = Path(__file__).resolve().parents[1]/"skills/bounty-pilot/scripts/fast_hunt_agent.py"
spec=importlib.util.spec_from_file_location("tested_owned_agent",p)
agent=importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)

TOKENS={"BP_TEST_OWNER_TOKEN":"test-owner-token-0001","BP_TEST_OTHER_TOKEN":"test-other-token-0002"}
def manifest(port):
    return {"schema_version":1,"environment":"researcher_owned_loopback",
       "ownership_attestation":"I_CONTROL_BOTH_TEST_IDENTITIES_AND_FIXTURE",
       "origin":f"http://127.0.0.1:{port}",
       "actors":{"owner":"BP_TEST_OWNER_TOKEN","outsider":"BP_TEST_OTHER_TOKEN"},
       "cases":[{"id":"case1","owner_path":"/records/a","outsider_path":"/records/b",
                 "missing_path":"/records/unknown","marker_field":"canary",
                 "expected_policy":"owner-only"}],
       "limits":{"max_http_requests":8,"max_llm_calls":0,"max_cases_checked":1,
                 "timeout_seconds":2,"max_response_bytes":2048},
       "decision_engine":{"kind":"heuristic"}}

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.count+=1
        auth=self.headers.get("Authorization")
        if auth is None:
            cookie=self.headers.get("Cookie","")
            if cookie=="pilot_session="+TOKENS["BP_TEST_OWNER_TOKEN"]:
                auth="Bearer "+TOKENS["BP_TEST_OWNER_TOKEN"]
            elif cookie=="pilot_session="+TOKENS["BP_TEST_OTHER_TOKEN"]:
                auth="Bearer "+TOKENS["BP_TEST_OTHER_TOKEN"]
        if self.path=="/records/unknown": status, body=404,{"error":"missing"}
        elif self.path=="/records/b":
            status,body=(200,{"canary":"other-marker"}) if auth=="Bearer "+TOKENS["BP_TEST_OTHER_TOKEN"] else (403,{})
        elif self.path=="/records/a":
            if auth=="Bearer "+TOKENS["BP_TEST_OWNER_TOKEN"]:
                status,body=200,{"canary":"owner-marker"}
            elif auth=="Bearer "+TOKENS["BP_TEST_OTHER_TOKEN"] and self.server.vulnerable:
                status,body=200,{"canary":"owner-marker"}
            else:
                status,body=(401 if auth is None else 403),{}
        else: status,body=404,{}
        self.send_response(status)
        self.send_header("Content-Type","application/json")
        self.end_headers()
        self.wfile.write(json.dumps(body).encode())
    def log_message(self,*args): pass

class OwnedReplayTests(unittest.TestCase):
    def setUp(self):
        self.s=ThreadingHTTPServer(("127.0.0.1",0),Handler)
        self.s.count=0
        self.s.vulnerable=True
        self.t=threading.Thread(target=self.s.serve_forever,daemon=True)
        self.t.start()
    def tearDown(self):
        self.s.shutdown()
        self.s.server_close()
        self.t.join(3)
    def test_dry_run_zero_network(self):
        x=agent.execute(manifest(self.s.server_port))
        self.assertEqual(x["network_requests_local"],0)
        self.assertEqual(self.s.count,0)
    def test_synthetic_boundary_replays_with_controls(self):
        x=agent.execute(manifest(self.s.server_port),enabled=True,environ=TOKENS)
        self.assertEqual(x["synthetic_reproduction_count"],1)
        self.assertEqual(x["network_requests_local"],7)
        self.assertEqual(x["confirmed_production_vulnerabilities"],0)
        self.assertTrue(x["cases_checked"][0]["negative_controls_denied"])
        text=json.dumps(x)
        self.assertNotIn("test-owner-token",text)
        self.assertNotIn("owner-marker",text)
    def test_owned_cookie_mode_with_two_sessions(self):
        doc=manifest(self.s.server_port)
        doc["auth"]={"mode":"cookie","cookie_name":"pilot_session"}
        outcome=agent.execute(doc,enabled=True,environ=TOKENS)
        self.assertEqual(outcome["synthetic_reproduction_count"],1)
        self.assertNotIn(TOKENS["BP_TEST_OWNER_TOKEN"],json.dumps(outcome))
    def test_unsafe_cookie_value_is_rejected(self):
        doc=manifest(self.s.server_port)
        doc["auth"]={"mode":"cookie","cookie_name":"pilot_session"}
        bad=dict(TOKENS)
        bad["BP_TEST_OWNER_TOKEN"]="value;extra=1"
        with self.assertRaises(ValueError):
            agent.execute(doc,enabled=True,environ=bad)
        self.assertEqual(self.s.count,0)
    def test_fixed_fixture_not_misreported(self):
        self.s.vulnerable=False
        x=agent.execute(manifest(self.s.server_port),enabled=True,environ=TOKENS)
        self.assertEqual(x["synthetic_reproduction_count"],0)
        self.assertEqual(x["network_requests_local"],3)
    def test_missing_credentials_refused_before_network(self):
        with self.assertRaises(ValueError):
            agent.execute(manifest(self.s.server_port),enabled=True,environ={})
        self.assertEqual(self.s.count,0)
    def test_manifest_refuses_nonlocal_target(self):
        doc=manifest(self.s.server_port)
        doc["origin"]="https://example.com"
        with self.assertRaises(ValueError):
            agent.validate(doc)
if __name__=="__main__": unittest.main()
