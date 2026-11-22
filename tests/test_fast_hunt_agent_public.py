"""Approved-public policy gates without contacting public networks."""
import copy
import datetime as dt
import http.client
import importlib.util
import json
from pathlib import Path
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SCRIPT=Path(__file__).resolve().parents[1]/"skills/bounty-pilot/scripts/fast_hunt_agent.py"
spec=importlib.util.spec_from_file_location("public_gate_under_test",SCRIPT)
agent=importlib.util.module_from_spec(spec);spec.loader.exec_module(agent)
NOW=dt.datetime(2026,11,22,tzinfo=dt.timezone.utc)
TOKENS={"BP_OWNED_A_TOKEN":"owned-a-00000001","BP_OWNED_B_TOKEN":"owned-b-00000002",
        "BP_RESEARCH_HANDLE":"reviewed-handle"}

def doc():
    origin="https://lab.example.test"
    return {"schema_version":1,"environment":"approved-public",
      "ownership_attestation":"I_CONTROL_BOTH_ACCOUNTS_AND_OBJECTS_ON_SCOPED_TARGET",
      "origin":origin,"pinned_ip":"8.8.8.8",
      "research_header":{"name":"X-Bug-Bounty","value_env":"BP_RESEARCH_HANDLE"},
      "program_policy":{"schema_version":1,"platform":"other",
        "program_id":"owned-fake","status":"active",
        "source_url":"https://lab.example.test/rules",
        "rules_sha256":"a"*64,"reviewed_at":"2026-11-20T00:00:00Z",
        "expires_at":"2026-11-30T00:00:00Z",
        "include":[{"origin":origin,"path_prefix":"/records","actions":["read-only"]}],
        "exclude":[{"origin":origin,"path_prefix":"/records/admin","actions":["read-only"]}],
        "required_headers":["X-Bug-Bounty"],"operator_reviewed":True},
      "actors":{"owner":"BP_OWNED_A_TOKEN","outsider":"BP_OWNED_B_TOKEN"},
      "cases":[{"id":"owned","owner_path":"/records/a",
                "outsider_path":"/records/b","missing_path":"/records/missing",
                "marker_field":"canary","expected_policy":"owner-only"}],
      "limits":{"max_http_requests":8,"max_llm_calls":0,"max_cases_checked":1,
                "timeout_seconds":2,"max_response_bytes":2048},
      "decision_engine":{"kind":"heuristic"}}

class Fixture(BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.calls.append((self.path,self.headers.get("X-Bug-Bounty")))
        if self.path=="/records/missing":status,body=404,{}
        elif self.path=="/records/b":status,body=200,{"canary":"other-fixture"}
        elif self.path=="/records/a":
            status,body=(401,{}) if not self.headers.get("Authorization") else (200,{"canary":"owned-private-fixture"})
        else:status,body=404,{}
        self.send_response(status);self.end_headers()
        self.wfile.write(json.dumps(body).encode())
    def log_message(self,*a):pass

class PublicGatesTests(unittest.TestCase):
    def setUp(self):
        self.server=ThreadingHTTPServer(("127.0.0.1",0),Fixture)
        self.server.calls=[]
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True)
        self.thread.start()
        self.plan=doc()
    def tearDown(self):
        self.server.shutdown();self.server.server_close();self.thread.join(3)
    def test_no_network_without_opt_in(self):
        output=agent.execute(self.plan,now=NOW)
        self.assertEqual(output["network_requests_local"],0)
        self.assertEqual(self.server.calls,[])
    def test_pinned_public_plan_with_fake_local_transport(self):
        def fake(port,timeout):
            return http.client.HTTPConnection("127.0.0.1",self.server.server_port,timeout=timeout)
        result=agent.execute(self.plan,enabled=True,environ=TOKENS,transport=fake,now=NOW)
        self.assertEqual(result["external_target_requests"],7)
        self.assertEqual(result["network_requests_local"],0)
        self.assertEqual(result["synthetic_reproduction_count"],0)
        self.assertEqual(result["owned_public_observation_count"],1)
        self.assertEqual(result["confirmed_production_vulnerabilities"],0)
        self.assertTrue(all(h=="reviewed-handle" for _,h in self.server.calls))
    def test_unreviewed_scope_expiry_wrong_pin_and_blocked_path(self):
        for mutate in ("expired","unreviewed","private_ip","excluded","other_origin"):
            d=copy.deepcopy(self.plan)
            if mutate=="expired":d["program_policy"]["expires_at"]="2026-11-21T00:00:00Z"
            if mutate=="unreviewed":d["program_policy"]["operator_reviewed"]=False
            if mutate=="private_ip":d["pinned_ip"]="127.0.0.1"
            if mutate=="excluded":d["cases"][0]["owner_path"]="/records/admin/debug"
            if mutate=="other_origin":d["origin"]="https://other.example.test"
            with self.subTest(mutate=mutate),self.assertRaises(ValueError):
                agent.validate(d,now=NOW)
        self.assertEqual(self.server.calls,[])
    def test_public_requires_header_value_before_network(self):
        def fake(port,timeout):raise AssertionError("should not connect")
        d=doc()
        with self.assertRaises(ValueError):
            agent.execute(d,enabled=True,environ={
                "BP_OWNED_A_TOKEN":TOKENS["BP_OWNED_A_TOKEN"],
                "BP_OWNED_B_TOKEN":TOKENS["BP_OWNED_B_TOKEN"]},transport=fake,now=NOW)
if __name__=="__main__":unittest.main()
