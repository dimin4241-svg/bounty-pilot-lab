"""Model-driven case scheduling on an operator-owned synthetic HTTP fixture."""
import importlib.util
import json
from pathlib import Path
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT=Path(__file__).resolve().parents[1]/"skills/bounty-pilot/scripts"
spec=importlib.util.spec_from_file_location("local_autonomy",ROOT/"fast_hunt_agent.py")
agent=importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)
TOKENS={"BP_TEST_OWNER_TOKEN":"lab-owner-value-123456",
        "BP_TEST_OTHER_TOKEN":"lab-other-value-654321",
        "BP_TEST_LLM_KEY":"lab-model-value-111111"}

class API(BaseHTTPRequestHandler):
    def do_GET(self):
        auth=self.headers.get("Authorization")
        pieces=self.path.split("/")
        status=404
        payload={}
        if len(pieces)==3 and pieces[1] in ("safe","unsafe"):
            scenario,resource=pieces[1:3]
            if resource=="owner":
                if auth=="Bearer "+TOKENS["BP_TEST_OWNER_TOKEN"]:
                    status,payload=200,{"canary":"private-A-lab"}
                elif auth is None: status=401
                elif scenario=="unsafe": status,payload=200,{"canary":"private-A-lab"}
                else: status=403
            elif resource=="other":
                if auth=="Bearer "+TOKENS["BP_TEST_OTHER_TOKEN"]:
                    status,payload=200,{"canary":"private-B-lab"}
                else: status=403
        self.send_response(status);self.end_headers()
        self.wfile.write(json.dumps(payload).encode())
    def log_message(self,*a):pass

class LocalModel(BaseHTTPRequestHandler):
    def do_POST(self):
        body=json.loads(self.rfile.read(int(self.headers.get("Content-Length","0"))))
        self.server.inputs.append(body)
        payload=json.loads(body["messages"][1]["content"])
        pick="safe" if "safe" in payload["choices"] else "unsafe"
        self.send_response(200);self.end_headers()
        self.wfile.write(json.dumps({"choices":[{"message":{"content":json.dumps({"case_id":pick})}}]}).encode())
    def log_message(self,*a):pass

def manifest(port,model_port):
    return {"schema_version":1,"environment":"researcher_owned_loopback",
      "ownership_attestation":"I_CONTROL_BOTH_TEST_IDENTITIES_AND_FIXTURE",
      "origin":f"http://127.0.0.1:{port}",
      "actors":{"owner":"BP_TEST_OWNER_TOKEN","outsider":"BP_TEST_OTHER_TOKEN"},
      "cases":[{"id":name,"owner_path":f"/{name}/owner",
                "outsider_path":f"/{name}/other","missing_path":f"/{name}/missing",
                "marker_field":"canary","expected_policy":"owner-only"}
                for name in ("safe","unsafe")],
      "limits":{"max_http_requests":16,"max_llm_calls":3,"max_cases_checked":2,
                "timeout_seconds":2,"max_response_bytes":4096},
      "decision_engine":{"kind":"openai-compatible",
          "endpoint":f"http://127.0.0.1:{model_port}/v1/chat/completions",
          "model":"deepseek-v4.1-flash","api_key_env":"BP_TEST_LLM_KEY"}}

class ModelFlowTests(unittest.TestCase):
    def setUp(self):
        self.api=ThreadingHTTPServer(("127.0.0.1",0),API)
        self.llm=ThreadingHTTPServer(("127.0.0.1",0),LocalModel)
        self.llm.inputs=[]
        self.threads=[]
        for s in (self.api,self.llm):
            t=threading.Thread(target=s.serve_forever,daemon=True)
            t.start();self.threads.append(t)
        self.doc=manifest(self.api.server_port,self.llm.server_port)
    def tearDown(self):
        for s in (self.api,self.llm):s.shutdown();s.server_close()
        for t in self.threads:t.join(3)
    def test_llm_moves_from_fixed_case_to_reproduced_case(self):
        # Deterministic model chooses fixed first, then only the remaining candidate.
        outcome=agent.execute(self.doc,enabled=True,environ=TOKENS)
        self.assertEqual([x["case_id"] for x in outcome["cases_checked"]],["safe","unsafe"])
        self.assertEqual(outcome["synthetic_reproduction_count"],1)
        self.assertEqual(outcome["llm_calls"],2)
        self.assertEqual(len(self.llm.inputs),2)
        self.assertLessEqual(outcome["network_requests_local"],16)
        dump=json.dumps(self.llm.inputs)
        for x in (TOKENS["BP_TEST_OWNER_TOKEN"],TOKENS["BP_TEST_OTHER_TOKEN"],
                  "private-A-lab","/unsafe/owner"):
            self.assertNotIn(x,dump)
    def test_model_may_not_choose_unreviewed_case(self):
        self.doc["limits"]["max_cases_checked"]=1
        with self.assertRaises(ValueError):
            agent.execute(self.doc,enabled=True,environ=TOKENS,
                          chooser=lambda observation:{"case_id":"not-allowlisted"})
    def test_unapproved_model_server_scheme_denied(self):
        self.doc["decision_engine"]["endpoint"]="http://example.net/v1/chat/completions"
        with self.assertRaises(ValueError):agent.validate(self.doc)
if __name__=="__main__":unittest.main()
