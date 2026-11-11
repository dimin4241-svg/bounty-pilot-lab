"""Phase 5 integrated owned-lab Web hunt: sanitized capture -> review queue -> local effect -> evidence."""
import copy
import datetime as dt
import importlib.util
import json
import subprocess
import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "skills" / "bounty-pilot" / "scripts"


def import_script(name):
    spec = importlib.util.spec_from_file_location("test_" + name, ROOT / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


capture = import_script("web_workflow_capture")
hunt = import_script("web_hunt_loop")
packet = import_script("web_evidence_packet")
bridge = import_script("web_dispatch_prepare")
NOW = dt.datetime(2026, 11, 11, 8, 0, tzinfo=dt.timezone.utc)
KEY = "e" * 64
HOST = "http://127.0.0.1:8423"


def har(status=200, path="/api/v1/orders/order-42"):
    return {"log": {"version": "1.2", "entries": [
        {"request": {"url": HOST + path + "?token=DO_NOT_SAVE",
                     "method": "GET",
                     "headers": [{"name": "Authorization",
                                  "value": "Bearer PRIVATE_SECRET"},
                                 {"name": "Cookie", "value": "sid=PRIVATE_COOKIE"}],
                     "postData": {"text": "PRIVATE_BODY"}},
         "response": {"status": status, "content": {"text": "private response"}},
         "startedDateTime": "2026-11-11T00:00:00Z"}
    ]}}


def policy():
    return {"schema_version": 1, "platform": "bizone", "program_id": "owned-fixture",
            "status": "active", "source_url": "https://bugbounty.bi.zone/companies/demo",
            "rules_sha256": "a" * 64, "reviewed_at": "2026-11-10T00:00:00Z",
            "expires_at": "2026-11-20T00:00:00Z",
            "include": [{"origin": "https://api.demo.test", "path_prefix": "/v1",
                         "actions": ["read-only", "account-test"]}],
            "exclude": [{"origin": "https://api.demo.test", "path_prefix": "/v1/admin",
                         "actions": ["read-only", "account-test"]}],
            "required_headers": [], "operator_reviewed": True}


def request():
    return [{"id": "preflight-one", "url": "https://api.demo.test/v1/items",
             "action": "read-only", "provided_header_names": []}]


def manifest(outsider_status=200, mark_owner_only=True):
    own = capture.capture(har(200), HOST, "owner", KEY)
    outsider = capture.capture(har(outsider_status), HOST, "outsider", KEY)
    return {"schema_version": 1, "environment": "researcher_owned_lab",
            "project": "owned-fixture", "source_revision": "f" * 40,
            "program_policy": policy(), "request_plan": request(),
            "owner_capture": own, "outsider_capture": outsider,
            "owner_only_route_keys": [own["events"][0]["route_key"]]
            if mark_owner_only else [],
            "static_analysis": None, "known_mechanisms": [],
            "budget": {"max_review_jobs": 4, "max_usd_per_job": 0.15,
                       "max_usd_total": 0.3},
            "local_effect_fixture": None}


def effect_plan(port):
    return {
        "schema_version": 1, "ownership_attestation": "I_CONTROL_THIS_LOCAL_FIXTURE",
        "origin": "http://127.0.0.1:" + str(port),
        "case_id": "owned-plan-effect", "resource_kind": "subscription",
        "business_effect": "plan_activated",
        "predicate": {"field": "plan_level", "relation": "increased", "value": None},
        "rounds": [{
            "candidate": {"state_path": "/r%d/c/state" % i,
                          "action_path": "/r%d/c/action" % i},
            "negative_control": {"state_path": "/r%d/n/state" % i,
                                 "action_path": "/r%d/n/action" % i}}
            for i in range(2)]
    }


def statement(campaign):
    return {
        "schema_version": 1, "project": campaign["project"],
        "source_revision": campaign["source_revision"],
        "candidate_id": campaign["review_jobs"][0]["candidate_id"],
        "effect_case_id": "owned-plan-effect", "reviewer_id": "independent-human",
        "reviewer_independent_asserted": True,
        "authorization_policy_evidence_sha256": "1" * 64,
        "source_reachability_evidence_sha256": "2" * 64,
        "effect_observation_evidence_sha256": "3" * 64,
        "negative_control_evidence_sha256": "4" * 64,
        "novelty_review_evidence_sha256": "5" * 64,
        "deployed_state_reviewed": True, "independent_replay_asserted": True
    }


class OwnedHTTPServer(ThreadingHTTPServer):
    daemon_threads = True


class FixtureHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.events.append(("GET", self.path))
        if not self.path.endswith("/state"):
            self.send_error(404)
            return
        level = self.server.state.get(self.path, 1)
        data = json.dumps({"plan_level": level, "secret": "NEVER_IN_REPORT"})
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(data.encode("utf-8"))

    def do_POST(self):
        self.server.events.append(("POST", self.path))
        if not self.path.endswith("/action"):
            self.send_error(404)
            return
        target = self.path.rsplit("/", 1)[0] + "/state"
        if "/c/" in self.path or self.server.bad_control:
            self.server.state[target] = 2
        self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"ok":true}')

    def log_message(self, *args):
        return


class WorkflowCaptureTests(unittest.TestCase):
    def test_redacts_sensitive_http_contents(self):
        r = capture.capture(har(), HOST, "owner", KEY)
        text = json.dumps(r)
        for secret in ("DO_NOT_SAVE", "PRIVATE_COOKIE", "PRIVATE_SECRET",
                       "PRIVATE_BODY", "private response", "order-42"):
            self.assertNotIn(secret, text)
        self.assertEqual(r["event_count"], 1)
        self.assertEqual(r["events"][0]["route_shape"], "/api/v1/orders/:opaque")
        self.assertFalse(r["events"][0]["privileged_business_effect_proven"])

    def test_owner_outsider_share_consistent_hmac_object_key(self):
        a = capture.capture(har(), HOST, "owner", KEY)
        b = capture.capture(har(), HOST, "outsider", KEY)
        self.assertEqual(a["events"][0]["object_key"], b["events"][0]["object_key"])
        self.assertEqual(a["events"][0]["route_key"], b["events"][0]["route_key"])
        other_key = capture.capture(har(), HOST, "outsider", "a" * 64)
        self.assertNotEqual(a["events"][0]["object_key"],
                            other_key["events"][0]["object_key"])

    def test_refuses_remote_and_cross_origin_traffic(self):
        for url in ("https://example.org/data", "http://localhost:8423/x",
                    "http://127.0.0.1:8424/api/v1/orders/a",
                    "http://user:pass@127.0.0.1:8423/x"):
            data = har()
            data["log"]["entries"][0]["request"]["url"] = url
            with self.assertRaises(ValueError):
                capture.capture(data, HOST, "owner", KEY)

    def test_rejects_path_traversal_nested_encoding_and_ambiguous_methods(self):
        for path in ("/api/v1/orders/%252e", "/api/../admin", "//other",
                     "/api/abc%2fhidden", "/api//users"):
            with self.assertRaises(ValueError):
                capture.capture(har(path=path), HOST, "owner", KEY)
        source = har()
        source["log"]["entries"][0]["request"]["method"] = "CONNECT"
        with self.assertRaises(ValueError):
            capture.capture(source, HOST, "owner", KEY)

    def test_root_route_is_supported_without_path_tokens(self):
        data = capture.capture(har(path="/"), HOST, "owner", KEY)
        self.assertEqual(data["events"][0]["route_shape"], "/")
        self.assertIsNone(data["events"][0]["object_key"])

    def test_multiple_routes_get_object_links_without_persisting_object_value(self):
        raw = har()
        raw["log"]["entries"].append({
            "request": {"url": HOST + "/api/v1/invoices/order-42", "method": "GET"},
            "response": {"status": 200}})
        data = capture.capture(raw, HOST, "owner", KEY)
        self.assertEqual(len(data["possible_object_links"]), 1)
        self.assertNotIn("order-42", json.dumps(data))


class EndToEndPlanTests(unittest.TestCase):
    def test_owner_only_status_200_is_only_review_lead(self):
        result = hunt.execute(manifest(), now=NOW)
        self.assertEqual(result["state"], "OFFLINE_REVIEW_QUEUE_NOT_EXECUTED")
        self.assertEqual(result["candidate_count"], 1)
        self.assertEqual(len(result["review_jobs"]), 1)
        self.assertEqual(result["review_jobs"][0]["planned_max_usd"], 0.15)
        self.assertFalse(result["ready_to_submit"])
        self.assertEqual(result["confirmed_vulnerabilities"], 0)
        self.assertEqual(result["real_model_calls"], 0)

    def test_no_permission_assertion_no_auth_bypass_claim(self):
        result = hunt.execute(manifest(mark_owner_only=False), now=NOW)
        self.assertEqual(result["candidate_count"], 0)
        self.assertEqual(len(result["review_jobs"]), 0)
        self.assertEqual(len(result["capture_summaries"]["cross_actor_same_object"]), 1)

    def test_outsider_403_does_not_create_false_bola(self):
        result = hunt.execute(manifest(outsider_status=403), now=NOW)
        self.assertEqual(result["candidate_count"], 0)
        self.assertIn("STATUS_DIFFERENCE",
                      result["capture_summaries"]["cross_actor_same_object"][0]["classification"])

    def test_cross_actor_distinct_objects_are_not_joined(self):
        m = manifest()
        m["outsider_capture"] = capture.capture(
            har(path="/api/v1/orders/order-99"), HOST, "outsider", KEY)
        result = hunt.execute(m, now=NOW)
        self.assertEqual(result["candidate_count"], 0)
        self.assertEqual(result["capture_summaries"]["cross_actor_same_object"], [])

    def test_blocked_scope_never_executes_even_owned_fixture(self):
        m = manifest()
        m["program_policy"]["status"] = "paused"
        result = hunt.execute(m, now=NOW)
        self.assertEqual(result["state"], "BLOCKED_POLICY_PLAN")
        self.assertEqual(result["review_jobs"], [])
        with self.assertRaises(ValueError):
            hunt.execute(m, run_owned_fixture=True, now=NOW)

    def test_missing_or_expired_policies_fail_closed(self):
        m = manifest()
        m["program_policy"]["expires_at"] = "2026-11-10T03:00:00Z"
        self.assertEqual(hunt.execute(m, now=NOW)["state"], "BLOCKED_POLICY_PLAN")
        m = manifest()
        m["program_policy"]["operator_reviewed"] = False
        self.assertEqual(hunt.execute(m, now=NOW)["state"], "BLOCKED_POLICY_PLAN")

    def test_reviewed_duplicate_suppressed_only_same_revision_and_mechanism(self):
        m = manifest()
        first = hunt.execute(m, now=NOW)
        c = first["root_cause_groups"][0]
        self.assertEqual(c["member_count"], 1)
        lead = hunt._cap_candidates(
            m["owner_capture"]["events"], m["outsider_capture"]["events"],
            set(m["owner_only_route_keys"]))[0][0]
        known = {key: lead[key] for key in (
            "source_file", "code_anchor", "invariant_id", "trust_boundary_id")}
        known.update({"project": m["project"], "revision": m["source_revision"],
                      "reviewed_by": "human1", "evidence_sha256": "a" * 64,
                      "disposition": "known-duplicate"})
        m["known_mechanisms"] = [known]
        suppressed = hunt.execute(m, now=NOW)
        self.assertEqual(len(suppressed["reviewed_suppressions"]), 1)
        self.assertEqual(suppressed["review_jobs"], [])
        m["source_revision"] = "0" * 40
        fresh = hunt.execute(m, now=NOW)
        self.assertEqual(len(fresh["review_jobs"]), 1)

    def test_static_ts_flow_join_and_root_cause_budget(self):
        m = manifest()
        m["static_analysis"] = {
            "schema_version": 1, "mode": "web-ts-cross-file-flow",
            "network_requests": 0, "confirmed_vulnerabilities": 0,
            "flows": [
                {"id": "flow" + str(i),
                 "classification": "UNVERIFIED_STATIC_ARGUMENT_FLOW",
                 "entry": {"file": "src/routes.ts", "method": "GET", "path": "/v1/items"},
                 "sink": {"file": "src/handlers.ts",
                          "call": "prisma.findUnique", "line": 14 + i}}
                for i in range(3)]
        }
        m["budget"] = {"max_review_jobs": 3, "max_usd_per_job": 0.2,
                       "max_usd_total": 0.4}
        result = hunt.execute(m, now=NOW)
        self.assertEqual(result["candidate_count"], 4)
        self.assertEqual(len(result["review_jobs"]), 2)
        self.assertEqual(result["budget"]["max_planned_spend_usd"], 0.4)
        self.assertEqual(result["unassigned_group_count"], 2)

    def test_nan_budget_and_overspend_rejected(self):
        m = manifest()
        for bad in (float("nan"), -1, 101):
            m["budget"]["max_usd_total"] = bad
            with self.assertRaises(ValueError):
                hunt.execute(m, now=NOW)
        m = manifest()
        m["budget"]["max_usd_per_job"] = float("inf")
        with self.assertRaises(ValueError):
            hunt.execute(m, now=NOW)

    def test_capture_identity_and_secret_raw_data_not_accepted(self):
        m = manifest()
        m["outsider_capture"]["actor"] = "owner"
        with self.assertRaises(ValueError):
            hunt.execute(m, now=NOW)
        m = manifest()
        m["outsider_capture"]["events"][0]["request_header"] = "SECRET"
        with self.assertRaises(ValueError):
            hunt.execute(m, now=NOW)

    def test_clean_cli_create_only_output_and_no_network(self):
        with tempfile.TemporaryDirectory() as tmp:
            m = manifest()
            mpath = Path(tmp) / "in.json"
            out = Path(tmp) / "out.json"
            mpath.write_text(json.dumps(m))
            self.assertEqual(hunt.main(["--input", str(mpath), "--out", str(out)]), 0)
            self.assertEqual(out.stat().st_mode & 0o777, 0o600)
            data = json.loads(out.read_text())
            self.assertEqual(data["real_model_calls"], 0)
            with self.assertRaises(SystemExit):
                hunt.main(["--input", str(mpath), "--out", str(out)])


class ActualOwnedFixtureReplayTests(unittest.TestCase):
    def setUp(self):
        self.server = OwnedHTTPServer(("127.0.0.1", 0), FixtureHandler)
        self.server.events = []
        self.server.state = {}
        self.server.bad_control = False
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def test_integrated_real_loopback_effect_and_packet_not_submittable(self):
        m = manifest()
        m["local_effect_fixture"] = effect_plan(self.server.server_port)
        campaign = hunt.execute(m, run_owned_fixture=True, now=NOW)
        self.assertEqual(campaign["state"], "CONTROLLED_LOCAL_EFFECT_REPLAY_UNVERIFIED")
        self.assertEqual(len(self.server.events), 12)
        self.assertEqual(campaign["owned_fixture_replay"]["oracle_review"][
            "controlled_effect_leads"], 1)
        self.assertEqual(campaign["network_requests_external"], 0)
        self.assertEqual(campaign["confirmed_vulnerabilities"], 0)
        self.assertNotIn("NEVER_IN_REPORT", json.dumps(campaign))
        reviewed = packet.review(campaign, statement(campaign))
        self.assertEqual(reviewed["status"],
                         "OPERATOR_ATTESTED_LOCAL_REVIEW_NOT_INDEPENDENTLY_VERIFIED")
        self.assertTrue(reviewed["repeated_local_effect"])
        self.assertFalse(reviewed["ready_to_submit"])

    def test_negative_control_changed_blocks_evidence_packet(self):
        m = manifest()
        m["local_effect_fixture"] = effect_plan(self.server.server_port)
        self.server.bad_control = True
        campaign = hunt.execute(m, run_owned_fixture=True, now=NOW)
        self.assertEqual(campaign["owned_fixture_replay"]["oracle_review"][
            "controlled_effect_leads"], 0)
        with self.assertRaises(ValueError):
            packet.review(campaign, statement(campaign))

    def test_packet_must_match_review_queue_and_exact_revision(self):
        m = manifest()
        m["local_effect_fixture"] = effect_plan(self.server.server_port)
        campaign = hunt.execute(m, run_owned_fixture=True, now=NOW)
        review = statement(campaign)
        review["candidate_id"] = "lead-nope"
        with self.assertRaises(ValueError):
            packet.review(campaign, review)
        review = statement(campaign)
        review["source_revision"] = "0" * 40
        with self.assertRaises(ValueError):
            packet.review(campaign, review)
        review = statement(campaign)
        review["negative_control_evidence_sha256"] = (
            review["effect_observation_evidence_sha256"])
        with self.assertRaises(ValueError):
            packet.review(campaign, review)
        review = statement(campaign)
        review["reviewer_independent_asserted"] = False
        result = packet.review(campaign, review)
        self.assertEqual(result["status"], "INCOMPLETE_INDEPENDENT_REVIEW")
        self.assertFalse(result["ready_to_submit"])


class DispatchBridgeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.repo = root / "owned-repo"
        self.repo.mkdir()
        (self.repo / "source.py").write_text(
            "def owner_view(account):\n    return account.private_value\n")
        (self.repo / "src").mkdir()
        (self.repo / "src" / "service.ts").write_text(
            "function review(req) {\n"
            "  const apiKey = 'SECRET_SHOULD_BE_MASKED';\n"
            "  if (!isAuthorized(req)) throw Error('denied');\n"
            "  return prisma.findUnique(req.id);\n"
            "}\n")
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        subprocess.run(["git", "-C", str(self.repo), "add", "."],
                       check=True)
        subprocess.run(["git", "-C", str(self.repo),
                        "-c", "user.name=Owned Fixture",
                        "-c", "user.email=owned@fixture.invalid",
                        "commit", "-qm", "owned fixture"], check=True)
        self.revision = subprocess.check_output(
            ["git", "-C", str(self.repo), "rev-parse", "HEAD"]
        ).decode().strip()
        self.run = root / "private-run"
        bounty = import_script("bounty")
        bounty.initialize(self.repo, self.run)
        m = manifest()
        m["source_revision"] = self.revision
        self.campaign = hunt.execute(m, now=NOW)

    def test_real_agent_dispatch_manifest_and_two_isolated_jobs_without_model_calls(self):
        prepared = bridge.prepare(self.campaign, self.run, replicas=2)
        self.assertEqual(prepared["status"],
                         "INDEPENDENT_JOBS_PLANNED_NOT_EXECUTED")
        self.assertEqual(prepared["dispatch_job_count"], 2)
        self.assertEqual(prepared["actual_spend_usd"], 0)
        self.assertEqual(prepared["provider_sessions_started"], 0)
        dispatch = json.loads(
            (self.run / "agents" / "dispatch.json").read_text())
        self.assertEqual(len(dispatch["jobs"]), 2)
        for row in dispatch["jobs"].values():
            self.assertEqual(row["status"], "queued")
            self.assertEqual(row["source_commit"], self.revision)
            self.assertEqual(row["latest_result"], None)
        bundling = json.loads(
            (self.run / "bundles" / "manifest.json").read_text())
        self.assertEqual(len(bundling["dispatches"][0]["bundles"]), 1)
        bundle = self.run / bundling["dispatches"][0]["bundles"][0]["bundle"]
        text = bundle.read_text()
        self.assertIn(self.campaign["review_jobs"][0]["candidate_id"], text)
        self.assertIn(self.revision, text)
        self.assertIn("captured-http", text)
        self.assertIn("Owner HTTP 200", text)
        self.assertIn("outsider HTTP 200", text)
        self.assertNotIn("PRIVATE_SECRET", text)
        self.assertEqual(bundle.stat().st_mode & 0o777, 0o600)

    def test_replica_budget_is_enforced_before_creating_bundles(self):
        campaign = copy.deepcopy(self.campaign)
        campaign["budget"]["max_usd_total"] = 0.20
        with self.assertRaisesRegex(ValueError, "budget"):
            bridge.prepare(campaign, self.run, replicas=2)
        self.assertFalse((self.run / "bundles" / "manifest.json").exists())

    def test_unchanged_pinned_git_revision_required(self):
        campaign = copy.deepcopy(self.campaign)
        campaign["source_revision"] = "0" * 40
        with self.assertRaisesRegex(ValueError, "revision"):
            bridge.prepare(campaign, self.run, replicas=2)

    def test_bridge_never_overwrites_existing_dispatch(self):
        bridge.prepare(self.campaign, self.run)
        with self.assertRaises(ValueError):
            bridge.prepare(self.campaign, self.run)

    def test_explicit_source_snippet_opt_in_redacts_secret_like_line(self):
        m = manifest(mark_owner_only=False)
        m["source_revision"] = self.revision
        m["static_analysis"] = {
            "schema_version": 1, "mode": "web-ts-cross-file-flow",
            "network_requests": 0, "confirmed_vulnerabilities": 0,
            "flows": [{
                "id": "local-flow",
                "classification": "UNVERIFIED_STATIC_ARGUMENT_FLOW",
                "entry": {"file": "src/routes.ts", "method": "GET",
                          "path": "/api/v1/items"},
                "sink": {"file": "src/service.ts", "call": "prisma.findUnique",
                         "line": 4}
            }]
        }
        campaign = hunt.execute(m, now=NOW)
        bridge.prepare(campaign, self.run, include_source_excerpts=True)
        manifest_path = self.run / "bundles" / "manifest.json"
        bundle_ref = json.loads(manifest_path.read_text())[
            "dispatches"][0]["bundles"][0]["bundle"]
        content = (self.run / bundle_ref).read_text()
        self.assertIn("prisma.findUnique", content)
        self.assertIn("[REDACTED_SECRET_LIKE_LINE]", content)
        self.assertNotIn("SECRET_SHOULD_BE_MASKED", content)
        self.assertIn("Pinned source SHA-256:", content)
        self.assertIn("isAuthorized(req)", content)

    def test_empty_or_blocked_review_queue_cannot_dispatch(self):
        campaign = copy.deepcopy(self.campaign)
        campaign["review_jobs"] = []
        with self.assertRaises(ValueError):
            bridge.prepare(campaign, self.run)
        campaign = copy.deepcopy(self.campaign)
        campaign["program_policy"]["checks"][0]["allowed_by_saved_preflight"] = False
        with self.assertRaises(ValueError):
            bridge.prepare(campaign, self.run)


if __name__ == "__main__":
    unittest.main()
