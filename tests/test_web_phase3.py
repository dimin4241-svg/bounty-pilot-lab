"""Phase 3 Web research lab: scope gates, actor effects, browser trust, parser and root-cause queues."""
import datetime as dt
import hashlib
import importlib.util
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "skills" / "bounty-pilot" / "scripts"


def module(name):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / (name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


policy = module("web_program_policy")
actor = module("web_actor_state_graph")
effect = module("web_effect_oracle")
browser = module("web_browser_trust_graph")
parserlab = module("web_parser_lab")
dedup = module("web_root_cause_dedup")
NOW = dt.datetime(2026, 11, 11, tzinfo=dt.timezone.utc)


def program():
    return {
        "schema_version": 1, "platform": "bizone", "program_id": "synthetic",
        "status": "active",
        "source_url": "https://bugbounty.bi.zone/companies/synthetic",
        "rules_sha256": "a" * 64, "reviewed_at": "2026-11-10T00:00:00Z",
        "expires_at": "2026-11-25T00:00:00Z",
        "include": [{"origin": "https://api.demo.test",
                     "path_prefix": "/v1", "actions": [
                         "read-only", "account-test", "automation"]}],
        "exclude": [{"origin": "https://api.demo.test",
                     "path_prefix": "/v1/admin", "actions": [
                         "read-only", "account-test", "automation"]}],
        "required_headers": ["X-Research-ID"], "operator_reviewed": True
    }


def request(url="https://api.demo.test/v1/orders", action="read-only"):
    return {"id": "test1", "url": url, "action": action,
            "provided_header_names": ["X-Research-ID"]}


def action_event(idx, user, res, observed=None, kind="read", evidence=None):
    return {"id": "e" + str(idx), "seq": idx, "type": "action", "actor": user,
            "resource": res, "action": kind, "subject": None, "new_owner": None,
            "observed_effect": observed, "evidence_sha256": evidence}


def grant_event(idx, typ, user="owner", subject="guest"):
    return {"id": "e" + str(idx), "seq": idx, "type": typ, "actor": user,
            "resource": "invoice1", "action": "read", "subject": subject,
            "new_owner": None, "observed_effect": None, "evidence_sha256": None}


def actor_doc(events):
    return {
        "schema_version": 1, "environment": "researcher_owned_lab",
        "actors": [{"id": "owner", "tenant": "t1"},
                   {"id": "guest", "tenant": "t1"},
                   {"id": "outsider", "tenant": "t2"}],
        "resources": [{"id": "invoice1", "owner": "owner",
                       "tenant": "t1", "visibility": "private"}],
        "initial_grants": [], "events": events
    }


def obs(digest, before=1, after=2):
    return {"before": {"subscription": before}, "after": {"subscription": after},
            "evidence_sha256": ("%064x" % digest),
            "effect_observed_at_step": 2}


def effect_doc():
    return {"schema_version": 1, "environment": "researcher_owned_lab",
            "cases": [{
                "id": "case1", "resource_kind": "subscription",
                "business_effect": "plan_activated",
                "predicate": {"field": "subscription",
                              "relation": "increased", "value": None},
                "candidate_repetitions": [obs(1), obs(2)],
                "negative_control": [obs(3, after=1), obs(4, after=1)]
            }]}


def browser_doc():
    return {
        "schema_version": 1, "environment": "offline_owned_source_or_fixture",
        "nodes": [
            {"id": "markdown", "kind": "user-content", "trust": "untrusted",
             "sensitive": False, "user_controlled": True},
            {"id": "url-checker", "kind": "origin-validator", "trust": "trusted",
             "sensitive": False, "user_controlled": False},
            {"id": "remote-image", "kind": "third-party-origin", "trust": "untrusted",
             "sensitive": False, "user_controlled": False},
            {"id": "credential-event", "kind": "sensitive-operation", "trust": "trusted",
             "sensitive": True, "user_controlled": False}],
        "edges": [
            {"from": "markdown", "to": "url-checker", "kind": "validates-url",
             "observed_in_source": True, "evidence_sha256": "a" * 64},
            {"from": "url-checker", "to": "remote-image", "kind": "fetches",
             "observed_in_source": True, "evidence_sha256": "b" * 64},
            {"from": "remote-image", "to": "credential-event", "kind": "sends-auth",
             "observed_in_source": True, "evidence_sha256": "c" * 64}
        ]}


def lead(ident, file="src/api.ts", invariant="owner-only", boundary="tenant-a",
         anchor="getPayment", cause=None, disposition="unreviewed", score=2):
    return {"id": ident, "source_file": file, "code_anchor": anchor,
            "invariant_id": invariant, "trust_boundary_id": boundary,
            "reviewed_root_cause_id": cause, "claimed_effect_id": "read",
            "evidence": {x: score for x in dedup.FIELDS},
            "evidence_digest": None, "disposition": disposition}


def dedup_doc(rows):
    return {"schema_version": 1, "project": "lab-demo",
            "pinned_revision": "f" * 40, "candidates": rows}


class ProgramPolicyTests(unittest.TestCase):
    def test_narrow_permitted_preflight_only(self):
        out = policy.evaluate(program(), [request()], NOW)
        self.assertTrue(out["checks"][0]["allowed_by_saved_preflight"])
        self.assertEqual(out["status"], "OFFLINE_PREFLIGHT_NOT_PERMISSION")
        self.assertEqual(out["network_requests"], 0)

    def test_exclusion_and_boundary_prevent_prefix_confusion(self):
        cases = [request("/not-url"), request("https://api.demo.test/v1/admin"),
                 request("https://api.demo.test/v1/admin-foo"),
                 request("https://api.demo.test/v1admin")]
        for i, case in enumerate(cases):
            case["id"] = "test" + str(i + 1)
        out = policy.evaluate(program(), cases, NOW)
        self.assertEqual([x["allowed_by_saved_preflight"] for x in out["checks"]],
                         [False, False, True, False])
        self.assertIn("EXPLICIT_EXCLUSION", out["checks"][1]["reasons"])

    def test_subdomains_wildcards_default_denied(self):
        self.assertFalse(policy.evaluate(program(),
            [request("https://nested.api.demo.test/v1/orders")], NOW)[
                "checks"][0]["allowed_by_saved_preflight"])
        raw = program()
        raw["include"][0]["origin"] = "https://*.demo.test"
        with self.assertRaises(ValueError):
            policy.evaluate(raw, [request()], NOW)

    def test_ambiguous_path_rejected(self):
        for raw in ("https://api.demo.test/v1/%2fadmin",
                    "https://api.demo.test/v1/%252e%252e",
                    "https://api.demo.test/v1/../admin",
                    "https://api.demo.test/v1/orders?key=secret",
                    "https://user:pass@api.demo.test/v1/orders"):
            out = policy.evaluate(program(), [request(raw)], NOW)
            self.assertFalse(out["checks"][0]["allowed_by_saved_preflight"], raw)

    def test_expired_unreviewed_paused_missing_header_denied(self):
        for change, val in (("status", "paused"), ("operator_reviewed", False),
                            ("expires_at", "2026-11-10T01:00:00Z")):
            raw = program()
            raw[change] = val
            result = policy.evaluate(raw, [request()], NOW)
            self.assertFalse(result["checks"][0]["allowed_by_saved_preflight"])
        r = request()
        r["provided_header_names"] = []
        self.assertIn("MISSING_REQUIRED_HEADER_NAMES",
                      policy.evaluate(program(), [r], NOW)["checks"][0]["reasons"])

    def test_duplicate_plan_ids_and_encoded_nonseparator_denied(self):
        with self.assertRaises(ValueError):
            policy.evaluate(program(), [request(), request()], NOW)
        out = policy.evaluate(program(), [
            request("https://api.demo.test/v1/%41ccount")], NOW)
        self.assertFalse(out["checks"][0]["allowed_by_saved_preflight"])

    def test_fails_closed_on_stale_schema_and_duplicate_keys(self):
        raw = program()
        raw["unknown"] = "ignore me"
        with self.assertRaises(ValueError):
            policy.evaluate(raw, [request()], NOW)
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "duplicate.json"
            p.write_text('{"a":1,"a":2}')
            with self.assertRaises(ValueError):
                policy.load(p)


class ActorGraphTests(unittest.TestCase):
    def test_cross_owner_effect_is_review_lead_not_confirmed(self):
        res = actor.analyze(actor_doc([action_event(1, "guest", "invoice1", True,
                                                   evidence="a" * 64)]))
        self.assertEqual(len(res["leads"]), 1)
        self.assertEqual(res["leads"][0]["kind"],
                         "DECLARED_ACTOR_POLICY_CONTRADICTION")
        self.assertEqual(res["confirmed_vulnerabilities"], 0)

    def test_revocation_persistence_and_granted_access(self):
        events = [
            grant_event(1, "grant"),
            action_event(2, "guest", "invoice1", True),
            grant_event(3, "revoke"),
            action_event(4, "guest", "invoice1", True, evidence="b" * 64)]
        res = actor.analyze(actor_doc(events))
        self.assertEqual(len(res["leads"]), 1)
        self.assertEqual(res["leads"][0]["kind"], "REVOKED_GRANT_STILL_EFFECTIVE")
        self.assertTrue(res["transition_facts"][0]["expected_allow"])
        self.assertFalse(res["transition_facts"][1]["expected_allow"])

    def test_unknown_http_status_cannot_prove_effect(self):
        res = actor.analyze(actor_doc([action_event(1, "guest", "invoice1", None)]))
        self.assertEqual(res["leads"], [])
        self.assertEqual(res["unknowns"][0]["reason"], "NO_EFFECT_OBSERVATION")

    def test_cross_tenant_grant_does_not_override_tenant_boundary(self):
        docs = actor_doc([grant_event(1, "grant", subject="outsider"),
                          action_event(2, "outsider", "invoice1", True)])
        res = actor.analyze(docs)
        self.assertEqual(len(res["leads"]), 1)

    def test_public_only_allows_read_and_transfer_changes_owner(self):
        d = actor_doc([action_event(1, "guest", "invoice1", True),
                       {"id": "e2", "seq": 2, "type": "transfer",
                        "actor": "owner", "resource": "invoice1",
                        "action": None, "subject": None, "new_owner": "guest",
                        "observed_effect": None, "evidence_sha256": None},
                       action_event(3, "guest", "invoice1", True)])
        res = actor.analyze(d)
        self.assertEqual(len(res["leads"]), 1)
        self.assertTrue(res["transition_facts"][1]["expected_allow"])

    def test_reject_duplicate_or_out_of_order_events(self):
        d = actor_doc([action_event(2, "guest", "invoice1"),
                       action_event(1, "guest", "invoice1")])
        with self.assertRaises(ValueError):
            actor.analyze(d)


class EffectOracleTests(unittest.TestCase):
    def test_repeated_business_effect_with_stable_controls(self):
        res = effect.analyze(effect_doc())
        self.assertEqual(res["controlled_effect_leads"], 1)
        self.assertEqual(res["confirmed_vulnerabilities"], 0)
        self.assertEqual(res["results"][0]["evidence_digest_count"], 4)

    def test_changed_control_blocks_proof(self):
        d = effect_doc()
        d["cases"][0]["negative_control"][1]["after"]["subscription"] = 2
        res = effect.analyze(d)
        self.assertEqual(res["controlled_effect_leads"], 0)
        self.assertEqual(res["results"][0]["status"], "INCONCLUSIVE_NEGATIVE_CONTROL_CHANGED")

    def test_inconsistent_cand_repetitions_blocks_proof(self):
        d = effect_doc()
        d["cases"][0]["candidate_repetitions"][0]["after"]["subscription"] = 1
        res = effect.analyze(d)
        self.assertEqual(res["results"][0]["status"],
                         "INCONCLUSIVE_INCONSISTENT_REPETITIONS")

    def test_initial_state_mismatch_and_repeat_hash_denied(self):
        d = effect_doc()
        d["cases"][0]["negative_control"][0]["before"]["subscription"] = 42
        with self.assertRaises(ValueError):
            effect.analyze(d)
        d = effect_doc()
        d["cases"][0]["negative_control"][0]["evidence_sha256"] = (
            d["cases"][0]["candidate_repetitions"][0]["evidence_sha256"])
        with self.assertRaises(ValueError):
            effect.analyze(d)

    def test_missing_state_value_is_not_http_status(self):
        d = effect_doc()
        d["cases"][0]["candidate_repetitions"][0]["before"] = {"status": 200}
        with self.assertRaises(ValueError):
            effect.analyze(d)


class BrowserTrustTests(unittest.TestCase):
    def test_cross_boundary_with_explicit_privileged_edge(self):
        res = browser.analyze(browser_doc())
        self.assertEqual(len(res["review_paths"]), 1)
        self.assertEqual(res["review_paths"][0]["status"],
                         "STATIC_SOURCE_BACKED_REVIEW_LEAD")
        self.assertEqual(res["confirmed_vulnerabilities"], 0)

    def test_no_privilege_transport_no_claim(self):
        doc = browser_doc()
        doc["edges"][-1]["kind"] = "reads-data"
        self.assertEqual(browser.analyze(doc)["review_paths"], [])

    def test_unknown_evidence_downgrades_review_lead(self):
        doc = browser_doc()
        doc["edges"][0]["evidence_sha256"] = None
        self.assertEqual(browser.analyze(doc)["review_paths"][0]["status"],
                         "UNVERIFIED_DECLARED_PATH")

    def test_untrusted_sink_without_crossed_boundary_not_promoted(self):
        doc = browser_doc()
        for node in doc["nodes"]:
            node["trust"] = "untrusted"
        self.assertEqual(browser.analyze(doc)["review_paths"], [])


class ParserLabTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("node"), "Node.js local WHATWG parser required")
    def test_real_local_node_python_url_differential(self):
        doc = {"schema_version": 1,
               "environment": "synthetic_offline_fixtures",
               "pairs": [{"id": "port443",
                          "candidate_url": "https://parser.invalid:443/a",
                          "negative_control_url": "https://parser.invalid/a"}]}
        result = parserlab.analyze(doc)
        self.assertEqual(result["controlled_leads"], 1)
        self.assertIn("PORT_NORMALIZATION_DIFFERENCE",
                      result["pairs"][0]["candidate_differences"])
        self.assertEqual(result["network_requests"], 0)
        self.assertNotIn("https://parser.invalid", json.dumps(result))

    def test_reject_external_url_and_userinfo(self):
        doc = {"schema_version": 1,
               "environment": "synthetic_offline_fixtures",
               "pairs": [{"id": "x", "candidate_url": "https://realbank.com/a",
                          "negative_control_url": "https://parser.invalid/a"}]}
        with self.assertRaises(ValueError):
            parserlab.analyze(doc)
        doc["pairs"][0]["candidate_url"] = "https://user:secret@parser.invalid/a"
        with self.assertRaises(ValueError):
            parserlab.analyze(doc)

    def test_negative_control_must_differ(self):
        with self.assertRaises(ValueError):
            parserlab.analyze({"schema_version": 1,
                               "environment": "synthetic_offline_fixtures",
                               "pairs": [{"id": "x",
                                          "candidate_url": "https://parser.invalid/a",
                                          "negative_control_url": "https://parser.invalid/a"}]})


class RootCauseTests(unittest.TestCase):
    def test_same_invariant_and_file_grouped_conservatively(self):
        result = dedup.analyze(dedup_doc([lead("a"), lead("b")]))
        self.assertEqual(len(result["groups"]), 1)
        self.assertEqual(result["groups"][0]["member_count"], 2)
        self.assertEqual(result["groups"][0]["dedup_status"],
                         "STRICT_STRUCTURAL_MATCH_NOT_VERIFIED")
        self.assertEqual(result["confirmed_vulnerabilities"], 0)

    def test_separate_files_and_different_invariants_not_merged(self):
        result = dedup.analyze(dedup_doc([
            lead("a"), lead("b", file="src/other.ts"),
            lead("c", invariant="independent-object-only")]))
        self.assertEqual(len(result["groups"]), 3)
        self.assertEqual(len(result["review_related"]), 1)

    def test_explicit_reviewed_root_cause_group_and_rank(self):
        result = dedup.analyze(dedup_doc([
            lead("one", cause="reviewed-issue-123", score=1),
            lead("two", file="other.ts", cause="reviewed-issue-123", score=2)]))
        self.assertEqual(len(result["groups"]), 1)
        self.assertEqual(result["groups"][0]["preferred_review_id"], "two")
        self.assertEqual(result["groups"][0]["top_evidence_score_0_to_10"], 10)

    def test_refuted_and_parked_queue_priority_is_bounded(self):
        result = dedup.analyze(dedup_doc([
            lead("park", disposition="parked", score=2),
            lead("active", disposition="unreviewed", score=1),
            lead("refuted", disposition="refuted", score=2)]))
        self.assertEqual(result["groups"][0]["preferred_review_id"], "active")
        self.assertEqual(result["groups"][0]["top_evidence_score_0_to_10"], 5)

    def test_duplicate_ids_and_bad_pinned_commit_fail(self):
        with self.assertRaises(ValueError):
            dedup.analyze(dedup_doc([lead("same"), lead("same")]))
        x = dedup_doc([lead("a")])
        x["pinned_revision"] = "main"
        with self.assertRaises(ValueError):
            dedup.analyze(x)

    def test_immutable_private_output_permissions(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "report.json"
            result = dedup.analyze(dedup_doc([lead("a")]))
            dedup._write(p, result)
            self.assertEqual(p.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(ValueError):
                dedup._write(p, result)


if __name__ == "__main__":
    unittest.main()
