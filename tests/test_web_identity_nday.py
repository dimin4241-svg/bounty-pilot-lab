"""Synthetic identity/intents and N-day differential tests; no public requests."""
import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills" / "bounty-pilot" / "scripts"


def load(name):
    spec = importlib.util.spec_from_file_location("test_" + name, SCRIPTS / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


identity = load("web_identity_flow")
nday = load("web_nday_regression")


class IdentityTests(unittest.TestCase):
    def test_revoked_token_replay_and_tenant_confusion(self):
        events = [
            {"kind": "issue", "session_ref": "fake-session", "subject": "alice",
             "tenant": "org-a"},
            {"kind": "revoke", "session_ref": "fake-session"},
            {"kind": "use", "session_ref": "fake-session", "subject": "alice",
             "tenant": "org-b", "accepted": True, "cross_tenant_grant": False},
        ]
        r = identity.sessions({"schema_version": 1, "events": events})
        self.assertEqual({x["kind"] for x in r["leads"]},
                         {"REVOKED_SESSION_ACCEPTED", "SESSION_TENANT_MISMATCH"})
        self.assertEqual(r["network_requests"], 0)
        self.assertEqual(r["confirmed_vulnerabilities"], 0)

    def test_new_session_not_confused_with_reissued_token(self):
        r = identity.sessions({"schema_version": 1, "events": [
            {"kind": "issue", "session_ref": "old", "subject": "a", "tenant": "x"},
            {"kind": "revoke", "session_ref": "old"},
            {"kind": "issue", "session_ref": "new", "subject": "a", "tenant": "x"},
            {"kind": "use", "session_ref": "new", "subject": "a",
             "tenant": "x", "accepted": True},
        ]})
        self.assertEqual(r["leads"], [])

    def test_intent_mismatch_requires_both_local_conditions(self):
        case = {"bound_fields": ["recipient", "amount"],
                "displayed": {"recipient": "owner", "amount": "10"},
                "signed": {"recipient": "owner", "amount": "10"},
                "executed": {"recipient": "outsider", "amount": "10"},
                "signature_verified_locally": True, "executed_locally": True}
        data = {"schema_version": 1, "cases": [case]}
        r = identity.signed_intents(data)
        self.assertEqual([x["field"] for x in r["leads"]], ["recipient"])
        case["executed_locally"] = False
        self.assertEqual(identity.signed_intents(data)["leads"], [])

    def test_tenant_private_context(self):
        events = [{"kind": "rag_retrieval", "caller_tenant": "a",
                   "resource_tenant": "b", "authorized_cross_tenant": False,
                   "allowed": True}, {"kind": "tool_use", "caller_tenant": "a"}]
        r = identity.tenant_isolation({"schema_version": 1, "events": events})
        self.assertEqual(len(r["leads"]), 1)
        self.assertEqual(r["incomplete_events"], [1])

    def test_no_credentials_written_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "evidence.json"
            identity._write(out, {"ok": True})
            self.assertEqual(out.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(ValueError):
                identity._write(out, {"ok": False})


class NdayTests(unittest.TestCase):
    def test_added_guard_generates_sibling_review(self):
        before = {"mode": "web-route-ast", "routes": [
            {"handler": "api.py:one", "method": "GET", "path": "/v1/pay",
             "guard_name_cues": [], "call_names": ["payments.lookup"]},
            {"handler": "api.py:two", "method": "GET", "path": "/v2/pay",
             "guard_name_cues": [], "call_names": ["payments.lookup"]}]}
        after = {"mode": "web-route-ast", "routes": [
            dict(before["routes"][0], guard_name_cues=["require_permission"]),
            before["routes"][1]]}
        r = nday.compare(before, after)
        self.assertEqual(len(r["leads"]), 1)
        self.assertEqual(r["leads"][0]["kind"], "AUTH_GUARD_CUE_ADDED")
        self.assertEqual(r["leads"][0]["unreviewed_sibling_candidates"][0]["path"], "/v2/pay")
        self.assertEqual(r["confirmed_vulnerabilities"], 0)
        self.assertEqual(r["network_requests"], 0)

    def test_unchanged_legacy_has_no_lead(self):
        snap = {"mode": "web-route-ast", "routes": [{
            "handler": "a.py:handler", "method": "GET", "path": "/abc",
            "guard_name_cues": [], "call_names": ["database.read"]}]}
        self.assertEqual(nday.compare(snap, snap)["leads"], [])

    def test_rejects_incompatible_snapshots(self):
        with self.assertRaises(ValueError):
            nday.compare({"mode": "not-ast"}, {"mode": "web-route-ast", "routes": []})


if __name__ == "__main__":
    unittest.main()
