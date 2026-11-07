"""Offline contract tests for optional Target Intel + Web/API Lab modules.

Never contacts a target, runs a native exploit or calls real jsluice. The
self-hosted Mac workflow is the only configured runner for this test file.
"""
import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1] / "skills/bounty-pilot/scripts"


def load(name):
    spec = importlib.util.spec_from_file_location("target_lab_" + name,
                                                  SCRIPTS / (name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


scope = load("program_scope_radar")
js = load("js_change_intel")
auth = load("web_auth_lab")
openapi = load("api_surface_import")
queue = load("target_intel_queue")


def programs(at, assets=None, program_type="paid_bounty"):
    return {"schema_version": 1, "snapshot_at": at,
            "programs": [{"id": "test-platform", "platform": "Bugcrowd",
                          "program_url": "https://bugcrowd.com/engagements/test-platform",
                          "program_type": program_type,
                          "in_scope": assets if assets is not None else [
                              {"name": "api.example.test", "asset_type": "api",
                               "bounty_eligible": True}],
                          "out_of_scope": []}]}


def auth_plan():
    return {
        "schema_version": 1,
        "base_url": "https://api.example.test",
        "program_url": "https://example.test/bug-bounty",
        "scope_confirmed_at": "2026-11-07T09:00:00Z",
        "authorization_confirmed": True,
        "automation_permitted": True,
        "test_actors": {
            "owner": {"bearer_env": "BP_TEST_OWNER_AUTH"},
            "outsider": {"bearer_env": "BP_TEST_OUTSIDER_AUTH"}},
        "cases": [{
            "id": "my-invoice", "private_resource_confirmed": True,
            "owner_resource": "/api/invoices/101",
            "outsider_control_resource": "/api/invoices/102",
            "owner_marker": "PRIVATE-INVOICE-OWNER-ABC123",
            "outsider_control_marker": "PRIVATE-INVOICE-OUTSIDER-DEF456",
        }],
    }


class ProgramScopeRadarTests(unittest.TestCase):
    def test_added_scope_and_changed_eligibility(self):
        a = programs("2026-11-01T00:00:00Z")
        b = programs("2026-11-02T00:00:00Z", [
            {"name": "api.example.test", "asset_type": "api",
             "bounty_eligible": False},
            {"name": "wallet.example.test", "asset_type": "website",
             "bounty_eligible": True},
        ])
        got = scope.compare(a, b)
        self.assertEqual({item["kind"] for item in got["leads"]},
                         {"in_scope-added", "in_scope-eligibility-changed"})
        self.assertIn("not", got["notice"].lower())

    def test_removed_program_not_considered_closed(self):
        before = programs("2026-11-01T00:00:00Z")
        after = {"schema_version": 1, "snapshot_at": "2026-11-02T00:00:00Z",
                 "programs": []}
        got = scope.compare(before, after)
        self.assertEqual(got["leads"][0]["kind"], "program-missing-in-snapshot")
        self.assertIn("not necessarily closed", got["leads"][0]["review"])

    def test_reject_ambiguous_in_and_out_scope(self):
        x = programs("2026-11-01T00:00:00Z")
        x["programs"][0]["out_of_scope"] = [
            {"name": "api.example.test", "asset_type": "api"}]
        with self.assertRaisesRegex(ValueError, "simultaneously"):
            scope.normalize(x)

    def test_library_programs_conversion(self):
        lib = {"schema_version": "1.5.0",
               "programs": [{
                   "id": "test", "platform": "Intigriti",
                   "program_url": "https://app.intigriti.com/programs/abc/test",
                   "last_verified_at": "2026-11-02T00:00:00Z",
                   "program_type": {"value": "paid_bounty"},
                   "asset_scope": {"in_scope": [{
                       "name": "*.example.test", "asset_type": "website",
                       "bounty_eligible": True}]}
               }]}
        converted = scope.normalize(lib)
        self.assertEqual(converted["count"], 1)
        self.assertEqual(converted["snapshot_at"], "2026-11-02T00:00:00+00:00")

    def test_security_library_recorded_history_not_equated_to_effective_date(self):
        item = {"schema_version": "1.0.0", "entries": [{
            "recorded_at": "2026-11-07T10:00:00Z",
            "changes": [{
                "name": "Program A", "platform": "Bugcrowd",
                "program_url": "https://bugcrowd.com/test",
                "fields": [{"field": "capture.in_scope",
                            "added": [{"name": "new-api.example.test",
                                       "asset_type": "api"}],
                            "removed": []}]
            }]
        }]}
        got = scope.from_library_history(item)
        self.assertEqual(got["count"], 1)
        self.assertEqual(got["leads"][0]["kind"], "history-capture.in_scope-added")
        self.assertIn("NOT", got["notice"])


class JSChangeTests(unittest.TestCase):
    def samples(self, root):
        a = root / "previous"
        b = root / "current"
        a.mkdir()
        b.mkdir()
        (a / "bundle.js").write_text(
            'fetch("/api/invoices/10?token=BEFORESECRET");', encoding="utf-8")
        (b / "bundle.js").write_text(
            'const authorization=true;fetch("/api/invoices/10?token=AFTERSECRET");'
            'fetch("/api/invoices/11?order=12");', encoding="utf-8")
        old = {"schema_version": 1, "captured_at": "2026-11-01T00:00:00Z",
               "assets": [{"id": "app-bundle", "script_url": "https://app.example.test/bundle-1.js",
                           "file": "bundle.js"}]}
        new = {"schema_version": 1, "captured_at": "2026-11-02T00:00:00Z",
               "assets": [{"id": "app-bundle", "script_url": "https://app.example.test/bundle-2.js",
                           "file": "bundle.js"}]}
        return old, new, a, b

    def test_new_api_and_secret_redaction(self):
        with tempfile.TemporaryDirectory() as tmp:
            previous, current, before, after = self.samples(Path(tmp))
            got = js.compare(previous, current, before, after)
            self.assertEqual(got["method"], "local-lexical")
            self.assertTrue(any(x["kind"] == "endpoint-added" and
                                x["endpoint"] == "/api/invoices/11"
                                for x in got["leads"]))
            self.assertIn("authorization", [x for x in got["leads"]
                                           if x["kind"] == "js-source-changed"][0]["present_topics"])
            self.assertNotIn("AFTERSECRET", json.dumps(got))
            self.assertNotIn("BEFORESECRET", json.dumps(got))

    def test_external_js_file_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            previous, current, before, after = self.samples(Path(tmp))
            previous["assets"][0]["file"] = "../current/bundle.js"
            with self.assertRaisesRegex(ValueError, "snapshot directory"):
                js.compare(previous, current, before, after)

    def test_optional_jsluice_only_local_fixed_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / "a.js"
            file.write_text("const x=1;")
            parsed = subprocess.CompletedProcess(
                ["jsluice"], 0, '{"url":"/api/private?token=never-output"}\n', "")
            with patch.object(js.subprocess, "run", return_value=parsed) as call:
                results = js.jsluice_local(file)
            self.assertIn(("/api/private", ("token",)), results)
            argv = call.call_args[0][0]
            self.assertEqual(argv[:3], ["jsluice", "urls", "-u"])
            self.assertEqual(argv[3], str(file))

    def test_invalid_scheme_not_leaked_as_endpoint(self):
        self.assertIsNone(js.route("javascript:alert(1)"))
        self.assertIsNone(js.route("//attacker.example/path"))


class OpenAPIImportTests(unittest.TestCase):
    def test_get_only_and_template_review(self):
        spec = {"openapi": "3.0.3", "paths": {
            "/api/v1/invoices/{invoiceId}": {
                "get": {"operationId": "getInvoice", "security": [{"BearerAuth": []}]},
                "delete": {"operationId": "deleteInvoice"}},
            "/health": {"get": {"operationId": "health"}}}}
        x = openapi.build(spec)
        self.assertEqual(x["count"], 2)
        self.assertEqual(x["leads"][0]["parameter_names"], ["invoiceId"])
        self.assertEqual(x["leads"][0]["review_category"], "object-identifier-review")
        self.assertTrue(x["leads"][0]["advertised_security"])


class WebAuthLabTests(unittest.TestCase):
    def test_authorization_plan_validated(self):
        p = auth_plan()
        self.assertEqual(auth.validate(p, "api.example.test"), p["base_url"])
        with self.assertRaisesRegex(ValueError, "differs"):
            auth.validate(p, "different.example.test")
        p["cases"][0]["owner_resource"] = "//other.example.test/secret"
        with self.assertRaisesRegex(ValueError, "same-origin"):
            auth.validate(p, "api.example.test")

    def test_different_test_accounts_mandatory(self):
        p = auth_plan()
        p["test_actors"]["outsider"]["bearer_env"] = "BP_TEST_OWNER_AUTH"
        with self.assertRaisesRegex(ValueError, "different"):
            auth.validate(p, "api.example.test")

    def test_private_confirmation_required(self):
        p = auth_plan()
        p["cases"][0]["private_resource_confirmed"] = False
        with self.assertRaisesRegex(ValueError, "private_resource_confirmed"):
            auth.validate(p, "api.example.test")

    def test_case_is_only_candidate_if_all_three_observations_valid(self):
        c = auth_plan()["cases"][0]
        valid = {"complete": True, "status": 200, "marker_present": True,
                 "body_sha256": "0" * 64}
        denied = dict(valid, status=403, marker_present=False)
        self.assertEqual(auth.evaluate_case(c, valid, valid, valid)["status"],
                         "cross-account-exposure-candidate-needs-review")
        self.assertEqual(auth.evaluate_case(c, valid, denied, valid)["status"], "inconclusive")
        self.assertEqual(auth.evaluate_case(c, valid, valid, denied)["status"], "inconclusive")

    def test_controlled_replay_mock_has_no_real_network(self):
        p = auth_plan()
        p["scope_confirmed_at"] = "2026-11-07T09:00:00Z"
        # Avoid clock-dependent policy attestation: test replay with the
        # validation gate stubbed; production validate checks policy freshness.
        observed = []
        def fake_fetch(_opener, url, token, marker):
            observed.append((url, token, marker))
            return {"complete": True, "status": 200, "marker_present": True,
                    "body_sha256": "a" * 64}
        with patch.object(auth, "validate", return_value=p["base_url"]), \
             patch.object(auth, "fetch", side_effect=fake_fetch), \
             patch.object(auth.time, "sleep"), \
             patch.dict(os.environ, {"BP_TEST_OWNER_AUTH": "secret-owner-token",
                                     "BP_TEST_OUTSIDER_AUTH": "secret-outsider-token"}):
            got = auth.run(p, "api.example.test")
        self.assertEqual(got["candidates"], 1)
        self.assertEqual(len(observed), 3)
        self.assertNotIn("secret-owner-token", json.dumps(got))
        self.assertNotIn("secret-outsider-token", json.dumps(got))


if __name__ == "__main__":
    unittest.main()
