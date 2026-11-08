"""CLI-level offline integration tests of the complete intelligence pipeline.

These tests deliberately start real Python subprocesses, parse their
on-disk JSON outputs and never contact remote endpoints or use credentials.
They complement, rather than duplicate, mocked unit tests.
"""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "skills/bounty-pilot/scripts"


def write(path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj), encoding="utf-8")
    return path


def call(script, args, output):
    argv = [sys.executable, str(SCRIPTS / script)] + list(args) + [
        "--out", str(output)]
    result = subprocess.run(argv, capture_output=True, text=True, timeout=15)
    if result.returncode:
        raise AssertionError(
            "%s returned %d\nstdout=%s\nstderr=%s" %
            (script, result.returncode, result.stdout[:1000],
             result.stderr[:1000]))
    if not output.is_file():
        raise AssertionError("missing actual JSON output: " + str(output))
    return json.loads(output.read_text(encoding="utf-8"))


def sample_scope(when, assets):
    return {
        "schema_version": 1,
        "snapshot_at": when,
        "programs": [{
            "id": "test", "platform": "Bugcrowd",
            "program_url": "https://bugcrowd.com/engagements/test",
            "program_type": "paid_bounty", "in_scope": assets,
            "out_of_scope": [],
        }]
    }


class EndToEndCLI(unittest.TestCase):
    def test_saved_scope_js_openapi_to_correlation_and_auth_dry_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            before = write(
                root / "scope-before.json",
                sample_scope("2026-11-01T00:00:00Z", []))
            after = write(
                root / "scope-after.json",
                sample_scope("2026-11-02T00:00:00Z", [
                    {"name": "https://app.example.test",
                     "asset_type": "website", "bounty_eligible": True}
                ]))
            scope_out = root / "scope-leads.json"
            scope_result = call("program_scope_radar.py",
                                ["--before", str(before), "--after", str(after)],
                                scope_out)
            self.assertEqual(scope_result["count"], 1)
            self.assertEqual(scope_result["leads"][0]["kind"], "in_scope-added")

            old_dir, new_dir = root / "old", root / "new"
            old_dir.mkdir()
            new_dir.mkdir()
            (old_dir / "app.js").write_text('fetch("/api/v1/owned");',
                                           encoding="utf-8")
            (new_dir / "app.js").write_text(
                'const authorization=true;'
                'fetch("/api/v1/owned");fetch("/api/v1/refunds?token=SECRET_VALUE");',
                encoding="utf-8")
            old_js = write(old_dir / "manifest.json", {
                "schema_version": 1, "captured_at": "2026-11-01T00:00:00Z",
                "assets": [{"id": "app", "file": "app.js",
                            "script_url": "https://app.example.test/app.js"}]})
            new_js = write(new_dir / "manifest.json", {
                "schema_version": 1, "captured_at": "2026-11-02T00:00:00Z",
                "assets": [{"id": "app", "file": "app.js",
                            "script_url": "https://app.example.test/app.js"}]})
            js_out = root / "js-leads.json"
            js_result = call("js_change_intel.py", [
                "--before", str(old_js), "--after", str(new_js)], js_out)
            self.assertGreater(js_result["count"], 0)
            self.assertTrue(any(x.get("endpoint") == "/api/v1/refunds"
                                for x in js_result["leads"]))
            self.assertNotIn("SECRET_VALUE", json.dumps(js_result))

            api = write(root / "openapi.json", {
                "openapi": "3.0.3", "paths": {
                    "/api/v1/orders/{id}": {
                        "get": {"operationId": "getOrder", "security": [
                            {"BearerAuth": []}]},
                        "post": {"operationId": "changeOrder"}},
                    "/health": {"get": {"operationId": "health"}},
                }})
            api_out = root / "api-leads.json"
            api_result = call("api_surface_import.py", ["--spec", str(api)], api_out)
            self.assertEqual(api_result["count"], 2)

            queue_out = root / "review-queue.json"
            queue_result = call("target_intel_queue.py", [
                "--program-leads", str(scope_out),
                "--js-leads", str(js_out),
                "--openapi-leads", str(api_out),
                "--api-host", "app.example.test"], queue_out)
            self.assertEqual(queue_result["execution"],
                             "offline-review-prioritization-only")
            self.assertGreater(queue_result["written"], 2)
            relevant = [r for r in queue_result["leads"]
                        if r["source"] in ("javascript", "openapi")]
            self.assertTrue(any(r["matching_scope_change_urls"] for r in relevant))
            self.assertNotIn("SECRET_VALUE", json.dumps(queue_result))
            self.assertTrue(all(r["requires_official_scope_recheck"]
                                for r in queue_result["leads"]))

            owned_plan = write(root / "authorization-plan.json", {
                "schema_version": 1,
                "base_url": "https://app.example.test",
                "test_actors": {
                    "owner": {"bearer_env": "BP_TEST_OWNER_TOKEN"},
                    "outsider": {"bearer_env": "BP_TEST_OTHER_TOKEN"},
                },
                "cases": [{
                    "id": "private-order", "private_resource_confirmed": True,
                    "owner_resource": "/api/v1/orders/101",
                    "outsider_control_resource": "/api/v1/orders/102",
                    "owner_marker": "OWNER-MARKER-EXAMPLE-001",
                    "outsider_control_marker": "OTHER-MARKER-EXAMPLE-002",
                }]
            })
            auth_out = root / "auth-dry-run.json"
            dry = call("web_auth_lab.py", ["--plan", str(owned_plan)], auth_out)
            self.assertEqual(dry["execution"], "dry-run")
            self.assertEqual(dry["cases"], 1)
            self.assertNotIn("OWNER-MARKER-EXAMPLE-001", json.dumps(dry))

    def test_offline_economic_deep_and_onchain_radar_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            commit = "a" * 40
            deep_spec = write(root / "flows.json", {
                "schema_version": 1, "source_revision": commit,
                "flows": [
                    {"id": "vault-withdrawal", "kind": "vault",
                     "in_scope": True, "value_at_risk_usd": "120000",
                     "unprivileged_reachable": True,
                     "changed_since_audit": True, "known_duplicate": False},
                    {"id": "bridge-exit", "kind": "bridge",
                     "in_scope": False, "value_at_risk_usd": "999999999"},
                ]
            })
            deep = call("deep_audit.py", [
                "--spec", str(deep_spec)], root / "deep-output.json")
            self.assertEqual(deep["execution"], "planning-only")
            self.assertEqual(len(deep["flows_selected"]), 1)

            addr = "0x" + ("1" * 40)
            old = write(root / "chain-old.json", {
                "schema_version": 1, "chain_id": 1, "block": 100,
                "targets": [{"address": addr, "errors": [], "reads": {
                    "pause": False}}]
            })
            new = write(root / "chain-new.json", {
                "schema_version": 1, "chain_id": 1, "block": 101,
                "targets": [{"address": addr, "errors": [], "reads": {
                    "pause": True}}]
            })
            chain = call("target_radar.py", [
                "--before", str(old), "--after", str(new)],
                root / "chain-leads.json")
            self.assertEqual(chain["leads"][0]["kind"], "deployed-config-changed")

            def measurement(balance_after, harm, violation):
                return {
                    "assets": [{
                        "id": "USDC", "decimals": 6, "before_raw": "1000000",
                        "after_raw": str(balance_after), "price_usd": "1"}],
                    "liabilities": [],
                    "unreflected_costs_usd": {
                        "gas": "0", "protocol_fees": "0",
                        "funding_fees": "0", "slippage": "0",
                        "unrecovered_capital": "0"},
                    "victim_loss_usd": str(harm),
                    "invariant": {"id": "correctness-rule", "violated": violation},
                }
            attestation_keys = [
                "native_execution", "paired_same_initial_state",
                "unmodified_target", "realistic_capital", "no_balance_cheatcodes",
                "all_positions_enumerated", "flash_loans_fully_repaid",
                "prices_pinned", "receipts_preserved"
            ]
            measurements = write(root / "observations.json", {
                "schema_version": 1,
                "source_revision": commit, "chain_id": 1, "fork_block": 100,
                "initial_state_digest": "b" * 64,
                "experiments": [{
                    "id": "paired-local-fixture",
                    "candidate": measurement(1200000, 1, True),
                    "negative_control": measurement(1000000, 0, False),
                    "attestations": {k: True for k in attestation_keys},
                }]
            })
            oracle = call("exploit_oracle.py", [
                "--measurements", str(measurements)],
                root / "oracle.json")
            self.assertEqual(oracle["candidates"], 1)
            self.assertEqual(oracle["results"][0]["candidate_net_usd"], "0.2")
            self.assertEqual(oracle["proof_level"],
                             "untrusted-native-harness-observation")

    def test_out_of_scope_and_non_bounty_assets_never_get_priority_boost(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            js = write(root / "js-leads.json", {
                "schema_version": 1,
                "leads": [{
                    "kind": "endpoint-added",
                    "endpoint": "/api/private",
                    "script_id": "app",
                    "script_url": "https://app.example.test/app.js",
                }]
            })
            for scenario, listed_kind, eligible in [
                ("excluded", "out_of_scope-added", True),
                ("historic-excluded",
                 "history-policy.asset_scope.out_of_scope-added", None),
                ("ineligible", "in_scope-added", False),
            ]:
                scope = write(root / (scenario + ".json"), {
                    "schema_version": 1,
                    "leads": [{
                        "kind": listed_kind,
                        "program_url": "https://bugcrowd.com/engagements/test",
                        "asset": {
                            "value": "app.example.test", "type": "website",
                            "bounty_eligible": eligible,
                        },
                    }]
                })
                output = root / (scenario + "-queue.json")
                result = call("target_intel_queue.py", [
                    "--program-leads", str(scope),
                    "--js-leads", str(js)], output)
                js_lead = next(r for r in result["leads"]
                               if r["source"] == "javascript")
                self.assertEqual(
                    js_lead["priority_score"], 75,
                    msg="out-of-scope or ineligible boosted: " + scenario)
                self.assertEqual(js_lead["matching_scope_change_urls"], [])


if __name__ == "__main__":
    unittest.main()
