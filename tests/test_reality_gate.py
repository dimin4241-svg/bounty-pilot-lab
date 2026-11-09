"""Reality-gate regressions — offline, no network and no target execution."""
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills/bounty-pilot/scripts"
sys.path.insert(0, str(SCRIPTS))


def load(name):
    path = SCRIPTS / (name + ".py")
    spec = importlib.util.spec_from_file_location("bp_" + name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gate = load("reality_gate")


def component(ident, kind, probes=None, **signals):
    row = {"id": ident, "kind": kind, "claims": ["advertised capability"],
           "probes": probes or []}
    if signals:
        row["signals"] = signals
    return row


def document(rows):
    return {"schema_version": 1, "program": "fixture", "components": rows}


class RealityGateTests(unittest.TestCase):
    def fixture(self):
        return document([
            component("drc", "onchain", assets_scanned=89, address_search_complete=True,
                      addresses_found=0,
                      probes=[{"kind": "dns", "target": "explorer.test", "status": 200}]),
            component("wallet", "client-app", assets_scanned=12,
                      client_search_complete=True,
                      client_crypto_libs=[], client_api_calls=0,
                      download_links={"total": 5, "resolving": 0},
                      probes=[{"kind": "page", "target": "https://wallet.test/", "status": 200}]),
            component("site", "api-backend", assets_scanned=40, probes=[
                {"kind": "page", "target": "https://site.test/", "status": 200},
                {"kind": "api", "target": "https://site.test/api/private", "status": 401,
                 "body_excerpt": '{"error":"Unauthorized"}'},
                {"kind": "auth", "target": "https://site.test/api/auth/callback", "status": 401,
                 "body_excerpt": "PrismaClientInitializationError FATAL: (ENOTFOUND) tenant/user postgres.abc not found"},
            ]),
            component("gated", "api-backend", probes=[
                {"kind": "api", "target": "https://gated.test/api/list", "status": 401,
                 "body_excerpt": '{"error":"Unauthorized"}'},
            ]),
            component("chain-live", "onchain", addresses_found=2, addresses_verified=2,
                      probes=[{"kind": "chain", "target": "rpc.test", "status": 200}]),
            component("api-live", "api-backend", probes=[
                {"kind": "api", "target": "https://live.test/api/feed", "status": 200,
                 "body_excerpt": '{"announcements":[{"id":1}]}'}]),
            component("address-only", "onchain", addresses_found=1, addresses_verified=0,
                      probes=[{"kind": "chain", "target": "rpc.test", "status": 200}]),
            component("empty", "infra"),
        ])

    def test_states_and_queues(self):
        out = gate.evaluate(self.fixture())
        states = {c["id"]: c["status"] for c in out["components"]}
        self.assertEqual(states["drc"], "NOT_DEPLOYED")
        self.assertEqual(states["wallet"], "MARKETING_ONLY")
        self.assertEqual(states["site"], "BACKEND_BROKEN")
        self.assertEqual(states["gated"], "AUTH_ONLY")
        self.assertEqual(states["chain-live"], "LIVE")
        self.assertEqual(states["api-live"], "LIVE")
        self.assertEqual(states["address-only"], "UNKNOWN")
        self.assertEqual(states["empty"], "UNKNOWN")
        self.assertEqual(out["status_counts"]["LIVE"], 2)
        self.assertEqual(set(out["live_components"]), {"chain-live", "api-live"})
        self.assertEqual(set(out["dead_claims"]), {"drc", "wallet"})
        self.assertEqual({b["id"] for b in out["blocked_components"]}, {"site", "gated"})
        self.assertEqual(set(out["unverified_components"]), {"address-only", "empty"})
        self.assertEqual(out["execution"], "offline-classification-of-supplied-probes")
        self.assertIn("does not prove", out["notice"])

    def test_warnings_are_component_scoped(self):
        out = gate.evaluate(self.fixture())
        warnings = set(out["warnings"])
        self.assertIn("wallet:inert-download-controls", warnings)
        self.assertIn("wallet:no-client-crypto-or-api", warnings)
        self.assertIn("address-only:addresses-without-bytecode", warnings)
        self.assertIn("empty:unprobed-component", warnings)
        self.assertNotIn("gated:api-claim-unprobed", warnings)

    def test_unprobed_claims_are_unknown_not_absent(self):
        out = gate.evaluate(document([component("contracts", "onchain")]))
        self.assertEqual(out["components"][0]["status"], "UNKNOWN")
        self.assertIn("contracts:chain-claim-unsearched", out["warnings"])
        out = gate.evaluate(document([
            component("api", "api-backend",
                      probes=[{"kind": "page", "target": "https://x.test/", "status": 200}])]))
        self.assertEqual(out["components"][0]["status"], "UNKNOWN")
        self.assertIn("api:api-claim-unprobed", out["warnings"])
        out = gate.evaluate(document([
            component("contracts-page-only", "onchain",
                      probes=[{"kind": "page", "target": "https://x.test/", "status": 200}])]))
        self.assertEqual(out["components"][0]["status"], "UNKNOWN")
        self.assertNotIn("contracts-page-only", out["dead_claims"])
        out = gate.evaluate(document([
            component("client-page-only", "client-app",
                      probes=[{"kind": "page", "target": "https://x.test/", "status": 200}])]))
        self.assertEqual(out["components"][0]["status"], "UNKNOWN")
        self.assertIn("client-page-only:client-search-incomplete", out["warnings"])

    def test_error_payloads_and_app_fallbacks_are_not_live(self):
        cases = [
            ("error-json", '{"error":"route not found"}'),
            ("problem-json", '{"title":"Not Found","status":404,"detail":"missing"}'),
            ("html-fallback", '<!doctype html><html><body>app shell</body></html>'),
            ("truncated-json", '{"items":[{"id":1}'),
            ("plain-text", "ok"),
            ("health-envelope", '{"status":"ok","uptime":120}'),
            ("json-error-string", '"route not found"'),
        ]
        for ident, excerpt in cases:
            with self.subTest(ident=ident):
                out = gate.evaluate(document([component(
                    ident, "api-backend", probes=[{
                        "kind": "api", "target": "/v1/orders", "status": 200,
                        "body_excerpt": excerpt,
                    }])]))
                self.assertEqual(out["components"][0]["status"], "UNKNOWN")
                self.assertNotIn(ident, out["live_components"])

    def test_auth_only_requires_every_api_probe_to_be_gated(self):
        out = gate.evaluate(document([component("mixed", "api-backend", probes=[
            {"kind": "api", "target": "/private", "status": 401,
             "body_excerpt": '{"error":"Unauthorized"}'},
            {"kind": "api", "target": "/missing", "status": 404,
             "body_excerpt": '{"error":"not found"}'},
        ])]))
        self.assertEqual(out["components"][0]["status"], "UNKNOWN")
        self.assertIn("mixed:api-claim-inconclusive", out["warnings"])

    def test_login_redirect_destination_is_recorded_as_auth_evidence(self):
        out = gate.evaluate(document([component("login", "api-backend", probes=[
            {"kind": "api", "target": "/private", "status": 302,
             "redirect_to": "https://example.test/login"},
        ])]))
        self.assertEqual(out["components"][0]["status"], "AUTH_ONLY")

    def test_chain_live_requires_successful_chain_probe(self):
        out = gate.evaluate(document([component(
            "rpc-down", "onchain", addresses_found=1, addresses_verified=1,
            probes=[{"kind": "chain", "target": "rpc.test", "status": 503}])]))
        self.assertEqual(out["components"][0]["status"], "UNKNOWN")
        self.assertIn("rpc-down:chain-probe-inconclusive", out["warnings"])

    def test_evidence_must_match_the_claimed_component_kind(self):
        api_is_not_chain = gate.evaluate(document([component(
            "api-only", "onchain", probes=[{
                "kind": "api", "target": "/status", "status": 200,
                "body_excerpt": '{"contracts":[]}',
            }])]))
        self.assertEqual(api_is_not_chain["components"][0]["status"], "UNKNOWN")
        self.assertNotIn("api-only", api_is_not_chain["live_components"])

    def test_address_absence_requires_explicit_complete_search(self):
        partial = gate.evaluate(document([component(
            "partial-scan", "onchain", assets_scanned=1, addresses_found=0,
            probes=[{"kind": "page", "target": "https://example.test/", "status": 200}])]))
        self.assertEqual(partial["components"][0]["status"], "UNKNOWN")
        self.assertNotIn("partial-scan", partial["dead_claims"])
        complete = gate.evaluate(document([component(
            "complete-scan", "onchain", assets_scanned=1,
            address_search_complete=True, addresses_found=0)]))
        self.assertEqual(complete["components"][0]["status"], "NOT_DEPLOYED")
        client_partial = gate.evaluate(document([component(
            "client-partial", "client-app", assets_scanned=1,
            probes=[{"kind": "page", "target": "https://example.test/", "status": 200}])]))
        self.assertEqual(client_partial["components"][0]["status"], "UNKNOWN")
        client_complete = gate.evaluate(document([component(
            "client-complete", "client-app", assets_scanned=1,
            client_search_complete=True,
            probes=[{"kind": "page", "target": "https://example.test/", "status": 200}])]))
        self.assertEqual(client_complete["components"][0]["status"], "MARKETING_ONLY")
        client_runtime = gate.evaluate(document([component(
            "client-runtime", "client-app", assets_scanned=1,
            client_search_complete=True, client_api_calls=2,
            probes=[{"kind": "page", "target": "https://example.test/", "status": 200}])]))
        self.assertEqual(client_runtime["components"][0]["status"], "UNKNOWN")
        self.assertIn("client-runtime:client-runtime-unverified", client_runtime["warnings"])

    def test_working_api_survives_a_failing_sibling_route(self):
        out = gate.evaluate(document([component("partial", "api-backend", probes=[
            {"kind": "api", "target": "/feed", "status": 200,
             "body_excerpt": '{"items":[1]}'},
            {"kind": "api", "target": "/private", "status": 503,
             "body_excerpt": "temporarily unavailable"},
        ])]))
        self.assertEqual(out["components"][0]["status"], "LIVE")
        self.assertIn("partial:partial-backend-failure", out["warnings"])

    def test_api_201_with_domain_payload_is_live(self):
        out = gate.evaluate(document([component("created", "api-backend", probes=[
            {"kind": "api", "target": "/v1/items", "status": 201,
             "body_excerpt": '{"item":{"id":"synthetic-1"}}'},
        ])]))
        self.assertEqual(out["components"][0]["status"], "LIVE")

    def test_client_release_or_crypto_calls_is_live(self):
        shipped = document([component(
            "wallet", "client-app", assets_scanned=5,
            client_crypto_libs=["viem"], client_api_calls=3,
            download_links={"total": 2, "resolving": 0})])
        self.assertEqual(gate.evaluate(shipped)["components"][0]["status"], "LIVE")
        released = document([component(
            "wallet", "client-app", download_links={"total": 2, "resolving": 2})])
        self.assertEqual(gate.evaluate(released)["components"][0]["status"], "LIVE")

    def test_bad_inputs_fail_closed(self):
        cases = [
            {"schema_version": 2, "components": []},
            document([]),
            document([component("x", "onchain"), component("x", "onchain")]),
            document([component("x", "unknown-kind")]),
            document([component("x", "onchain", addresses_found=1, addresses_verified=2)]),
            document([component("x", "client-app",
                                download_links={"total": 1, "resolving": 2})]),
            document([component("x", "onchain", mystery=1)]),
            document([component("x", "onchain", address_search_complete="yes")]),
            document([component("x", "client-app", client_search_complete=1)]),
            document([component("x", "onchain",
                                probes=[{"kind": "request", "status": 200}])]),
            document([component("x", "onchain",
                                probes=[{"kind": "api", "status": 999}])]),
            document([component("x", "onchain",
                                probes=[{"kind": "api", "status": 200,
                                         "body_excerpt": "x" * 2001}])]),
            document([component("x", "onchain",
                                probes=[{"kind": "api", "status": 200,
                                         "redirect_to": "x" * 501}])]),
        ]
        for case in cases:
            with self.assertRaises(ValueError):
                gate.evaluate(case)

    def test_cli_refuses_overwrite_and_missing_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = root / "probes.json"
            src.write_text(json.dumps(self.fixture()))
            out = root / "gate.json"
            cmd = [sys.executable, str(SCRIPTS / "reality_gate.py"),
                   "--probes", str(src), "--out", str(out)]
            first = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            self.assertEqual(first.returncode, 0, first.stderr)
            data = json.loads(out.read_text())
            self.assertEqual(data["component_count"], 8)
            repeat = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            self.assertNotEqual(repeat.returncode, 0)
            missing = subprocess.run(
                [sys.executable, str(SCRIPTS / "reality_gate.py"),
                 "--probes", str(root / "nope.json"), "--out", str(root / "x.json")],
                capture_output=True, text=True, timeout=15)
            self.assertNotEqual(missing.returncode, 0)
            self.assertFalse((root / "x.json").exists())

    def test_bounty_entrypoint_exposes_the_same_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = root / "probes.json"
            src.write_text(json.dumps(self.fixture()))
            out = root / "gate-from-bounty.json"
            p = subprocess.run(
                [sys.executable, str(SCRIPTS / "bounty.py"), "reality-gate",
                 "--probes", str(src), "--out", str(out)],
                capture_output=True, text=True, timeout=20)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertEqual(json.loads(out.read_text())["status_counts"]["LIVE"], 2)


if __name__ == "__main__":
    unittest.main()
