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
            component("drc", "onchain", assets_scanned=89, addresses_found=0,
                      probes=[{"kind": "dns", "target": "explorer.test", "status": 200}]),
            component("wallet", "client-app", assets_scanned=12,
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
        self.assertEqual(out["components"][0]["status"], "MARKETING_ONLY")
        self.assertIn("api:api-claim-unprobed", out["warnings"])

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
            document([component("x", "onchain",
                                probes=[{"kind": "request", "status": 200}])]),
            document([component("x", "onchain",
                                probes=[{"kind": "api", "status": 999}])]),
            document([component("x", "onchain",
                                probes=[{"kind": "api", "status": 200,
                                         "body_excerpt": "x" * 2001}])]),
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
