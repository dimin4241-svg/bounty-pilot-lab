"""Route coverage must not claim unimplemented native runtimes as tested."""
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "skills/bounty-pilot/scripts/surface_route.py"
spec = importlib.util.spec_from_file_location("bp_surface_route", PATH)
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)


class SurfaceRouteTests(unittest.TestCase):
    def test_all_expanded_22_surfaces_document_the_evidence_boundary(self):
        self.assertEqual(len(r.MATRIX), 22)
        out = r.select(list(r.MATRIX))
        self.assertEqual(out["count"], 22)
        self.assertTrue(all(row["finding_status"] == "no-finding-research-plan-only"
                            and row["scope_and_deployment_check_required"]
                            for row in out["shapes"]))

    def test_offline_models_have_specific_native_evidence_requirements(self):
        keys = ["cex-custody", "rollup-l2", "restaking-lst", "perps",
                "launchpad", "prediction-market", "airdrop",
                "data-availability", "lottery-vrf"]
        results = r.select(keys)["shapes"]
        self.assertTrue(all(row["implementation"] == "offline-transition-model"
                            for row in results))
        self.assertTrue(all("local" in row["required_native_evidence"]
                            or "pinned" in row["required_native_evidence"]
                            or "native" in row["required_native_evidence"]
                            for row in results))

    def test_new_stacks_are_never_mislabelled_as_implemented(self):
        keys = ["ton", "near", "fuel-sway", "hyperliquid",
                "stacks-clarity", "algorand", "aleo",
                "bitcoin-bitvm", "tee-fhe"]
        out = r.select(keys)
        self.assertTrue(all(row["implementation"] == "methodology-only"
                            for row in out["shapes"]))

    def test_duplicates_or_unknown_fail_closed(self):
        for shapes in [[], ["ton", "ton"], ["unknown"]]:
            with self.assertRaises(ValueError):
                r.select(shapes)

    def test_cli_list_and_private_export(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "route.json"
            cmd = [sys.executable, str(PATH), "--shape", "cex-custody",
                   "--shape", "rollup-l2", "--out", str(out)]
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=12)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertEqual(json.loads(out.read_text())["count"], 2)
            second = subprocess.run(cmd, capture_output=True, text=True, timeout=12)
            self.assertNotEqual(second.returncode, 0)


if __name__ == "__main__":
    unittest.main()
