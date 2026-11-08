"""Deterministic offline Vyper advisory checks and source-version cautions."""
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "skills/bounty-pilot/scripts/vyper_bugs.py"
spec = importlib.util.spec_from_file_location("bp_vyper_bugs", PATH)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def inventory(*versions):
    return {"schema_version": 1,
            "builds": [{"id": "build-%d" % i, "compiler": "vyper",
                        "version": v, "verified_actual_compiler": True}
                       for i, v in enumerate(versions)]}


class VyperBugsTests(unittest.TestCase):
    def test_official_named_lock_regression_exact_affected_versions(self):
        result = mod.evaluate(inventory("0.2.15", "0.2.16", "0.3.0", "0.3.1",
                                        "0.3.10", "0.4.0"))
        self.assertEqual([bool(r["matches"]) for r in result["builds"]],
                         [True, True, True, False, False, False])
        for row in result["builds"][:3]:
            self.assertEqual(row["matches"][0]["id"], "GHSA-5824-cm3x-3c38")
            self.assertEqual(row["matches"][0]["status"], "version-match-only")

    def test_unverified_compiler_does_not_claim_deployed_match(self):
        data = inventory("0.3.0")
        data["builds"][0]["verified_actual_compiler"] = False
        r = mod.evaluate(data)
        self.assertEqual(r["builds"][0]["status"],
                         "unverified-build-compiler-version")

    def test_offline_import_with_explicit_introduced_fixed_versions(self):
        catalog = {"schema_version": 1, "advisories": [{
            "id": "GHSA-aaaa-bbbb-cccc",
            "url": mod.OFFICIAL + "GHSA-aaaa-bbbb-cccc",
            "title": "operator supplied example, not a real advisory",
            "ranges": [{"introduced": "0.4.0", "fixed": "0.4.2"}],
            "required_conditions": ["confirm source and published range"],
        }]}
        r = mod.evaluate(inventory("0.4.0", "0.4.1", "0.4.2"), catalog)
        self.assertEqual([len(x["matches"]) for x in r["builds"]],
                         [1, 1, 0])
        self.assertEqual(r["builds"][0]["matches"][0]["catalog_source"],
                         "operator-import-unverified")

    def test_bogus_advisory_and_version_fail_closed(self):
        bad = {"schema_version": 1, "advisories": [{
            "id": "GHSA-aaaa-bbbb-cccc",
            "url": "https://attacker.example/claim",
            "exact_versions": ["0.4.0"],
        }]}
        with self.assertRaises(ValueError):
            mod.evaluate(inventory("0.4.0"), bad)
        with self.assertRaises(ValueError):
            mod.evaluate(inventory("0.4.0rc1"))
        with self.assertRaises(ValueError):
            mod.evaluate(inventory("0.3.0", "0.3.0", "0.3.0"), {
                "schema_version": 1,
                "advisories": [{"id": "GHSA-aaaa-bbbb-cccc",
                                "url": mod.OFFICIAL + "GHSA-aaaa-bbbb-cccc",
                                "ranges": [{"introduced": "0.4.2",
                                            "fixed": "0.4.1"}]}]})
        with self.assertRaises(ValueError):
            mod.evaluate({"schema_version": 1,
                          "builds": [{"id": "x", "compiler": "vyper",
                                      "version": "0.3.0",
                                      "verified_actual_compiler": 1}]})

    def test_cli_private_result_and_duplicate_json_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, out = root / "inventory.json", root / "result.json"
            source.write_text(json.dumps(inventory("vyper:0.3.0", "0.3.1")))
            cmd = [sys.executable, str(PATH), "--inventory", str(source),
                   "--out", str(out)]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=12)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(len(json.loads(out.read_text())["builds"]), 2)
            again = subprocess.run(cmd, capture_output=True, text=True, timeout=12)
            self.assertNotEqual(again.returncode, 0)
            source.write_text('{"schema_version":1,"schema_version":2,"builds":[]}')
            with self.assertRaises(ValueError):
                mod._read(source)


if __name__ == "__main__":
    unittest.main()
