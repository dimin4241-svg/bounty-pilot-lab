"""Local-only mock decompiler and separate vulnerable/fixed scorer controls."""
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "skills" / "bounty-pilot" / "scripts"
sys.path.insert(0, str(SCRIPTS))
import mobile_decompile as decompile
import historical_paired_eval as paired


class DecompileAndBenchmarkTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.apk = self.root / "fixture.apk"
        with zipfile.ZipFile(self.apk, "w") as z:
            z.writestr("AndroidManifest.xml",
                       '<manifest xmlns:android="http://schemas.android.com/apk/res/android" />')

    def test_explicit_confirm_required_and_no_tool_invoked(self):
        calls = []
        with self.assertRaisesRegex(ValueError, "confirm-isolated"):
            decompile.analyze(self.apk, self.root / "out", confirm=False,
                              finder=lambda t: calls.append(t))
        self.assertEqual(calls, [])

    def test_jadx_command_executes_only_explicitly_local_mock(self):
        calls = []
        binary = self.root / "mock-jadx"
        binary.write_text("#!/bin/true\n")
        def fake_execute(cmd, timeout):
            calls.append((cmd, timeout))
            output_dir = Path(cmd[cmd.index("-d") + 1])
            (output_dir / "Entry.java").write_text("class Entry {}")
        result = decompile.analyze(
            self.apk, self.root / "out", "jadx", True, 12,
            finder=lambda tool: str(binary), executor=fake_execute)
        self.assertEqual(result["status"], "DECOMPILATION_COMPLETED_UNVERIFIED")
        self.assertEqual(result["inventory"]["source_kinds"][".java"], 1)
        self.assertEqual(calls[0][0][-1], str(self.apk))
        self.assertFalse(result["code_flow_verified"])
        self.assertFalse(result["native_app_executed"])

    def test_apktool_command_mock(self):
        binary = self.root / "mock-apktool"
        binary.write_text("mock")
        def fake_execute(cmd, timeout):
            self.assertEqual(cmd[1:3], ["d", "-o"])
            (Path(cmd[3]) / "Main.smali").write_text("smali")
        result = decompile.analyze(
            self.apk, self.root / "out", "apktool", True, 10,
            finder=lambda t: str(binary), executor=fake_execute)
        self.assertEqual(result["inventory"]["source_kinds"][".smali"], 1)

    def test_missing_tool_fails(self):
        with self.assertRaisesRegex(ValueError, "not installed"):
            decompile.analyze(self.apk, self.root / "out", "jadx", True,
                              finder=lambda _: None)

    def test_non_apk_rejected(self):
        bad = self.root / "unknown.zip"
        bad.write_bytes(self.apk.read_bytes())
        with self.assertRaisesRegex(ValueError, "only APK"):
            decompile.analyze(bad, self.root / "out", confirm=True)

    def test_output_must_be_new(self):
        out = self.root / "out"
        out.mkdir()
        with self.assertRaisesRegex(ValueError, "must be NEW"):
            decompile.analyze(self.apk, out, confirm=True)

    @staticmethod
    def truth():
        return {"schema_version": 1, "cases": [
            {"case_id": "v1", "pair_id": "issueA", "variant": "vulnerable",
             "source_commit": "a" * 40, "license": "MIT"},
            {"case_id": "f1", "pair_id": "issueA", "variant": "fixed",
             "source_commit": "b" * 40, "license": "MIT"},
        ]}

    @staticmethod
    def predictions(vuln=True, fixed=False):
        return {"schema_version": 1, "cases": [
            {"case_id": "v1", "detected": vuln},
            {"case_id": "f1", "detected": fixed},
        ]}

    def test_one_paired_correct_does_not_verify_blinding(self):
        result = paired.evaluate(self.truth(), self.predictions())
        self.assertEqual(result["fully_correct_pairs"], 1)
        self.assertEqual(result["confusion"], {"tp": 1, "fp": 0, "tn": 1, "fn": 0})
        self.assertFalse(result["blinding_verified"])
        self.assertEqual(result["vulnerabilities_proven_by_this_scorer"], 0)

    def test_miss_and_false_positive_are_separate(self):
        result = paired.evaluate(self.truth(), self.predictions(False, True))
        self.assertEqual(result["fully_correct_pairs"], 0)
        self.assertEqual(result["confusion"]["fp"], 1)
        self.assertEqual(result["confusion"]["fn"], 1)

    def test_same_revision_pair_denied(self):
        truth = self.truth()
        truth["cases"][1]["source_commit"] = "a" * 40
        with self.assertRaisesRegex(ValueError, "different commits"):
            paired.evaluate(truth, self.predictions())

    def test_missing_or_duplicate_answers_denied(self):
        predictions = self.predictions()
        predictions["cases"].pop()
        with self.assertRaisesRegex(ValueError, "identical case"):
            paired.evaluate(self.truth(), predictions)
        truth = self.truth()
        truth["cases"][1]["case_id"] = "v1"
        with self.assertRaises(ValueError):
            paired.evaluate(truth, self.predictions())

    def test_missing_fixed_variant_denied(self):
        truth = self.truth()
        truth["cases"][1]["pair_id"] = "issueB"
        with self.assertRaisesRegex(ValueError, "each pair"):
            paired.evaluate(truth, self.predictions())


if __name__ == "__main__":
    unittest.main()
