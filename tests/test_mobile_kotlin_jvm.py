"""Pinned Kotlin-compiled classfiles for bounded JVM callsite alignment.

No Kotlin source, class or method is executed by these tests.
The classfiles do not attest a rebuild from the current sources.
"""
import base64
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills" / "bounty-pilot" / "scripts"
sys.path.insert(0, str(SCRIPTS))
import mobile_crossfile
import mobile_kotlin_jvm

FIXTURE = json.loads(
    (ROOT / "tests" / "fixtures" / "mobile_kotlin_jvm_pinned.json").read_text(
        encoding="utf-8"))


class KotlinJvmEvidenceTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.sources = self.root / "src"
        self.classes = self.root / "compiled"
        self.sources.mkdir()
        self.classes.mkdir()
        for name, value in FIXTURE["sources"].items():
            (self.sources / name).write_text(value, encoding="utf-8")
        for name, value in FIXTURE["classes"].items():
            file = self.classes / name
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_bytes(base64.b64decode(value))

    def scan(self):
        return mobile_crossfile.analyze(
            self.sources, "android", jvm_classes=self.classes)

    def test_real_kotlin_classfile_invocation_matches_lexical_source(self):
        report = self.scan()
        self.assertEqual(report["lead_count"], 1, report)
        align = report["leads"][0]["kotlin_jvm_alignment"]
        self.assertEqual(
            align["status"], "ALL_HOPS_JVM_BYTECODE_ALIGNED_UNATTESTED_SOURCE_BUILD")
        self.assertEqual(align["edges"][0]["opcode"], "INVOKEVIRTUAL")
        self.assertEqual(align["edges"][0]["callee_jvm_descriptor"],
                         "(Ljava/lang/String;)V")
        self.assertEqual(len(align["edges"][0]["caller_class_sha256"]), 64)
        self.assertFalse(align["source_build_freshness_verified"])
        self.assertFalse(align["compiler_provenance_authenticated"])
        self.assertFalse(align["runtime_effect_verified"])
        self.assertFalse(align["taint_validated_by_bytecode"])
        self.assertEqual(report["leads"][0]["impact"], "NOT_ESTABLISHED")

    def test_pinned_kotlin_source_shift_rejects_stale_jvm_line(self):
        source = self.sources / "Entry.kt"
        source.write_text("// shift source without rebuilding\n"
                          + source.read_text(encoding="utf-8"), encoding="utf-8")
        result = self.scan()
        self.assertEqual(result["lead_count"], 1, result)
        self.assertEqual(result["leads"][0]["kotlin_jvm_alignment"]["status"],
                         "SOME_HOPS_NOT_JVM_ALIGNED")

    def test_wrong_compiled_method_name_cannot_align(self):
        path = self.classes / "fixture" / "Entry.class"
        data = path.read_bytes()
        self.assertIn(b"forward", data)
        path.write_bytes(data.replace(b"forward", b"forWARD"))
        self.assertEqual(self.scan()["leads"][0]["kotlin_jvm_alignment"]["status"],
                         "SOME_HOPS_NOT_JVM_ALIGNED")

    def test_classfile_without_kotlin_metadata_marker_is_rejected(self):
        path = self.classes / "fixture" / "Entry.class"
        data = path.read_bytes()
        self.assertIn(b"Lkotlin/Metadata;", data)
        path.write_bytes(data.replace(b"Lkotlin/Metadata;",
                                      b"Lkotlin/MetadAta;"))
        self.assertEqual(self.scan()["leads"][0]["kotlin_jvm_alignment"]["status"],
                         "SOME_HOPS_NOT_JVM_ALIGNED")

    def test_duplicate_jvm_owner_not_arbitrarily_selected(self):
        path = self.classes / "repacked" / "Entry.class"
        path.parent.mkdir()
        path.write_bytes((self.classes / "fixture" / "Entry.class").read_bytes())
        report = self.scan()
        self.assertEqual(report["leads"][0]["kotlin_jvm_alignment"]["status"],
                         "SOME_HOPS_NOT_JVM_ALIGNED")
        self.assertEqual(report["kotlin_jvm_comparison"]["coverage"]
                         ["duplicate_jvm_owners"], 1)

    def test_malformed_class_is_skipped_and_not_executed(self):
        target = self.classes / "fixture" / "Entry.class"
        target.write_bytes(b"\xca\xfe\xba\xbe" + b"bad\x00\x00")
        result = self.scan()
        self.assertEqual(result["lead_count"], 1)
        self.assertEqual(result["leads"][0]["kotlin_jvm_alignment"]["status"],
                         "SOME_HOPS_NOT_JVM_ALIGNED")
        self.assertGreater(result["kotlin_jvm_comparison"]["coverage"]
                           ["skipped_files"], 0)

    def test_classfile_parser_fails_closed_on_malformed_magic(self):
        with self.assertRaises(ValueError):
            mobile_kotlin_jvm.parse_classfile(b"not a classfile")

    def test_classfile_parse_real_kotlin_compiler_metadata(self):
        data = (self.classes / "fixture" / "Entry.class").read_bytes()
        cls = mobile_kotlin_jvm.parse_classfile(data)
        self.assertEqual(cls["owner"], "fixture/Entry")
        self.assertEqual(cls["source_name"], "Entry.kt")
        self.assertTrue(cls["kotlin_metadata_marker"])
        invocations = cls["methods"][("open", "()V")]
        self.assertIn(
            (7, "fixture/Router", "forward", "(Ljava/lang/String;)V",
             "INVOKEVIRTUAL", 12), invocations)

    def test_symlinked_classfile_never_indexed(self):
        outside = self.root / "external.class"
        outside.write_bytes((self.classes / "fixture" / "Entry.class").read_bytes())
        (self.classes / "fixture" / "Entry.class").unlink()
        (self.classes / "fixture" / "Entry.class").symlink_to(outside)
        result = self.scan()
        self.assertEqual(result["leads"][0]["kotlin_jvm_alignment"]["status"],
                         "SOME_HOPS_NOT_JVM_ALIGNED")
        self.assertGreater(result["kotlin_jvm_comparison"]["coverage"]
                           ["skipped_files"], 0)

    def test_reproducible_compiled_alignment(self):
        self.assertEqual(self.scan(), self.scan())

    def test_reject_unsupported_platform_for_classfile_alignment(self):
        with self.assertRaisesRegex(ValueError, "only with android"):
            mobile_crossfile.analyze(self.sources, "ios", jvm_classes=self.classes)

    def test_cli_report_private_and_no_overwrite(self):
        out = self.root / "evidence.json"
        cmd = [sys.executable, str(SCRIPTS / "bounty.py"), "mobile-lab",
               "crossfile", "--platform", "android",
               "--sources", str(self.sources),
               "--jvm-classes", str(self.classes), "--out", str(out)]
        proc = subprocess.run(cmd, text=True, capture_output=True, timeout=40)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        report = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(report["kotlin_jvm_comparison"]["aligned_leads"], 1)
        self.assertEqual(out.stat().st_mode & 0o777, 0o600)
        again = subprocess.run(cmd, text=True, capture_output=True, timeout=40)
        self.assertNotEqual(again.returncode, 0)


if __name__ == "__main__":
    unittest.main()
