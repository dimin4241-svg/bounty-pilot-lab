"""Pinned Kotlin-compiled classfiles for bounded JVM callsite alignment.

No Kotlin source, class or method is executed by these tests.
The classfiles do not attest a rebuild from the current sources.
"""
import base64
import hashlib
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


    def snapshot_lock(self):
        return {
            "schema_version": 1,
            "kind": "operator-pinned-kotlin-jvm-snapshot",
            "source_sha256": {
                name: hashlib.sha256((self.sources / name).read_bytes()).hexdigest()
                for name in ("Entry.kt", "Router.kt")
            },
            "class_sha256": {
                "fixture/" + name: hashlib.sha256(
                    (self.classes / "fixture" / (name + ".class")).read_bytes()
                ).hexdigest()
                for name in ("Entry", "Router")
            },
        }

    def locked_scan(self, lock):
        return mobile_crossfile.analyze(
            self.sources, "android", jvm_classes=self.classes,
            jvm_snapshot_lock=lock)

    def test_snapshot_lock_exact_current_bytes_match_not_build_attestation(self):
        report = self.locked_scan(self.snapshot_lock())
        self.assertEqual(report["lead_count"], 1, report)
        match = report["leads"][0]["kotlin_jvm_alignment"]
        self.assertEqual(
            match["snapshot_lock"]["status"],
            "OPERATOR_PINNED_BYTES_MATCH_UNATTESTED_BUILD")
        self.assertTrue(
            match["snapshot_lock"]["source_and_class_bytes_match_operator_lock"])
        self.assertFalse(match["snapshot_lock"]["independently_signed"])
        self.assertFalse(match["snapshot_lock"]["reproducible_build_verified"])
        self.assertFalse(match["source_build_freshness_verified"])
        self.assertEqual(report["kotlin_jvm_comparison"]["aligned_leads"], 1)

    def test_snapshot_lock_source_changed_without_line_shift_fails_closed(self):
        snapshot = self.snapshot_lock()
        src = self.sources / "Entry.kt"
        text = src.read_text(encoding="utf-8")
        self.assertIn("val raw = ", text)
        src.write_text(text.replace("val raw = ", "val raw  = "), encoding="utf-8")
        result = self.locked_scan(snapshot)
        self.assertEqual(result["lead_count"], 1, result)
        self.assertEqual(result["leads"][0]["kotlin_jvm_alignment"]["status"],
                         "JVM_SNAPSHOT_LOCK_MISMATCH_OR_MISSING")
        self.assertEqual(result["kotlin_jvm_comparison"]["aligned_leads"], 0)

    def test_snapshot_lock_class_changed_without_source_change_fails_closed(self):
        snapshot = self.snapshot_lock()
        target = self.classes / "fixture" / "Entry.class"
        data = target.read_bytes()
        self.assertIn(b"INSTANCE", data)
        target.write_bytes(data.replace(b"INSTANCE", b"INSTANCe"))
        result = self.locked_scan(snapshot)
        self.assertEqual(result["lead_count"], 1, result)
        self.assertEqual(result["leads"][0]["kotlin_jvm_alignment"]["status"],
                         "JVM_SNAPSHOT_LOCK_MISMATCH_OR_MISSING")

    def test_snapshot_lock_missing_callee_digest_fails_closed(self):
        snapshot = self.snapshot_lock()
        snapshot["class_sha256"].pop("Router")
        result = self.locked_scan(snapshot)
        self.assertEqual(result["lead_count"], 1)
        self.assertEqual(result["leads"][0]["kotlin_jvm_alignment"]["status"],
                         "JVM_SNAPSHOT_LOCK_MISMATCH_OR_MISSING")

    def test_snapshot_lock_rejects_traversal_path(self):
        snapshot = self.snapshot_lock()
        snapshot["source_sha256"]["../Entry.kt"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "unsafe Kotlin source"):
            self.locked_scan(snapshot)

    def test_snapshot_lock_rejects_invalid_digest_value(self):
        snapshot = self.snapshot_lock()
        snapshot["class_sha256"]["fixture/Entry"] = "not-a-sha"
        with self.assertRaisesRegex(ValueError, "unsafe Kotlin JVM class"):
            self.locked_scan(snapshot)

    def test_snapshot_lock_rejects_wrong_schema_or_untrusted_kind(self):
        snapshot = self.snapshot_lock()
        snapshot["kind"] = "trusted-reproducible-kotlin-build"
        with self.assertRaisesRegex(ValueError, "operator snapshot lock"):
            self.locked_scan(snapshot)

    def test_snapshot_lock_requires_classfile_directory(self):
        with self.assertRaisesRegex(ValueError, "requires --jvm-classes"):
            mobile_crossfile.analyze(
                self.sources, "android", jvm_snapshot_lock=self.snapshot_lock())

    def test_snapshot_lock_cli_accepts_exact_file_and_preserves_private_report(self):
        lock = self.root / "operator-lock.json"
        lock.write_text(json.dumps(self.snapshot_lock()), encoding="utf-8")
        output = self.root / "operator-report.json"
        cmd = [sys.executable, str(SCRIPTS / "bounty.py"), "mobile-lab",
               "crossfile", "--platform", "android",
               "--sources", str(self.sources),
               "--jvm-classes", str(self.classes),
               "--jvm-snapshot-lock", str(lock), "--out", str(output)]
        process = subprocess.run(cmd, capture_output=True, text=True, timeout=40)
        self.assertEqual(process.returncode, 0, process.stderr)
        result = json.loads(output.read_text(encoding="utf-8"))
        item = result["leads"][0]["kotlin_jvm_alignment"]
        self.assertTrue(item["snapshot_lock"]["source_and_class_bytes_match_operator_lock"])
        self.assertFalse(item["snapshot_lock"]["reproducible_build_verified"])
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)

    def test_snapshot_lock_cli_rejects_duplicate_json_keys(self):
        lock = self.root / "bad.json"
        lock.write_text('{"schema_version":1,"schema_version":2}', encoding="utf-8")
        output = self.root / "not-created.json"
        cmd = [sys.executable, str(SCRIPTS / "bounty.py"), "mobile-lab",
               "crossfile", "--platform", "android",
               "--sources", str(self.sources),
               "--jvm-classes", str(self.classes),
               "--jvm-snapshot-lock", str(lock), "--out", str(output)]
        process = subprocess.run(cmd, capture_output=True, text=True, timeout=40)
        self.assertNotEqual(process.returncode, 0)
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
