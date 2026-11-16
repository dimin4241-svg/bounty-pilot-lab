"""Offline Smali exact descriptor-binding synthetic controls.

These fixtures demonstrate neither Android framework reachability nor any
security impact. No Smali instruction, class or APK is executed.
"""
import json
import sys
import tempfile
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills" / "bounty-pilot" / "scripts"
sys.path.insert(0, str(SCRIPTS))
import mobile_smali_crossfile

ENTRY = """.class public Lfixture/Entry;
.super Landroid/app/Activity;
.method public open()V
    .locals 3
    invoke-virtual {p0}, Landroid/app/Activity;->getIntent()Landroid/content/Intent;
    move-result-object v0
    invoke-virtual {v0}, Landroid/content/Intent;->getDataString()Ljava/lang/String;
    move-result-object v1
    invoke-static {v1}, Lfixture/Router;->forward(Ljava/lang/String;)V
    return-void
.end method
"""
ROUTER = """.class public Lfixture/Router;
.super Ljava/lang/Object;
.method public static forward(Ljava/lang/String;)V
    .locals 1
    new-instance v0, Landroid/webkit/WebView;
    invoke-virtual {v0, p0}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
    return-void
.end method
"""


class SmaliDescriptorFlowTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.source = self.root / "smali"
        self.source.mkdir()
        self.put("Entry.smali", ENTRY)
        self.put("Router.smali", ROUTER)

    def put(self, name, content):
        path = self.source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def rewrite(self, name, before, after):
        path = self.source / name
        old = path.read_text(encoding="utf-8")
        self.assertIn(before, old)
        path.write_text(old.replace(before, after), encoding="utf-8")

    def scan(self):
        return mobile_smali_crossfile.analyze(self.source)

    def test_exact_static_descriptor_resolves_crossfile_sink(self):
        report = self.scan()
        self.assertEqual(report["lead_count"], 1, report)
        item = report["leads"][0]
        self.assertEqual(item["source"]["file"], "Entry.smali")
        self.assertEqual(item["sink"]["file"], "Router.smali")
        self.assertEqual(item["sink"]["kind"], "WEBVIEW_LOAD")
        self.assertEqual(item["hops"][0]["binding"],
                         "DEX_LEXICAL_EXACT_STATIC_DESCRIPTOR")
        self.assertEqual(item["impact"], "NOT_ESTABLISHED")
        self.assertFalse(item["runtime_effect_verified"])
        self.assertEqual(len(item["source"]["sha256"]), 64)
        self.assertNotIn("getDataString", json.dumps(item["source"]))

    def test_second_static_helper_descriptor_hop(self):
        self.rewrite("Router.smali",
                     "new-instance v0, Landroid/webkit/WebView;\n"
                     "    invoke-virtual {v0, p0}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V",
                     "invoke-static {p0}, Lfixture/Sink;->render(Ljava/lang/String;)V")
        self.put("Sink.smali", ROUTER.replace("Lfixture/Router;", "Lfixture/Sink;")
                 .replace("forward(", "render("))
        report = self.scan()
        self.assertEqual(report["lead_count"], 1, report)
        self.assertEqual(len(report["leads"][0]["hops"]), 2)

    def test_string_constant_overwrite_blocks_sink(self):
        self.rewrite("Router.smali", "new-instance v0, Landroid/webkit/WebView;",
                     'const-string p0, "safe"\n    new-instance v0, Landroid/webkit/WebView;')
        self.assertEqual(self.scan()["lead_count"], 0)

    def test_move_object_preserves_origin(self):
        self.rewrite("Router.smali", "new-instance v0, Landroid/webkit/WebView;",
                     "move-object v1, p0\n    new-instance v0, Landroid/webkit/WebView;")
        self.rewrite("Router.smali", "loadUrl(Ljava/lang/String;)V",
                     "loadUrl(Ljava/lang/String;)V") # stable placeholder for exact matching
        self.rewrite("Router.smali", "{v0, p0}", "{v0, v1}")
        self.assertEqual(self.scan()["lead_count"], 1)

    def test_local_register_overwrite_in_caller_blocks_forward(self):
        self.rewrite("Entry.smali",
                     "invoke-static {v1}, Lfixture/Router;->forward",
                     'const-string v1, "fixed"\n    invoke-static {v1}, Lfixture/Router;->forward')
        self.assertEqual(self.scan()["lead_count"], 0)

    def test_wrong_target_descriptor_is_not_resolved(self):
        self.rewrite("Entry.smali", "Lfixture/Router;->forward",
                     "Lother/Router;->forward")
        self.assertEqual(self.scan()["lead_count"], 0)

    def test_wrong_static_parameter_type_is_not_resolved(self):
        self.rewrite("Entry.smali", "forward(Ljava/lang/String;)V",
                     "forward(Landroid/net/Uri;)V")
        self.assertEqual(self.scan()["lead_count"], 0)

    def test_virtual_dispatch_is_not_assumed_static(self):
        self.rewrite("Entry.smali", "invoke-static {v1}", "invoke-virtual {v0, v1}")
        self.assertEqual(self.scan()["lead_count"], 0)

    def test_malformed_range_invocation_is_rejected(self):
        self.rewrite("Entry.smali", "invoke-static {v1}", "invoke-static/range {v1 .. v3}")
        self.assertEqual(self.scan()["lead_count"], 0)

    def test_unknown_branch_rejects_all_entire_method(self):
        self.rewrite("Router.smali", "new-instance v0, Landroid/webkit/WebView;",
                     "if-eqz p0, :safe\n    new-instance v0, Landroid/webkit/WebView;")
        self.assertEqual(self.scan()["lead_count"], 0)
        self.assertGreater(self.scan()["coverage"]["unsupported_method_visits"], 0)

    def test_unknown_instruction_refuses_provenance(self):
        self.rewrite("Router.smali", "new-instance v0, Landroid/webkit/WebView;",
                     "iget-object v2, p0, Lfixture/Other;->secret:Ljava/lang/String;\n"
                     "    new-instance v0, Landroid/webkit/WebView;")
        self.assertEqual(self.scan()["lead_count"], 0)

    def test_false_source_owner_is_not_android_intent(self):
        self.rewrite("Entry.smali",
                     "Landroid/content/Intent;->getDataString",
                     "Lfixture/FakeIntent;->getDataString")
        self.assertEqual(self.scan()["lead_count"], 0)

    def test_no_getintent_receiver_seeding_blocks_unrelated_string(self):
        self.rewrite("Entry.smali",
                     "Landroid/app/Activity;->getIntent",
                     "Lfixture/Random;->getIntent")
        self.assertEqual(self.scan()["lead_count"], 0)

    def test_wrong_webview_owner_not_claimed(self):
        self.rewrite("Router.smali",
                     "Landroid/webkit/WebView;->loadUrl",
                     "Lfixture/WebView;->loadUrl")
        self.assertEqual(self.scan()["lead_count"], 0)

    def test_ambiguous_same_descriptor_classes_not_selected(self):
        self.put("duplicates/Router.smali", ROUTER)
        report = self.scan()
        self.assertEqual(report["lead_count"], 0)
        self.assertEqual(report["coverage"]["duplicate_class_descriptors"], 1)

    def test_closest_call_requires_move_result_object(self):
        self.rewrite("Entry.smali",
                     "move-result-object v1",
                     "nop\n    move-result-object v1")
        self.assertEqual(self.scan()["lead_count"], 0)

    def test_deterministic_report_and_bad_limit(self):
        self.assertEqual(self.scan(), self.scan())
        with self.assertRaises(ValueError):
            mobile_smali_crossfile.analyze(self.source, 0)

    def test_symlink_input_not_indexed(self):
        outside = self.root / "outside.smali"
        outside.write_text(ROUTER, encoding="utf-8")
        (self.source / "Alias.smali").symlink_to(outside)
        r = self.scan()
        self.assertEqual(r["lead_count"], 1)
        self.assertGreaterEqual(r["coverage"]["skipped_files"], 1)

    def test_cli_private_report_and_no_overwrite(self):
        out = self.root / "private.json"
        cmd = [sys.executable, str(SCRIPTS / "bounty.py"), "mobile-lab",
               "smali-crossfile", "--sources", str(self.source),
               "--out", str(out)]
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        self.assertEqual(p.returncode, 0, p.stderr)
        report = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(report["engine"], "mobile-smali-descriptor-crossfile")
        self.assertEqual(out.stat().st_mode & 0o777, 0o600)
        p2 = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        self.assertNotEqual(p2.returncode, 0)


if __name__ == "__main__":
    unittest.main()
