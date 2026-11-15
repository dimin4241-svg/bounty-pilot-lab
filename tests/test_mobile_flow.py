"""Offline mobile function-flow analyzer: positive and negative synthetic pairs."""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills" / "bounty-pilot" / "scripts"
sys.path.insert(0, str(SCRIPTS))
import mobile_flow


class MobileFlowTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.src = self.root / "src"
        self.src.mkdir()

    def write(self, filename, source):
        (self.src / filename).write_text(source, encoding="utf-8")

    def scan(self, platform="android"):
        return mobile_flow.analyze(str(self.src), platform)

    def test_java_direct_flow_is_unverified_and_anchored(self):
        self.write("Entry.java", """class Entry {
void open() {
String data = getIntent().getDataString();
webView.loadUrl(data);
}
}""")
        output = self.scan()
        self.assertEqual(output["lead_count"], 1)
        item = output["leads"][0]
        self.assertEqual(item["source_line"], 3)
        self.assertEqual(item["sink_line"], 4)
        self.assertEqual(item["sink_kind"], "WEBVIEW_LOAD")
        self.assertEqual(item["status"], "LEXICAL_DEF_USE_REVIEW_UNVERIFIED")
        self.assertEqual(item["impact"], "NOT_ESTABLISHED")
        self.assertEqual(item["reachability"], "UNKNOWN")
        self.assertNotIn("getDataString", json.dumps(item))

    def test_sanitized_constant_overwrite_negative(self):
        self.write("Entry.java", """class Entry {
void open() {
String data = getIntent().getDataString();
data = "https://fixed.invalid/";
webView.loadUrl(data);
}
}""")
        self.assertEqual(self.scan()["lead_count"], 0)

    def test_same_file_but_different_functions_not_flow(self):
        self.write("Entry.java", """class Entry {
void left(){ String token = getIntent().getDataString(); }
void right(){ String token = "constant"; webView.loadUrl(token); }
}""")
        self.assertEqual(self.scan()["lead_count"], 0)

    def test_unrelated_sink_argument_negative(self):
        self.write("Entry.java", """class Entry {
void open(){
String token = getIntent().getDataString();
String safe = "constant";
webView.loadUrl(safe);
}
}""")
        self.assertEqual(self.scan()["lead_count"], 0)

    def test_comments_and_literals_not_seen_as_sources(self):
        self.write("Entry.java", """class Entry {
void open(){
String text = "getIntent()";
webView.loadUrl(text); // getIntent()
/* getIntent(); webView.loadUrl(getIntent()); */
}
}""")
        self.assertEqual(self.scan()["lead_count"], 0)

    def test_inline_intent_source_to_sink(self):
        self.write("Entry.java", """class Entry {
void open() {
webView.loadUrl(getIntent().getDataString());
}
}""")
        self.assertEqual(self.scan()["lead_count"], 1)

    def test_single_helper_call_forwarded(self):
        self.write("Entry.java", """class Entry {
void open() {
String data = getIntent().getDataString();
forward(data);
}
void forward(String value) {
webView.loadUrl(value);
}
}""")
        result = self.scan()
        self.assertEqual(result["lead_count"], 1, result)
        self.assertEqual(result["leads"][0]["hops"][0]["method"], "open")
        self.assertEqual(result["leads"][0]["method"], "forward")

    def test_helper_with_clean_argument_does_not_flow(self):
        self.write("Entry.java", """class Entry {
void open() {
String data = getIntent().getDataString();
forward("https://fixed.invalid/");
}
void forward(String value) { webView.loadUrl(value); }
}""")
        self.assertEqual(self.scan()["lead_count"], 0)

    def test_overloaded_helper_is_not_guessed(self):
        self.write("Entry.java", """class Entry {
void open() { String data = getIntent().getDataString(); forward(data); }
void forward(String value) { webView.loadUrl(value); }
void forward(Uri value) { webView.loadUrl(value); }
}""")
        self.assertEqual(self.scan()["lead_count"], 0)

    def test_kotlin_lexical_flow(self):
        self.write("Screen.kt", """class Screen {
fun open() {
val raw = getIntent().getDataString()
web.loadUrl(raw)
}
}""")
        self.assertEqual(self.scan()["lead_count"], 1)

    def test_swift_callback_parameter_flow(self):
        self.write("App.swift", """class App {
func application(_ app: AppType, open url: URL) {
webView.load(URLRequest(url: url))
}
}""")
        r = self.scan("ios")
        self.assertEqual(r["lead_count"], 1, r)
        self.assertEqual(r["leads"][0]["source_kind"], "ENTRY_PARAMETER")

    def test_swift_unrelated_url_is_not_seeded(self):
        self.write("App.swift", """class App {
func ordinary(url: URL) {
webView.load(URLRequest(url: url))
}
}""")
        self.assertEqual(self.scan("ios")["lead_count"], 0)

    def test_smali_register_path(self):
        self.write("Entry.smali", """.class public Lfixture/Entry;
.method public onCreate(Landroid/os/Bundle;)V
    invoke-virtual {p0}, Landroid/app/Activity;->getIntent()Landroid/content/Intent;
    move-result-object v0
    invoke-virtual {v0}, Landroid/content/Intent;->getDataString()Ljava/lang/String;
    move-result-object v1
    invoke-virtual {p1, v1}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
.end method
""")
        r = self.scan()
        self.assertEqual(r["lead_count"], 1, r)
        self.assertEqual(r["leads"][0]["sink_line"], 7)

    def test_smali_clear_register_control(self):
        self.write("Entry.smali", """.method public onCreate()V
    invoke-virtual {p0}, Landroid/app/Activity;->getIntent()Landroid/content/Intent;
    move-result-object v0
    const-string v0, "safe"
    invoke-virtual {p1, v0}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
.end method
""")
        self.assertEqual(self.scan()["lead_count"], 0)

    def test_flow_cli_creates_private_output_and_refuses_overwrite(self):
        self.write("Entry.java", "class Entry { void open(){ web.loadUrl(getIntent()); } }")
        out = self.root / "private.json"
        cmd = [sys.executable, str(SCRIPTS / "bounty.py"), "mobile-lab", "flow",
               "--sources", str(self.src), "--platform", "android", "--out", str(out)]
        first = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(first.returncode, 0, first.stderr)
        report = json.loads(out.read_text())
        self.assertEqual(report["engine"], "mobile-function-flow")
        self.assertEqual(out.stat().st_mode & 0o777, 0o600)
        again = subprocess.run(cmd, capture_output=True, text=True)
        self.assertNotEqual(again.returncode, 0)

    def test_reproducibility_and_bad_platform(self):
        self.write("Entry.java", "class Entry { void open(){ web.loadUrl(getIntent()); } }")
        first, second = self.scan(), self.scan()
        self.assertEqual(first, second)
        with self.assertRaisesRegex(ValueError, "platform"):
            self.scan("windows")


if __name__ == "__main__":
    unittest.main()
