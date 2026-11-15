"""Synthetic, local-only review tests for the conservative cross-file matcher."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "bounty-pilot" / "scripts"))
import mobile_crossfile


class CrossFileTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)

    def put(self, path, source):
        dest = self.root / path
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(source, encoding="utf-8")
        return dest

    def inspect(self, platform="android"):
        return mobile_crossfile.analyze(str(self.root), platform)

    def test_java_same_package_class_call(self):
        self.put("Entry.java", """package fixture;
class Entry {
void open() {
String raw = getIntent().getDataString();
Router.forward(raw);
}
}""")
        self.put("Router.java", """package fixture;
class Router {
static void forward(String url) { webView.loadUrl(url); }
}""")
        report = self.inspect()
        self.assertEqual(report["lead_count"], 1, report)
        finding = report["leads"][0]
        self.assertEqual(finding["source"]["file"], "Entry.java")
        self.assertEqual(finding["sink"]["file"], "Router.java")
        self.assertEqual(finding["sink"]["kind"], "WEBVIEW_LOAD")
        self.assertEqual(finding["hops"][0]["caller_method"], "open")
        self.assertEqual(finding["status"], "UNVERIFIED_EXPLICIT_CROSSFILE_LEXICAL_PATH")
        self.assertEqual(finding["impact"], "NOT_ESTABLISHED")
        self.assertEqual(len(report["graph"]["edges"]), 1)
        self.assertFalse(report["graph"]["edges"][0]["verified_runtime"])
        self.assertIn("Entry.java::open", [n["id"] for n in report["graph"]["nodes"]])
        self.assertNotIn("getDataString", json.dumps(finding))

    def test_java_explicit_import_cross_package(self):
        self.put("app/Entry.java", """package app;
import targets.Router;
class Entry {
void open(){ String raw = getIntent().getDataString(); Router.forward(raw); }
}""")
        self.put("targets/Router.java", """package targets;
class Router { static void forward(String x) { webView.loadUrl(x); } }""")
        self.assertEqual(self.inspect()["lead_count"], 1)

    def test_without_import_no_cross_package_guess(self):
        self.put("app/Entry.java", """package app;
class Entry {void open(){String raw=getIntent().getDataString(); Router.forward(raw);}}""")
        self.put("targets/Router.java", """package targets;
class Router {static void forward(String value){webView.loadUrl(value);}}""")
        self.assertEqual(self.inspect()["lead_count"], 0)

    def test_different_file_with_same_method_name_not_called(self):
        self.put("Entry.java", """package fixture;
class Entry {
void open(){String raw=getIntent().getDataString(); unrelated(raw);}
}""")
        self.put("Sink.java", """package fixture;
class Sink {static void unrelated(String value){webView.loadUrl(value);}}""")
        self.assertEqual(self.inspect()["lead_count"], 0)

    def test_simple_constructor_receiver(self):
        self.put("Entry.java", """package fixture;
class Entry {void open(){
String raw = getIntent().getDataString();
Router r = new Router();
r.forward(raw);
}}""")
        self.put("Router.java", """package fixture;
class Router {void forward(String x){webView.loadUrl(x);}}""")
        self.assertEqual(self.inspect()["lead_count"], 1)

    def test_kotlin_object_call(self):
        self.put("Entry.kt", """package fixture
class Entry {
fun open() {
val raw = getIntent().getDataString()
Router.forward(raw)
}
}""")
        self.put("Router.kt", """package fixture
object Router { fun forward(data: String) { web.loadUrl(data) } }""")
        self.assertEqual(self.inspect()["lead_count"], 1)

    def test_swift_static_class_call(self):
        self.put("App.swift", """class App {
func application(_ app: AppType, open url: URL) {
Router.forward(url)
}
}""")
        self.put("Router.swift", """class Router {
static func forward(_ value: URL) {
webView.load(URLRequest(url: value))
}
}""")
        report = self.inspect("ios")
        self.assertEqual(report["lead_count"], 1, report)
        self.assertEqual(report["leads"][0]["source"]["kind"], "ENTRY_PARAMETER")

    def test_swift_allocated_receiver(self):
        self.put("App.swift", """class App {
func application(_ app: AppType, open url: URL) {
let router = Router()
router.forward(url)
}
}""")
        self.put("Router.swift", """class Router {
func forward(_ value: URL) { webView.load(URLRequest(url: value)) }
}""")
        self.assertEqual(self.inspect("ios")["lead_count"], 1)

    def test_constant_overwrite_drops_taint(self):
        self.put("Entry.java", """package fixture;
class Entry {
void open() {
String raw = getIntent().getDataString();
raw = "static-constant";
Router.forward(raw);
}
}""")
        self.put("Router.java", """package fixture;
class Router {static void forward(String x){webView.loadUrl(x);}}""")
        self.assertEqual(self.inspect()["lead_count"], 0)

    def test_no_helper_call_with_constant(self):
        self.put("Entry.java", """package fixture;
class Entry {
void open() {
String raw = getIntent().getDataString();
Router.forward("static");
}
}""")
        self.put("Router.java", """package fixture;
class Router {static void forward(String x){webView.loadUrl(x);}}""")
        self.assertEqual(self.inspect()["lead_count"], 0)

    def test_ambiguous_overload_refused(self):
        self.put("Entry.java", """package fixture;
class Entry {
void open() {String raw=getIntent().getDataString();Router.forward(raw);}
}""")
        self.put("Router.java", """package fixture;
class Router {
static void forward(String x){webView.loadUrl(x);}
static void forward(Uri x){webView.loadUrl(x);}
}""")
        self.assertEqual(self.inspect()["lead_count"], 0)

    def test_duplicate_package_class_refused(self):
        self.put("Entry.java", """package fixture;
class Entry {
void open() {String raw=getIntent().getDataString();Router.forward(raw);}
}""")
        self.put("one/Router.java", """package fixture;
class Router {static void forward(String x){webView.loadUrl(x);}}""")
        self.put("two/Router.java", """package fixture;
class Router {static void forward(String x){webView.loadUrl(x);}}""")
        self.assertEqual(self.inspect()["lead_count"], 0)

    def test_multifile_two_hops(self):
        self.put("Entry.java", """package fixture;
class Entry {
void open() {String raw=getIntent().getDataString();Router.forward(raw);}
}""")
        self.put("Router.java", """package fixture;
class Router {
static void forward(String data){Sink.render(data);}
}""")
        self.put("Sink.java", """package fixture;
class Sink {static void render(String x){webView.loadUrl(x);}}
""")
        report = self.inspect()
        self.assertEqual(report["lead_count"], 1, report)
        self.assertEqual(len(report["leads"][0]["hops"]), 2)

    def test_comment_and_string_not_a_call(self):
        self.put("Entry.java", """package fixture;
class Entry {void open(){
String raw=getIntent().getDataString();
// Router.forward(raw);
String literal = "Router.forward(raw)";
}}
""")
        self.put("Router.java", """package fixture;
class Router {static void forward(String x){webView.loadUrl(x);}}""")
        self.assertEqual(self.inspect()["lead_count"], 0)

    def test_multiple_classes_in_same_file_are_skipped(self):
        self.put("Entry.java", """package fixture;
class Entry {void open(){String raw=getIntent().getDataString();Router.forward(raw);}}
""")
        self.put("Router.java", """package fixture;
class Router {static void forward(String x){webView.loadUrl(x);}}
class Router {static void forward(String x){webView.loadUrl(x);}}""")
        self.assertEqual(self.inspect()["lead_count"], 0)

    def test_report_determinism(self):
        self.test_java_same_package_class_call()
        self.assertEqual(self.inspect(), self.inspect())

    def test_wrong_platform_and_lead_limit_rejected(self):
        with self.assertRaises(ValueError):
            mobile_crossfile.analyze(str(self.root), "windows")
        with self.assertRaises(ValueError):
            mobile_crossfile.analyze(str(self.root), "android", 0)


if __name__ == "__main__":
    unittest.main()
