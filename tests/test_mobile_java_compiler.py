"""Real JDK compiler call-target controls; never run target Java classes."""
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "skills" / "bounty-pilot" / "scripts"
sys.path.insert(0, str(SCRIPTS))
import mobile_java_compiler
import mobile_crossfile


@unittest.skipUnless(shutil.which("java") and shutil.which("javac"),
                     "JDK 17+ required for compiler-backed tests")
class JavaCompilerGraphTests(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.top = Path(scratch.name)
        self.src = self.top / "src"
        self.src.mkdir()

    def put(self, path, content):
        file = self.src / path
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(content, encoding="utf-8")
        return file

    def fixture(self):
        self.put("p/Entry.java", """package p;
class Entry {
    static class Intent {
        String getDataString() { return "fixture"; }
    }
    Intent getIntent() { return new Intent(); }
    void start() {
        String raw = getIntent().getDataString();
        Router.forward(raw);
    }
}
""")
        self.put("p/Router.java", """package p;
class Router {
    static void forward(String input) { webView.loadUrl(input); }
    static Web webView = new Web();
    static class Web { void loadUrl(String value) {} }
}
""")

    def test_compiler_resolves_interfile_call_and_digests(self):
        self.fixture()
        result = mobile_java_compiler.analyze(str(self.src))
        self.assertEqual(result["coverage"]["diagnostic_errors"], 0, result)
        self.assertEqual(result["edge_count"], 1, result)
        edge = result["edges"][0]
        self.assertEqual(edge["caller_file"], "p/Entry.java")
        self.assertEqual(edge["callee_file"], "p/Router.java")
        self.assertEqual(edge["caller_method"], "start")
        self.assertEqual(edge["callee_method"], "forward")
        self.assertIn("java.lang.String", edge["callee_signature"])
        self.assertEqual(edge["binding_source"], "JDK_COMPILER_SYMBOL")
        self.assertFalse(edge["runtime_invocation_verified"])
        self.assertEqual(edge["caller_sha256"],
                         result["source_digests"]["p/Entry.java"])

    def test_compiler_overload_disambiguates_using_symbol(self):
        self.put("p/Entry.java", """package p;
class Entry {
    void go() { Router.forward("ok"); }
}""")
        self.put("p/Router.java", """package p;
class Router {
    static void forward(String value) {}
    static void forward(int value) {}
}""")
        result = mobile_java_compiler.analyze(self.src)
        self.assertEqual(result["coverage"]["diagnostic_errors"], 0, result)
        self.assertEqual(result["edge_count"], 1, result)
        self.assertIn("java.lang.String", result["edges"][0]["callee_signature"])
        self.assertNotIn("(int)", result["edges"][0]["callee_signature"])

    def test_same_method_in_another_package_not_bound(self):
        self.put("p/Entry.java", """package p;
class Entry { void go() { Other.method(); } }""")
        self.put("different/Other.java", """package different;
class Other { static void method() {} }""")
        result = mobile_java_compiler.analyze(self.src)
        self.assertGreater(result["coverage"]["diagnostic_errors"], 0)
        self.assertEqual(result["edge_count"], 0)

    def test_compiler_call_provenance_aligns_lexical_taint_lead(self):
        self.fixture()
        graph = mobile_java_compiler.analyze(self.src)
        report = mobile_crossfile.analyze(self.src, "android",
                                          compiler_graph=graph)
        self.assertEqual(report["lead_count"], 1, report)
        self.assertEqual(report["compiler_comparison"]["aligned_leads"], 1)
        self.assertEqual(report["leads"][0]["compiler_alignment"]["status"],
                         "ALL_HOPS_AST_SYMBOL_ALIGNED")
        self.assertEqual(report["leads"][0]["impact"], "NOT_ESTABLISHED")
        self.assertFalse(report["leads"][0]["compiler_alignment"]
                         ["taint_validated_by_compiler"])

    def test_stale_source_digest_fails(self):
        self.fixture()
        graph = mobile_java_compiler.analyze(self.src)
        (self.src / "p" / "Router.java").write_text(
            (self.src / "p" / "Router.java").read_text() + "\n// changed\n")
        with self.assertRaisesRegex(ValueError, "stale"):
            mobile_crossfile.analyze(self.src, "android", compiler_graph=graph)

    def test_missing_compiler_edge_does_not_claim_alignment(self):
        self.fixture()
        graph = mobile_java_compiler.analyze(self.src)
        graph["edges"] = []
        report = mobile_crossfile.analyze(self.src, "android",
                                          compiler_graph=graph)
        self.assertEqual(report["lead_count"], 1)
        self.assertEqual(report["compiler_comparison"]["unaligned_java_leads"], 1)
        self.assertEqual(report["leads"][0]["compiler_alignment"]["status"],
                         "SOME_HOPS_NOT_AST_ALIGNED")

    def test_no_java_target_class_execution(self):
        self.put("p/Entry.java", """package p;
class Entry {
  static { if (System.currentTimeMillis() > 0) {
      throw new AssertionError("not executed by compiler"); }}
  void start() { Router.forward("x"); }
}
""")
        self.put("p/Router.java", """package p;
class Router { static void forward(String s) {} }
""")
        report = mobile_java_compiler.analyze(self.src)
        self.assertEqual(report["coverage"]["diagnostic_errors"], 0, report)
        self.assertEqual(report["edge_count"], 1)

    def test_cli_private_compiler_report(self):
        self.fixture()
        out = self.top / "compiler-report.json"
        proc = subprocess.run(
            [sys.executable, str(SCRIPTS / "bounty.py"), "mobile-lab",
             "compiler-java", "--sources", str(self.src),
             "--out", str(out)],
            capture_output=True, text=True, timeout=150)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(out.read_text())
        self.assertEqual(payload["engine"], "mobile-java-compiler-graph")
        self.assertEqual(out.stat().st_mode & 0o777, 0o600)

    def test_cli_crossfile_pinned_compiler_graph(self):
        self.fixture()
        compiler = mobile_java_compiler.analyze(self.src)
        graph_file = self.top / "compiler.json"
        graph_file.write_text(json.dumps(compiler))
        out = self.top / "crossfile.json"
        proc = subprocess.run(
            [sys.executable, str(SCRIPTS / "bounty.py"), "mobile-lab",
             "crossfile", "--sources", str(self.src),
             "--platform", "android", "--compiler-graph", str(graph_file),
             "--out", str(out)], capture_output=True, text=True, timeout=90)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(json.loads(out.read_text())["compiler_comparison"]
                         ["aligned_leads"], 1)

    def test_symlinked_source_file_is_not_compiled(self):
        self.fixture()
        link = self.src / "p" / "Evil.java"
        link.symlink_to(self.top / "missing.java")
        report = mobile_java_compiler.analyze(self.src)
        self.assertEqual(report["coverage"]["source_files"], 2)
        self.assertEqual(report["edge_count"], 1)


if __name__ == "__main__":
    unittest.main()
