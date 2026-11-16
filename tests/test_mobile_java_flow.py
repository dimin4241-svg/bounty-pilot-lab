"""JDK-backed, bounded Java argument-flow synthetic controls.

These test only *source-code review leads*, not actual Android intent
origins, app authorization, runtime exploitability or impact.
"""
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "skills" / "bounty-pilot" / "scripts"
sys.path.insert(0, str(SCRIPTS))
import mobile_java_flow


@unittest.skipUnless(shutil.which("java") and shutil.which("javac"),
                     "local JDK 17+ is required for compiler AST tests")
class JavaAstDataflowTests(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.root = Path(scratch.name)
        self.sources = self.root / "sources"
        self.sources.mkdir()

    def put(self, path, code):
        dest = self.sources / path
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(code, encoding="utf-8")

    def prepare(self, body=None, helper=None):
        self.put("fixture/Entry.java", """package fixture;
class Entry {
    static class Intent { String getDataString() { return "safe"; } }
    Intent getIntent() { return new Intent(); }
    void run() {
        String raw = getIntent().getDataString();
        %s
    }
}
""" % (body if body is not None else "Router.forward(raw);"))
        self.put("fixture/Router.java", """package fixture;
class Router {
    static Web web = new Web();
    static class Web { void loadUrl(String value) {} }
    %s
}
""" % (helper if helper is not None else
       "static void forward(String input) { web.loadUrl(input); }"))

    def test_resolved_one_hop_argument_flow(self):
        self.prepare()
        report = mobile_java_flow.analyze(self.sources)
        self.assertEqual(report["coverage"]["diagnostic_errors"], 0, report)
        self.assertEqual(report["lead_count"], 1, report)
        lead = report["leads"][0]
        self.assertEqual(lead["source"]["file"], "fixture/Entry.java")
        self.assertEqual(lead["sink"]["file"], "fixture/Router.java")
        self.assertEqual(lead["sink"]["api_name_cue"], "loadUrl")
        self.assertEqual(len(lead["hops"]), 1)
        self.assertEqual(lead["hops"][0]["method_binding"],
                         "JDK_EXECUTABLE_ELEMENT")
        self.assertEqual(lead["impact"], "NOT_ESTABLISHED")
        self.assertFalse(lead["attacker_origin_verified"])
        self.assertFalse(lead["sink_effect_verified"])

    def test_two_hops_in_distinct_classes(self):
        self.prepare(helper="static void forward(String x) { Target.render(x); }")
        self.put("fixture/Target.java", """package fixture;
class Target {
    static Web web = new Web();
    static class Web { void loadUrl(String s) {} }
    static void render(String s) { web.loadUrl(s); }
}""")
        report = mobile_java_flow.analyze(self.sources)
        self.assertEqual(report["lead_count"], 1, report)
        lead = report["leads"][0]
        self.assertEqual(len(lead["hops"]), 2)
        self.assertEqual(lead["sink"]["file"], "fixture/Target.java")

    def test_constant_assignment_clears_taint(self):
        self.prepare(body='raw = "constant"; Router.forward(raw);')
        self.assertEqual(mobile_java_flow.analyze(self.sources)["lead_count"], 0)

    def test_constant_at_invocation_is_not_tainted(self):
        self.prepare(body='Router.forward("literal");')
        self.assertEqual(mobile_java_flow.analyze(self.sources)["lead_count"], 0)

    def test_renamed_local_alias_propagates(self):
        self.prepare(body='String copy = raw; Router.forward(copy);')
        self.assertEqual(mobile_java_flow.analyze(self.sources)["lead_count"], 1)

    def test_safe_helper_assignment_is_not_assumed_tainted(self):
        self.prepare(body="String copy = Router.clean(raw); Router.forward(copy);",
                     helper="""static String clean(String s) { return "safe"; }
static void forward(String x) { web.loadUrl(x); }""")
        result = mobile_java_flow.analyze(self.sources)
        self.assertEqual(result["coverage"]["diagnostic_errors"], 0)
        self.assertEqual(result["lead_count"], 0)

    def test_branch_invalidates_taint_for_fail_closed_analysis(self):
        self.prepare(body='if (System.currentTimeMillis() > 0) { raw = "safe"; } Router.forward(raw);')
        report = mobile_java_flow.analyze(self.sources)
        self.assertEqual(report["lead_count"], 0)
        self.assertGreater(report["coverage"]["unsupported_control_flow_statements"], 0)

    def test_sink_inside_condition_is_not_claimed(self):
        self.prepare(helper="""static void forward(String s) {
    if (s.length() > 0) web.loadUrl(s);
}""")
        report = mobile_java_flow.analyze(self.sources)
        self.assertEqual(report["lead_count"], 0)
        self.assertGreater(report["coverage"]["unsupported_control_flow_statements"], 0)

    def test_compiler_selects_string_overload(self):
        self.prepare(helper="""static void forward(String s) { web.loadUrl(s); }
static void forward(int number) { web.loadUrl(Integer.toString(number)); }""")
        report = mobile_java_flow.analyze(self.sources)
        self.assertEqual(report["lead_count"], 1, report)
        self.assertIn("java.lang.String", report["leads"][0]["hops"][0]
                      ["callee_signature"])
        self.assertNotIn("(int)", report["leads"][0]["hops"][0]
                         ["callee_signature"])

    def test_unresolved_other_package_does_not_cross(self):
        self.prepare(body="External.forward(raw);")
        self.put("different/External.java", """package different;
class External { static void forward(String s) { } }""")
        report = mobile_java_flow.analyze(self.sources)
        self.assertEqual(report["lead_count"], 0)
        self.assertGreater(report["coverage"]["diagnostic_errors"], 0)

    def test_onnewintent_parameter_name_seed(self):
        self.put("fixture/Entry.java", """package fixture;
class Entry {
    static class Intent { }
    void onNewIntent(Intent intent) { Router.forward(intent); }
}""")
        self.put("fixture/Router.java", """package fixture;
class Router {
    static Web web = new Web();
    static class Web { void startActivity(Entry.Intent intent) {} }
    static void forward(Entry.Intent input) { web.startActivity(input); }
}""")
        report = mobile_java_flow.analyze(self.sources)
        self.assertEqual(report["lead_count"], 1, report)
        self.assertEqual(report["leads"][0]["source"]["kind"],
                         "ONNEWINTENT_PARAMETER_NAME_CUE")

    def test_string_literal_source_not_used_as_source(self):
        self.prepare(body='String comment = "getIntent().getDataString()"; Router.forward(comment);')
        self.assertEqual(mobile_java_flow.analyze(self.sources)["lead_count"], 0)

    def test_nested_wrapper_expression_is_not_assumed_to_forward(self):
        self.prepare(body="Router.forward(Router.clean(raw));",
                     helper="""static String clean(String s) { return s; }
static void forward(String x) { web.loadUrl(x); }""")
        result = mobile_java_flow.analyze(self.sources)
        self.assertEqual(result["coverage"]["diagnostic_errors"], 0)
        self.assertEqual(result["lead_count"], 0)

    def test_target_static_initializer_does_not_run(self):
        self.prepare()
        self.put("fixture/Explode.java", """package fixture;
class Explode {
    static { if (System.currentTimeMillis() > 0)
        throw new AssertionError("never executed"); }
}""")
        report = mobile_java_flow.analyze(self.sources)
        self.assertEqual(report["lead_count"], 1)

    def test_source_hashes_are_pinned(self):
        self.prepare()
        first = mobile_java_flow.analyze(self.sources)
        second = mobile_java_flow.analyze(self.sources)
        self.assertEqual(first, second)
        self.assertEqual(len(first["source_digests"]["fixture/Entry.java"]), 64)

    def test_cli_creates_private_report(self):
        self.prepare()
        out = self.root / "java-flow.json"
        result = subprocess.run(
            [sys.executable, str(SCRIPTS / "bounty.py"), "mobile-lab",
             "flow-java", "--sources", str(self.sources), "--out", str(out)],
            capture_output=True, text=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(out.read_text())
        self.assertEqual(report["engine"], "mobile-java-compiler-flow")
        self.assertEqual(out.stat().st_mode & 0o777, 0o600)

    def test_symlinked_java_source_is_skipped(self):
        self.prepare()
        link = self.sources / "fixture" / "Bad.java"
        link.symlink_to(self.root / "missing.java")
        report = mobile_java_flow.analyze(self.sources)
        self.assertEqual(report["coverage"]["source_files"], 2)
        self.assertEqual(report["lead_count"], 1)


    def test_same_file_static_helper_is_compiler_bound(self):
        self.put("fixture/Entry.java", """package fixture;
class Entry {
    static class Intent { String getDataString() { return "safe"; } }
    Intent getIntent() { return new Intent(); }
    static void relay(String value) { Router.forward(value); }
    void run() {
        String raw = getIntent().getDataString();
        relay(raw);
    }
}""")
        self.put("fixture/Router.java", """package fixture;
class Router {
    static class Web { void loadUrl(String s) {} }
    static Web web = new Web();
    static void forward(String s) { web.loadUrl(s); }
}""")
        report = mobile_java_flow.analyze(self.sources)
        self.assertEqual(report["coverage"]["diagnostic_errors"], 0, report)
        self.assertEqual(report["lead_count"], 1, report)
        self.assertEqual(len(report["leads"][0]["hops"]), 2)
        self.assertEqual(report["leads"][0]["hops"][0]["caller_file"],
                         report["leads"][0]["hops"][0]["callee_file"])

    def test_private_same_file_instance_helper_is_fixed_dispatch(self):
        self.put("fixture/Entry.java", """package fixture;
class Entry {
    static class Intent { String getDataString() { return "safe"; } }
    Intent getIntent() { return new Intent(); }
    private void relay(String s) { Router.forward(s); }
    void run() { String raw = getIntent().getDataString(); relay(raw); }
}""")
        self.put("fixture/Router.java", """package fixture;
class Router {
    static class Web { void loadUrl(String s) {} }
    static Web web = new Web();
    static void forward(String s) { web.loadUrl(s); }
}""")
        report = mobile_java_flow.analyze(self.sources)
        self.assertEqual(report["coverage"]["diagnostic_errors"], 0, report)
        self.assertEqual(report["lead_count"], 1, report)

    def test_virtual_overridable_declaration_not_assumed_executed(self):
        self.prepare(body="Router r = new Derived(); r.forward(raw);",
                     helper="""void forward(String s) { web.loadUrl(s); }""")
        self.put("fixture/Derived.java", """package fixture;
class Derived extends Router {
    @Override void forward(String s) { /* deliberately no sink */ }
}""")
        report = mobile_java_flow.analyze(self.sources)
        self.assertEqual(report["coverage"]["diagnostic_errors"], 0, report)
        self.assertEqual(report["lead_count"], 0, report)

    def test_final_instance_method_can_be_followed(self):
        self.prepare(body="Router r = new Router(); r.forward(raw);",
                     helper="""final void forward(String s) { web.loadUrl(s); }""")
        report = mobile_java_flow.analyze(self.sources)
        self.assertEqual(report["coverage"]["diagnostic_errors"], 0, report)
        self.assertEqual(report["lead_count"], 1, report)

    def test_matching_assignment_only_branches_preserve_origin(self):
        self.prepare(body="""String copy = "";
boolean flag = false;
if (flag) { copy = raw; } else { copy = raw; }
Router.forward(copy);""")
        report = mobile_java_flow.analyze(self.sources)
        self.assertEqual(report["coverage"]["diagnostic_errors"], 0, report)
        self.assertEqual(report["lead_count"], 1, report)
        self.assertGreater(report["coverage"]["unsupported_control_flow_statements"], 0)

    def test_implicit_else_must_not_preserve_one_sided_copy(self):
        self.prepare(body="""String copy = "";
boolean flag = false;
if (flag) { copy = raw; }
Router.forward(copy);""")
        report = mobile_java_flow.analyze(self.sources)
        self.assertEqual(report["lead_count"], 0, report)

    def test_sanitized_on_one_branch_drops_provenance(self):
        self.prepare(body="""boolean flag = false;
if (flag) { raw = "safe"; } else { raw = raw; }
Router.forward(raw);""")
        report = mobile_java_flow.analyze(self.sources)
        self.assertEqual(report["lead_count"], 0, report)

    def test_mutating_condition_is_unsupported(self):
        self.prepare(body="""if ((raw = "safe") != null) { }
Router.forward(raw);""")
        report = mobile_java_flow.analyze(self.sources)
        self.assertEqual(report["lead_count"], 0, report)
        self.assertGreater(report["coverage"]["unsupported_control_flow_statements"], 0)

    def test_calls_inside_conditional_block_remain_unanalyzed(self):
        self.prepare(body="""boolean flag = true;
if (flag) { Router.forward(raw); }""")
        report = mobile_java_flow.analyze(self.sources)
        self.assertEqual(report["lead_count"], 0, report)

if __name__ == "__main__":
    unittest.main()
