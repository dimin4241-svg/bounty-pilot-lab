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

    def test_pure_nested_wrapper_is_now_bound_with_return_evidence(self):
        self.prepare(body="Router.forward(Router.clean(raw));",
                     helper="""static String clean(String s) { return s; }
static void forward(String x) { web.loadUrl(x); }""")
        result = mobile_java_flow.analyze(self.sources)
        self.assertEqual(result["coverage"]["diagnostic_errors"], 0)
        self.assertEqual(result["lead_count"], 1, result)
        self.assertEqual([edge["edge_kind"] for edge in result["leads"][0]["hops"]],
                         ["METHOD_CALL", "RETURN_TO_CALLER", "METHOD_CALL"])

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


    def test_pure_return_helper_propagates_with_balanced_edges(self):
        self.prepare(body="String copy = Helper.identity(raw); Router.forward(copy);")
        self.put("fixture/Helper.java", """package fixture;
final class Helper {
    static String identity(String value) { return value; }
}""")
        report = mobile_java_flow.analyze(self.sources)
        self.assertEqual(report["coverage"]["diagnostic_errors"], 0, report)
        self.assertEqual(report["lead_count"], 1, report)
        edges = report["leads"][0]["hops"]
        self.assertEqual([hop["edge_kind"] for hop in edges],
                         ["METHOD_CALL", "RETURN_TO_CALLER", "METHOD_CALL"])
        self.assertEqual(edges[1]["method_binding"], "JDK_BOUND_RETURN_TO_CALLER")
        self.assertEqual(report["leads"][0]["impact"], "NOT_ESTABLISHED")

    def test_pure_return_helper_as_nested_sink_argument(self):
        self.prepare(body="Router.forward(Helper.identity(raw));")
        self.put("fixture/Helper.java", """package fixture;
class Helper { static String identity(String x) { return x; } }""")
        report = mobile_java_flow.analyze(self.sources)
        self.assertEqual(report["lead_count"], 1, report)
        self.assertEqual(len(report["leads"][0]["hops"]), 3)

    def test_same_file_private_static_return_helper(self):
        self.put("fixture/Entry.java", """package fixture;
class Entry {
    static class Intent { String getDataString() { return "sample"; } }
    Intent getIntent() { return new Intent(); }
    private static String identity(String s) { return s; }
    void run() {
        String raw = getIntent().getDataString();
        Router.forward(identity(raw));
    }
}""")
        self.put("fixture/Router.java", """package fixture;
class Router {
    static void forward(String s) { new Web().loadUrl(s); }
    static class Web { void loadUrl(String s) {} }
}""")
        report = mobile_java_flow.analyze(self.sources)
        self.assertEqual(report["coverage"]["diagnostic_errors"], 0, report)
        self.assertEqual(report["lead_count"], 1, report)
        self.assertEqual([h["edge_kind"] for h in report["leads"][0]["hops"]],
                         ["METHOD_CALL", "RETURN_TO_CALLER", "METHOD_CALL"])

    def test_literal_return_is_not_considered_propagation(self):
        self.prepare(body="String clean = Helper.clean(raw); Router.forward(clean);")
        self.put("fixture/Helper.java", """package fixture;
class Helper { static String clean(String s) { return "fixed"; } }""")
        report = mobile_java_flow.analyze(self.sources)
        self.assertEqual(report["coverage"]["diagnostic_errors"], 0, report)
        self.assertEqual(report["lead_count"], 0)

    def test_mutation_before_return_invalidates_propagation(self):
        self.prepare(body="String clean = Helper.clean(raw); Router.forward(clean);")
        self.put("fixture/Helper.java", """package fixture;
class Helper {
    static String clean(String s) { s = "fixed"; return s; }
}""")
        report = mobile_java_flow.analyze(self.sources)
        self.assertEqual(report["lead_count"], 0)

    def test_side_effecting_helper_cannot_be_summarized_as_pure(self):
        self.prepare(body="Router.forward(Helper.notPure(raw));")
        self.put("fixture/Helper.java", """package fixture;
class Helper {
    static void effect() {}
    static String notPure(String value) { effect(); return value; }
}""")
        report = mobile_java_flow.analyze(self.sources)
        self.assertEqual(report["coverage"]["diagnostic_errors"], 0, report)
        self.assertEqual(report["lead_count"], 0)

    def test_return_from_branch_does_not_qualify(self):
        self.prepare(body="Router.forward(Helper.maybe(raw));")
        self.put("fixture/Helper.java", """package fixture;
class Helper {
    static String maybe(String value) {
        if (value == null) return "";
        return value;
    }
}""")
        report = mobile_java_flow.analyze(self.sources)
        self.assertEqual(report["lead_count"], 0)

    def test_virtual_overridden_return_must_not_propagate(self):
        self.prepare(body="""Helper helper = new Derived();
Router.forward(helper.identity(raw));""")
        self.put("fixture/Helper.java", """package fixture;
class Helper { String identity(String s) { return s; } }""")
        self.put("fixture/Derived.java", """package fixture;
class Derived extends Helper {
    @Override String identity(String s) { return "fixed"; }
}""")
        report = mobile_java_flow.analyze(self.sources)
        self.assertEqual(report["coverage"]["diagnostic_errors"], 0, report)
        self.assertEqual(report["lead_count"], 0)

    def test_private_this_field_tracks_same_method(self):
        self.prepare()
        self.put("fixture/Entry.java", """package fixture;
class Entry {
    static class Intent { String getDataString() { return "sample"; } }
    Intent getIntent() { return new Intent(); }
    private String payload;
    void run() {
        String raw = getIntent().getDataString();
        this.payload = raw;
        Router.forward(this.payload);
    }
}""")
        report = mobile_java_flow.analyze(self.sources)
        self.assertEqual(report["coverage"]["diagnostic_errors"], 0, report)
        self.assertEqual(report["lead_count"], 1, report)

    def test_private_unqualified_field_tracks_same_method(self):
        self.prepare()
        self.put("fixture/Entry.java", """package fixture;
class Entry {
    static class Intent { String getDataString() { return "sample"; } }
    Intent getIntent() { return new Intent(); }
    private String payload;
    void run() {
        String raw = getIntent().getDataString();
        payload = raw;
        Router.forward(payload);
    }
}""")
        report = mobile_java_flow.analyze(self.sources)
        self.assertEqual(report["lead_count"], 1, report)

    def test_private_field_literal_overwrite_clears_origin(self):
        self.prepare()
        self.put("fixture/Entry.java", """package fixture;
class Entry {
    static class Intent { String getDataString() { return "sample"; } }
    Intent getIntent() { return new Intent(); }
    private String payload;
    void run() {
        String raw = getIntent().getDataString();
        this.payload = raw;
        this.payload = "fixed";
        Router.forward(this.payload);
    }
}""")
        self.assertEqual(mobile_java_flow.analyze(self.sources)["lead_count"], 0)

    def test_unknown_method_call_invalidates_private_field(self):
        self.prepare()
        self.put("fixture/Entry.java", """package fixture;
class Entry {
    static class Intent { String getDataString() { return "sample"; } }
    Intent getIntent() { return new Intent(); }
    private String payload;
    void modify() { this.payload = "fixed"; }
    void run() {
        String raw = getIntent().getDataString();
        this.payload = raw;
        modify();
        Router.forward(this.payload);
    }
}""")
        self.assertEqual(mobile_java_flow.analyze(self.sources)["lead_count"], 0)

    def test_public_fields_do_not_acquire_heap_provenance(self):
        self.prepare()
        self.put("fixture/Entry.java", """package fixture;
class Entry {
    static class Intent { String getDataString() { return "sample"; } }
    Intent getIntent() { return new Intent(); }
    public String payload;
    void run() {
        String raw = getIntent().getDataString();
        this.payload = raw;
        Router.forward(this.payload);
    }
}""")
        self.assertEqual(mobile_java_flow.analyze(self.sources)["lead_count"], 0)

    def test_arbitrary_object_field_is_not_assumed_to_alias_this(self):
        self.prepare()
        self.put("fixture/Entry.java", """package fixture;
class Entry {
    static class Intent { String getDataString() { return "sample"; } }
    Intent getIntent() { return new Intent(); }
    static class Holder { private String payload; }
    void run() {
        String raw = getIntent().getDataString();
        Holder a = new Holder();
        Holder b = new Holder();
        a.payload = raw;
        Router.forward(b.payload);
    }
}""")
        self.assertEqual(mobile_java_flow.analyze(self.sources)["lead_count"], 0)

    def test_unmatched_reverse_provenance_is_rejected(self):
        import base64
        def encode(value):
            return base64.urlsafe_b64encode(str(value).encode()).rstrip(b"=").decode()
        values = ["fixture/Entry.java", "3", "ANDROID_INTENT_SOURCE_SYNTAX_CUE",
                  "fixture/Router.java", "7", "forward", "fixture.Router#forward(java.lang.String)",
                  "loadUrl", "1",
                  "fixture/Entry.java", "run", "fixture.Entry#run()", "5",
                  "fixture/Router.java", "forward", "6",
                  "fixture.Router#forward(java.lang.String)", "RETURN_TO_CALLER"]
        payload = "META\t2\t0\t2\t1\t0\t0\nFLOW\t" + "\t".join(map(encode, values))
        with self.assertRaisesRegex(ValueError, "return does not match"):
            mobile_java_flow._parse(payload, {
                "fixture/Entry.java": "a" * 64, "fixture/Router.java": "b" * 64})


    def test_join_must_reject_different_wrapper_provenance(self):
        self.prepare(body="""String viaHelper = Helper.identity(raw);
String direct = raw;
String selected = "";
boolean flag = true;
if (flag) { selected = viaHelper; } else { selected = direct; }
Router.forward(selected);""")
        self.put("fixture/Helper.java", """package fixture;
class Helper { static String identity(String x) { return x; } }""")
        report = mobile_java_flow.analyze(self.sources)
        self.assertEqual(report["coverage"]["diagnostic_errors"], 0, report)
        self.assertEqual(report["lead_count"], 0, report)

    def test_join_retains_identical_return_provenance(self):
        self.prepare(body="""String copy = Helper.identity(raw);
String selected = "";
boolean flag = true;
if (flag) { selected = copy; } else { selected = copy; }
Router.forward(selected);""")
        self.put("fixture/Helper.java", """package fixture;
class Helper { static String identity(String x) { return x; } }""")
        report = mobile_java_flow.analyze(self.sources)
        self.assertEqual(report["coverage"]["diagnostic_errors"], 0, report)
        self.assertEqual(report["lead_count"], 1, report)
        self.assertEqual(len(report["leads"][0]["hops"]), 3)


    def capsule_fixture(self, body, box=None):
        self.put("fixture/Entry.java", """package fixture;
class Entry {
    static class Intent { String getDataString() { return "sample"; } }
    Intent getIntent() { return new Intent(); }
    void run() {
        String raw = getIntent().getDataString();
        %s
    }
}""" % body)
        self.put("fixture/Box.java", box or """package fixture;
final class Box {
    private String payload;
    void put(String s) { this.payload = s; }
    String read() { return payload; }
}""")
        self.put("fixture/Router.java", """package fixture;
class Router {
    static class Web { void loadUrl(String s) {} }
    static Web web = new Web();
    static void forward(String s) { web.loadUrl(s); }
}""")

    def test_fresh_object_alias_through_setter_and_getter(self):
        self.capsule_fixture("""Box first = new Box();
Box alias = first;
first.put(raw);
Router.forward(alias.read());""")
        result = mobile_java_flow.analyze(self.sources)
        self.assertEqual(result["coverage"]["diagnostic_errors"], 0, result)
        self.assertEqual(result["lead_count"], 1, result)
        lead = result["leads"][0]
        self.assertEqual(lead["impact"], "NOT_ESTABLISHED")
        self.assertEqual(lead["reachability"], "UNKNOWN")
        self.assertEqual([h["edge_kind"] for h in lead["hops"]], [
            "METHOD_CALL", "RETURN_TO_CALLER", "METHOD_CALL",
            "RETURN_TO_CALLER", "METHOD_CALL"])
        self.assertEqual(lead["hops"][0]["callee_file"], "fixture/Box.java")
        self.assertEqual(lead["sink"]["file"], "fixture/Router.java")

    def test_transitive_alias_across_three_names(self):
        self.capsule_fixture("""Box first = new Box();
Box second = first;
Box third = second;
first.put(raw);
String result = third.read();
Router.forward(result);""")
        report = mobile_java_flow.analyze(self.sources)
        self.assertEqual(report["coverage"]["diagnostic_errors"], 0, report)
        self.assertEqual(report["lead_count"], 1, report)

    def test_two_fresh_objects_do_not_share_private_state(self):
        self.capsule_fixture("""Box first = new Box();
Box second = new Box();
first.put(raw);
Router.forward(second.read());""")
        report = mobile_java_flow.analyze(self.sources)
        self.assertEqual(report["coverage"]["diagnostic_errors"], 0, report)
        self.assertEqual(report["lead_count"], 0, report)

    def test_alias_reassignment_detaches_original_object(self):
        self.capsule_fixture("""Box first = new Box();
Box second = first;
second = new Box();
first.put(raw);
Router.forward(second.read());""")
        self.assertEqual(mobile_java_flow.analyze(self.sources)["lead_count"], 0)

    def test_literal_setter_overwrite_clears_old_data(self):
        self.capsule_fixture("""Box a = new Box();
Box b = a;
a.put(raw);
b.put("known");
Router.forward(a.read());""")
        self.assertEqual(mobile_java_flow.analyze(self.sources)["lead_count"], 0)

    def test_setter_also_supports_unqualified_private_field(self):
        box = """package fixture;
final class Box {
    private String payload;
    void put(String s) { payload = s; }
    String read() { return this.payload; }
}"""
        self.capsule_fixture("""Box a = new Box();
a.put(raw);
Router.forward(a.read());""", box=box)
        report = mobile_java_flow.analyze(self.sources)
        self.assertEqual(report["coverage"]["diagnostic_errors"], 0, report)
        self.assertEqual(report["lead_count"], 1, report)

    def test_unknown_receiver_method_invalidates_object_state(self):
        box = """package fixture;
final class Box {
    private String payload;
    void put(String s) { payload = s; }
    void reset() { payload = "fixed"; }
    String read() { return payload; }
}"""
        self.capsule_fixture("""Box a = new Box();
a.put(raw);
a.reset();
Router.forward(a.read());""", box=box)
        self.assertEqual(mobile_java_flow.analyze(self.sources)["lead_count"], 0)

    def test_escaped_object_not_reacquired_even_after_new_setter(self):
        self.capsule_fixture("""Box a = new Box();
Escaper.hold(a);
a.put(raw);
Router.forward(a.read());""")
        self.put("fixture/Escaper.java", """package fixture;
class Escaper { static Box hidden; static void hold(Box a) { hidden = a; } }""")
        report = mobile_java_flow.analyze(self.sources)
        self.assertEqual(report["coverage"]["diagnostic_errors"], 0, report)
        self.assertEqual(report["lead_count"], 0, report)

    def test_unknown_expression_storing_object_invalidates_it(self):
        self.capsule_fixture("""Box a = new Box();
Object[] array = new Object[] { a };
a.put(raw);
Router.forward(a.read());""")
        report = mobile_java_flow.analyze(self.sources)
        self.assertEqual(report["lead_count"], 0, report)

    def test_nonfinal_class_does_not_get_capsule_identity(self):
        box = """package fixture;
class Box {
    private String payload;
    void put(String s) { payload = s; }
    String read() { return payload; }
}"""
        self.capsule_fixture("""Box a = new Box();
a.put(raw);
Router.forward(a.read());""", box=box)
        self.assertEqual(mobile_java_flow.analyze(self.sources)["lead_count"], 0)

    def test_explicit_constructor_cannot_be_assumed_side_effect_free(self):
        box = """package fixture;
final class Box {
    private String payload;
    Box() { External.leak(this); }
    void put(String s) { payload = s; }
    String read() { return payload; }
}
class External { static Object leaked; static void leak(Object x) { leaked = x; } }"""
        self.capsule_fixture("""Box a = new Box();
a.put(raw);
Router.forward(a.read());""", box=box)
        self.assertEqual(mobile_java_flow.analyze(self.sources)["lead_count"], 0)

    def test_mutating_instance_initializer_is_not_treated_as_fresh(self):
        box = """package fixture;
final class Box {
    private String payload;
    { payload = "initial"; }
    void put(String s) { payload = s; }
    String read() { return payload; }
}"""
        self.capsule_fixture("""Box a = new Box();
a.put(raw);
Router.forward(a.read());""", box=box)
        self.assertEqual(mobile_java_flow.analyze(self.sources)["lead_count"], 0)

    def test_public_field_accessor_is_not_private_heap_summary(self):
        box = """package fixture;
final class Box {
    public String payload;
    void put(String s) { payload = s; }
    String read() { return payload; }
}"""
        self.capsule_fixture("""Box a = new Box();
a.put(raw);
Router.forward(a.read());""", box=box)
        self.assertEqual(mobile_java_flow.analyze(self.sources)["lead_count"], 0)

    def test_complex_accessor_is_not_summarized(self):
        box = """package fixture;
final class Box {
    private String payload;
    void put(String s) { payload = s; }
    String read() { if (payload == null) return "safe"; return payload; }
}"""
        self.capsule_fixture("""Box a = new Box();
a.put(raw);
Router.forward(a.read());""", box=box)
        self.assertEqual(mobile_java_flow.analyze(self.sources)["lead_count"], 0)

    def test_incomplete_branch_drops_capsule_facts(self):
        self.capsule_fixture("""Box a = new Box();
a.put(raw);
boolean flag = false;
if (flag) { a.put("fixed"); }
Router.forward(a.read());""")
        report = mobile_java_flow.analyze(self.sources)
        self.assertEqual(report["lead_count"], 0, report)

    def test_object_field_alias_not_mistaken_for_local_variable(self):
        self.capsule_fixture("""Box a = new Box();
Holder holder = new Holder();
holder.box = a;
a.put(raw);
Router.forward(holder.box.read());""")
        self.put("fixture/Holder.java", """package fixture;
class Holder { Box box; }""")
        self.assertEqual(mobile_java_flow.analyze(self.sources)["lead_count"], 0)

    def test_local_alias_and_source_snapshot_is_deterministic(self):
        self.capsule_fixture("""Box a = new Box();
Box b = a;
a.put(raw);
Router.forward(b.read());""")
        a = mobile_java_flow.analyze(self.sources)
        b = mobile_java_flow.analyze(self.sources)
        self.assertEqual(a, b)
        self.assertEqual(a["lead_count"], 1)

if __name__ == "__main__":
    unittest.main()
