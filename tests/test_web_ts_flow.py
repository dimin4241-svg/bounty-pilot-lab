"""Cross-file TypeScript argument propagation, parser pinning and no-exec tests."""
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1] / "skills" / "bounty-pilot" / "scripts"
SPEC = importlib.util.spec_from_file_location("web_ts_flow_test_mod", SCRIPTS / "web_ts_flow.py")
flow = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(flow)


def index_fixture(inject=True):
    req_param = ["req", "params", "id"] if inject else []
    return {"schema_version": 1, "files": [
        {"path": "api/routes.ts", "imports": [
            {"specifier": "./handler", "names": [
                {"local": "getInvoice", "exported": "getInvoice"}]}],
         "functions": [],
         "routes": [{"path": "/api/invoices/:id", "method": "GET",
                     "handler": "getInvoice", "middleware": ["requireAuth"],
                     "line": 5}], "parse_diagnostics": 0},
        {"path": "api/handler.ts", "imports": [
            {"specifier": "./data", "names": [
                {"local": "lookup", "exported": "findInvoice"}]}],
         "functions": [{"name": "getInvoice", "params": ["req", "res"],
                        "exported": True, "aliases": [],
                        "calls": [{"callee": "lookup", "line": 10, "args": [req_param]}]}],
         "routes": [], "parse_diagnostics": 0},
        {"path": "api/data.ts", "imports": [],
         "functions": [{"name": "findInvoice", "params": ["id"],
                        "exported": True, "aliases": [],
                        "calls": [{"callee": "db.invoice.findUnique", "line": 17,
                                   "args": [["where", "id"]]}]}],
         "routes": [], "parse_diagnostics": 0},
    ]}


def dom_index_fixture(sourced=True, sanitized=False):
    q_from = ["URLSearchParams", "get", "location", "search"] if sourced else ["props"]
    calls = [{"callee": "dangerouslySetInnerHTML", "line": 4, "args": [["q"]]}]
    if sanitized:
        calls.insert(0, {"callee": "DOMPurify.sanitize", "line": 3, "args": [["q"]]})
    return {"schema_version": 1, "files": [
        {"path": "web/Banner.tsx", "imports": [], "routes": [], "parse_diagnostics": 0,
         "functions": [{"name": "Banner", "line": 2, "params": [], "exported": True,
                        "aliases": [{"name": "q", "from": q_from}], "calls": calls}]},
        {"path": "web/Safe.tsx", "imports": [], "routes": [], "parse_diagnostics": 0,
         "functions": [{"name": "Safe", "line": 10, "params": ["el", "trusted"],
                        "exported": True, "aliases": [],
                        "calls": [{"callee": "el.innerHTML", "line": 11,
                                  "args": [["trusted"]]}]}]},
    ]}


class TSGraphTests(unittest.TestCase):
    def test_cross_file_import_alias_and_argument_to_sink(self):
        out = flow.analyze_index(index_fixture(), "0" * 64, 300, {})
        self.assertEqual(len(out["flows"]), 1)
        lead = out["flows"][0]
        self.assertTrue(lead["cross_file"])
        self.assertEqual(lead["sink"]["call"], "db.invoice.findUnique")
        self.assertEqual([hop["file"] for hop in lead["call_chain"]],
                         ["api/handler.ts", "api/data.ts"])
        self.assertEqual(lead["guard_name_cues"], ["requireAuth"])
        self.assertEqual(out["confirmed_vulnerabilities"], 0)
        self.assertEqual(out["network_requests"], 0)

    def test_literal_instead_of_input_has_no_flow(self):
        out = flow.analyze_index(index_fixture(False), "0" * 64, 300, {})
        self.assertEqual(out["flows"], [])

    def test_dom_source_reaching_dangerously_set_inner_html_is_flagged(self):
        out = flow.analyze_index(dom_index_fixture(), "0" * 64, 300, {})
        dom = [f for f in out["flows"] if f["kind"] == "DOM_XSS_CANDIDATE_FLOW"]
        self.assertEqual(len(dom), 1)
        self.assertEqual(dom[0]["sink"]["call"], "dangerouslySetInnerHTML")
        self.assertEqual(dom[0]["sink"]["function"], "Banner")
        self.assertEqual(dom[0]["sanitizer_name_cues"], [])

    def test_unrelated_parameter_into_inner_html_is_not_flagged(self):
        # `Safe.tsx` writes `el.innerHTML = trusted`, where `trusted` is an ordinary
        # parameter unrelated to any DOM source identifier - must never be flagged.
        out = flow.analyze_index(dom_index_fixture(sourced=False), "0" * 64, 300, {})
        self.assertEqual([f for f in out["flows"] if f["kind"] == "DOM_XSS_CANDIDATE_FLOW"], [])

    def test_sanitizer_call_in_chain_is_recorded_as_a_cue_not_a_clearance(self):
        out = flow.analyze_index(dom_index_fixture(sanitized=True), "0" * 64, 300, {})
        dom = [f for f in out["flows"] if f["kind"] == "DOM_XSS_CANDIDATE_FLOW"]
        self.assertEqual(len(dom), 1)
        self.assertEqual(dom[0]["sanitizer_name_cues"], ["DOMPurify.sanitize"])
        self.assertEqual(dom[0]["classification"], "UNVERIFIED_STATIC_ARGUMENT_FLOW")

    def test_request_argument_into_eval_is_its_own_classification(self):
        fixture = index_fixture()
        fixture["files"][1]["functions"][0]["calls"] = [
            {"callee": "runUserCode", "line": 10, "args": [["req", "params", "id"]]}]
        fixture["files"].append({
            "path": "api/run.ts", "imports": [], "routes": [], "parse_diagnostics": 0,
            "functions": [{"name": "runUserCode", "line": 1, "params": ["code"],
                           "exported": True, "aliases": [],
                           "calls": [{"callee": "Function", "line": 2, "args": [["code"]]}]}]})
        fixture["files"][1]["imports"].append(
            {"specifier": "./run", "names": [{"local": "runUserCode", "exported": "runUserCode"}]})
        out = flow.analyze_index(fixture, "0" * 64, 300, {})
        kinds = {f["kind"] for f in out["flows"]}
        self.assertIn("SYNTACTIC_REQUEST_ARGUMENT_TO_CODE_EVALUATION", kinds)
        self.assertNotIn("DOM_XSS_CANDIDATE_FLOW", kinds)

    def test_unresolved_handler_never_converted_to_a_finding(self):
        fixture = index_fixture()
        fixture["files"][1]["functions"] = []
        result = flow.analyze_index(fixture, "0" * 64, 30, {})
        self.assertEqual(result["flows"], [])
        self.assertEqual(result["unresolved_routes"][0]["reason"], "HANDLER_UNRESOLVED")

    def test_import_escape_cannot_resolve_to_other_repo(self):
        self.assertIsNone(flow._resolve_import("a/handler.ts", "../../private",
                                                {"private.ts"}))
        self.assertEqual(flow._resolve_import("a/routes.ts", "./handler",
                                               {"a/handler.ts"}), "a/handler.ts")

    def test_source_scope_and_symlink_exclusion(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            (root / "src").mkdir()
            (root / "node_modules").mkdir()
            (root / "src" / "included.ts").write_text("export const x = 1;")
            (root / "node_modules" / "ignored.ts").write_text("export const y = 2;")
            outside = Path(tmp) / "outside.ts"
            outside.write_text("source")
            (root / "src" / "link.ts").symlink_to(outside)
            found, omitted, size = flow._collect(root, ["src"])
            self.assertEqual([r["path"] for r in found], ["src/included.ts"])
            self.assertEqual(omitted["symlinked"], 1)
            self.assertGreater(size, 0)
            with self.assertRaises(ValueError):
                flow._collect(root, ["../other"])

    def test_parent_alias_simulating_macos_var_is_not_source_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            real = base / "private-storage"
            root_real = real / "repo"
            (root_real / "src").mkdir(parents=True)
            (root_real / "src" / "normal.ts").write_text("export const value = 1;\n")
            top_alias = base / "var-alias"
            top_alias.symlink_to(real, target_is_directory=True)
            root_alias = top_alias / "repo"
            # The root itself isn't a symlink, only one of its ancestors.
            self.assertFalse(root_alias.is_symlink())
            found, omitted, size = flow._collect(root_alias, ["src"])
            self.assertEqual([x["path"] for x in found], ["src/normal.ts"])
            self.assertEqual(omitted["symlinked"], 0)
            self.assertGreater(size, 0)
            root_resolved = flow._root(root_alias)
            found_again, _, _ = flow._collect(root_resolved, ["src"])
            self.assertEqual([x["path"] for x in found_again], ["src/normal.ts"])

    def test_parent_alias_preserves_in_repo_symlink_file_exclusion(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            real = base / "private-storage"
            root_real = real / "repo"
            (root_real / "src").mkdir(parents=True)
            (root_real / "src" / "normal.ts").write_text("export const n = 1;\n")
            external = base / "out.ts"
            external.write_text("outside")
            (root_real / "src" / "link.ts").symlink_to(external)
            top_alias = base / "var-alias"
            top_alias.symlink_to(real, target_is_directory=True)
            found, omitted, _ = flow._collect(top_alias / "repo", ["src"])
            self.assertEqual([x["path"] for x in found], ["src/normal.ts"])
            self.assertEqual(omitted["symlinked"], 1)

    def test_source_budget_not_silently_truncated(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for i in range(flow.MAX_FILES + 1):
                (root / ("f%d.ts" % i)).write_text("x")
            with self.assertRaisesRegex(ValueError, "budget"):
                flow._collect(root)

    def test_parser_pin_required(self):
        with tempfile.TemporaryDirectory() as tmp:
            parser = Path(tmp) / "typescript.js"
            parser.write_text("fixture")
            with self.assertRaises(ValueError):
                flow._parser(parser, "0" * 64)
            self.assertEqual(flow._parser(parser, hashlib.sha256(
                parser.read_bytes()).hexdigest()), str(parser.resolve()))

    @unittest.skipUnless(os.getenv("BP_TYPESCRIPT_PARSER"),
                         "optional pinned local TypeScript compiler unavailable")
    def test_real_typescript_parser_multifile_fixture(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            api = root / "api"
            api.mkdir()
            (api / "routes.ts").write_text('''
import { getInvoice } from "./handler";
app.get("/api/invoices/:id", requireAuth, getInvoice);
app.post("/api/fixed", async (req) => { return Promise.resolve("ok"); });
''')
            (api / "handler.ts").write_text('''
import { findInvoice as lookup } from "./data";
export async function getInvoice(req: any, res: any) {
  const docId = req.params.id;
  return lookup(docId);
}
''')
            (api / "data.ts").write_text('''
export async function findInvoice(id: string) {
  return db.invoice.findUnique({where: {id}});
}
''')
            marker = root / "must-not-run"
            (api / "unsafe.ts").write_text(
                "require('fs').writeFileSync(" + json.dumps(str(marker)) + ", 'BAD');")
            parser = Path(os.environ["BP_TYPESCRIPT_PARSER"])
            sha = hashlib.sha256(parser.read_bytes()).hexdigest()
            result = flow.inspect(root, parser, sha)
            self.assertFalse(marker.exists(), "parsing must never execute target code")
            self.assertEqual(result["parse_problems"], [])
            self.assertEqual(len(result["flows"]), 1)
            self.assertEqual(result["flows"][0]["sink"]["call"], "db.invoice.findUnique")
            self.assertTrue(result["flows"][0]["cross_file"])

    @unittest.skipUnless(os.getenv("BP_TYPESCRIPT_PARSER"),
                         "optional pinned local TypeScript compiler unavailable")
    def test_real_typescript_parser_dom_xss_fixture(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            web = root / "web"
            web.mkdir()
            (web / "Banner.tsx").write_text('''
function Banner() {
  const q = new URLSearchParams(location.search).get("msg");
  return <div dangerouslySetInnerHTML={{__html: q}} />;
}
function Widget(el: any) {
  const h = location.hash;
  el.innerHTML = h;
}
function Safe(el: any, trusted: string) {
  el.innerHTML = trusted;
}
function evalLike(code: string) {
  const f = new Function(code);
  return f();
}
''')
            parser = Path(os.environ["BP_TYPESCRIPT_PARSER"])
            sha = hashlib.sha256(parser.read_bytes()).hexdigest()
            result = flow.inspect(root, parser, sha)
            self.assertEqual(result["parse_problems"], [])
            dom = {f["sink"]["function"]: f for f in result["flows"]
                  if f["kind"] == "DOM_XSS_CANDIDATE_FLOW"}
            self.assertEqual(set(dom), {"Banner", "Widget"})
            self.assertEqual(dom["Banner"]["sink"]["call"], "dangerouslySetInnerHTML")
            self.assertEqual(dom["Widget"]["sink"]["call"], "el.innerHTML")
            self.assertNotIn("Safe", {f["sink"]["function"] for f in result["flows"]})
            # evalLike's `code` is an ordinary parameter, not a DOM source and not reached
            # from any route in this fixture, so `new Function(code)` is correctly silent here.
            self.assertNotIn("evalLike", {f["sink"]["function"] for f in result["flows"]})

    def test_child_parser_receives_fixed_tool_path_and_no_credentials(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            (root / "a.ts").write_text("const value = 1")
            parser = Path(tmp) / "typescript.js"
            parser.write_text("fixture")
            sha = hashlib.sha256(parser.read_bytes()).hexdigest()
            stub = {"schema_version": 1, "files": [{
                "path": "a.ts", "imports": [], "functions": [], "routes": [],
                "parse_diagnostics": 0}]}
            with patch.object(flow.subprocess, "run") as run:
                run.return_value.returncode = 0
                run.return_value.stdout = json.dumps(stub)
                result = flow.inspect(root, parser, sha)
                env = run.call_args.kwargs["env"]
                self.assertNotIn("ANTHROPIC_API_KEY", env)
                self.assertEqual(env.get("NODE_OPTIONS"), "")
                self.assertEqual(result["flows"], [])


if __name__ == "__main__":
    unittest.main()
