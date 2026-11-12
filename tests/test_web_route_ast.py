"""Offline Python AST source graph: synthetic FastAPI-style route fixtures."""
import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "skills" / "bounty-pilot" / "scripts" / "web_route_ast.py"
spec = importlib.util.spec_from_file_location("web_route_ast_for_tests", PATH)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class RouteAstTests(unittest.TestCase):
    def test_extracts_route_method_handler_and_guard_cues(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "service.py"
            f.write_text('''
from fastapi import Depends
@app.get("/api/doc/{id}", dependencies=[Depends(check_permission)])
def doc(id: str):
    return database.read(id)

@app.patch("/api/doc/{id}")
def doc_edit(id: str):
    return database.write(id)

@app.post("/api/doc/{id}", dependencies=[Depends(check_permission)])
@app.get("/api/doc/{id}")
def mixed(id: str):
    return database.read(id)
''')
            output = mod.inspect_repo(tmp)
            self.assertEqual(len(output["routes"]), 4)
            self.assertEqual(output["network_requests"], 0)
            self.assertEqual(output["confirmed_vulnerabilities"], 0)
            self.assertTrue(any(x["handler"] == "service.py:mixed" for x in output["leads"]))
            self.assertTrue(any(x["method"] == "PATCH" for x in output["routes"]))
            self.assertTrue(any("check_permission" in x["guard_name_cues"] for x in output["routes"]))
            self.assertEqual(output["files_scanned"], 1)
            doc_route = next(x for x in output["routes"] if x["handler"] == "service.py:doc")
            self.assertGreaterEqual(doc_route["end_line"], doc_route["line"])

    def test_exact_file_allowlist_excludes_untracked_and_rejects_traversal(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "allowed.py").write_text(
                "@app.get('/allowed')\ndef allowed(): return True\n")
            (Path(tmp) / "untracked.py").write_text(
                "@app.get('/untracked')\ndef untracked(): return True\n")
            report = mod.inspect_repo(tmp, allowed_files={"allowed.py"})
            self.assertEqual([row["path"] for row in report["routes"]], ["/allowed"])
            with self.assertRaisesRegex(ValueError, "inside checkout"):
                mod.inspect_repo(tmp, allowed_files={"../outside.py"})

    def test_does_not_execute_source_code(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "code.py"
            marker = Path(tmp) / "should-not-exist"
            p.write_text("open(" + repr(str(marker)) + ", 'w').write('BAD')\n"
                         "@app.get('/api/hello')\n"
                         "def hello():\n    return 1\n")
            output = mod.inspect_repo(tmp)
            self.assertFalse(marker.exists())
            self.assertEqual(output["routes"][0]["method"], "GET")

    def test_rejects_symlink_to_outside(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "src"
            root.mkdir()
            target = Path(tmp) / "external.py"
            target.write_text("@app.get('/x')\ndef x(): return 1\n")
            (root / "linked.py").symlink_to(target)
            output = mod.inspect_repo(root)
            self.assertEqual(output["routes"], [])

    def test_unparseable_file_has_explicit_error_not_missing_guard(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "bad.py").write_text("@app.get('/hello')\ndef example(")
            output = mod.inspect_repo(tmp)
            self.assertEqual(output["files_scanned"], 0)
            self.assertEqual(output["parse_errors"][0]["kind"], "SyntaxError")
            self.assertEqual(output["leads"], [])


if __name__ == "__main__":
    unittest.main()
