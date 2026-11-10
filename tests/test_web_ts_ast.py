"""JS/TS AST parser adapter contracts and optional native parser integration fixture."""
import hashlib
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "skills" / "bounty-pilot" / "scripts" / "web_ts_ast.py"
spec = importlib.util.spec_from_file_location("web_ts_ast_test", PATH)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class TSRouteTests(unittest.TestCase):
    def test_unpinned_parser_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            (repo / "app.ts").write_text('app.get("/docs", list)')
            parser = Path(tmp) / "typescript.js"
            parser.write_text("trusted-placeholder")
            with self.assertRaisesRegex(ValueError, "pinned"):
                module.inspect(repo, parser, "0" * 63)
            with self.assertRaisesRegex(ValueError, "SHA mismatch"):
                module.inspect(repo, parser, "0" * 64)

    def test_rejects_symlink_and_source_exfiltration(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "other.ts"
            source.write_text('app.get("/secret", handler)')
            repo = Path(tmp) / "repo"
            repo.mkdir()
            (repo / "extern.ts").symlink_to(source)
            parser = Path(tmp) / "typescript.js"
            parser.write_text("placeholder")
            sha = hashlib.sha256(parser.read_bytes()).hexdigest()
            result = module.inspect(repo, parser, sha)
            self.assertEqual(result["files_inspected"], 0)
            self.assertEqual(result["network_requests"], 0)

    def test_sanitizes_routes_and_recognizes_guard_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            (repo / "api.ts").write_text("fake content")
            parser = Path(tmp) / "typescript.js"
            parser.write_text("parser placeholder")
            sha = hashlib.sha256(parser.read_bytes()).hexdigest()
            routes = {"parser_diagnostics": 0, "routes": [
                {"method": "GET", "path": "/docs/{id}", "handler": "show",
                 "line": 2, "middleware": ["requireAuth"],
                 "calls": ["db.read"]},
                {"method": "POST", "path": "/docs/{id}", "handler": "show",
                 "line": 4, "middleware": [],
                 "calls": ["db.read"]}]}
            fake = SimpleNamespace(returncode=0, stdout=json.dumps(routes), stderr="")
            with patch.object(module.subprocess, "run", return_value=fake) as run:
                got = module.inspect(repo, parser, sha)
                args = run.call_args
                self.assertEqual(args.kwargs["cwd"], str(PATH.parent))
                self.assertNotIn("ANTHROPIC_API_KEY", args.kwargs["env"])
            self.assertEqual(len(got["routes"]), 2)
            self.assertEqual(len(got["leads"]), 1)
            self.assertEqual(got["leads"][0]["kind"], "MIDDLEWARE_CUE_DIFFERENCE")
            self.assertEqual(got["confirmed_vulnerabilities"], 0)

    @unittest.skipUnless(os.environ.get("BP_TYPESCRIPT_PARSER"),
                         "optional pinned local TypeScript parser unavailable")
    def test_real_typescript_parser(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "api.ts").write_text('''
router.get("/api/docs/:id", requireAuth, showDoc);
router.post("/api/docs/:id", showDoc);
''')
            f = root / "src" / "app" / "api" / "payments" / "route.ts"
            f.parent.mkdir(parents=True)
            f.write_text('''
export async function GET(req: Request) {
  return Response.json(await db.getAll());
}
export const POST = async (req: Request) => Response.json(await db.create());
''')
            marker = root / "must-not-be-created"
            (root / "danger.ts").write_text(
                "require('fs').writeFileSync(" + json.dumps(str(marker)) + ", 'BAD');")
            parser = Path(os.environ["BP_TYPESCRIPT_PARSER"])
            sha = hashlib.sha256(parser.read_bytes()).hexdigest()
            got = module.inspect(root, parser, sha)
            self.assertEqual(got["parse_problems"], [])
            self.assertFalse(marker.exists(), "AST parsing must not execute target JavaScript")
            self.assertEqual(len(got["routes"]), 4)
            self.assertTrue(any(r["path"] == "/api/payments" and
                                r["method"] == "GET" for r in got["routes"]))
            self.assertTrue(any(r["method"] == "POST" and
                                r["path"] == "/api/docs/:id" for r in got["routes"]))
            self.assertEqual(len(got["leads"]), 1)


if __name__ == "__main__":
    unittest.main()
