#!/usr/bin/env python3
"""Offline JS/TS route AST via an explicitly pinned TypeScript compiler parser.

Requires operator-provided absolute TypeScript 'lib/typescript.js' file AND
its SHA-256. The target source is sent to the vetted parser via stdin; target
code is never imported/eval'd. No network traffic is initiated by this helper.
The parser itself is executable third-party code: run in a disposable, network-
isolated environment with no credentials. Outputs are static review leads only.
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

METHODS = {"GET", "POST", "PATCH", "PUT", "DELETE"}
SUPPORTED = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts"}
SKIP = {".git", "node_modules", ".next", "dist", "build", "coverage", ".turbo",
        ".cache", ".venv"}
SHA = re.compile(r"^[0-9a-f]{64}$")
MAX_FILE = 250_000
MAX_FILES = 300
JS = r"""
'use strict';
const fs = require('fs');
const ts = require(process.argv[2]);
const filename = process.argv[1];
const code = fs.readFileSync(0, 'utf8');
const lower = filename.toLowerCase();
const kind = lower.endsWith('.tsx') ? ts.ScriptKind.TSX :
  lower.endsWith('.jsx') || lower.endsWith('.js') || lower.endsWith('.mjs') ||
  lower.endsWith('.cjs') ? ts.ScriptKind.JS : ts.ScriptKind.TS;
const sf = ts.createSourceFile(filename, code, ts.ScriptTarget.Latest, true, kind);
const ROUTE_METHODS = new Set(['get', 'post', 'put', 'patch', 'delete']);
const METHODS = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE']);
function callee(e) {
  if (!e) return '';
  if (ts.isIdentifier(e)) return e.text;
  if (ts.isPropertyAccessExpression(e)) return callee(e.expression) + '.' + e.name.text;
  if (ts.isCallExpression(e)) return callee(e.expression);
  return '';
}
function text(n) {
  return n && (ts.isStringLiteral(n) || ts.isNoSubstitutionTemplateLiteral(n)) ? n.text : null;
}
function line(n) { return sf.getLineAndCharacterOfPosition(n.getStart(sf)).line + 1; }
function calls(n) {
  let found = new Set();
  function visit(cur) {
    if (ts.isCallExpression(cur)) found.add(callee(cur.expression));
    ts.forEachChild(cur, visit);
  }
  visit(n);
  return [...found].filter(Boolean).sort().slice(0, 100);
}
function nextPath(filename) {
  const p = filename.replaceAll('\\', '/');
  const m = p.match(/(?:^|\/)app\/(.+)\/route\.[jt]sx?$/);
  if (!m) return null;
  const segments = m[1].split('/').filter(s => s && !/^\(.+\)$/.test(s));
  return '/' + segments.map(s => /^\[(.+)\]$/.test(s) ? '{' + s.slice(1,-1) + '}' : s).join('/');
}
const nextRoute = nextPath(filename);
const routes = [];
function visit(n) {
  if (ts.isCallExpression(n) && ts.isPropertyAccessExpression(n.expression)) {
    const method = n.expression.name.text.toLowerCase();
    const obj = callee(n.expression.expression).toLowerCase();
    const path = text(n.arguments[0]);
    if (ROUTE_METHODS.has(method) && path && path.startsWith('/') &&
        /(^|\.)(router|app|server|fastify)$/.test(obj) && n.arguments.length >= 2) {
      const args = [...n.arguments].slice(1);
      const final = args[args.length-1];
      let handler = ts.isIdentifier(final) ? final.text : 'inline@' + line(final);
      const middle = args.slice(0, -1).map(x => callee(x)).filter(Boolean);
      routes.push({method:method.toUpperCase(), path, handler, line:line(n),
        middleware:middle.slice(0, 30), calls:calls(final)});
    }
  }
  if (nextRoute && ts.isFunctionDeclaration(n) && n.name &&
      METHODS.has(n.name.text) && n.modifiers &&
      n.modifiers.some(m => m.kind === ts.SyntaxKind.ExportKeyword)) {
    routes.push({method:n.name.text, path:nextRoute, handler:n.name.text,
      line:line(n), middleware:[], calls:calls(n.body || n)});
  }
  // Next.js exported const GET = async (...) => ...
  if (nextRoute && ts.isVariableStatement(n) && n.modifiers &&
      n.modifiers.some(m => m.kind === ts.SyntaxKind.ExportKeyword)) {
    for (const d of n.declarationList.declarations) {
      if (ts.isIdentifier(d.name) && METHODS.has(d.name.text) && d.initializer) {
        routes.push({method:d.name.text, path:nextRoute, handler:d.name.text,
          line:line(n), middleware:[], calls:calls(d.initializer)});
      }
    }
  }
  ts.forEachChild(n, visit);
}
visit(sf);
process.stdout.write(JSON.stringify({routes, parser_diagnostics:sf.parseDiagnostics.length}));
"""


def _safe_root(repo):
    root = Path(repo).expanduser()
    if root.is_symlink() or not root.is_dir():
        raise ValueError("source root must be a non-symlink directory")
    return root.resolve()


def _files(root):
    found = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in SUPPORTED:
            continue
        rel = path.relative_to(root)
        if any(part in SKIP for part in rel.parts):
            continue
        if path.is_symlink() or any(p.is_symlink() for p in path.parents if p != root):
            continue
        if path.stat().st_size > MAX_FILE:
            continue
        found.append(path)
        if len(found) > MAX_FILES:
            raise ValueError("too many JS/TS files; provide a smaller source root")
    return found


def _parser(path, expected_sha):
    p = Path(path)
    if not p.is_absolute() or p.is_symlink() or not p.is_file() or (
            p.name != "typescript.js" or p.stat().st_size > 20_000_000):
        raise ValueError("use an absolute, vetted TypeScript lib/typescript.js file")
    if not isinstance(expected_sha, str) or not SHA.fullmatch(expected_sha):
        raise ValueError("pinned --parser-sha256 is required")
    got = hashlib.sha256(p.read_bytes()).hexdigest()
    if got != expected_sha:
        raise ValueError("TypeScript parser SHA mismatch; refuse execution")
    return p.resolve()


def _path(s):
    if (not isinstance(s, str) or len(s) > 450 or not s.startswith("/") or
            s.startswith("//") or any(ord(c) < 32 for c in s)):
        return None
    return "/".join("{opaque}" if len(part) >= 30 else part for part in s.split("/"))


def inspect(repo, parser_path, parser_sha256):
    root = _safe_root(repo)
    parser = _parser(parser_path, parser_sha256)
    routes, problems = [], []
    for file in _files(root):
        relative = file.relative_to(root).as_posix()
        # Only a vetted parser is loaded; the target repo is not the subprocess cwd.
        try:
            result = subprocess.run(
                ["node", "--max-old-space-size=256", "-e", JS, relative, str(parser)],
                input=file.read_text(encoding="utf-8", errors="replace"),
                text=True, capture_output=True, timeout=12,
                cwd=str(Path(__file__).resolve().parent),
                env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
                check=False)
        except (OSError, subprocess.TimeoutExpired):
            problems.append({"file": relative, "kind": "PARSER_UNAVAILABLE_OR_TIMEOUT"})
            continue
        if result.returncode != 0 or len(result.stdout) > 2_000_000:
            problems.append({"file": relative, "kind": "PARSER_FAILED"})
            continue
        try:
            raw = json.loads(result.stdout)
        except (json.JSONDecodeError, ValueError):
            problems.append({"file": relative, "kind": "PARSER_BAD_JSON"})
            continue
        if raw.get("parser_diagnostics"):
            problems.append({"file": relative, "kind": "PARSER_DIAGNOSTIC",
                             "count": min(int(raw["parser_diagnostics"]), 1000)})
        for op in raw.get("routes", [])[:1000]:
            method, path = op.get("method"), _path(op.get("path"))
            if method not in METHODS or path is None:
                continue
            handler = op.get("handler")
            if not isinstance(handler, str) or len(handler) > 120:
                continue
            middleware = [x for x in op.get("middleware", [])[:30]
                          if isinstance(x, str) and len(x) < 100]
            guards = sorted({x for x in middleware if re.search(
                r"auth|permission|role|session|access|owner|tenant|guard", x, re.I)})
            routes.append({
                "method": method, "path": path,
                "handler": relative + ":" + handler, "file": relative,
                "line": op.get("line"),
                "middleware_cues": middleware,
                "apparent_guard_cues": guards,
                "call_names": [x for x in op.get("calls", [])[:100]
                               if isinstance(x, str) and len(x) < 120],
                "provenance": "PINNED_TYPESCRIPT_PARSER_AST"})
    groups = defaultdict(list)
    for row in routes:
        groups[row["handler"]].append(row)
    leads = []
    for handler, members in sorted(groups.items()):
        guards = {tuple(x["apparent_guard_cues"]) for x in members}
        if len(members) > 1 and len(guards) > 1:
            leads.append({"kind": "MIDDLEWARE_CUE_DIFFERENCE",
                          "handler": handler, "routes": sorted(
                              x["method"] + " " + x["path"] for x in members),
                          "classification": "UNVERIFIED_SOURCE_LEAD"})
    return {
        "schema_version": 1, "mode": "web-js-ts-route-ast",
        "routes": sorted(routes, key=lambda r: (r["file"], r["line"], r["method"])),
        "leads": leads, "parse_problems": problems,
        "parser_sha256": parser_sha256,
        "files_inspected": len(_files(root)),
        "network_requests": 0, "confirmed_vulnerabilities": 0,
        "limitations": ("Static Express/router and Next App Router subset only. "
                        "No whole-program JS/TS dataflow, inherited middleware, imports, "
                        "runtime reachability, effective permissions or impact verification.")}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--repo", required=True)
    p.add_argument("--typescript-parser", required=True,
                   help="absolute vetted TypeScript compiler lib/typescript.js")
    p.add_argument("--parser-sha256", required=True, help="pinned local compiler file SHA-256")
    p.add_argument("--out", required=True)
    a = p.parse_args(argv)
    try:
        result = inspect(a.repo, a.typescript_parser, a.parser_sha256)
        dest = Path(a.out)
        if dest.exists() or dest.is_symlink():
            raise ValueError("output must be new")
        dest.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(dest), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, sort_keys=True, indent=2)
            f.write("\n")
    except (OSError, ValueError, TypeError) as exc:
        p.error(str(exc))
    print(json.dumps({"routes": len(result["routes"]), "leads": len(result["leads"]),
                      "parse_problems": len(result["parse_problems"])}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
