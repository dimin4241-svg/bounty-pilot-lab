#!/usr/bin/env python3
"""Offline Python AST route/source graph for FastAPI/Flask-style decorators.

Call names and apparent auth guards are *cues*, not permission proofs. Route
dependencies installed on router/app instances, metaprogramming, imports and
runtime policies may be unseen. No repository code is imported or executed.
"""
import argparse
import ast
import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path

METHODS = {"get", "post", "put", "patch", "delete"}
GUARD_HINT = re.compile(r"(auth|permission|role|session|owner|tenant|user|jwt|token|policy|access)", re.I)
MAX_FILES = 500
MAX_FILE = 200_000
SKIP = {".git", ".venv", "venv", "node_modules", "__pycache__", "dist", "build", ".next"}
SOURCE_EXT = {".py"}


def _name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return _name(node.value) + "." + node.attr
    if isinstance(node, ast.Call):
        return _name(node.func)
    return ""


def _strings(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _paths(repo):
    root = Path(repo).resolve()
    if not root.is_dir() or root.is_symlink():
        raise ValueError("repo must be a real local source directory")
    entries = []
    for path in root.rglob("*.py"):
        if any(p in SKIP for p in path.relative_to(root).parts):
            continue
        if path.is_symlink() or any(p.is_symlink() for p in path.parents if p != root):
            continue
        if not path.is_file() or path.stat().st_size > MAX_FILE:
            continue
        entries.append(path)
        if len(entries) > MAX_FILES:
            raise ValueError("too many candidate Python sources; narrow checkout")
    return root, sorted(entries)


def _decorator_route(deco):
    if not isinstance(deco, ast.Call):
        return None
    fn = _name(deco.func)
    method = fn.rsplit(".", 1)[-1].lower()
    if method not in METHODS or len(fn.split(".")) < 2:
        return None
    if not deco.args:
        return None
    path = _strings(deco.args[0])
    if not path or not path.startswith("/") or path.startswith("//") or len(path) > 400:
        return None
    return method.upper(), path, deco


def _guard_cues(fn, deco):
    """Return guard-like names, NEVER claim that missing cues imply missing auth."""
    names = []
    for arg in fn.args.defaults + fn.args.kw_defaults:
        if arg is None:
            continue
        if isinstance(arg, ast.Call) and _name(arg.func).split(".")[-1] in (
                "Depends", "Security"):
            names.extend(_name(x) for x in arg.args)
    for dec in fn.decorator_list:
        if dec is deco:
            continue
        names.append(_name(dec))
    for kw in deco.keywords:
        if kw.arg in ("dependencies", "permission_classes", "guards"):
            names.extend(_name(x) for x in ast.walk(kw.value)
                         if isinstance(x, (ast.Call, ast.Name, ast.Attribute)))
    return sorted({n for n in names if n and GUARD_HINT.search(n)})[:30]


def inspect_repo(repo):
    root, files = _paths(repo)
    routes = []
    errors = []
    scanned = 0
    for path in files:
        rel = path.relative_to(root).as_posix()
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=rel)
        except (SyntaxError, UnicodeDecodeError) as exc:
            errors.append({"file": rel, "kind": type(exc).__name__})
            continue
        scanned += 1
        for fn in ast.walk(tree):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            calls = sorted({_name(c.func) for c in ast.walk(fn)
                            if isinstance(c, ast.Call) and _name(c.func)})[:100]
            for deco in fn.decorator_list:
                item = _decorator_route(deco)
                if not item:
                    continue
                method, route, d = item
                # Paths can contain secret-like identifiers in unusual generated
                # source, so avoid long opaque path segments in results.
                route = "/".join("{opaque}" if len(part) >= 30 else part
                                 for part in route.split("/"))
                routes.append({
                    "method": method, "path": route,
                    "handler": rel + ":" + fn.name, "file": rel, "line": fn.lineno,
                    "route_line": d.lineno,
                    "guard_name_cues": _guard_cues(fn, d), "call_names": calls,
                    "provenance": "PYTHON_AST_STATIC_CUES"})
    groups = defaultdict(list)
    for route in routes:
        groups[route["handler"]].append(route)
    leads = []
    for handler, members in sorted(groups.items()):
        if len(members) < 2:
            continue
        guards = {tuple(x["guard_name_cues"]) for x in members}
        if len(guards) > 1:
            leads.append({
                "handler": handler, "operation_keys": sorted(
                    x["method"] + " " + x["path"] for x in members),
                "kind": "DECORATOR_GUARD_CUE_DIFFERENCE",
                "classification": "UNVERIFIED_SOURCE_LEAD",
                "reason": "Route decorators on one handler contain different apparent guard names",
            })
    return {
        "schema_version": 1, "mode": "web-route-ast",
        "routes": sorted(routes, key=lambda x: (x["file"], x["line"], x["method"])),
        "leads": leads, "files_scanned": scanned,
        "parse_errors": errors, "network_requests": 0,
        "confirmed_vulnerabilities": 0,
        "limitations": ("Only Python decorator routes are parsed; implicit app/router/global "
                        "policies, dependency implementation and call reachability are not proven. "
                        "JS/TS and dynamic routes are not parsed by this tool.")}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--repo", required=True, help="local source root, no imports or execution")
    p.add_argument("--out", required=True, help="new output path")
    a = p.parse_args(argv)
    try:
        data = inspect_repo(a.repo)
        path = Path(a.out)
        if path.is_symlink() or path.exists():
            raise ValueError("output must not exist")
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, sort_keys=True, indent=2)
            f.write("\n")
    except (ValueError, OSError) as exc:
        p.error(str(exc))
    print(json.dumps({"routes": len(data["routes"]), "leads": len(data["leads"])}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
