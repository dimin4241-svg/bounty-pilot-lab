#!/usr/bin/env python3
"""Plan bounded cross-file security slices while preserving every primary source.

This is dependency *evidence planning*, not a verified call graph. Imports and
unique symbol-name references are cues; nothing here proves reachability.
"""
import argparse
import importlib.util
import json
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("bp_source_shards", HERE / "source_shards.py")
shards = importlib.util.module_from_spec(spec)
spec.loader.exec_module(shards)

MAX_FILES = 10000
MAX_BRIDGES = 200
# Bridge the cues that are evidence before the ones that are coincidence.
CUE_RANK = {"local-import-cue": 0, "go-package-import-cue": 0, "unique-file-stem-cue": 1}
RELATIVE_IMPORT = re.compile(
    r"""(?:\bimport\s+(?:[^;\n]*?\bfrom\s+)?|\brequire\s*\()\s*["']([^"']+)["']"""
)
RUST_MOD = re.compile(r"\b(?:pub\s+)?mod\s+([A-Za-z_]\w*)\s*;")
PY_IMPORT = re.compile(r"(?m)^\s*(?:from|import)\s+([A-Za-z_][\w.]*)")
# A Go import names a package directory, not a file, and the usual form is a parenthesised
# block, so neither RELATIVE_IMPORT nor _resolve ever matched one: measured on Obol charon
# (--scope core) and go-ethereum (--scope core), every dependency edge was a filename-stem
# coincidence and not one was an import.
GO_IMPORT_BLOCK = re.compile(r"(?ms)^import\s*\((.*?)^\)")
GO_IMPORT_SINGLE = re.compile(r"""(?m)^\s*import\s+(?:[A-Za-z_.]\w*\s+)?["']([^"']+)["']""")
GO_IMPORT_SPEC = re.compile(r"""(?m)^\s*(?:[A-Za-z_.]\w*\s+)?["']([^"']+)["']""")
IDENT = re.compile(r"\b[A-Za-z_]\w*\b")


def _resolve(request, origin, known):
    base = Path(origin).parent
    values = []
    if request.startswith("."):
        values.append((base / request).as_posix())
    else:
        # Rust 'mod x;' resolves beside the importer; root-qualified package
        # imports may resolve from the checkout root. Ambiguity is not guessed.
        values.extend([request, (base / request).as_posix()])
    if request.startswith("crate::"):
        values.append(request[len("crate::"):].replace("::", "/"))
    if "." in request and not request.endswith((".sol", ".ts", ".py", ".js")):
        values.append(request.replace(".", "/"))
    matches = []
    for value in values:
        # Import paths are data. Reject traversal beyond repo root.
        parts = []
        for part in Path(value).parts:
            if part in ("", "."):
                continue
            if part == "..":
                if not parts:
                    break
                parts.pop()
            else:
                parts.append(part)
        else:
            stem = "/".join(parts)
            for candidate in ([stem] + [stem + ext for ext in
                    (".sol", ".rs", ".ts", ".tsx", ".js", ".jsx", ".py", ".move",
                     "/mod.rs", "/index.ts", "/index.tsx", "/index.js", "/__init__.py")]):
                if candidate in known:
                    matches.append(candidate)
    unique = set(matches)
    return next(iter(unique)) if len(unique) == 1 else None


def _go_module(root):
    """The module path declared in go.mod, which prefixes every in-module import."""
    manifest = root / "go.mod"
    try:
        text = manifest.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    match = re.search(r"(?m)^\s*module\s+(\S+)", text)
    return match.group(1).strip().strip('"') if match else None


def _go_imports(text):
    requests = [m.group(1) for m in GO_IMPORT_SINGLE.finditer(text)]
    for block in GO_IMPORT_BLOCK.finditer(text):
        requests.extend(m.group(1) for m in GO_IMPORT_SPEC.finditer(block.group(1)))
    return requests


def _go_package_files(request, origin, module, directories):
    """Every scoped file of an imported in-module package; nothing for a third-party one.

    The package is the unit a Go import names, so one import is an edge to each of that
    package's files. Imports outside the module (and packages outside --scope) resolve to
    nothing rather than to a guess.
    """
    if not module or not request.startswith(module):
        return []
    remainder = request[len(module):].strip("/")
    if request != module and not request[len(module):].startswith("/"):
        return []
    return [path for path in directories.get(remainder, ()) if path != origin]


def _cues(repo, paths):
    root = Path(repo).expanduser().resolve()
    known = set(paths)
    sizes = {p: (root / p).stat().st_size for p in paths}
    stem_index = {}
    directories = {}
    for path in paths:
        stem_index.setdefault(Path(path).stem, []).append(path)
        if path.endswith(".go"):
            parent = Path(path).parent.as_posix()
            directories.setdefault("" if parent == "." else parent, []).append(path)
    for files in directories.values():
        files.sort()
    module = _go_module(root) if directories else None
    edges = {}
    for path in paths:
        text = (root / path).read_text(encoding="utf-8", errors="replace")
        deps = {}
        imports = [m.group(1) for m in RELATIVE_IMPORT.finditer(text)]
        if path.endswith(".rs"):
            imports.extend(m.group(1) for m in RUST_MOD.finditer(text))
        if path.endswith(".py"):
            imports.extend(m.group(1) for m in PY_IMPORT.finditer(text))
        if path.endswith(".go"):
            for request in _go_imports(text):
                for dep in _go_package_files(request, path, module, directories):
                    deps[dep] = "go-package-import-cue"
        for imported in imports:
            dep = _resolve(imported, path, known)
            if dep and dep != path:
                deps[dep] = "local-import-cue"
        # Named types and interfaces are a useful secondary cue for cross-shard
        # composition, but only when the name belongs to exactly one source.
        tokens = set(IDENT.findall(text))
        for symbol in tokens:
            hits = stem_index.get(symbol, [])
            if len(hits) == 1 and hits[0] != path:
                deps.setdefault(hits[0], "unique-file-stem-cue")
        edges[path] = deps
    return edges, sizes


def plan(repo, scope=None, max_source_bytes=160000, max_bridges=MAX_BRIDGES):
    if type(max_bridges) is not int or not 0 <= max_bridges <= MAX_BRIDGES:
        raise ValueError("max_bridges must be 0..200")
    primary = shards.plan(repo, scope=scope, max_source_bytes=max_source_bytes)
    paths = [p for row in primary["shards"] for p in row["paths"]]
    if len(paths) > MAX_FILES:
        raise ValueError("source file count exceeds bounded semantic slice planner")
    if not paths:
        raise ValueError("no scoped tracked source; cannot plan semantic slices")
    edges, sizes = _cues(repo, paths)
    owner = {p: row["index"] for row in primary["shards"] for p in row["paths"]}
    packs = []
    unresolved = []
    for group in primary["shards"]:
        core = list(group["paths"])
        context = []
        used = sum(sizes[p] for p in core)
        for src in core:
            for dest in sorted(edges[src]):
                if dest in core or dest in context:
                    continue
                if used + sizes[dest] <= max_source_bytes:
                    context.append(dest)
                    used += sizes[dest]
                else:
                    unresolved.append((src, dest, edges[src][dest]))
        paths_with_context = core + context
        packs.append({
            "index": group["index"], "kind": "primary-with-context",
            "core_paths": core, "context_paths": context,
            "paths": paths_with_context, "source_bytes": used,
            "scope_args": [part for p in paths_with_context for part in ("--scope", p)],
            "requires_manual_file_split": group["requires_manual_file_split"]})
    # A primary module can be close to budget, leaving no space for a dependency.
    # Create a separate two-file bridge rather than claiming the edge was read.
    bridges = []
    seen_pairs = set()
    # An import is evidence; a shared filename stem is a coincidence. When max_bridges binds —
    # on charon's `core` the real Go imports alone exceed it — the evidence is bridged first.
    ordered = sorted(unresolved, key=lambda row: (CUE_RANK.get(row[2], 9), row[0], row[1]))
    for src, dest, reason in ordered:
        if owner[src] == owner[dest]:
            continue
        pair = tuple(sorted((src, dest)))
        if pair in seen_pairs:
            continue
        seen_pairs.add(pair)
        amount = sizes[src] + sizes[dest]
        if amount <= max_source_bytes and len(bridges) < max_bridges:
            bridges.append({
                "index": len(bridges) + 1, "kind": "cross-shard-bridge",
                "core_paths": [], "context_paths": list(pair), "paths": list(pair),
                "source_bytes": amount,
                "scope_args": [item for p in pair for item in ("--scope", p)],
                "relationship": reason, "requires_manual_file_split": False})
    unrepresented_edges = [
        {"from": src, "to": dest, "cue": reason,
         "reason": "oversized-pair-or-bridge-cap"}
        for src, dest, reason in ordered
        if tuple(sorted((src, dest))) not in {
            tuple(b["paths"]) for b in bridges} and owner[src] != owner[dest]]
    return {
        "schema_version": 1, "target_commit": primary["target_commit"],
        "method": "source-ownership-plus-bounded-dependency-cues",
        "primary_files": len(paths), "primary_shards": len(packs),
        "bridge_shards": len(bridges), "shards": packs + bridges,
        "dependency_edges": sum(len(v) for v in edges.values()),
        "unrepresented_cross_shard_edges": unrepresented_edges,
        "excluded": primary["excluded"],
        "oversized_single_files": primary["oversized_single_files"],
        "notice": ("Each primary path appears in exactly one primary shard; context and "
                   "bridge paths may repeat intentionally. Dependency links are "
                   "import/name cues, not verified calls: a Go edge is an import of the "
                   "package a file belongs to, not a call into that file, and a "
                   "unique-file-stem-cue is only a name coincidence. Manually inspect "
                   "unresolved edges "
                   "and ensure scoped runtime artifacts/configuration are included. "
                   "Every shard requires a fresh private run directory.")}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--scope", action="append")
    parser.add_argument("--max-source-bytes", type=int, default=160000)
    parser.add_argument("--max-bridges", type=int, default=MAX_BRIDGES)
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    result = plan(args.repo, args.scope, args.max_source_bytes, args.max_bridges)
    out = Path(args.out).expanduser()
    if out.exists() or out.is_symlink():
        parser.error("--out already exists (create only)")
    if out.resolve().is_relative_to(Path(args.repo).resolve()):
        parser.error("--out must stay outside target checkout")
    with out.open("x", encoding="utf-8") as handle:
        json.dump(result, handle, ensure_ascii=False, indent=2)
    out.chmod(0o600)
    print(json.dumps({"out": str(out), "primary_shards": result["primary_shards"],
                      "bridge_shards": result["bridge_shards"],
                      "unrepresented_edges": len(result["unrepresented_cross_shard_edges"])}))


if __name__ == "__main__":
    main()
