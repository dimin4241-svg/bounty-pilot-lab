#!/usr/bin/env python3
"""Adapt a pinned compiler-resolved graph to AVRE's state/sequence schema.

Unlike state_graph.py's regex inventory, these static call references come
from compiler ASTs. They still do not establish dynamic reachability,
authorization, actual storage effects of external calls, or exploitability.
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path

SHA = re.compile(r"^[0-9a-f]{40,64}$")
MAX_SYMBOLS = 10000
MAX_EDGES = 50000


def _line(root, path, span):
    if not isinstance(path, str) or not path:
        return None
    relative = Path(path)
    if relative.is_absolute() or ".." in relative.parts:
        return None
    source = root / relative
    if source.is_symlink() or not source.is_file() or source.stat().st_size > 2_000_000:
        return None
    if not isinstance(span, str):
        return None
    try:
        pos = int(span.split(":", 1)[0])
    except (ValueError, TypeError):
        return None
    if pos < 0:
        return None
    raw = source.read_bytes()
    if pos > len(raw):
        return None
    return raw[:pos].count(b"\n") + 1


def adapt(graph, root, revision):
    if not isinstance(graph, dict) or graph.get("method") != "compiler-ast-plus-python-ast":
        raise ValueError("semantic graph must come from Bounty Pilot impact-plan AST pipeline")
    if not SHA.fullmatch(str(revision)) or graph.get("source_revision") != revision:
        raise ValueError("compiler graph source_revision must match target checkout")
    original = graph.get("symbols")
    original_edges = graph.get("edges")
    if not isinstance(original, list) or not 1 <= len(original) <= MAX_SYMBOLS:
        raise ValueError("compiler graph symbols must be 1..10000")
    if not isinstance(original_edges, list) or len(original_edges) > MAX_EDGES:
        raise ValueError("compiler graph edges must be <=50000")
    root = Path(root).resolve()
    adapted, skipped = [], []
    old_to_new = {}
    for row in original:
        if not isinstance(row, dict) or not isinstance(row.get("id"), str):
            raise ValueError("AST symbols need stable compiler identifiers")
        relative = row.get("path")
        line = _line(root, relative, row.get("source_span"))
        if line is None:
            skipped.append({"id": row["id"], "path": relative,
                            "reason": "source path/byte span unavailable or not pinned"})
            continue
        ident = "ast:" + row["id"]
        old_to_new[row["id"]] = ident
        reads = [str(x) for x in (row.get("reads") or []) if isinstance(x, str)]
        writes = [str(x) for x in (row.get("writes") or []) if isinstance(x, str)]
        name = row.get("name") or row.get("short") or row["id"]
        adapted.append({
            "id": ident, "path": relative, "symbol": str(name),
            "line": line, "language": row.get("language", "unknown"),
            "reads_approx": sorted(set(reads))[:150],
            "qualified_writes_approx": sorted(set(writes))[:150],
            "local_assignments_not_state": [],
            "signals": (["asset"] if row.get("sinks") else []) +
                       (["authority"] if row.get("guards") else []) +
                       (["state"] if writes else []),
            "compiler_ast": {"id": row["id"], "entry": row.get("entry", False),
                             "signature": row.get("signature"),
                             "guards": row.get("guards", []),
                             "sinks": row.get("sinks", []),
                             "source": row.get("source", "compiler-ast")},
        })
    links = []
    for row in original_edges:
        if not isinstance(row, dict):
            continue
        start = old_to_new.get(row.get("from"))
        end = old_to_new.get(row.get("to"))
        if start is None or end is None:
            continue
        kind = row.get("kind")
        if kind not in ("static-call-reference", "inherited-entry", "writer-reader-overlap"):
            continue
        links.append({
            "from": start, "to": end,
            "reason": "compiler-" + kind,
            "token": str(row.get("state") or kind),
            "confidence": "medium" if kind == "static-call-reference" else "low",
            "static_only": True,
        })
    return {
        "schema": 1, "source": str(root),
        "method": "compiler-ast-static-effect-bridge",
        "sound": False, "reachability_verified": False,
        "symbols": adapted, "edges": links,
        "skipped_sources": graph.get("skipped_sources", []),
        "skipped_symbols": skipped,
        "in_scope_files": len(set(row["path"] for row in adapted)),
        "scenario_seeds": [],
        "truncated_files": [],
        "notice": ("Compiler-resolved calls and state token identities with source byte-span "
                   "check. External calls/dynamic dispatch not resolved. Reproduce native "
                   "transitions and inspect all skipped symbols before reporting.")}


def from_file(path, repo, revision):
    source = Path(path).expanduser()
    if source.is_symlink() or not source.is_file() or source.stat().st_size > 25_000_000:
        raise ValueError("AST graph must be a regular file <=25MB")
    doc = json.loads(source.read_text(encoding="utf-8"))
    return adapt(doc, repo, revision)


def bind_graph(graph, repo):
    """Bind local HEAD and snapshot hashes; not a proof of compiled source identity."""
    root = Path(repo).expanduser().resolve()
    cmd = ["git", "--no-optional-locks", "-c", "core.fsmonitor=false",
           "-c", "core.hooksPath=/dev/null", "-C", str(root), "rev-parse", "HEAD"]
    head = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          check=True, timeout=15).stdout.decode("ascii").strip()
    if not isinstance(graph, dict) or graph.get("method") != "compiler-ast-plus-python-ast":
        raise ValueError("expected Bounty Pilot impact-plan compiler graph")
    symbols = graph.get("symbols")
    if not isinstance(symbols, list) or not symbols:
        raise ValueError("compiler graph has no symbols")
    if graph.get("source_revision") not in (None, head):
        raise ValueError("existing graph revision mismatches checkout")
    files, missing = {}, []
    paths = {s.get("path") for s in symbols if isinstance(s, dict)
             and isinstance(s.get("path"), str)}
    for path in sorted(paths):
        candidate = root / path
        if Path(path).is_absolute() or ".." in Path(path).parts \
                or candidate.is_symlink() or not candidate.is_file() \
                or candidate.stat().st_size > 2_000_000:
            missing.append(path)
        else:
            files[path] = hashlib.sha256(candidate.read_bytes()).hexdigest()
    return {**graph, "source_revision": head,
            "source_snapshot": {"sha256_by_path": files,
                                "missing_paths": missing,
                                "compiled_input_equality_verified": False},
            "provenance_warning": "HEAD/source hashes observed; compiler build provenance not authenticated."}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--graph", required=True)
    p.add_argument("--repo", required=True)
    p.add_argument("--out", required=True)
    a = p.parse_args(argv)
    source = Path(a.graph).expanduser()
    if source.is_symlink() or not source.is_file() or source.stat().st_size > 25_000_000:
        p.error("graph must be a regular <=25MB file")
    output = bind_graph(json.loads(source.read_text(encoding="utf-8")), a.repo)
    target = Path(a.out).expanduser()
    if target.exists() or target.is_symlink() \
            or Path(a.repo).resolve() in target.resolve().parents:
        p.error("output must be create-only outside repo")
    fd = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(output, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
    print(json.dumps({"out": str(target), "source_revision": output["source_revision"],
                      "missing_paths": len(output["source_snapshot"]["missing_paths"])}))


if __name__ == "__main__":
    main()
