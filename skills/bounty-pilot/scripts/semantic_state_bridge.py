#!/usr/bin/env python3
"""Adapt a pinned compiler-resolved graph to AVRE's state/sequence schema.

Unlike state_graph.py's regex inventory, these static call references come
from compiler ASTs. They still do not establish dynamic reachability,
authorization, actual storage effects of external calls, or exploitability.
"""
import json
import re
from pathlib import Path

SHA = re.compile(r"^[0-9a-f]{40,64}$")
MAX_SYMBOLS = 10000
MAX_EDGES = 50000


def _line(root, path, span):
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
