#!/usr/bin/env python3
"""Bounded graph variant and before/after guard-delta review (offline, lexical).

An unguarded graph path does not prove an authorization bypass. Caller edges,
guards and sinks are operator-supplied graph claims that need independent proof.
"""
import argparse
import json
import os
import sys
from collections import defaultdict
from pathlib import Path

KINDS = {"entry", "method", "sink"}
MAX_NODES = 2000
MAX_EDGES = 12000
MAX_DEPTH = 25
MAX_PATHS = 100
MAX_LEADS = 150


def _graph(value):
    if not isinstance(value, dict):
        raise ValueError("graph must be object")
    nodes, edges = value.get("nodes"), value.get("edges")
    if not isinstance(nodes, list) or len(nodes) > MAX_NODES:
        raise ValueError("too many nodes")
    if not isinstance(edges, list) or len(edges) > MAX_EDGES:
        raise ValueError("too many edges")
    table = {}
    for node in nodes:
        if (not isinstance(node, dict) or
                not isinstance(node.get("id"), str) or
                not 1 <= len(node["id"]) <= 128 or
                node.get("kind") not in KINDS or
                type(node.get("guard_present")) is not bool):
            raise ValueError("node requires id, kind, guard_present")
        if node["id"] in table:
            raise ValueError("duplicate node")
        table[node["id"]] = node
    adj = defaultdict(set)
    for e in edges:
        if (not isinstance(e, dict) or e.get("from") not in table
                or e.get("to") not in table):
            raise ValueError("edge must reference existing nodes")
        adj[e["from"]].add(e["to"])
    return table, {k: sorted(v) for k, v in adj.items()}


def _paths(table, adj):
    starts = sorted(k for k, v in table.items() if v["kind"] == "entry")
    results = defaultdict(list)
    truncated = False
    for start in starts:
        stack = [(start, [start], bool(table[start]["guard_present"]))]
        while stack:
            current, path, guarded = stack.pop()
            if table[current]["kind"] == "sink":
                if len(results[current]) < MAX_PATHS:
                    results[current].append({"entry": start, "path": path,
                                             "guard_cue_on_path": guarded})
                else:
                    truncated = True
                continue
            if len(path) >= MAX_DEPTH:
                truncated = True
                continue
            for target in reversed(adj.get(current, [])):
                if target not in path:
                    stack.append((target, path + [target],
                                  guarded or table[target]["guard_present"]))
                else:
                    truncated = True
    return results, truncated


def analyze(doc):
    if not isinstance(doc, dict) or doc.get("schema_version") != 1:
        raise ValueError("variant case schema_version=1 required")
    before = doc.get("before")
    after = doc.get("after")
    before_table, before_adj = _graph(before)
    after_table, after_adj = _graph(after)
    first, truncated_before = _paths(before_table, before_adj)
    second, truncated_after = _paths(after_table, after_adj)
    guard_deltas = []
    for key in sorted(set(before_table).intersection(after_table)):
        if before_table[key]["guard_present"] != after_table[key]["guard_present"]:
            guard_deltas.append({
                "node": key, "before_guard_cue": before_table[key]["guard_present"],
                "after_guard_cue": after_table[key]["guard_present"],
                "status": "OPERATOR_GRAPH_GUARD_CUE_CHANGED",
            })
    leads = []
    for sink, paths in sorted(second.items()):
        unguarded = [p for p in paths if not p["guard_cue_on_path"]]
        guarded = [p for p in paths if p["guard_cue_on_path"]]
        earlier = first.get(sink, [])
        was_guarded = bool(earlier) and all(p["guard_cue_on_path"] for p in earlier)
        for path in unguarded[:MAX_LEADS - len(leads)]:
            leads.append({
                "sink": sink, "entry": path["entry"],
                "path": path["path"], "guard_cue_on_path": False,
                "classification": (
                    "NEW_GUARDLESS_VARIANT_REVIEW" if was_guarded
                    else "ALTERNATE_GUARDLESS_PATH_REVIEW"
                ), "same_sink_has_guarded_path": bool(guarded),
                "impact_verified": False,
            })
    return {
        "schema_version": 1, "engine": "graph-variant-review",
        "status": "LEXICAL_GRAPH_VARIANTS_NOT_EXPLOIT_PROOF",
        "guard_deltas": guard_deltas[:MAX_LEADS],
        "leads": leads, "lead_count": len(leads),
        "truncated": truncated_before or truncated_after
                     or len(guard_deltas) > MAX_LEADS,
        "source": "operator_supplied_call_graph_and_guard_cues",
        "limits": ["graph node guards are cues, not authoritative policy",
                   "edges not compiler-resolved or executed by this tool",
                   "guard feasibility and authorization unverified"],
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--case", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    try:
        path = Path(a.case)
        if path.is_symlink() or path.stat().st_size > 2 * 1024 * 1024:
            raise ValueError("small regular graph JSON required")
        doc = analyze(json.loads(path.read_text("utf-8")))
        out = Path(a.out)
        if out.exists() or out.is_symlink() or not out.parent.is_dir():
            raise ValueError("output must be a new file")
        fd = os.open(str(out), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as s:
            json.dump(doc, s, indent=2, sort_keys=True)
            s.write("\n")
        print(json.dumps({"lead_count": doc["lead_count"], "verified": False}))
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print("Error: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
