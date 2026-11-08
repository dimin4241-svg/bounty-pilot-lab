#!/usr/bin/env python3
"""Partial Rust MIR and normalized Move/Rust def-use lead extraction.

Rust mode reads an already-produced rustc --emit=mir textual artifact; it
does not invoke rustc or target code. Move mode reads explicit compiler/
researcher-translated normalized graph JSON. Control flow, ownership, auth
guards, macro expansions and storage reachability are NOT proven.
"""
import argparse
import json
import re
import sys
from collections import deque
from pathlib import Path

MAX_INPUT = 4_000_000
MAX_NODES = 4000
MAX_EDGES = 24000
HEX40 = re.compile(r"^[0-9a-f]{40}$")
FN = re.compile(r"^\s*fn\s+([a-zA-Z_][a-zA-Z0-9_:<>]*)\s*\((.*)\)\s*->")
PARAM = re.compile(r"\b(_\d+)\s*:")
ASSIGN = re.compile(r"^\s*(_\d+)\s*=\s*(.+?);\s*$")
VAR = re.compile(r"\b_\d+\b")
SENSITIVE = re.compile(r"(?i)\b(transfer|withdraw|settle|mint|burn|"
                       r"invoke_signed|set_authority|deposit|publish|"
                       r"write_resource|borrow_global_mut|move_to|move_from)\b")
SOURCES = {"external-input", "signer", "untrusted-response", "receipt",
           "cross-chain-message"}
SINKS = {"asset-transfer", "authority-write", "resource-write",
         "mint-burn", "settlement", "persistent-state-write"}


def _pairs(items):
    v = {}
    for k, x in items:
        if k in v:
            raise ValueError("duplicate JSON field")
        v[k] = x
    return v


def load(path):
    p = Path(path).expanduser()
    if p.is_symlink() or not p.is_file() or p.stat().st_size > MAX_INPUT:
        raise ValueError("input must be local nonsymlink file <=4MB")
    return p.read_text(encoding="utf-8")


def scan_rust_mir(s, revision):
    if not HEX40.fullmatch(revision):
        raise ValueError("exact pinned revision required")
    # A lexical, intra-function def/use approximation. No claims that
    # every _N argument is externally controlled; Rust uses internal calls.
    leads, name, params, taint, total = [], None, set(), {}, 0
    for line_no, line in enumerate(s.splitlines(), 1):
        f = FN.match(line)
        if f:
            name = f.group(1)
            params = set(PARAM.findall(f.group(2)))
            taint = {v: [v] for v in params}
        if name is None:
            continue
        if line.strip() == "}":
            # Rust MIR may also have nested blocks, so this is a conservative
            # early termination and a coverage blocker, never a negative proof.
            pass
        m = ASSIGN.match(line)
        if m:
            out, expr = m.groups()
            used = sorted({v for v in VAR.findall(expr) if v in taint})
            if used:
                taint[out] = sorted({source for u in used for source in taint[u]})[:24]
            elif out in taint and out not in params:
                del taint[out]
        if SENSITIVE.search(line):
            inputs = sorted({v for v in VAR.findall(line) if v in taint})
            if inputs:
                leads.append({"function": name, "line": line_no,
                              "input_registers": inputs[:16],
                              "seed_parameters": sorted({
                                  a for v in inputs for a in taint[v]})[:16],
                              "sink_hint": SENSITIVE.search(line).group(1),
                              "status": "unverified-mir-lexical-defuse"})
                if len(leads) >= 300:
                    break
        total += 1
    return {"schema_version": 1, "language": "rust",
            "mode": "rust-mir-partial-lexical-defuse", "source_revision": revision,
            "leads": leads, "count": len(leads), "lines_examined": total,
            "limitations": ["not-all-functions-or-CFG-edges-recovered",
                            "internal-parameters-not-proven-untrusted",
                            "no-macro-or-storage-liveness-proof",
                            "no-authorization-or-reachability-verdict"]}


def normalize_graph(d):
    if not isinstance(d, dict) or d.get("schema_version") != 1:
        raise ValueError("normalized IR requires schema_version 1")
    language, revision = d.get("language"), d.get("source_revision")
    if language not in ("rust", "move") or not isinstance(revision, str) or (
            not HEX40.fullmatch(revision)):
        raise ValueError("normalized IR needs rust/move and pinned source revision")
    nodes = d.get("nodes")
    if not isinstance(nodes, list) or not 1 <= len(nodes) <= MAX_NODES:
        raise ValueError("nodes must be 1..4000")
    ids, edges, origin = {}, {}, {}
    for row in nodes:
        if not isinstance(row, dict):
            raise ValueError("node must be object")
        nid = row.get("id")
        if not isinstance(nid, str) or not re.fullmatch(r"[A-Za-z0-9_:.-]{1,100}", nid):
            raise ValueError("invalid IR node ID")
        if nid in ids:
            raise ValueError("duplicate node ID")
        kind = row.get("kind")
        if kind not in SOURCES | SINKS | {"value", "call", "state-read",
                                         "authorization-check", "merge"}:
            raise ValueError("unsupported node kind")
        rel = row.get("file")
        line = row.get("line")
        if not isinstance(rel, str) or rel.startswith("/") or ".." in Path(rel).parts or (
                "\\" in rel) or not 1 <= len(rel) <= 240:
            raise ValueError("node needs safe source-relative file")
        if type(line) is not int or not 1 <= line <= 10000000:
            raise ValueError("node needs line number")
        ids[nid] = row
        incoming = row.get("inputs", [])
        if not isinstance(incoming, list) or len(incoming) > 30 or not all(
                isinstance(x, str) for x in incoming):
            raise ValueError("node inputs must be bounded list")
        edges[nid] = incoming
    total = sum(map(len, edges.values()))
    if total > MAX_EDGES:
        raise ValueError("too many edges")
    for v in edges.values():
        if any(n not in ids for n in v):
            raise ValueError("dangling dependency")
    # Build forward adjacency. Multi-step storage relationships MUST appear
    # as explicit edges provided by a separate native state-aware extractor.
    nexts = {n: [] for n in ids}
    for end, starts in edges.items():
        for start in starts:
            nexts[start].append(end)
    for start, obj in ids.items():
        if obj["kind"] in SOURCES:
            origin[start] = start
    leads = []
    for start in sorted(origin):
        queue = deque([(start, [start])])
        seen = {start}
        while queue:
            node, path = queue.popleft()
            if ids[node]["kind"] in SINKS:
                leads.append({
                    "source": start, "sink": node,
                    "source_kind": ids[start]["kind"],
                    "sink_kind": ids[node]["kind"],
                    "anchors": [{"file": ids[n]["file"], "line": ids[n]["line"]}
                                for n in path],
                    "nodes": path, "status": "normalized-ir-unverified-defuse"
                })
                if len(leads) >= 500:
                    break
            if len(path) >= 30:
                continue
            for nxt in sorted(nexts[node]):
                if nxt not in seen:
                    seen.add(nxt)
                    queue.append((nxt, path + [nxt]))
        if len(leads) >= 500:
            break
    return {"schema_version": 1, "language": language, "source_revision": revision,
            "mode": "operator-supplied-normalized-ir",
            "node_count": len(nodes), "edge_count": total,
            "leads": leads, "count": len(leads),
            "limitations": ["normalized-IR-is-not-authenticated-against-compiler",
                            "control-flow-and-authorization-not-proven",
                            "state-cross-transaction-edges-must-be-supplied",
                            "reachability-and-impact-require-native-test"]}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--rust-mir", help="existing compiler text output; never invoke rustc")
    group.add_argument("--normalized-ir", help="operator/exporter-supplied Rust/Move JSON graph")
    p.add_argument("--source-revision", help="required for rust MIR (40 hex)")
    p.add_argument("--out", required=True)
    args = p.parse_args(argv)
    try:
        result = (scan_rust_mir(load(args.rust_mir), args.source_revision or "")
                  if args.rust_mir else normalize_graph(
                      json.loads(load(args.normalized_ir), object_pairs_hook=_pairs)))
        out = Path(args.out).expanduser()
        if out.exists() or out.is_symlink():
            raise ValueError("output exists")
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("x", encoding="utf-8") as f:
            json.dump(result, f, sort_keys=True, indent=2)
            f.write("\n")
    except (ValueError, OSError, TypeError, UnicodeError) as exc:
        p.error(str(exc))
    print(json.dumps({"mode": result["mode"], "count": result["count"],
                      "out": args.out}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
