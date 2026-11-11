#!/usr/bin/env python3
"""Offline browser/URL/third-party/cookie trust path explorer.

Consumes a researcher-authored, bounded declaration of nodes and observed
dataflow edges; never runs JS, fetches URLs, decodes credentials or concludes
that an actual session was exposed. Emits unverified review paths only.
"""
import argparse
import hashlib
import json
import os
import re
import sys
from collections import defaultdict, deque
from pathlib import Path

IDENT = re.compile(r"^[A-Za-z0-9_.:-]{1,100}$")
KINDS = frozenset(("user-content", "browser", "origin-validator",
                   "backend", "third-party-script", "third-party-origin",
                   "cookie-store", "session-context", "url-parser", "cache",
                   "sensitive-operation", "other"))
EDGES = frozenset(("renders", "validates-url", "normalizes-url", "loads-script",
                   "fetches", "redirects-to", "sends-cookie", "sends-auth",
                   "reads-cookie", "reads-data", "executes-script", "uses-auth",
                   "reaches-operation", "shares-cache-key"))
MAX_NODES = 200
MAX_EDGES = 600
MAX_DEPTH = 6


def _load(path):
    p = Path(path).expanduser()
    if p.is_symlink() or not p.is_file() or p.stat().st_size > 1_000_000:
        raise ValueError("only bounded non-symlink JSON")
    return json.loads(p.read_text(encoding="utf-8"), object_pairs_hook=_unique)


def _unique(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise ValueError("duplicate JSON key")
        out[k] = v
    return out


def _write(path, obj):
    p = Path(path).expanduser()
    if p.exists() or p.is_symlink():
        raise ValueError("output must be a new file")
    p.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(p), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(obj, f, sort_keys=True, indent=2, ensure_ascii=False)
        f.write("\n")


def analyze(doc):
    if (not isinstance(doc, dict) or set(doc) != {
            "schema_version", "environment", "nodes", "edges"} or
            type(doc["schema_version"]) is not int or doc["schema_version"] != 1 or
            doc["environment"] != "offline_owned_source_or_fixture"):
        raise ValueError("bounded offline graph schema required")
    nodes, edges = doc["nodes"], doc["edges"]
    if (not isinstance(nodes, list) or not 1 <= len(nodes) <= MAX_NODES or
            not isinstance(edges, list) or len(edges) > MAX_EDGES):
        raise ValueError("bounded node and edge arrays required")
    ns = {}
    for node in nodes:
        if not isinstance(node, dict) or set(node) != {
                "id", "kind", "trust", "sensitive", "user_controlled"}:
            raise ValueError("node must have explicit trust/context")
        ident = node["id"]
        if not isinstance(ident, str) or not IDENT.fullmatch(ident) or ident in ns:
            raise ValueError("duplicate/invalid node")
        if (node["kind"] not in KINDS or node["trust"] not in (
                "trusted", "untrusted", "unknown") or
                type(node["sensitive"]) is not bool or
                type(node["user_controlled"]) is not bool):
            raise ValueError("invalid trust node")
        ns[ident] = node
    adj = defaultdict(list)
    for edge in edges:
        if not isinstance(edge, dict) or set(edge) != {
                "from", "to", "kind", "observed_in_source", "evidence_sha256"}:
            raise ValueError("invalid trust edge")
        src, dst = edge["from"], edge["to"]
        if src not in ns or dst not in ns or edge["kind"] not in EDGES:
            raise ValueError("edge not in declared graph")
        if (type(edge["observed_in_source"]) not in (bool, type(None)) or
                edge["evidence_sha256"] is not None and (
                    not isinstance(edge["evidence_sha256"], str) or
                    not re.fullmatch(r"[a-f0-9]{64}", edge["evidence_sha256"]))):
            raise ValueError("observed_in_source/evidence digest invalid")
        adj[src].append(edge)
    paths, seen = [], set()
    for src, node in sorted(ns.items()):
        if not node["user_controlled"] or node["trust"] != "untrusted":
            continue
        queue = deque([(src, [src], [], False, False)])
        while queue and len(paths) < 100:
            current, visited, hops, crossed, carried = queue.popleft()
            if len(hops) >= MAX_DEPTH:
                continue
            for edge in adj[current]:
                dest = edge["to"]
                if dest in visited:
                    continue
                destination = ns[dest]
                # A crossing is only declared when trusted and untrusted
                # contexts explicitly connect, not inferred from a hostname.
                new_cross = (crossed or (
                    ns[current]["trust"] != "unknown" and
                    destination["trust"] != "unknown" and
                    ns[current]["trust"] != destination["trust"]))
                # Do not infer secret exposure from URL fetch alone; privilege
                # transport must be represented explicitly in the edge list.
                new_carried = carried or edge["kind"] in (
                    "sends-cookie", "sends-auth", "uses-auth", "executes-script")
                trace = hops + [{"from": current, "to": dest,
                                 "kind": edge["kind"],
                                 "observed": edge["observed_in_source"],
                                 "evidence_sha256": edge["evidence_sha256"]}]
                if destination["sensitive"] and new_cross and new_carried:
                    fingerprint = hashlib.sha256(json.dumps([
                        src, dest, [x["kind"] for x in trace]], sort_keys=True
                    ).encode("utf-8")).hexdigest()[:18]
                    if fingerprint not in seen:
                        seen.add(fingerprint)
                        paths.append({
                            "id": fingerprint, "source": src, "sink": dest,
                            "hops": trace, "crosses_trust_boundary": True,
                            "privileged_context_edge_seen": True,
                            "status": ("STATIC_SOURCE_BACKED_REVIEW_LEAD" if
                                       all(x["observed"] is True and
                                           x["evidence_sha256"] for x in trace)
                                       else "UNVERIFIED_DECLARED_PATH"),
                            "confirmed_vulnerability": False})
                elif len(trace) < MAX_DEPTH:
                    queue.append((dest, visited + [dest], trace, new_cross, new_carried))
    return {"schema_version": 1, "mode": "web-browser-trust-graph",
            "nodes": len(nodes), "edges": len(edges), "review_paths": paths,
            "network_requests": 0, "confirmed_vulnerabilities": 0,
            "limitations": ("Edges and trust labels are investigator supplied. "
                            "This is not browser execution, flow-sensitive taint "
                            "analysis, proof of cookies crossing SameSite rules, "
                            "or exploit verification. Requires actual local "
                            "browser/HTTP evidence before claiming impact.")}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--input", required=True)
    p.add_argument("--out", required=True)
    a = p.parse_args(argv)
    try:
        result = analyze(_load(a.input))
        _write(a.out, result)
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
        p.error(str(exc))
    print(json.dumps({"out": a.out, "review_paths": len(result["review_paths"]),
                      "confirmed_vulnerabilities": 0}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
