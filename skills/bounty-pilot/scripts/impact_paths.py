#!/usr/bin/env python3
"""Impact-first review queue: reverse from economic/security sinks to upstream entries.

Traversing a state dependency is a *candidate* transition, not executable control flow.
Runtime reachability, actual access controls and measurable impact still need proof.
"""
import argparse
import json
from collections import defaultdict, deque
from pathlib import Path

# `arbitrary-call` leads: a caller-chosen call target with users' standing approvals is the
# most repeated production exploit class in references/hack-patterns.md. A low-level call to a
# fixed or caller-own address is plumbing and ranks last.
CLASS_WEIGHTS = {
    "arbitrary-call": 7, "asset-movement": 6, "debt-solvency": 6, "privileged-power": 6,
    "delegatecall": 6, "self-destruct": 6, "token-pull": 6,
    "settlement": 5, "permit": 5, "price-oracle": 4, "low-level-call": 3
}


def _contract_of(sym):
    return sym.get("contract") or str(sym.get("name", "")).rsplit(".", 1)[0]


def approval_holders(symbols):
    """(path, contract) pairs that pull tokens with transferFrom or permit: users hold standing
    approvals to these."""
    return {(s.get("path"), _contract_of(s)) for s in symbols.values()
            if {"token-pull", "permit"} & set(s.get("sinks") or [])}


def priority(sink, holders):
    """Family weight plus the AST facts that make a sink worse. Returns (score, reasons)."""
    score = max(CLASS_WEIGHTS.get(x, 0) for x in sink["sinks"])
    reasons = []
    details = [d for d in sink.get("sink_details") or [] if isinstance(d, dict)]
    if "arbitrary-call" in sink["sinks"]:
        if any(d.get("target_source") == "parameter" for d in details):
            score += 1
            reasons.append("call target is a parameter of this function")
        if (sink.get("path"), _contract_of(sink)) in holders:
            score += 1
            reasons.append("the same contract pulls tokens with transferFrom/permit, so users' "
                           "standing approvals point at it")
    if any(d.get("kind") == "token-pull" and d.get("from_source") not in (
            "msg.sender", "this", "literal", "constant", "immutable") for d in details):
        score += 1
        reasons.append("transferFrom pulls from an address that is not msg.sender")
    if any(d.get("kind") == "permit" and d.get("owner_source") == "parameter" for d in details):
        reasons.append("permit owner is a parameter: front-run or replayed signatures")
    return score, reasons

def rank(graph, max_depth=5, limit=120):
    if max_depth < 1 or max_depth > 12 or limit < 1 or limit > 500:
        raise ValueError("invalid depth/limit")
    symbols = {s["id"]: s for s in graph["symbols"]}
    incoming = defaultdict(list)
    for edge in graph["edges"]:
        if edge["to"] in symbols and edge["from"] in symbols:
            incoming[edge["to"]].append(edge)
    findings = []
    holders = approval_holders(symbols)
    for sink in sorted(symbols.values(), key=lambda s: s["id"]):
        if not sink.get("sinks"):
            continue
        score, reasons = priority(sink, holders)
        queue = deque([(sink["id"], [sink["id"]], [], False)])
        candidate = []
        steps_checked = 0
        bounded = False
        while queue:
            steps_checked += 1
            if steps_checked > 2500:
                bounded = True
                break
            cur, path, evidence, uncertain = queue.popleft()
            if symbols[cur].get("entry"):
                candidate.append({"entry": cur, "path": list(reversed(path)),
                                  "edges": list(reversed(evidence)),
                                  "includes_state_candidate_edge": uncertain})
            if len(path) > max_depth:
                continue
            for edge in sorted(incoming[cur], key=lambda e: (e["from"], e["kind"])):
                previous = edge["from"]
                if previous in path:
                    continue
                uncertain_next = uncertain or edge["kind"] == "writer-reader-overlap"
                queue.append((previous, path + [previous], evidence + [edge],
                              uncertain_next))
                # Bound exploration per sink, not just returned top N.
                if len(queue) > 1000:
                    bounded = True
                    break
            if len(candidate) >= 20:
                break
        # A high-impact sink without a proven public entry is still a review lead.
        if not candidate:
            candidate = [{"entry": None, "path": [sink["id"]], "edges": [],
                          "includes_state_candidate_edge": False}]
        for row in candidate[:20]:
            findings.append({"sink": sink["id"], "impact_families": sink["sinks"],
                             "priority_heuristic": score,
                             "priority_reasons": reasons,
                             "entry": row["entry"], "path": row["path"],
                             "edges": row["edges"],
                             "confidence": ("unverified-no-public-entry" if row["entry"] is None
                                 else "unverified-possible-sequence" if row["includes_state_candidate_edge"]
                                 else "unverified-static-path"),
                             "search_truncated": bounded,
                             "todo": ["confirm source revision/deployment",
                                      "confirm public reachability and authority",
                                      "prove violated invariant and third-party loss",
                                      "execute native PoC and negative control"]})
    findings.sort(key=lambda r: (-r["priority_heuristic"],
                                  r["confidence"] != "unverified-static-path",
                                  r["sink"], r["path"]))
    graph_truncated = bool(graph.get("truncated"))
    return {"schema": 1, "method": "backwards-impact-review",
            "ranked": findings[:limit], "total_paths": len(findings),
            "graph_truncated": graph_truncated,
            "graph_edge_counts": graph.get("edge_counts"),
            "notice": "No entry or sink is asserted exploitable. Static code links and lexical impact "
                      "labels are triage hints, never severity classifications."
                      + (" The input graph hit its edge cap (truncated); some upstream paths are missing."
                         if graph_truncated else "")}

def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--graph", required=True)
    p.add_argument("--max-depth", type=int, default=5)
    p.add_argument("--limit", type=int, default=120)
    p.add_argument("--out")
    a = p.parse_args(argv)
    try:
        report = rank(json.loads(Path(a.graph).read_text(encoding="utf-8")),
                      a.max_depth, a.limit)
    except (ValueError, KeyError, OSError, json.JSONDecodeError) as exc:
        p.error(str(exc))
    payload = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if a.out:
        Path(a.out).write_text(payload, encoding="utf-8")
        print(json.dumps({"out": a.out, "paths": len(report["ranked"])}))
    else:
        print(payload, end="")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
