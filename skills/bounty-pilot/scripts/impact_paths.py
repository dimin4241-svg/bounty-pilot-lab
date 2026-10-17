#!/usr/bin/env python3
"""Impact-first review queue: reverse from economic/security sinks to upstream entries.

Traversing a state dependency is a *candidate* transition, not executable control flow.
Runtime reachability, actual access controls and measurable impact still need proof.
"""
import argparse
import json
import re
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
# One sink reached from forty entry points is one place to read: the rows kept per sink are
# its best few entries, so a library helper every function calls cannot fill the queue.
MAX_ROWS_PER_SINK = 3
# Guard tokens that say nothing about who or what: a reentrancy lock and a pause flag.
NEUTRAL_GUARD = re.compile(r"(?:reentran|paus|^_?status$|^entered$|^_?not_?entered$|^_?locked$)",
                           re.I)
# Tokens that restrict the caller: a sender comparison or an owner/role/admin check.
CALLER_GUARD = re.compile(r"(?:^msg\.sender$|^tx\.origin$|owner|role|admin|auth|govern|guardian|"
                          r"operator|keeper|whitelist|allowlist|"
                          r"^only(?!proxy|delegate|initializ|calls?ofproxy))", re.I)
GUARD_RANK = {"none": 0, "condition": 1, "caller": 2, "unknown": 1}


def _contract_of(sym):
    return sym.get("contract") or str(sym.get("name", "")).rsplit(".", 1)[0]


def entry_guard(sym):
    """`caller`, `condition` or `none`: what an entry point's guard tokens restrict. A lexical
    reading of token names, never a proof that the check holds."""
    if "guards" not in sym:
        return "unknown"
    tokens = [str(t).rsplit(":", 1)[-1] for t in sym.get("guards") or []]
    if any(CALLER_GUARD.search(t) for t in tokens):
        return "caller"
    if any(not NEUTRAL_GUARD.search(t) for t in tokens):
        return "condition"
    return "none"


def is_entry(sym):
    """A public entry a transaction can start at; a constructor runs once, at deployment."""
    return bool(sym.get("entry")) and sym.get("function_kind") != "constructor"


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
    pulls = [d for d in details if d.get("kind") == "token-pull" and d.get("from_source") not in (
        "msg.sender", "this", "literal", "constant", "immutable")]
    if pulls and is_entry(sink) or any(d.get("from_source") != "parameter" for d in pulls):
        score += 1
        reasons.append("transferFrom pulls from an address that is not msg.sender")
    elif pulls:
        # `_deposit(caller, ...)`: who `caller` is depends on every call site.
        reasons.append("transferFrom pulls from a parameter of an internal function: check what "
                       "each caller passes")
    if any(d.get("kind") == "permit" and d.get("owner_source") == "parameter" for d in details):
        reasons.append("permit owner is a parameter: front-run or replayed signatures")
    return score, reasons

def _scoped(sym):
    return sym.get("scope_role", "in-scope") != "dependency"


def rank(graph, max_depth=5, limit=120, rows_per_sink=MAX_ROWS_PER_SINK):
    if max_depth < 1 or max_depth > 12 or limit < 1 or limit > 500 or rows_per_sink < 1:
        raise ValueError("invalid depth/limit")
    symbols = {s["id"]: s for s in graph["symbols"]}
    incoming = defaultdict(list)
    for edge in graph["edges"]:
        if edge["to"] in symbols and edge["from"] in symbols:
            incoming[edge["to"]].append(edge)
    # An entry whose code is vendored, when an in-scope contract deploys it: the heir is the
    # entry point to read, so the vendored declaration's own row ranks after it.
    deployed = {e["to"] for e in graph["edges"] if e.get("kind") == "inherited-entry"
                and e["from"] in symbols and _scoped(symbols[e["from"]])}
    findings = []
    capped_out = 0
    holders = approval_holders(symbols)
    for sink in sorted(symbols.values(), key=lambda s: s["id"]):
        # An heir symbol runs its declaration's code: the declaration is the sink.
        if not sink.get("sinks") or sink.get("inherits"):
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
            if is_entry(symbols[cur]) and _scoped(symbols[cur]):
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
            if len(candidate) >= 40:
                break
        # A high-impact sink without a proven public entry is still a review lead - in scope.
        if not candidate:
            if not _scoped(sink):
                continue
            candidate = [{"entry": None, "path": [sink["id"]], "edges": [],
                          "includes_state_candidate_edge": False}]
        rows = []
        for row in candidate:
            entry = symbols.get(row["entry"]) if row["entry"] else None
            guard = entry_guard(entry) if entry else "unknown"
            shadowed = bool(entry and row["entry"] in deployed)
            confidence = ("unverified-no-public-entry" if row["entry"] is None
                          else "unverified-possible-sequence" if row["includes_state_candidate_edge"]
                          else "unverified-static-path")
            rows.append({"sink": sink["id"], "impact_families": sink["sinks"],
                         "priority_heuristic": score,
                         "priority_reasons": reasons,
                         "entry": row["entry"], "path": row["path"],
                         "edges": row["edges"],
                         "entry_guard": guard,
                         "entry_deployed_by_in_scope_heir": shadowed,
                         "confidence": confidence,
                         "search_truncated": bounded,
                         "todo": ["confirm source revision/deployment",
                                  "confirm public reachability and authority",
                                  "prove violated invariant and third-party loss",
                                  "execute native PoC and negative control"]})
        rows.sort(key=_row_order)
        capped_out += max(0, len(rows) - rows_per_sink)
        findings.extend(rows[:rows_per_sink])
    findings.sort(key=lambda r: (-r["priority_heuristic"],) + _row_order(r)[:3]
                  + (r["sink"], r["path"]))
    graph_truncated = bool(graph.get("truncated"))
    return {"schema": 1, "method": "backwards-impact-review",
            "ranked": findings[:limit], "total_paths": len(findings),
            "rows_per_sink": rows_per_sink, "paths_beyond_rows_per_sink": capped_out,
            "graph_truncated": graph_truncated,
            "graph_edge_counts": graph.get("edge_counts"),
            "notice": "No entry or sink is asserted exploitable. Static code links and lexical impact "
                      "labels are triage hints, never severity classifications. Within one priority, "
                      "rows whose entry carries no guard come first (entry_guard is a reading of "
                      "guard-token names, not a proof of access control); a vendored entry an "
                      "in-scope contract deploys ranks after that contract's own row; constructors "
                      "are not entries; each sink keeps its best %d rows." % rows_per_sink
                      + (" The input graph hit its edge cap (truncated); some upstream paths are missing."
                         if graph_truncated else "")}


def _row_order(row):
    """Unguarded before guarded, in-scope heir before the vendored entry it deploys, a static
    path before a state-overlap sequence, a short path first."""
    return (GUARD_RANK.get(row["entry_guard"], 1), row["entry_deployed_by_in_scope_heir"],
            row["confidence"] != "unverified-static-path", len(row["path"]))

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
