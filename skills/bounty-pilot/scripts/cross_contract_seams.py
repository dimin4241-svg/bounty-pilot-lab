#!/usr/bin/env python3
"""Offline, bounded Solidity cross-contract *lead* generator from solc build-info.

No source execution, network, reachability proof, runtime state attribution or
vulnerability classification. Every edge and lead must be reviewed manually.
"""
import argparse
import json
from collections import defaultdict, deque
from pathlib import Path

MAX_NODES = 20000
MAX_EDGES = 50000

def walk(node):
    if isinstance(node, dict):
        yield node
        for value in node.values():
            yield from walk(value)
    elif isinstance(node, list):
        for value in node:
            yield from walk(value)

def _name(node):
    return node.get("name") or node.get("memberName") or ""

def _call_target(node):
    expr = node.get("expression") or {}
    if not isinstance(expr, dict):
        return None
    if expr.get("nodeType") == "MemberAccess":
        base = expr.get("expression") or {}
        return {"member": expr.get("memberName"), "base_type": (base.get("typeDescriptions") or {}).get("typeString", ""),
                "base_name": _name(base), "kind": node.get("kind")}
    return None

def analyze(build_info, max_depth=4):
    if not 1 <= max_depth <= 8:
        raise ValueError("max_depth must be 1..8")
    output = build_info.get("output", {})
    sources = output.get("sources", {})
    contracts = {}
    functions = {}
    calls = []
    writes = []
    truncated = False
    for path in sorted(sources):
        ast = sources[path].get("ast")
        if not isinstance(ast, dict):
            continue
        for item in walk(ast):
            if item.get("nodeType") != "ContractDefinition":
                continue
            cid = item.get("id")
            if cid is None:
                continue
            key = str(cid)
            contracts[key] = {"id": key, "name": item.get("name"), "path": path}
            for fn in item.get("nodes", []):
                if fn.get("nodeType") != "FunctionDefinition":
                    continue
                fid = fn.get("id")
                if fid is None or len(functions) >= MAX_NODES:
                    truncated = True
                    continue
                fkey = str(fid)
                functions[fkey] = {"id": fkey, "contract_id": key, "name": fn.get("name") or fn.get("kind"),
                                   "visibility": fn.get("visibility"), "src": fn.get("src"), "path": path}
                body = fn.get("body")
                if not body:
                    continue
                for part in walk(body):
                    if part.get("nodeType") == "FunctionCall":
                        target = _call_target(part)
                        if target and len(calls) < MAX_EDGES:
                            calls.append({"from_function": fkey, "contract_id": key, "target": target,
                                          "src": part.get("src"), "confidence": "unverified_static"})
                        elif target:
                            truncated = True
                    if part.get("nodeType") == "Assignment":
                        lhs = part.get("leftHandSide") or {}
                        ref = lhs.get("referencedDeclaration")
                        if ref is None and lhs.get("nodeType") == "IndexAccess":
                            ref = (lhs.get("baseExpression") or {}).get("referencedDeclaration")
                        if ref is not None and len(writes) < MAX_EDGES:
                            writes.append({"function": fkey, "contract_id": key, "state_ref": str(ref),
                                           "src": part.get("src")})
                        elif ref is not None:
                            truncated = True
    # Resolve only unambiguous Solidity contract types; no guesses by variable name.
    by_name = defaultdict(list)
    for cid, contract in contracts.items():
        by_name[contract["name"]].append(cid)
    edges = []
    unresolved = []
    for call in calls:
        typ = call["target"]["base_type"]
        candidates = [cid for name, ids in by_name.items() if typ in ("contract " + str(name), "contract " + str(name) + " payable") for cid in ids]
        member = call["target"]["member"]
        matches = [f for f in functions.values() if f["contract_id"] in candidates and f["name"] == member]
        if len(candidates) == 1 and matches:
            # Overloads remain ambiguous: keep candidates but do not assert exact dispatch.
            edges.append({"from_function": call["from_function"], "to_contract": candidates[0],
                          "candidate_functions": sorted(f["id"] for f in matches), "src": call["src"],
                          "confidence": "static_type_only"})
        else:
            unresolved.append(call)
    graph = defaultdict(set)
    for edge in edges:
        origin = functions[edge["from_function"]]["contract_id"]
        graph[origin].add(edge["to_contract"])
    paths = []
    for start in sorted(graph):
        queue = deque([(start, (start,))])
        while queue and len(paths) < MAX_EDGES:
            current, route = queue.popleft()
            if len(route) > 1:
                paths.append(list(route))
            if len(route) - 1 >= max_depth:
                continue
            for nxt in sorted(graph[current]):
                if nxt not in route:
                    queue.append((nxt, route + (nxt,)))
        if len(paths) >= MAX_EDGES:
            truncated = True
            break
    write_contracts = {w["contract_id"] for w in writes}
    leads = []
    for route in paths:
        if len(route) >= 2 and any(cid in write_contracts for cid in route):
            leads.append({"kind": "cross_contract_state_review", "contracts": route,
                          "question": "Does the entire call sequence preserve ownership, balances and liabilities?",
                          "status": "UNVERIFIED", "evidence": "static AST only"})
    return {"schema_version": 1, "status": "UNVERIFIED", "contracts": contracts, "functions": functions,
            "edges": edges, "unresolved_calls": unresolved, "state_write_sites": writes,
            "paths": paths, "leads": leads, "limits": {
                "truncated": truncated, "max_depth": max_depth,
                "unsupported": ["dynamic dispatch", "delegatecall storage semantics", "proxy implementation resolution",
                                "inter-transaction state", "runtime reachability", "external contracts without AST",
                                "economic profitability", "exploit proof"]}}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-info", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--max-depth", type=int, default=4)
    args = parser.parse_args()
    source = Path(args.build_info)
    if not source.is_file() or source.stat().st_size > 100_000_000:
        parser.error("build-info must be a file <=100MB")
    result = analyze(json.loads(source.read_text(encoding="utf-8")), args.max_depth)
    dest = Path(args.out)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("UNVERIFIED cross-contract leads:", len(result["leads"]))

if __name__ == "__main__":
    main()
