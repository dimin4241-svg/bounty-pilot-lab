#!/usr/bin/env python3
"""Bounded dependency-aware sequence planning for AVRE.

The planner consumes the existing lexical state graph. Its paths are experiment seeds, never
proof of runtime reachability. It does not execute the target or invoke a test runner.
"""
import re


OPERATION_PATTERNS = (
    ("deposit", r"deposit|stake|supply|mint|wrap"),
    ("withdraw", r"withdraw|unstake|exit|redeem|burn"),
    ("claim", r"claim|reward|harvest|distribute|checkpoint"),
    ("debt", r"borrow|repay|liquidat|debt|settle"),
    ("authorization", r"authoriz|approve|grant|revoke|delegate|permit|role"),
    ("identity", r"owner|operator|payer|receiver|spender|signer|account|session"),
    ("configuration", r"set|configure|enable|disable|pause|unpause|oracle|registry"),
    ("migration", r"upgrade|migrate|initialize|reinitializer|version"),
    ("async", r"retry|resume|queue|process|relay|callback|ack|event|message|finaliz"),
    ("epoch", r"epoch|checkpoint|snapshot|deadline|expiry|timestamp|block"),
)
REPEATABLE = re.compile(r"(?i)(claim|process|execute|relay|retry|resume|settle|finaliz|callback|ack)")
ACTOR_MARKERS = re.compile(r"(?i)(msg\.sender|tx\.origin|caller|owner|operator|delegate|payer|receiver|signer)")


def operation(symbol):
    name = (symbol.get("symbol") or "").lower()
    words = " ".join(symbol.get("reads_approx", [])).lower()
    return next((label for label, pattern in OPERATION_PATTERNS
                 if re.search(pattern, name + " " + words)), "state")


def _edge_key(edge):
    return edge.get("from"), edge.get("to"), edge.get("token"), edge.get("reason")


def _sequence(path, edge_rows, symbols, variant="dependency_path"):
    actions = [symbols[ident] for ident in path]
    operations = [operation(row) for row in actions]
    unique_edges = {_edge_key(row) for row in edge_rows}
    diversity = len(set(operations))
    score = round(len(unique_edges) * 2.0 + diversity * 1.5 +
                  sum(bool(row.get("signals")) for row in actions) * 0.25, 3)
    return {
        "actions": [{"symbol_id": row["id"], "path": row["path"],
                     "function": row["symbol"], "line": row["line"],
                     "operation_class": op}
                    for row, op in zip(actions, operations)],
        "dependency_edges": [{"from": row.get("from"), "to": row.get("to"),
                              "shared_state_or_symbol": row.get("token"),
                              "reason": row.get("reason"), "confidence": row.get("confidence", "low")}
                             for row in edge_rows],
        "mutation": variant, "coverage_feedback": {"unique_edges": len(unique_edges),
                                                       "operation_classes": diversity},
        "priority_score": score, "status": "unverified_sequence_seed",
        "notice": "Lexical dependencies do not prove executable order, caller permissions, or reachability.",
    }


def _mutations(base, symbols, edges):
    paths = [row["symbol_id"] for row in base["actions"]]
    output = [base]
    if len(paths) > 2:
        output.append(_sequence(list(reversed(paths)), list(reversed(edges)), symbols,
                                "reverse_order_candidate"))
        for end in range(2, len(paths)):
            output.append(_sequence(paths[:end], edges[:end - 1], symbols, "partial_prefix"))
    if paths:
        last = symbols[paths[-1]]
        if REPEATABLE.search(last["symbol"]):
            output.append(_sequence(paths + [paths[-1]], edges + (edges[-1:] or []), symbols,
                                    "duplicate_operation"))
        names = " ".join(row["symbol"] for row in (symbols[p] for p in paths))
        if ACTOR_MARKERS.search(names):
            item = _sequence(paths, edges, symbols, "actor_switch_candidate")
            item["actor_schedule"] = ["synthetic-user-A", "synthetic-user-B"]
            output.append(item)
        classes = {operation(symbols[p]) for p in paths}
        if "configuration" in classes and "migration" in classes:
            output.append(_sequence(paths, edges, symbols, "configuration-migration-boundary"))
        if "epoch" in classes:
            output.append(_sequence(paths, edges, symbols, "epoch-boundary-before-after"))
    unique = {}
    for row in output:
        key = (tuple(item["symbol_id"] for item in row["actions"]), row["mutation"])
        unique.setdefault(key, row)
    return list(unique.values())


def generate(graph, budget=200, max_length=5, beam_width=16):
    """Return a bounded beam of dependency-linked paths and their safe mutations."""
    if type(budget) is not int or not 1 <= budget <= 5000:
        raise ValueError("sequence budget must be between 1 and 5000")
    if type(max_length) is not int or not 2 <= max_length <= 8:
        raise ValueError("maximum sequence length must be between 2 and 8")
    if type(beam_width) is not int or not 1 <= beam_width <= 100:
        raise ValueError("beam width must be between 1 and 100")
    symbols = {row["id"]: row for row in graph.get("symbols", [])
               if isinstance(row, dict) and isinstance(row.get("id"), str)}
    edges = [edge for edge in graph.get("edges", []) if edge.get("from") in symbols
             and edge.get("to") in symbols]
    adjacency = {}
    for edge in edges:
        adjacency.setdefault(edge["from"], []).append(edge)
    for rows in adjacency.values():
        rows.sort(key=lambda edge: (-int(edge.get("confidence") == "medium"),
                                    str(edge.get("token", "")), edge.get("to", "")))
    beam = []
    for edge in edges:
        beam.append(([edge["from"], edge["to"]], [edge]))
    beam.sort(key=lambda item: (-_sequence(item[0], item[1], symbols)["priority_score"],
                                tuple(item[0])))
    beam = beam[:beam_width]
    paths, seen_paths = [], set()
    while beam:
        next_beam = []
        for ids, used_edges in beam:
            key = tuple(ids)
            if key not in seen_paths:
                seen_paths.add(key)
                paths.append((ids, used_edges))
            if len(ids) >= max_length:
                continue
            for edge in adjacency.get(ids[-1], [])[:beam_width]:
                # Permit a repeat only for idempotency/replay-shaped operations; other loops
                # balloon without useful new coverage.
                if edge["to"] in ids and not REPEATABLE.search(symbols[edge["to"]]["symbol"]):
                    continue
                next_beam.append((ids + [edge["to"]], used_edges + [edge]))
        next_beam.sort(key=lambda item: (
            -_sequence(item[0], item[1], symbols)["priority_score"],
            -len(set(_edge_key(row) for row in item[1])), tuple(item[0])))
        # Beam diversity: do not let one first action consume every slot.
        selected, roots = [], set()
        for item in next_beam:
            root = item[0][0]
            if root not in roots:
                selected.append(item)
                roots.add(root)
            if len(selected) >= beam_width:
                break
        if len(selected) < beam_width:
            for item in next_beam:
                if item not in selected:
                    selected.append(item)
                if len(selected) >= beam_width:
                    break
        beam = selected
    # Coverage feedback rewards unique dependency edges across the campaign.
    candidates = []
    covered = set()
    for ids, edge_rows in sorted(paths, key=lambda item: (-len(set(_edge_key(e) for e in item[1])),
                                                          -len(item[0]), tuple(item[0]))):
        base = _sequence(ids, edge_rows, symbols)
        for row in _mutations(base, symbols, edge_rows):
            row["coverage_feedback"]["new_edges_in_campaign"] = sum(
                _edge_key(edge) not in covered for edge in edge_rows)
            candidates.append(row)
        covered.update(_edge_key(edge) for edge in edge_rows)
        if len(candidates) >= budget * 3:
            break
    candidates.sort(key=lambda row: (-row["coverage_feedback"].get("new_edges_in_campaign", 0),
                                     -row["priority_score"], row["mutation"],
                                     tuple(x["symbol_id"] for x in row["actions"])))
    output, seen = [], set()
    for row in candidates:
        key = (tuple(item["symbol_id"] for item in row["actions"]), row["mutation"])
        if key in seen:
            continue
        seen.add(key)
        output.append(row)
        if len(output) >= budget:
            break
    return {"schema": 1, "method": "bounded_dependency_aware_beam",
            "beam_width": beam_width, "max_length": max_length,
            "paths_explored": len(paths), "candidate_count": len(output),
            "sequences": output,
            "notice": "Coverage scores are lexical feedback only. Validate each call edge and state transition before writing a native test."}


def minimize_sequence(sequence, reproduces, max_replays=100):
    """Delta-debug an already reproduced sequence using a caller-supplied local replay predicate.

    This function does not execute a target itself. `reproduces(candidate)` must invoke a safe,
    pinned local test and return whether the same invariant failure still occurs.
    """
    if not isinstance(sequence, list) or not sequence:
        raise ValueError("sequence must be a nonempty list")
    if not callable(reproduces):
        raise ValueError("reproduces must be a local replay predicate")
    if type(max_replays) is not int or not 1 <= max_replays <= 10000:
        raise ValueError("max_replays must be between 1 and 10000")
    current = list(sequence)
    calls = 0
    if calls < max_replays:
        calls += 1
        if not reproduces(current):
            return {"sequence": current, "replays": calls, "minimality": "input-does-not-reproduce"}
    granularity = 2
    while len(current) >= 2 and calls < max_replays:
        chunk_size = (len(current) + granularity - 1) // granularity
        reduced = False
        for start in range(0, len(current), chunk_size):
            candidate = current[:start] + current[start + chunk_size:]
            if not candidate:
                continue
            calls += 1
            if reproduces(candidate):
                current = candidate
                granularity = max(2, granularity - 1)
                reduced = True
                break
            if calls >= max_replays:
                break
        if not reduced:
            if granularity >= len(current):
                break
            granularity = min(len(current), granularity * 2)
    return {"sequence": current, "replays": calls,
            "minimality": "1-minimal" if calls < max_replays else "budget-limited"}
