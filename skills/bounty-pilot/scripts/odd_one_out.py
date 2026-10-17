#!/usr/bin/env python3
"""Odd-one-out leads over a semantic graph: the check, or the paired write, that comparable
entry points carry and one of them does not.

Reads the semantic-graph.json written by semantic_graph.py (compiler AST). Every row is a lead
to read, never a finding: intentional asymmetries exist - an emergency exit without
whenNotPaused, a transfer that leaves totalSupply alone - and the graph is syntactic.
"""
import argparse
import hashlib
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

# guard-asymmetry: a writer of a state variable is flagged for a guard token when at least
# GUARD_MIN_CARRIERS of the *other* writers carry it and they are a strict majority of those
# others. Two is the smallest "the others agree"; the majority keeps a split vote out.
GUARD_MIN_CARRIERS = 2
# paired-write-omission: B is A's partner when at least PAIR_MIN_COWRITERS entry points write
# both and they are at least PAIR_MIN_RATIO of A's writers. Two thirds, not three quarters,
# because the smallest real case has three writers: borrow and repay move debt and totalDebt,
# liquidate moves only debt.
PAIR_MIN_COWRITERS = 2
PAIR_MIN_RATIO = 2.0 / 3.0
MAX_LEADS_PER_KIND = 400
# Name-paired operations that should mirror each other's checks and accounting.
SIBLING_VERBS = (
    ("deposit", "withdraw"), ("deposit", "redeem"), ("mint", "burn"), ("mint", "redeem"),
    ("stake", "unstake"), ("lock", "unlock"), ("add", "remove"), ("open", "close"),
    ("borrow", "repay"), ("supply", "withdraw"), ("lend", "withdraw"), ("enter", "exit"),
    ("join", "exit"), ("join", "leave"), ("create", "cancel"), ("request", "claim"),
    ("increase", "decrease"), ("wrap", "unwrap"), ("bond", "unbond"),
    ("delegate", "undelegate"), ("register", "unregister"), ("list", "delist"),
    ("queue", "execute"), ("propose", "execute"), ("grant", "revoke"), ("buy", "sell"),
    ("freeze", "unfreeze"), ("enable", "disable"), ("activate", "deactivate"),
    ("subscribe", "unsubscribe"), ("allocate", "deallocate"), ("pause", "unpause"),
)
INITIALIZER_MODIFIERS = ("initializer", "reinitializer", "onlyInitializing")
INITIALIZER_NAME = re.compile(r"^_*(?:initiali[sz]e|init)(?:[A-Z0-9_]|$)")
NOTICE = ("Heuristic over the compiler AST: each row is a lead to read, not a finding. "
          "Intentional asymmetries exist (an emergency exit without a pause check, a transfer "
          "that leaves totalSupply alone), guards are syntactic (require/assert/if-revert "
          "conditions, applied modifiers and internal calls, every override of a virtual call "
          "followed) and writes include internal call chains. Confirm reachability, the "
          "deployed revision and real loss before any severity.")


def _short(sym):
    return str(sym.get("name", "")).split(".")[-1]


def _contract(sym):
    name = str(sym.get("name", ""))
    return sym.get("contract") or (name.rsplit(".", 1)[0] if "." in name else "")


def _ref(sym):
    return {"id": sym.get("id"), "name": sym.get("name"), "path": sym.get("path")}


def _lead_id(kind, *parts):
    digest = hashlib.sha256("|".join([kind] + [str(p) for p in parts]).encode("utf-8"))
    return "ooo-" + digest.hexdigest()[:12]


def role(sym):
    """`constructor`, `initializer` or `entry`: set-up code writes everything once and carries
    no caller check, so comparing it with the rest would flag it every time."""
    if sym.get("function_kind") == "constructor":
        return "constructor"
    modifiers = [str(m) for m in sym.get("modifiers_unverified") or []]
    if any(m in INITIALIZER_MODIFIERS for m in modifiers) or INITIALIZER_NAME.match(_short(sym)):
        return "initializer"
    return "entry"


def _effective_writes(symbols):
    """State written by each symbol through its modifiers and internal call chains, without
    what only a modifier writes (a reentrancy lock is a guard, not accounting)."""
    by_id = {s.get("id"): s for s in symbols}
    closed = {}
    for sym in symbols:
        if "writes_transitive" in sym:
            writes = set(sym.get("writes_transitive") or [])
        else:  # a graph written before writes_transitive existed: follow call edges here
            writes, seen = set(), set()
            todo = [sym.get("id")]
            while todo:
                current = by_id.get(todo.pop())
                if not current or current.get("id") in seen:
                    continue
                seen.add(current.get("id"))
                writes |= set(current.get("writes") or [])
                todo.extend(current.get("internal_calls", current.get("calls")) or [])
        closed[sym.get("id")] = writes - set(sym.get("writes_via_modifiers") or [])
    return closed


def _candidates(symbols):
    """Implemented entry points that can change state."""
    return [s for s in symbols if s.get("entry") and s.get("implemented", True)
            and s.get("state_mutability") not in ("view", "pure")]


def guard_asymmetry(symbols, writes):
    entries = _candidates(symbols)
    writers, setup = defaultdict(list), defaultdict(list)
    for sym in entries:
        for var in writes.get(sym.get("id"), ()):
            (writers if role(sym) == "entry" else setup)[var].append(sym)
    modifier_names = {str(m) for s in symbols for m in s.get("modifiers_unverified") or []}
    grouped = {}
    for var in sorted(writers):
        group = writers[var]
        if len(group) < GUARD_MIN_CARRIERS + 1:
            continue
        for sym in group:
            mine = set(sym.get("guards") or [])
            others = [o for o in group if o is not sym]
            counts = Counter(t for o in others for t in set(o.get("guards") or []) if t != var)
            missing, implied = [], set()
            for token, carried in counts.items():
                if token in mine or carried < GUARD_MIN_CARRIERS or carried * 2 <= len(others):
                    continue
                if token in modifier_names:
                    # `onlyOwner` against an inline `_checkOwner()`: the modifier's carriers all
                    # share its inner tokens; a writer holding every one of them performs the
                    # same check under another name.
                    carriers = [set(o.get("guards") or []) for o in others
                                if token in (o.get("guards") or [])]
                    core = set.intersection(*carriers) - modifier_names - {var}
                    if core and core <= mine:
                        continue
                    implied |= core
                missing.append((token, carried, len(others)))
            if not missing:
                continue
            key = (sym.get("id"), tuple(sorted(t for t, _, _ in missing)))
            entry = grouped.setdefault(key, {"sym": sym, "missing": {}, "variables": {},
                                             "implied": set()})
            entry["implied"] |= implied
            for token, carried, total in missing:
                best = entry["missing"].get(token)
                if not best or carried * best[1] > best[0] * total:
                    entry["missing"][token] = (carried, total)
            entry["variables"][var] = {
                "writers": len(group),
                "carriers": sorted({o.get("name") for o in others
                                    if any(t in (o.get("guards") or []) for t, _, _ in missing)}),
                "setup_writers": sorted({s.get("name") for s in setup.get(var, [])})}
    leads = []
    for (sym_id, tokens), entry in grouped.items():
        sym = entry["sym"]
        variables = sorted(entry["variables"])
        strength = max(c / float(t) for c, t in entry["missing"].values())
        carried, total = max(entry["missing"].values(), key=lambda ct: (ct[0] / float(ct[1]), ct[0]))
        setup = sorted({n for v in entry["variables"].values() for n in v["setup_writers"]})
        # A token a missing modifier already carries (`_paused` under `whenNotPaused`) is named
        # in missing_guards but not in the question.
        primary = [t for t in tokens if t not in entry["implied"]] or list(tokens)
        leads.append({
            "id": _lead_id("guard-asymmetry", sym.get("name"), sym.get("path"), *tokens),
            "kind": "guard-asymmetry", "functions": [_ref(sym)], "path": sym.get("path"),
            "variables": variables, "missing_guards": list(tokens),
            "missing_guards_primary": primary,
            "support": {"carried_by": carried, "of_other_writers": total},
            "evidence": {v: entry["variables"][v] for v in variables},
            "setup_writers_not_compared": setup,
            "question": "%s writes %s without %s, which %d of the %d other entry points writing "
                        "it carry. Is the missing check intended, and who can reach %s?"
                        % (sym.get("name"), _listed(variables, limit=3),
                           ", ".join(primary), carried, total, _short(sym)),
            "_strength": strength})
    return leads


def paired_write_omission(symbols, writes):
    entries = [s for s in _candidates(symbols) if role(s) == "entry"]
    by_id = {s.get("id"): s for s in entries}
    writers = defaultdict(set)
    for sym in entries:
        for var in writes.get(sym.get("id"), ()):
            writers[var].add(sym.get("id"))
    leads = []
    for var in sorted(writers):
        group = writers[var]
        if len(group) < PAIR_MIN_COWRITERS + 1:
            continue
        together = Counter(other for sid in group for other in writes.get(sid, ()) if other != var)
        partners = [b for b, n in together.items()
                    if n >= PAIR_MIN_COWRITERS and n / float(len(group)) >= PAIR_MIN_RATIO
                    and n < len(group)]
        skipped = defaultdict(list)
        for partner in partners:
            for sid in group - writers[partner]:
                skipped[sid].append(partner)
        for sid, missed in skipped.items():
            sym = by_id[sid]
            missed = sorted(missed)
            evidence = {b: sorted(by_id[o].get("name") for o in group & writers[b])
                        for b in missed}
            ratio = max(len(evidence[b]) / float(len(group)) for b in missed)
            first = missed[0]
            leads.append({
                "id": _lead_id("paired-write-omission", sym.get("name"), sym.get("path"), var,
                               *missed),
                "kind": "paired-write-omission", "functions": [_ref(sym)],
                "path": sym.get("path"), "variable": var, "skipped_partners": missed,
                "support": {"writers_of_variable": len(group),
                            "also_write_partner": {b: len(evidence[b]) for b in missed}},
                "evidence": evidence,
                "question": "%s writes %s but not %s, which %d of the %d entry points writing "
                            "%s (%s) also write. Does %s drift out of step on this path?"
                            % (sym.get("name"), var, ", ".join(missed), len(evidence[first]),
                               len(group), var, ", ".join(evidence[first][:4]), first),
                "_strength": ratio})
    return leads


def _verb_split(name, verb):
    if not name.startswith(verb):
        return None
    rest = name[len(verb):]
    if rest and not (rest[0].isupper() or rest[0] in "_0123456789"):
        return None
    return rest


def _listed(tokens, first=(), limit=4):
    """Modifier names before what they imply, cut to `limit` with a count of the rest."""
    ordered = sorted(tokens, key=lambda t: (t not in first, t))
    return ", ".join(ordered[:limit]) + (" (+%d)" % (len(ordered) - limit)
                                         if len(ordered) > limit else "")


def sibling_asymmetry(symbols, writes):
    modifier_names = {str(m) for s in symbols for m in s.get("modifiers_unverified") or []}
    by_contract = defaultdict(lambda: defaultdict(list))
    for sym in _candidates(symbols):
        if role(sym) != "entry":
            continue
        for contract in {_contract(sym)} | set(sym.get("inherited_by") or []):
            by_contract[contract][_short(sym)].append(sym)
    leads, seen = [], set()
    for contract in sorted(by_contract):
        functions = by_contract[contract]
        for first_verb, second_verb in SIBLING_VERBS:
            for name in sorted(functions):
                suffix = _verb_split(name, first_verb)
                if suffix is None or (second_verb + suffix) not in functions:
                    continue
                for one in functions[name]:
                    for two in functions[second_verb + suffix]:
                        pair = (one.get("id"), two.get("id"))
                        if pair in seen or one.get("id") == two.get("id"):
                            continue
                        seen.add(pair)
                        g1, g2 = set(one.get("guards") or []), set(two.get("guards") or [])
                        w1, w2 = writes.get(one.get("id"), set()), writes.get(two.get("id"), set())
                        diff = {"guards_only_in_first": sorted(g1 - g2),
                                "guards_only_in_second": sorted(g2 - g1),
                                "writes_only_in_first": sorted(w1 - w2),
                                "writes_only_in_second": sorted(w2 - w1)}
                        if not any(diff.values()):
                            continue
                        parts = []
                        for label, a, b in (("checks", one, diff["guards_only_in_first"]),
                                            ("checks", two, diff["guards_only_in_second"]),
                                            ("writes", one, diff["writes_only_in_first"]),
                                            ("writes", two, diff["writes_only_in_second"])):
                            if b:
                                other = two if a is one else one
                                parts.append("%s %s %s that %s does not"
                                             % (_short(a), label, _listed(b, modifier_names),
                                                _short(other)))
                        leads.append({
                            "id": _lead_id("sibling-asymmetry", contract, one.get("name"),
                                           two.get("name"), json.dumps(diff, sort_keys=True)),
                            "kind": "sibling-asymmetry", "contract": contract,
                            "functions": [_ref(one), _ref(two)], "path": one.get("path"),
                            "pair": [first_verb, second_verb], "difference": diff,
                            "question": "In %s, %s. Is each difference intended?"
                                        % (contract, "; ".join(parts)),
                            "_strength": float(len(diff["guards_only_in_first"])
                                               + len(diff["guards_only_in_second"])) + 0.5})
    return leads


def analyze(graph):
    if not isinstance(graph, dict) or not isinstance(graph.get("symbols"), list):
        raise ValueError("expected a semantic graph with a symbols list")
    symbols = [s for s in graph["symbols"] if isinstance(s, dict)]
    writes = _effective_writes(symbols)
    found = {"guard-asymmetry": guard_asymmetry(symbols, writes),
             "paired-write-omission": paired_write_omission(symbols, writes),
             "sibling-asymmetry": sibling_asymmetry(symbols, writes)}
    leads, truncated = [], {}
    for kind, rows in found.items():
        rows.sort(key=lambda r: (-r["_strength"], str(r["path"]), r["id"]))
        truncated[kind] = len(rows) > MAX_LEADS_PER_KIND
        for row in rows[:MAX_LEADS_PER_KIND]:
            row.pop("_strength", None)
            leads.append(row)
    result = {"schema": 1, "method": "odd-one-out-heuristic",
              "counts": {kind: min(len(rows), MAX_LEADS_PER_KIND) for kind, rows in found.items()},
              "found": {kind: len(rows) for kind, rows in found.items()},
              "truncated": truncated,
              "thresholds": {"guard_min_carriers": GUARD_MIN_CARRIERS,
                             "guard_carriers": "strict majority of the other writers",
                             "pair_min_cowriters": PAIR_MIN_COWRITERS,
                             "pair_min_ratio": round(PAIR_MIN_RATIO, 4),
                             "sibling_verbs": [list(p) for p in SIBLING_VERBS]},
              "leads": leads, "review_state": "unreviewed-leads", "notice": NOTICE}
    solidity = [s for s in symbols if s.get("language") == "solidity"]
    if solidity and not any("guards" in s for s in solidity):
        result["warning"] = ("This graph carries no guards field: it predates guard extraction, "
                             "so guard-asymmetry and sibling guard differences are empty. "
                             "Re-run impact-plan to rebuild semantic-graph.json.")
    return result


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--graph", required=True, help="semantic-graph.json from impact-plan")
    p.add_argument("--out")
    a = p.parse_args(argv)
    try:
        report = analyze(json.loads(Path(a.graph).read_text(encoding="utf-8")))
    except (ValueError, KeyError, OSError, json.JSONDecodeError) as exc:
        p.error(str(exc))
    payload = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if a.out:
        Path(a.out).write_text(payload, encoding="utf-8")
        print(json.dumps({"out": a.out, "leads": len(report["leads"]),
                          "counts": report["counts"]}))
    else:
        print(payload, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
