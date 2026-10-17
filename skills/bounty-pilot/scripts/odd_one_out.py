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
# An authorization hook the base contract leaves to its heir: an empty override (UUPS
# `_authorizeUpgrade(address) internal override {}`) lets anyone through.
AUTH_HOOK = re.compile(r"^_?authori[sz]e", re.I)
MAX_HOOK_ENTRIES = 5
PARAMETERIZED = re.compile(r"^([A-Za-z_$][\w$]*)\(")
INITIALIZER_MODIFIERS = ("initializer", "reinitializer", "onlyInitializing")
INITIALIZER_NAME = re.compile(r"^_*(?:initiali[sz]e|init)(?:[A-Z0-9_]|$)")
NOTICE = ("Heuristic over the compiler AST: each row is a lead to read, not a finding. "
          "Intentional asymmetries exist (an emergency exit without a pause check, a transfer "
          "that leaves totalSupply alone), guards are syntactic (require/assert/if-revert "
          "conditions, applied modifiers with their arguments, and internal calls, virtual "
          "calls resolved in each deployable contract) and writes include internal call chains. "
          "Functions are compared only within one contract's deployed surface, inherited "
          "functions included; a lead on an inherited vendored function says so in "
          "function_inherited_from. Confirm reachability, the deployed revision and real loss "
          "before any severity.")


def _short(sym):
    return str(sym.get("name", "")).split(".")[-1]


def _contract(sym):
    name = str(sym.get("name", ""))
    return sym.get("contract") or (name.rsplit(".", 1)[0] if "." in name else "")


def _ref(sym):
    ref = {"id": sym.get("id"), "name": sym.get("name"), "path": sym.get("path")}
    if sym.get("inherits"):
        ref["inherited_from"] = sym.get("inherited_from")
        ref["declaration_path"] = sym.get("declaration_path")
    return ref


def _surface(sym):
    """The deployed contract a symbol belongs to: its own contract, at its own path."""
    return (str(sym.get("path", "")), _contract(sym))


def _modifier_tokens(symbols):
    """Every guard token that names a modifier: `onlyOwner`, and `onlyRole(MINTER_ROLE)`."""
    names = {str(m) for s in symbols for m in s.get("modifiers_unverified") or []}
    for s in symbols:
        names.update((s.get("modifier_guards") or {}).keys())
    return names


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
    """Implemented entry points that can change state, one contract surface at a time.

    A declaration in an abstract contract is represented by its heir symbols when it has any;
    a symbol impact-plan kept only as a dependency of the scope is not compared."""
    represented = {s.get("inherits") for s in symbols if s.get("inherits")}
    surfaces = {"%s:%s" % _surface(s) for s in symbols
                if s.get("contract_deployable") and s.get("scope_role") != "dependency"}
    return [s for s in symbols if s.get("entry") and s.get("implemented", True)
            and s.get("state_mutability") not in ("view", "pure")
            and not (s.get("contract_deployable") is False and (
                s.get("id") in represented or surfaces & set(s.get("deployed_by") or ())))
            and s.get("scope_role") != "dependency"]


def guard_asymmetry(symbols, writes):
    entries = _candidates(symbols)
    writers, setup = defaultdict(list), defaultdict(list)
    for sym in entries:
        for var in writes.get(sym.get("id"), ()):
            (writers if role(sym) == "entry" else setup)[(_surface(sym), var)].append(sym)
    modifier_names = _modifier_tokens(symbols)
    grouped = {}
    for where in sorted(writers):
        var = where[1]
        group = writers[where]
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
                    # `onlyOwner` against an inline `_checkOwner()`: a writer that holds every
                    # check the modifier itself performs does the same check under another
                    # name. Only the modifier's own checks count - not whatever else its
                    # carriers share (`nonReentrant` beside `updateReward`) - and a modifier
                    # that checks nothing (`updateReward`) is never implied.
                    carriers = [o for o in others if token in (o.get("guards") or [])]
                    owns = [set((o.get("modifier_guards") or {}).get(token, ()))
                            for o in carriers if "modifier_guards" in o]
                    core = (set.intersection(*owns) - modifier_names - {var}) if owns and \
                        len(owns) == len(carriers) else set()
                    if core and core <= mine:
                        continue
                    implied |= core
                missing.append((token, carried, len(others)))
            basis = {}
            # `onlyRole(PAUSER_ROLE)` where the other writers applying onlyRole use
            # `onlyRole(MINTER_ROLE)`: compared among the writers that apply the same modifier,
            # so unguarded writers of the same variable do not outvote the role.
            for token in sorted({t for o in others for t in o.get("guards") or []
                                 if PARAMETERIZED.match(t)} - mine):
                bare = PARAMETERIZED.match(token).group(1)
                if bare not in mine or any(t == token for t, _, _ in missing):
                    continue
                peers = [o for o in others if bare in (o.get("guards") or [])]
                carried = sum(1 for o in peers if token in (o.get("guards") or []))
                if carried >= GUARD_MIN_CARRIERS and carried * 2 > len(peers):
                    missing.append((token, carried, len(peers)))
                    basis[token] = bare
                    implied |= set(((peers[0].get("modifier_guards") or {}).get(token) or ())) \
                        - set(mine)
            for token, _, _ in missing:
                match = PARAMETERIZED.match(token)
                if match:
                    implied.add(match.group(1))  # `updateReward` is named by updateReward(x)
            if not missing:
                continue
            key = (sym.get("id"), tuple(sorted(t for t, _, _ in missing)))
            entry = grouped.setdefault(key, {"sym": sym, "missing": {}, "variables": {},
                                             "implied": set(), "basis": {}})
            entry["implied"] |= implied
            entry["basis"].update(basis)
            for token, carried, total in missing:
                best = entry["missing"].get(token)
                if not best or carried * best[1] > best[0] * total:
                    entry["missing"][token] = (carried, total)
            entry["variables"][var] = {
                "writers": len(group),
                "carriers": sorted({o.get("name") for o in others
                                    if any(t in (o.get("guards") or []) for t, _, _ in missing)}),
                "setup_writers": sorted({s.get("name") for s in setup.get(where, [])})}
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
            "contract": _contract(sym),
            "function_inherited_from": sym.get("inherited_from") if sym.get("inherits") else None,
            "variables": variables, "missing_guards": list(tokens),
            "missing_guards_primary": primary,
            "support": {"carried_by": carried, "of_other_writers": total},
            "evidence": {v: entry["variables"][v] for v in variables},
            "setup_writers_not_compared": setup,
            "compared_among_modifier_peers": dict(sorted(entry["basis"].items())),
            "question": "%s writes %s without %s, which %d of the %d other entry points writing "
                        "it carry%s. Is the missing check intended, and who can reach %s?"
                        % (sym.get("name"), _listed(variables, limit=3),
                           ", ".join(primary), carried, total, _peer_note(sym, entry["basis"]),
                           _short(sym)),
            "_strength": strength, "_vendored": _inherited_vendored(sym)})
    return leads


def _peer_note(sym, basis):
    """` (counted among the writers that apply onlyRole; burn applies onlyRole(BURNER_ROLE))`"""
    if not basis:
        return ""
    bares = sorted(set(basis.values()))
    applied = sorted(t for t in sym.get("guards") or []
                     if PARAMETERIZED.match(t) and PARAMETERIZED.match(t).group(1) in bares)
    return " (counted among the writers that apply %s; %s applies %s)" % (
        ", ".join(bares), _short(sym), ", ".join(applied))


def _inherited_vendored(sym):
    """An inherited function whose code is vendored: its leads are listed after the others."""
    return bool(sym.get("inherits") and sym.get("vendored_declaration"))


def unguarded_hooks(symbols):
    """An authorization hook (`_authorizeUpgrade`) that a deployed entry point runs and that
    checks nothing: no condition, no modifier, no guarded helper."""
    by_id = {s.get("id"): s for s in symbols}
    users = defaultdict(list)
    for sym in symbols:
        if (sym.get("entry") and (sym.get("contract_deployable") or sym.get("inherits"))
                and sym.get("scope_role") != "dependency"):
            for reached in sym.get("resolution") or []:
                users[reached].append(sym)
    leads = []
    for hook_id in sorted(users, key=str):
        hook = by_id.get(hook_id)
        if (not hook or not AUTH_HOOK.match(_short(hook)) or not hook.get("implemented", True)
                or hook.get("guards") or "guards" not in hook):
            continue
        by_surface = defaultdict(list)
        for sym in users[hook_id]:
            by_surface[_surface(sym)].append(sym)
        for (path, contract), entries in sorted(by_surface.items()):
            entries = sorted(entries, key=lambda e: str(e.get("name")))
            names = [_short(e) for e in entries[:MAX_HOOK_ENTRIES]]
            leads.append({
                "id": _lead_id("unguarded-hook", hook.get("name"), contract, path),
                "kind": "unguarded-hook", "functions": [_ref(hook)] + [
                    _ref(e) for e in entries[:MAX_HOOK_ENTRIES]],
                "path": path, "contract": contract, "hook": hook.get("name"),
                "entry_points": [e.get("name") for e in entries],
                "entry_guards": {e.get("name"): sorted(e.get("guards") or [])
                                 for e in entries[:MAX_HOOK_ENTRIES]},
                "question": "%s checks nothing - no condition, modifier or guarded call - and %s "
                            "runs it from %s. Who can call %s, and is that intended?"
                            % (hook.get("name"), contract, ", ".join(names), names[0]),
                "_strength": 2.0, "_vendored": False})
    return leads


def paired_write_omission(symbols, writes):
    entries = [s for s in _candidates(symbols) if role(s) == "entry"]
    by_id = {s.get("id"): s for s in entries}
    writers = defaultdict(set)
    for sym in entries:
        for var in writes.get(sym.get("id"), ()):
            writers[(_surface(sym), var)].add(sym.get("id"))
    leads = []
    for key in sorted(writers):
        surface, var = key
        group = writers[key]
        if len(group) < PAIR_MIN_COWRITERS + 1:
            continue
        together = Counter(other for sid in group for other in writes.get(sid, ()) if other != var)
        partners = [b for b, n in together.items()
                    if n >= PAIR_MIN_COWRITERS and n / float(len(group)) >= PAIR_MIN_RATIO
                    and n < len(group)]
        skipped = defaultdict(list)
        for partner in partners:
            for sid in group - writers[(surface, partner)]:
                skipped[sid].append(partner)
        for sid, missed in skipped.items():
            sym = by_id[sid]
            missed = sorted(missed)
            evidence = {b: sorted(by_id[o].get("name") for o in group & writers[(surface, b)])
                        for b in missed}
            ratio = max(len(evidence[b]) / float(len(group)) for b in missed)
            first = missed[0]
            leads.append({
                "id": _lead_id("paired-write-omission", sym.get("name"), sym.get("path"), var,
                               *missed),
                "kind": "paired-write-omission", "functions": [_ref(sym)],
                "path": sym.get("path"), "contract": _contract(sym),
                "function_inherited_from": (sym.get("inherited_from") if sym.get("inherits")
                                            else None),
                "variable": var, "skipped_partners": missed,
                "support": {"writers_of_variable": len(group),
                            "also_write_partner": {b: len(evidence[b]) for b in missed}},
                "evidence": evidence,
                "question": "%s writes %s but not %s, which %d of the %d entry points writing "
                            "%s (%s) also write. Does %s drift out of step on this path?"
                            % (sym.get("name"), var, ", ".join(missed), len(evidence[first]),
                               len(group), var, ", ".join(evidence[first][:4]), first),
                "_strength": ratio, "_vendored": _inherited_vendored(sym)})
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
    modifier_names = _modifier_tokens(symbols)
    # A graph with heir symbols carries every inherited function in its heir's surface; an
    # older graph only names the heirs in inherited_by.
    surfaces = any("contract_deployable" in s for s in symbols)
    by_contract = defaultdict(lambda: defaultdict(list))
    for sym in _candidates(symbols):
        if role(sym) != "entry":
            continue
        if surfaces:
            keys = {_surface(sym)}
        else:
            keys = {(None, c) for c in {_contract(sym)} | set(sym.get("inherited_by") or [])}
        for key in keys:
            by_contract[key][_short(sym)].append(sym)
    leads, seen = [], set()
    for key in sorted(by_contract, key=lambda k: (str(k[0]), str(k[1]))):
        contract = key[1]
        functions = by_contract[key]
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
                                               + len(diff["guards_only_in_second"])) + 0.5,
                            "_vendored": _inherited_vendored(one) and _inherited_vendored(two)})
    return leads


def analyze(graph):
    if not isinstance(graph, dict) or not isinstance(graph.get("symbols"), list):
        raise ValueError("expected a semantic graph with a symbols list")
    symbols = [s for s in graph["symbols"] if isinstance(s, dict)]
    writes = _effective_writes(symbols)
    found = {"guard-asymmetry": guard_asymmetry(symbols, writes),
             "paired-write-omission": paired_write_omission(symbols, writes),
             "sibling-asymmetry": sibling_asymmetry(symbols, writes),
             "unguarded-hook": unguarded_hooks(symbols)}
    leads, truncated = [], {}
    for kind, rows in found.items():
        # Leads on inherited vendored code last: they are real surface, but rarely the bug.
        rows.sort(key=lambda r: (r["_vendored"], -r["_strength"], str(r["path"]), r["id"]))
        truncated[kind] = len(rows) > MAX_LEADS_PER_KIND
        for row in rows[:MAX_LEADS_PER_KIND]:
            row.pop("_strength", None)
            row.pop("_vendored", None)
            leads.append(row)
    result = {"schema": 1, "method": "odd-one-out-heuristic",
              "counts": {kind: min(len(rows), MAX_LEADS_PER_KIND) for kind, rows in found.items()},
              "found": {kind: len(rows) for kind, rows in found.items()},
              "truncated": truncated,
              "thresholds": {"guard_min_carriers": GUARD_MIN_CARRIERS,
                             "guard_carriers": "strict majority of the other writers",
                             "pair_min_cowriters": PAIR_MIN_COWRITERS,
                             "pair_min_ratio": round(PAIR_MIN_RATIO, 4),
                             "sibling_verbs": [list(p) for p in SIBLING_VERBS],
                             "authorization_hook": AUTH_HOOK.pattern},
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
