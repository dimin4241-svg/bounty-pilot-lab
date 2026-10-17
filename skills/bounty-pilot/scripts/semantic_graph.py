#!/usr/bin/env python3
"""Compiler-aware source graph for Solidity AST and Python AST (stdlib only).

Solidity: explicitly supplied solc standard-json output / Foundry build-info JSON.
Python: ast.parse of git-tracked .py source. This does not execute target code.
Edges are syntactic call references and possible state dependencies, NOT verified
runtime exploit paths. Rust and other stacks remain on the heuristic adapter path.
"""
import argparse
import ast
import json
import re
import subprocess
from collections import defaultdict
from pathlib import Path

SINK_TERMS = {
    "asset-movement": ("transfer", "transferfrom", "safetransfer", "withdraw",
                       "redeem", "release", "burn", "mint", "sweep"),
    "debt-solvency": ("borrow", "liquidat", "repay", "baddebt", "collateral"),
    "privileged-power": ("upgrade", "grantrole", "setowner", "ownership",
                         "authoriz", "admin", "delegate"),
    "settlement": ("claim", "settle", "finaliz", "acknowledge", "processmessage"),
    "price-oracle": ("price", "oracle", "twap", "exchange_rate"),
}
# Families read from the compiler AST rather than from names. `arbitrary-call` is a low-level
# call, an OpenZeppelin Address.functionCall* or a delegatecall whose target is neither a
# literal, a constant, an immutable nor `this` (nor the caller itself) and whose calldata is not
# an empty literal: the router/adapter shape that, with users' standing approvals, is the most
# repeated production exploit class in references/hack-patterns.md.
AST_SINK_FAMILIES = ("arbitrary-call", "delegatecall", "low-level-call", "self-destruct",
                     "permit", "token-pull")
# Whole camelCase/underscore words of a function's own name or a called name.
SINK_WORDS = {"permit": "permit", "selfdestruct": "self-destruct"}
LOW_LEVEL_MEMBERS = {"call": "low-level-call", "delegatecall": "delegatecall",
                     "callcode": "delegatecall"}
ADDRESS_LIB_MEMBERS = {"functionCall": "address-functioncall",
                       "functionCallWithValue": "address-functioncall",
                       "functionDelegateCall": "address-functiondelegatecall"}
TOKEN_PULL_MEMBERS = ("transferFrom", "safeTransferFrom")
YUL_SINKS = {"call": "assembly-call", "callcode": "assembly-delegatecall",
             "delegatecall": "assembly-delegatecall", "selfdestruct": "selfdestruct"}
# Where a call target or an argument comes from. Only these four are fixed at deployment.
FIXED_SOURCES = ("literal", "constant", "immutable", "this")
CALLER_SOURCES = ("msg.sender", "tx.origin")
# Magic-variable members a guard condition can compare against.
ENV_TOKENS = {("msg", "sender"): "msg.sender", ("tx", "origin"): "tx.origin",
              ("block", "timestamp"): "block.timestamp", ("block", "number"): "block.number",
              ("msg", "value"): "msg.value"}
SENDER_ALIASES = ("_msgsender", "msgsender")
# Builtins whose call in a condition says nothing about who or when: hashing, ABI coding.
GUARD_SKIPPED_BASES = ("abi", "bytes", "string")
GUARD_KEPT_BUILTINS = ("ecrecover",)
# `require(token.transferFrom(...))` checks that a transfer succeeded; it says nothing about
# who may call, so the moved-value call is not a guard token.
GUARD_SKIPPED_CALLS = ("transfer", "transferFrom", "safeTransfer", "safeTransferFrom", "send",
                       "approve", "safeApprove", "call", "delegatecall", "staticcall")
MAX_AST_BYTES = 256_000_000
MAX_NODES = 150_000
EDGE_CAP = 7500

def walk_json(node):
    todo = [node]
    count = 0
    while todo:
        x = todo.pop()
        count += 1
        if count > MAX_NODES:
            raise ValueError("compiler AST too large")
        if isinstance(x, dict):
            yield x
            todo.extend(reversed([v for v in x.values() if isinstance(v, (dict, list))]))
        elif isinstance(x, list):
            todo.extend(reversed(x))

BUILD_INFO_HINT = (
    "Foundry build-info without AST: a plain `forge build` writes a minimal build-info "
    "(id/source_id_to_path/language, no AST). Run `forge build --build-info` and point this "
    "at the resulting out/build-info/*.json, or pass solc standard-json compiled with "
    "outputSelection including sources.*.ast.")


def load_solc(path, max_ast_bytes=MAX_AST_BYTES):
    p = Path(path)
    if p.stat().st_size > max_ast_bytes:
        raise ValueError("compiler JSON exceeds size cap (%d bytes); raise --max-ast-mb" % max_ast_bytes)
    raw = json.loads(p.read_text(encoding="utf-8"))
    data = raw
    if "output" in data and isinstance(data["output"], dict):
        data = data["output"]
    sources = data.get("sources", {})
    if not isinstance(sources, dict):
        raise ValueError("Solidity compiler JSON missing sources")
    # A minimal `forge build` build-info has source_id_to_path but no compiled output.
    if not sources and (isinstance(raw.get("source_id_to_path"), dict)
                        or ("language" in raw and "output" not in raw)):
        raise ValueError(BUILD_INFO_HINT)
    trees = []
    saw_source_entry = False
    for filename, desc in sorted(sources.items()):
        if not isinstance(desc, dict):
            continue
        saw_source_entry = True
        tree = desc.get("ast")
        if isinstance(tree, dict) and tree.get("nodeType") == "SourceUnit":
            trees.append((filename, tree))
    if not trees:
        if saw_source_entry:
            # sources present but none carry an AST → the AST output was not requested.
            raise ValueError(BUILD_INFO_HINT)
        raise ValueError("no Solidity SourceUnit AST; " + BUILD_INFO_HINT)
    return trees

ETH_MOVE_MEMBERS = ("send", "transfer")


def _builtin(ident):
    """A magic name (msg, require, selfdestruct, ...): solc gives builtins negative ids."""
    rid = ident.get("referencedDeclaration")
    return not isinstance(rid, int) or rid < 0


def _callee(call):
    """The expression a FunctionCall invokes, through `{value: ...}` call options."""
    expression = call.get("expression") or {}
    while expression.get("nodeType") == "FunctionCallOptions":
        expression = expression.get("expression") or {}
    return expression


def _env_token(node):
    """`msg.sender`, `tx.origin`, `block.timestamp`, ... for a magic member access, else None."""
    if node.get("nodeType") != "MemberAccess":
        return None
    base = node.get("expression") or {}
    if base.get("nodeType") != "Identifier" or not _builtin(base):
        return None
    return ENV_TOKENS.get((base.get("name"), node.get("memberName")))


def _value_source(expr, params, state_info, depth=0):
    """Where a call target or argument comes from: literal, constant, immutable, this,
    msg.sender, tx.origin, parameter, state, local or expression. Syntactic only."""
    if not isinstance(expr, dict) or depth > 12:
        return "expression"
    nt = expr.get("nodeType")
    if nt == "Literal":
        return "literal"
    if nt == "TupleExpression":
        parts = [c for c in expr.get("components") or [] if isinstance(c, dict)]
        return _value_source(parts[0], params, state_info, depth + 1) if len(parts) == 1 \
            else "expression"
    if nt == "FunctionCall" and expr.get("kind") == "typeConversion":
        args = [a for a in expr.get("arguments") or [] if isinstance(a, dict)]
        return _value_source(args[0], params, state_info, depth + 1) if args else "expression"
    if nt == "Identifier":
        rid = expr.get("referencedDeclaration")
        if expr.get("name") == "this" and _builtin(expr):
            return "this"
        if rid in state_info:
            return state_info[rid]
        if rid in params:
            return "parameter"
        return "local"
    if nt == "MemberAccess":
        env = _env_token(expr)
        if env:
            return env
        rid = expr.get("referencedDeclaration")
        if rid in state_info:  # `Config.TARGET`, a constant reached through its contract
            return state_info[rid]
        root = _value_source(expr.get("expression"), params, state_info, depth + 1)
        return root if root in ("parameter", "state") else "expression"
    if nt == "IndexAccess":
        root = _value_source(expr.get("baseExpression"), params, state_info, depth + 1)
        return root if root in ("parameter", "state") else "expression"
    return "expression"


def _empty_literal(expr):
    """`""` or `hex""`: calldata that carries no selector, i.e. a plain ETH send."""
    return (isinstance(expr, dict) and expr.get("nodeType") == "Literal"
            and not expr.get("value") and not expr.get("hexValue"))


def _library_style(base, libraries):
    """`Address.functionCall(target, ...)` rather than `target.functionCall(...)`."""
    if base.get("nodeType") != "Identifier":
        return False
    if base.get("referencedDeclaration") in libraries:
        return True
    type_string = str((base.get("typeDescriptions") or {}).get("typeString") or "")
    return type_string.startswith("type(library ")


def _call_sink(call, params, state_info, libraries):
    """One sink detail for a FunctionCall node, or None."""
    expression = _callee(call)
    args = [a for a in call.get("arguments") or [] if isinstance(a, dict)]
    nt = expression.get("nodeType")
    if nt == "Identifier":
        if expression.get("name") in ("selfdestruct", "suicide") and _builtin(expression):
            return {"kind": "selfdestruct", "member": expression.get("name"),
                    "beneficiary_source": (_value_source(args[0], params, state_info)
                                           if args else "expression")}
        return None
    if nt != "MemberAccess":
        return None
    member = expression.get("memberName")
    base = expression.get("expression") or {}
    library = _library_style(base, libraries)
    detail = None
    if member in LOW_LEVEL_MEMBERS and not library:
        detail = {"kind": LOW_LEVEL_MEMBERS[member], "member": member,
                  "target_source": _value_source(base, params, state_info),
                  "empty_data": bool(args) and _empty_literal(args[0])}
    elif member in ADDRESS_LIB_MEMBERS:
        target = args[0] if library and args else (None if library else base)
        data = args[1:2] if library else args[0:1]
        detail = {"kind": ADDRESS_LIB_MEMBERS[member], "member": member,
                  "target_source": _value_source(target, params, state_info),
                  "empty_data": bool(data) and _empty_literal(data[0])}
    elif member in TOKEN_PULL_MEMBERS:
        # IERC20(t).transferFrom(from, ...), t.safeTransferFrom(from, ...) with `using`, and
        # SafeERC20.safeTransferFrom(t, from, ...) called on the library itself.
        position = 1 if library else 0
        detail = {"kind": "token-pull", "member": member,
                  "from_source": (_value_source(args[position], params, state_info)
                                  if len(args) > position else "expression")}
    elif member == "permit":
        position = 1 if library else 0
        detail = {"kind": "permit", "member": member,
                  "owner_source": (_value_source(args[position], params, state_info)
                                   if len(args) > position else "expression")}
    if detail and "target_source" in detail:
        detail["dynamic_target"] = detail["target_source"] not in FIXED_SOURCES
    return detail


def _detail_families(detail):
    kind = detail.get("kind")
    if kind in ("selfdestruct",):
        return {"self-destruct"}
    if kind == "permit":
        return {"permit"}
    if kind == "token-pull":
        return {"token-pull"}
    if kind in ("assembly-call",):
        return {"low-level-call"}
    if kind in ("assembly-delegatecall",):
        return {"delegatecall"}
    families = set()
    delegate = kind in ("delegatecall", "address-functiondelegatecall")
    if delegate:
        families.add("delegatecall")
    chosen = detail.get("dynamic_target") and detail.get("target_source") not in CALLER_SOURCES
    if chosen and (delegate or not detail.get("empty_data")):
        families.add("arbitrary-call")
    elif not delegate:
        families.add("low-level-call")
    return families


def _reverts(statement):
    """True when a branch reverts at its top level: `revert X()`, `revert(...)`, a
    `_revertSomething()` helper, or a block holding one of those."""
    if not isinstance(statement, dict):
        return False
    nt = statement.get("nodeType")
    if nt == "RevertStatement":
        return True
    if nt == "Block":
        return any(_reverts(s) for s in statement.get("statements") or [])
    if nt == "ExpressionStatement":
        call = statement.get("expression") or {}
        if call.get("nodeType") != "FunctionCall":
            return False
        name = str(_callee(call).get("name") or _callee(call).get("memberName") or "")
        return name == "revert" or bool(re.match(r"_?revert", name, re.I))
    return False


def _guard_conditions(body):
    """Condition expressions of require/assert and of an `if` whose branch reverts."""
    conditions = []
    for x in walk_json(body):
        nt = x.get("nodeType")
        if nt == "FunctionCall":
            expression = _callee(x)
            args = [a for a in x.get("arguments") or [] if isinstance(a, dict)]
            if (expression.get("nodeType") == "Identifier" and args and _builtin(expression)
                    and expression.get("name") in ("require", "assert")):
                conditions.append(args[0])
        elif nt == "IfStatement" and isinstance(x.get("condition"), dict):
            if _reverts(x.get("trueBody")) or _reverts(x.get("falseBody")):
                conditions.append(x["condition"])
    return conditions


def _condition_tokens(condition, decls, funcs, local_ptr):
    """Guard tokens of one condition, and the declared functions it calls.

    `msg.sender` used only as a mapping key (`balances[msg.sender] >= x`) is a sufficiency
    check, not an identity check, so it is not a token there.
    """
    tokens, callees = set(), set()
    keyed, receivers = set(), set()
    for x in walk_json(condition):
        if x.get("nodeType") == "IndexAccess" and isinstance(x.get("indexExpression"), dict):
            keyed.update(id(y) for y in walk_json(x["indexExpression"]))
        if x.get("nodeType") == "FunctionCall":
            expression = _callee(x)
            if expression.get("nodeType") == "MemberAccess" and \
                    expression.get("memberName") in GUARD_SKIPPED_CALLS:
                # `asset` in `require(asset.transferFrom(...))` is where value moves, not a
                # check; the arguments still count.
                receivers.update(id(y) for y in walk_json(expression.get("expression") or {}))
    for x in walk_json(condition):
        nt = x.get("nodeType")
        if id(x) in receivers:
            continue
        env = _env_token(x)
        if env and id(x) not in keyed:
            tokens.add(env)
        if nt in ("Identifier", "MemberAccess"):
            rid = x.get("referencedDeclaration")
            if rid in decls:
                tokens.add(decls[rid])
            elif rid in local_ptr:
                tokens.add(local_ptr[rid])
        if nt != "FunctionCall" or x.get("kind", "functionCall") != "functionCall":
            continue
        expression = _callee(x)
        rid = expression.get("referencedDeclaration")
        if expression.get("nodeType") == "Identifier":
            name = expression.get("name")
            if _builtin(expression) and rid not in funcs and name not in GUARD_KEPT_BUILTINS:
                continue
        elif expression.get("nodeType") == "MemberAccess":
            base = expression.get("expression") or {}
            if base.get("nodeType") == "Identifier" and base.get("name") in GUARD_SKIPPED_BASES \
                    and _builtin(base):
                continue
            name = expression.get("memberName")
        else:
            continue
        if not isinstance(name, str) or not name or name in GUARD_SKIPPED_CALLS:
            continue
        tokens.add("msg.sender" if name.lower() in SENDER_ALIASES else name)
        if rid in funcs:
            callees.add(rid)
    return tokens, callees


def _analyze_body(body, decls, funcs, params=(), state_info=None, libraries=()):
    """Collect state reads/writes, resolved calls, called-member names, ETH movement, guard
    conditions and call sinks from a function or modifier body. Returns a dict of sets."""
    state_info = state_info or {}
    reads, writes, calls, callnames = set(), set(), set(), set()
    internal = set()
    sink_details = []
    eth_move = False
    # Pass 1: map local storage pointers (`Pos storage p = pos[x];`) to their state var.
    local_ptr = {}
    for x in walk_json(body):
        if x.get("nodeType") != "VariableDeclarationStatement":
            continue
        target_decl = None
        for d in x.get("declarations") or []:
            if isinstance(d, dict) and d.get("storageLocation") == "storage" and isinstance(d.get("id"), int):
                target_decl = d["id"]
                break
        if target_decl is None:
            continue
        for ref in walk_json(x.get("initialValue") or {}):
            rid = ref.get("referencedDeclaration")
            if rid in decls:
                local_ptr[target_decl] = decls[rid]
                break

    def resolve_write(ref_id):
        if ref_id in decls:
            writes.add(decls[ref_id])
        elif ref_id in local_ptr:
            writes.add(local_ptr[ref_id])

    for x in walk_json(body):
        nt = x.get("nodeType")
        if nt in ("Identifier", "MemberAccess"):
            rid = x.get("referencedDeclaration")
            if rid in decls:
                reads.add(decls[rid])
            elif rid in local_ptr:
                reads.add(local_ptr[rid])
        elif nt == "Assignment":
            for lhs in walk_json(x.get("leftHandSide") or {}):
                resolve_write(lhs.get("referencedDeclaration"))
        elif nt == "UnaryOperation" and x.get("operator") in ("++", "--", "delete"):
            for lhs in walk_json(x.get("subExpression") or {}):
                resolve_write(lhs.get("referencedDeclaration"))
        elif nt == "FunctionCallOptions":
            # `addr.call{value: ...}(...)` moves ETH.
            if "value" in (x.get("names") or []):
                eth_move = True
        elif nt == "YulFunctionCall":
            name = (x.get("functionName") or {}).get("name")
            if name in YUL_SINKS:
                # Inline assembly operands are Yul names; the target is not resolved.
                sink_details.append({"kind": YUL_SINKS[name], "member": name,
                                     "assembly": True, "dynamic_target": None,
                                     "src": x.get("src")})
        elif nt == "FunctionCall":
            expression = x.get("expression") or {}
            if expression.get("nodeType") == "MemberAccess":
                member = expression.get("memberName")
                if isinstance(member, str):
                    callnames.add(member)
                    if member in ETH_MOVE_MEMBERS:
                        eth_move = True  # addr.send / addr.transfer
                    if member in ("push", "pop"):
                        for ref in walk_json(expression.get("expression") or {}):
                            resolve_write(ref.get("referencedDeclaration"))
            target = expression.get("referencedDeclaration")
            if target in funcs:
                calls.add(funcs[target]["id"])
                callnames.add(funcs[target]["short"])
                # An internal call runs in this contract's context, so its checks and writes
                # are this function's: a plain identifier, `super.f()`, or any library function.
                base = expression.get("expression") or {}
                if (expression.get("nodeType") == "Identifier"
                        or funcs[target].get("contract_kind") == "library"
                        or (base.get("nodeType") == "Identifier" and base.get("name") == "super")):
                    internal.add(target)
            detail = _call_sink(x, params, state_info, libraries)
            if detail:
                detail["src"] = x.get("src")
                sink_details.append(detail)
                if detail["kind"] == "selfdestruct" or detail.get("member") == "functionCallWithValue":
                    eth_move = True
    guard_tokens, guard_callees = set(), set()
    for condition in _guard_conditions(body):
        tokens, callees = _condition_tokens(condition, decls, funcs, local_ptr)
        guard_tokens |= tokens
        guard_callees |= callees
    return {"reads": reads, "writes": writes, "calls": calls,
            "callnames": callnames, "eth_move": eth_move, "internal": internal,
            "guard_tokens": guard_tokens, "guard_callees": guard_callees,
            "sink_details": sink_details}


def _close_over(base, edges):
    """Least fixed point of value[f] = base[f] | union(value[g] for g in edges[f]).
    A worklist over reverse edges, so call cycles terminate."""
    value = {k: set(v) for k, v in base.items()}
    callers = defaultdict(set)
    for caller, callees in edges.items():
        for callee in callees:
            callers[callee].add(caller)
    todo = list(value)
    queued = set(todo)
    while todo:
        current = todo.pop()
        queued.discard(current)
        merged = set(value[current])
        for callee in edges.get(current, ()):
            merged |= value.get(callee, set())
        if merged != value[current]:
            value[current] = merged
            for caller in callers[current]:
                if caller not in queued:
                    queued.add(caller)
                    todo.append(caller)
    return value


def solidity_symbols(trees):
    decls, parent = {}, {}
    state_info = {}
    modifier_defs = {}
    contracts = {}
    for path, tree in trees:
        for node in walk_json(tree):
            nt = node.get("nodeType")
            if nt == "VariableDeclaration" and node.get("stateVariable"):
                ident = node.get("id")
                if isinstance(ident, int):
                    decls[ident] = str(path) + ":" + str(node.get("name", ident))
                    mutability = node.get("mutability") or (
                        "constant" if node.get("constant") else "mutable")
                    state_info[ident] = (mutability if mutability in ("constant", "immutable")
                                         else "state")
            if nt == "ContractDefinition":
                cname = node.get("name", "")
                if isinstance(node.get("id"), int):
                    contracts[node["id"]] = {
                        "name": str(cname), "kind": node.get("contractKind", "contract"),
                        "bases": [b for b in node.get("linearizedBaseContracts") or []
                                  if isinstance(b, int)]}
                for child in node.get("nodes", []):
                    if isinstance(child, dict):
                        parent[child.get("id")] = node.get("id")
            if nt == "ModifierDefinition" and isinstance(node.get("id"), int):
                modifier_defs[node["id"]] = node
    libraries = {cid for cid, c in contracts.items() if c["kind"] == "library"}
    funcs, nodes = {}, {}
    for path, tree in trees:
        for node in walk_json(tree):
            if node.get("nodeType") != "FunctionDefinition":
                continue
            num = node.get("id")
            if not isinstance(num, int):
                continue
            short = str(node.get("name") or node.get("kind") or "unnamed")
            owner = contracts.get(parent.get(num), {})
            nodes[num] = node
            funcs[num] = {"id": "solc:" + str(num), "path": str(path),
                          "name": str(owner.get("name", "")) + "." + short, "short": short,
                          "declaration": num, "language": "solidity",
                          "implemented": node.get("implemented", True),
                          "entry": (node.get("visibility") in ("external", "public")
                                    and node.get("implemented", True)),
                          "visibility": node.get("visibility", "unknown"),
                          "line": None, "source_span": node.get("src"),
                          "modifiers_unverified": [str((m.get("modifierName") or {}).get("name", "unknown"))
                              for m in node.get("modifiers", []) if isinstance(m, dict)],
                          "writes": [], "reads": [],
                          "calls": [], "sinks": [], "source": "compiler-ast",
                          "contract": str(owner.get("name", "")),
                          "contract_kind": owner.get("kind", "unknown"),
                          "function_kind": node.get("kind", "function"),
                          "state_mutability": node.get("stateMutability", "unknown"),
                          "guards": [], "internal_calls": [], "writes_transitive": [],
                          "writes_via_modifiers": [], "sink_details": [],
                          "inherited_by": []}
    # Pre-compute each modifier's own effects so a function inherits them.
    modifier_effects = {}
    for mid, node in modifier_defs.items():
        params = {p.get("id") for p in ((node.get("parameters") or {}).get("parameters") or [])
                  if isinstance(p, dict)}
        modifier_effects[mid] = _analyze_body(node.get("body") or {}, decls, funcs, params,
                                              state_info, libraries)
    guard_base, internal_edges, modifier_internal, modifier_writes = {}, {}, {}, {}
    direct_writes = {}
    for num, node in nodes.items():
        current = funcs[num]
        if not current["implemented"]:
            # Interfaces / abstract declarations have no body: never a source or sink.
            continue
        params = {p.get("id") for p in ((node.get("parameters") or {}).get("parameters") or [])
                  if isinstance(p, dict)}
        eff = _analyze_body(node.get("body") or {}, decls, funcs, params, state_info, libraries)
        writes, reads, calls = set(eff["writes"]), set(eff["reads"]), set(eff["calls"])
        callnames, eth_move = set(eff["callnames"]), eff["eth_move"]
        internal = set(eff["internal"])
        details = list(eff["sink_details"])
        guards, guard_callees = set(eff["guard_tokens"]), set(eff["guard_callees"])
        mod_internal, mod_writes = set(), set()
        # Inherit the reads/writes/calls of every applied modifier (nonReentrant's
        # write to `locked`, onlyOwner's read of `owner`, ...), and its guards.
        for m in node.get("modifiers", []) or []:
            if not isinstance(m, dict) or m.get("kind") == "baseConstructorSpecifier":
                continue
            ref = m.get("modifierName") or {}
            mid = ref.get("referencedDeclaration")
            if mid in contracts:
                continue  # a base constructor call written without its kind
            meff = modifier_effects.get(mid)
            if ref.get("name"):
                guards.add(str(ref.get("name")).split(".")[-1])
            if meff:
                writes |= meff["writes"]
                reads |= meff["reads"]
                calls |= meff["calls"]
                callnames |= meff["callnames"]
                eth_move = eth_move or meff["eth_move"]
                internal |= meff["internal"]
                details.extend(meff["sink_details"])
                guards |= meff["guard_tokens"]
                guard_callees |= meff["guard_callees"]
                mod_internal |= meff["internal"]
                mod_writes |= meff["writes"]
        current["writes"] = sorted(writes)
        current["reads"] = sorted(reads)
        current["calls"] = sorted(calls)
        current["sink_details"] = details
        # Classify from the function's OWN name and the names it calls, never the
        # contract name or an emitted event identifier.
        current["sinks"] = classify({current["short"]} | callnames, eth_move, details)
        direct_writes[num] = writes
        internal_edges[num] = internal
        modifier_internal[num] = mod_internal
        modifier_writes[num] = mod_writes
        guard_base[num] = (guards, guard_callees)
    # An internal call to a virtual function runs whichever override the deployed contract
    # has: `upgradeToAndCall` reaches the `onlyOwner` of every `_authorizeUpgrade` override.
    # Every override is followed, so a guard or write may come from a sibling contract's
    # override - an over-approximation that hides an asymmetry rather than inventing one.
    overriders = defaultdict(set)
    for num, node in nodes.items():
        for base_fn in node.get("baseFunctions") or []:
            if isinstance(base_fn, int):
                overriders[base_fn].add(num)
    expanded = {}

    def with_overrides(callee):
        if callee not in expanded:
            seen, todo = {callee}, [callee]
            while todo:
                for child in overriders.get(todo.pop(), ()):
                    if child not in seen:
                        seen.add(child)
                        todo.append(child)
            expanded[callee] = seen
        return expanded[callee]

    for table in (internal_edges, modifier_internal):
        for num in table:
            table[num] = {x for c in table[num] for x in with_overrides(c)}
    # A condition that calls a getter (`owner()`, `hasRole(...)`) also depends on the state
    # that getter reads, so `msg.sender == owner` and `owner() == _msgSender()` share a token.
    base_tokens = {}
    for num, (guards, guard_callees) in guard_base.items():
        tokens = set(guards)
        for callee in guard_callees:
            if callee in funcs:
                tokens |= set(funcs[callee]["reads"])
        base_tokens[num] = tokens
    guards_closed = _close_over(base_tokens, internal_edges)
    writes_closed = _close_over(direct_writes, internal_edges)
    for num in guard_base:
        current = funcs[num]
        current["guards"] = sorted(guards_closed[num])
        current["internal_calls"] = sorted(funcs[c]["id"] for c in internal_edges[num]
                                           if c in funcs)
        current["writes_transitive"] = sorted(writes_closed[num])
        via = set(modifier_writes[num])
        for callee in modifier_internal[num]:
            via |= writes_closed.get(callee, set())
        current["writes_via_modifiers"] = sorted(via)
    # A function a derived contract inherits without overriding is that contract's entry point
    # too: `Vault.deposit` names `VaultBase.deposit` when Vault is VaultBase and does not
    # redefine deposit.
    defined = defaultdict(set)
    for num, f in funcs.items():
        defined[parent.get(num)].add(f["short"])
    for num, f in funcs.items():
        home = parent.get(num)
        if f["function_kind"] == "constructor" or home not in contracts:
            continue
        heirs = []
        for cid, info in contracts.items():
            bases = info["bases"]
            if cid == home or home not in bases:
                continue
            closer = bases[:bases.index(home)]
            if not any(f["short"] in defined[c] for c in closer):
                heirs.append(info["name"])
        f["inherited_by"] = sorted(set(heirs))
    for f in funcs.values():
        f.pop("short", None)
    return list(funcs.values())


def _name_words(name):
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", str(name))
    return {w.lower() for w in re.split(r"[^A-Za-z0-9]+", spaced) if w}


def classify(names, eth_move=False, details=None):
    joined = " ".join(str(n).lower() for n in names)
    sinks = {key for key, words in SINK_TERMS.items() if any(w in joined for w in words)}
    words = set()
    for n in names:
        words |= _name_words(n)
    sinks |= {family for word, family in SINK_WORDS.items() if word in words}
    if eth_move:
        sinks.add("asset-movement")
    for detail in details or ():
        sinks |= _detail_families(detail)
    return sorted(sinks)


def attr_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = attr_name(node.value)
        return (prefix + "." if prefix else "") + node.attr
    return ""

def py_symbols(root):
    root = Path(root).resolve()
    raw = subprocess.run(["git", "-C", str(root), "ls-files", "-z"],
                         check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    tracked = raw.stdout.decode("utf-8", "replace").split("\0")
    defs = []
    files = [x for x in tracked if x.endswith(".py") and
             not set(Path(x).parts).intersection(
                 {"test", "tests", "vendor", "node_modules", "build", "dist", ".git", "secrets", "credentials", ".env"})]
    if len(files) > 2000:
        raise ValueError("too many Python files; narrow repository")
    for path in sorted(files):
        p = root / path
        if p.is_symlink() or not p.is_file() or p.stat().st_size > 250_000:
            continue
        try:
            tree = ast.parse(p.read_text(encoding="utf-8"), filename=path)
        except (SyntaxError, UnicodeDecodeError):
            continue
        funcs = []
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                funcs.append(("", node))
            elif isinstance(node, ast.ClassDef):
                funcs.extend((node.name, child) for child in node.body
                             if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)))
        by_name = {name + "." + n.name if name else n.name for name, n in funcs}
        for owner, n in funcs:
            fullname = owner + "." + n.name if owner else n.name
            writes, reads, calls, names = set(), set(), set(), {fullname}
            for v in ast.walk(n):
                if isinstance(v, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                    lhs = v.targets if isinstance(v, ast.Assign) else [v.target]
                    for target in lhs:
                        for item in ast.walk(target):
                            if isinstance(item, ast.Attribute) and isinstance(item.value, ast.Name) and item.value.id in ("self", "cls"):
                                writes.add(item.attr)
                if isinstance(v, ast.Attribute) and isinstance(v.value, ast.Name) and v.value.id in ("self", "cls"):
                    reads.add(v.attr)
                if isinstance(v, ast.Call):
                    symbol = attr_name(v.func)
                    names.add(symbol)
                    if symbol in by_name:
                        calls.add(path + ":" + symbol)
                    elif owner and symbol in ("self." + x.name for _, x in funcs):
                        calls.add(path + ":" + owner + "." + symbol.split(".", 1)[1])
            defs.append({"id": path + ":" + fullname, "path": path,
                         "name": fullname, "declaration": None,
                         "language": "python", "entry": False,
                         "visibility": "unknown", "line": n.lineno,
                         "writes": sorted(writes), "reads": sorted(reads),
                         "calls": sorted(calls), "sinks": classify(names),
                         "source": "python-ast"})
    return defs

def build(symbols):
    symbols = sorted(symbols, key=lambda x: x["id"])
    known = {x["id"] for x in symbols}
    edges = []
    for s in symbols:
        for callee in s["calls"]:
            if callee in known:
                edges.append({"from": s["id"], "to": callee,
                              "kind": "static-call-reference", "confidence": "ast-reference"})
    call_edges = len(edges)
    truncated = False
    readers = defaultdict(list)
    for s in symbols:
        for name in s["reads"]:
            readers[name].append(s["id"])
    for s in symbols:
        for name in s["writes"]:
            for other in readers[name][:150]:
                if other != s["id"]:
                    edges.append({"from": s["id"], "to": other,
                                  "kind": "writer-reader-overlap", "state": name,
                                  "confidence": "candidate-only"})
                if len(edges) >= EDGE_CAP:
                    truncated = True
                    break
            if truncated:
                break
        if truncated:
            break
    edges = edges[:EDGE_CAP]
    return {"schema": 1, "method": "compiler-ast-plus-python-ast",
            "symbols": symbols, "edges": edges,
            "truncated": truncated,
            "edge_counts": {"total": len(edges), "static_call_reference": call_edges,
                            "writer_reader_overlap": len(edges) - call_edges, "cap": EDGE_CAP},
            "semantic_scope": "Solidity compiler-resolved declarations and calls; Python syntax only",
            "reachable_verified": False,
            "warning": "Solidity calls are static references, not full dynamic dispatch. Writer-reader "
                       "overlap is NOT an executable path. Python entrypoints/calls can be unresolved. "
                       "No Rust/Move/Cairo semantics are claimed."
                       + (" Edge cap reached: graph is TRUNCATED and some overlaps are omitted."
                          if truncated else "")}

def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo", help="git checkout for Python AST; optional when --solc provided")
    ap.add_argument("--solc", help="solc output/build-info JSON with sources AST")
    ap.add_argument("--max-ast-mb", type=int, default=MAX_AST_BYTES // 1_000_000,
                    help="size cap for the compiler JSON (default %d MB)" % (MAX_AST_BYTES // 1_000_000))
    ap.add_argument("--out")
    args = ap.parse_args(argv)
    if not args.repo and not args.solc:
        ap.error("pass --repo or --solc")
    if args.max_ast_mb < 1 or args.max_ast_mb > 4096:
        ap.error("--max-ast-mb must be between 1 and 4096")
    try:
        symbols = []
        if args.solc:
            symbols += solidity_symbols(load_solc(args.solc, args.max_ast_mb * 1_000_000))
        if args.repo:
            symbols += py_symbols(args.repo)
        report = build(symbols)
    except (ValueError, OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        ap.error(str(exc))
    payload = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    if args.out:
        Path(args.out).write_text(payload, encoding="utf-8")
        print(json.dumps({"out": args.out, "symbols": len(report["symbols"]),
                          "edges": len(report["edges"])}))
    else:
        print(payload, end="")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
