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

# The target checkout is untrusted: its .git/config can name an fsmonitor or hooks program
# that git would run even for a read-only `ls-files` or `status`.
GIT_HARDENING = ("--no-optional-locks", "-c", "core.fsmonitor=false",
                 "-c", "core.hooksPath=/dev/null")

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
# `_msgSender()` (OpenZeppelin Context and ERC-2771) and the relay-SDK spellings return the caller.
SENDER_ALIASES = ("_msgsender", "msgsender", "_getmsgsender")
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
# Directories a checkout carries but does not own (bounty.py VENDOR_PARTS, kept in step by hand).
VENDOR_PARTS = {'node_modules', 'vendor', 'third_party', 'thirdparty', 'lib', 'libs',
                'dependencies', 'submodules', 'target', 'dist', 'build', 'out', 'artifacts',
                'cache', 'generated', 'venv', '.venv'}
# A view or pure function moves nothing: its name says what it reports, not what it does. Only a
# price read keeps its family, because a manipulable price is read, never moved.
READ_ONLY_NAME_FAMILIES = ("price-oracle",)
DATA_LOCATION = re.compile(r"\s+(?:memory|calldata|storage)(?:\s+(?:pointer|ref|slice))?\b")

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


def _node_count(node, limit):
    """Nodes under `node`, stopping one past `limit`."""
    todo, count = [node], 0
    while todo and count <= limit:
        x = todo.pop()
        count += 1
        if isinstance(x, dict):
            todo.extend(v for v in x.values() if isinstance(v, (dict, list)))
        elif isinstance(x, list):
            todo.extend(x)
    return count


class SourceTrees(list):
    """The SourceUnit ASTs load_solc returns, plus the sources it skipped and why."""

    def __init__(self, trees=(), skipped=()):
        super().__init__(trees)
        self.skipped = list(skipped)


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
    trees, skipped = [], []
    saw_source_entry = False
    for filename, desc in sorted(sources.items()):
        if not isinstance(desc, dict):
            continue
        saw_source_entry = True
        tree = desc.get("ast")
        if isinstance(tree, dict) and tree.get("nodeType") == "SourceUnit":
            # One flattened file over the node cap is skipped and named, not fatal: the rest of
            # the build still has a graph, and the skipped file is reported for reading by hand.
            if _node_count(tree, MAX_NODES) > MAX_NODES:
                skipped.append({"path": str(filename),
                                "reason": "AST over %d nodes; not analysed" % MAX_NODES})
                continue
            trees.append((filename, tree))
    if not trees:
        if skipped:
            raise ValueError("every source AST is over the %d-node cap: %s"
                             % (MAX_NODES, ", ".join(x["path"] for x in skipped[:5])))
        if saw_source_entry:
            # sources present but none carry an AST → the AST output was not requested.
            raise ValueError(BUILD_INFO_HINT)
        raise ValueError("no Solidity SourceUnit AST; " + BUILD_INFO_HINT)
    return SourceTrees(trees, skipped)

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
    if nt == "FunctionCall" and _sender_call(expr):
        return "msg.sender"
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


def _sender_call(call):
    """`_msgSender()` with no arguments: the caller, through Context or an ERC-2771 forwarder."""
    if call.get("kind", "functionCall") != "functionCall" or call.get("arguments"):
        return False
    callee = _callee(call)
    name = callee.get("name") if callee.get("nodeType") == "Identifier" else (
        callee.get("memberName") if callee.get("nodeType") == "MemberAccess" else None)
    return isinstance(name, str) and name.lower() in SENDER_ALIASES


def _render(expr, depth=0):
    """Short source-like text of a modifier argument: `MINTER_ROLE`, `Roles.ADMIN`, `1`."""
    if not isinstance(expr, dict) or depth > 6:
        return "?"
    nt = expr.get("nodeType")
    if nt == "Identifier":
        return str(expr.get("name") or "?")
    if nt == "MemberAccess":
        return _render(expr.get("expression"), depth + 1) + "." + str(expr.get("memberName") or "?")
    if nt == "Literal":
        return str(expr.get("value") if expr.get("value") is not None else expr.get("hexValue") or "?")
    if nt == "IndexAccess":
        return "%s[%s]" % (_render(expr.get("baseExpression"), depth + 1),
                           _render(expr.get("indexExpression"), depth + 1))
    if nt == "FunctionCall":
        args = [a for a in expr.get("arguments") or [] if isinstance(a, dict)]
        return "%s(%s)" % (_render(_callee(expr), depth + 1),
                           ",".join(_render(a, depth + 1) for a in args))
    if nt == "TupleExpression":
        parts = [c for c in expr.get("components") or [] if isinstance(c, dict)]
        return _render(parts[0], depth + 1) if len(parts) == 1 else "?"
    return "?"


def _param_types(node):
    """[(source type, ABI type)] of a function's parameters, or None when the AST has no types.

    `contract IERC20 memory` reads IERC20 in source and address in the ABI; an enum is uint8."""
    found = []
    for p in ((node.get("parameters") or {}).get("parameters") or []):
        if not isinstance(p, dict):
            continue
        text = (p.get("typeDescriptions") or {}).get("typeString")
        if not isinstance(text, str) or not text.strip():
            return None
        text = DATA_LOCATION.sub("", text.strip())
        if text.startswith("address payable"):
            text = "address" + text[len("address payable"):]
        kind = text.split(" ", 1)[0]
        source = text.split(" ", 1)[1] if kind in ("contract", "struct", "enum", "library",
                                                   "interface") and " " in text else text
        suffix = re.search(r"(?:\[\d*\])*$", source).group(0)  # array dimensions only
        abi = ("address" + suffix if kind in ("contract", "interface") else
               "uint8" + suffix if kind == "enum" else source)
        found.append((source.replace(" ", ""), abi.replace(" ", "")))
    return found


def _vendored_path(path):
    parts = Path(str(path)).parts
    return bool(parts) and (parts[0].startswith("@") or
                            any(part.lower() in VENDOR_PARTS for part in parts[:-1]))


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
    keyed, receivers, passed = set(), set(), set()
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
            if x.get("kind", "functionCall") == "functionCall":
                # `_healthy(msg.sender)` asks about the caller; it does not restrict who calls.
                # The callee and the state it reads stay tokens, so `hasRole(r, msg.sender)` is
                # still a guard through hasRole.
                for arg in x.get("arguments") or []:
                    if isinstance(arg, dict):
                        passed.update(id(y) for y in walk_json(arg))
    for x in walk_json(condition):
        nt = x.get("nodeType")
        if id(x) in receivers:
            continue
        env = _env_token(x)
        if env and id(x) not in keyed and not (env in CALLER_SOURCES and id(x) in passed):
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
        if name.lower() in SENDER_ALIASES:
            if id(x) not in passed and id(x) not in keyed:
                tokens.add("msg.sender")
            continue
        tokens.add(name)
        if rid in funcs:
            callees.add(rid)
    return tokens, callees


def _analyze_body(body, decls, funcs, params=(), state_info=None, libraries=()):
    """Collect state reads/writes, resolved calls, called-member names, ETH movement, guard
    conditions and call sinks from a function or modifier body. Returns a dict of sets."""
    state_info = state_info or {}
    reads, writes, calls, callnames = set(), set(), set(), set()
    internal, via_super = set(), set()
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
                is_super = base.get("nodeType") == "Identifier" and base.get("name") == "super"
                if (expression.get("nodeType") == "Identifier"
                        or funcs[target].get("contract_kind") == "library" or is_super):
                    internal.add(target)
                    if is_super:
                        via_super.add(target)
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
            "super": via_super, "guard_tokens": guard_tokens, "guard_callees": guard_callees,
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


def _transitive(table, root, cache):
    """`root` and everything `table` reaches from it (overriders, or base functions)."""
    if root not in cache:
        seen, todo = {root}, [root]
        while todo:
            for child in table.get(todo.pop(), ()):
                if child not in seen:
                    seen.add(child)
                    todo.append(child)
        cache[root] = seen
    return cache[root]


def _function_key(node, types):
    """What makes two functions one entry point: the selector, else the name and its types."""
    kind = node.get("kind", "function")
    if kind in ("receive", "fallback"):
        return kind
    selector = node.get("functionSelector")
    if isinstance(selector, str) and selector:
        return selector
    params = (node.get("parameters") or {}).get("parameters") or []
    shape = ",".join(t[0] for t in types) if types is not None else "?%d" % len(params)
    return "%s(%s)" % (node.get("name") or kind, shape)


def solidity_symbols(trees):
    """One symbol per function declaration, plus one per function a deployable contract
    inherits (an "heir symbol", `Heir.f`, carrying `inherits`).

    Virtual calls, `super` and overridden modifiers are resolved in one contract's
    linearization at a time: a declaration in a deployable contract is analysed in that
    contract, an heir symbol in its heir. A declaration in an abstract contract has no
    deployment of its own; there an unresolved virtual call follows every override, an
    over-approximation its heir symbols do not share.
    """
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
                children = [c for c in node.get("nodes") or [] if isinstance(c, dict)]
                if isinstance(node.get("id"), int):
                    kind = node.get("contractKind", "contract")
                    bases = [b for b in node.get("linearizedBaseContracts") or []
                             if isinstance(b, int)]
                    # solc marks `abstract`; a hand-built or partial AST may only show a
                    # function declared without a body.
                    abstract = (node.get("abstract") is True
                                or node.get("fullyImplemented") is False
                                or any(c.get("nodeType") == "FunctionDefinition"
                                       and c.get("implemented", True) is False
                                       for c in children))
                    contracts[node["id"]] = {
                        "name": str(cname), "kind": kind, "path": str(path),
                        "bases": bases if node["id"] in bases else [node["id"]] + bases,
                        "deployable": kind == "contract" and not abstract}
                for child in children:
                    parent[child.get("id")] = node.get("id")
            if nt == "ModifierDefinition" and isinstance(node.get("id"), int):
                modifier_defs[node["id"]] = node
    libraries = {cid for cid, c in contracts.items() if c["kind"] == "library"}
    funcs, nodes, types_of = {}, {}, {}
    for path, tree in trees:
        for node in walk_json(tree):
            if node.get("nodeType") != "FunctionDefinition":
                continue
            num = node.get("id")
            if not isinstance(num, int):
                continue
            short = str(node.get("name") or node.get("kind") or "unnamed")
            owner = contracts.get(parent.get(num), {})
            types = _param_types(node)
            nodes[num] = node
            types_of[num] = types
            funcs[num] = {"id": "solc:" + str(num), "path": str(path),
                          "name": str(owner.get("name", "")) + "." + short, "short": short,
                          "declaration": num, "language": "solidity",
                          "implemented": node.get("implemented", True),
                          "entry": (node.get("visibility") in ("external", "public")
                                    and node.get("implemented", True)),
                          "visibility": node.get("visibility", "unknown"),
                          "line": None, "source_span": node.get("src"),
                          "modifiers_unverified": [str((m.get("modifierName") or {}).get("name", "unknown"))
                              for m in node.get("modifiers") or [] if isinstance(m, dict)],
                          "writes": [], "reads": [],
                          "calls": [], "sinks": [], "source": "compiler-ast",
                          "contract": str(owner.get("name", "")),
                          "contract_kind": owner.get("kind", "unknown"),
                          "function_kind": node.get("kind", "function"),
                          "state_mutability": node.get("stateMutability", "unknown"),
                          "guards": [], "internal_calls": [], "writes_transitive": [],
                          "writes_via_modifiers": [], "sink_details": [],
                          "inherited_by": [],
                          "contract_deployable": bool(owner.get("deployable")),
                          "vendored_declaration": _vendored_path(path),
                          "parameter_types": None if types is None else [t[0] for t in types],
                          "abi_parameter_types": None if types is None else [t[1] for t in types],
                          "signature": "%s(%s)" % (short, "?" if types is None
                                                   else ",".join(t[0] for t in types)),
                          "modifier_guards": {}, "resolution": []}
    implemented = {num for num, f in funcs.items() if f["implemented"]}
    # Each body once: its own reads, writes, calls, conditions and sinks.
    effects = {}
    for num in sorted(implemented):
        node = nodes[num]
        params = {p.get("id") for p in ((node.get("parameters") or {}).get("parameters") or [])
                  if isinstance(p, dict)}
        effects[num] = _analyze_body(node.get("body") or {}, decls, funcs, params, state_info,
                                     libraries)
    modifier_effects = {}
    for mid, node in modifier_defs.items():
        params = {p.get("id") for p in ((node.get("parameters") or {}).get("parameters") or [])
                  if isinstance(p, dict)}
        modifier_effects[mid] = _analyze_body(node.get("body") or {}, decls, funcs, params,
                                              state_info, libraries)
    # Applied modifiers, with their arguments: `onlyRole(MINTER_ROLE)` and
    # `onlyRole(PAUSER_ROLE)` are different checks under one modifier name.
    invocations = {}
    for num, node in nodes.items():
        rows = []
        for m in node.get("modifiers") or []:
            if not isinstance(m, dict) or m.get("kind") == "baseConstructorSpecifier":
                continue
            ref = m.get("modifierName") or {}
            mid = ref.get("referencedDeclaration")
            name = str(ref.get("name") or "").split(".")[-1]
            if mid in contracts or not name:
                continue  # a base constructor call written without its kind
            args = [a for a in m.get("arguments") or [] if isinstance(a, dict)]
            arg_decls = set()
            for arg in args:
                for x in walk_json(arg):
                    rid = x.get("referencedDeclaration")
                    if x.get("nodeType") in ("Identifier", "MemberAccess") and rid in decls:
                        arg_decls.add(decls[rid])
            rows.append({"mid": mid, "name": name, "arg_decls": arg_decls,
                         "token": ("%s(%s)" % (name, ",".join(_render(a) for a in args))
                                   if args else None)})
        invocations[num] = rows
    # Declaration-level facts: what the body and its declared modifiers touch.
    for num in sorted(implemented):
        current = funcs[num]
        eff = effects[num]
        writes, reads, calls = set(eff["writes"]), set(eff["reads"]), set(eff["calls"])
        callnames, eth_move = set(eff["callnames"]), eff["eth_move"]
        details = list(eff["sink_details"])
        for inv in invocations.get(num, ()):
            meff = modifier_effects.get(inv["mid"])
            if meff:
                writes |= meff["writes"]
                reads |= meff["reads"]
                calls |= meff["calls"]
                callnames |= meff["callnames"]
                eth_move = eth_move or meff["eth_move"]
                details.extend(meff["sink_details"])
        current["writes"] = sorted(writes)
        current["reads"] = sorted(reads)
        current["calls"] = sorted(calls)
        current["sink_details"] = details
        # Classify from the function's OWN name and the names it calls, never the
        # contract name or an emitted event identifier.
        current["sinks"] = classify({current["short"]} | callnames, eth_move, details,
                                    read_only=current["state_mutability"] in ("view", "pure"))
    overriders, bases_of, modifier_overriders = defaultdict(set), defaultdict(set), defaultdict(set)
    for num, node in nodes.items():
        for base_fn in node.get("baseFunctions") or []:
            if isinstance(base_fn, int):
                overriders[base_fn].add(num)
                bases_of[num].add(base_fn)
    for mid, node in modifier_defs.items():
        for base_mod in node.get("baseModifiers") or []:
            if isinstance(base_mod, int):
                modifier_overriders[base_mod].add(mid)
    down, up, mod_down = {}, {}, {}
    by_contract = defaultdict(list)
    for num in sorted(funcs):
        by_contract[parent.get(num)].append(num)

    def resolve_call(ref, owner, positions, lin, is_super, union):
        """The implementation an internal call to `ref` runs in this linearization."""
        if ref not in funcs:
            return ()
        home = parent.get(ref)
        if home not in contracts or home in libraries or home not in positions:
            # a library or free function, or another contract's function named in a
            # condition: a static reference, not dispatched here
            return (ref,) if ref in implemented else ()
        family = _transitive(overriders, ref, down)
        start = positions[owner] + 1 if is_super and owner in positions else 0
        best, best_at = None, None
        for candidate in family:
            at = positions.get(parent.get(candidate))
            if candidate in implemented and at is not None and at >= start and (
                    best_at is None or at < best_at):
                best, best_at = candidate, at
        if best is not None:
            return (best,)
        if union:
            return tuple(sorted(c for c in family if c in implemented))
        return ()

    def resolve_modifier(mid, positions):
        best, best_at = mid, None
        for candidate in _transitive(modifier_overriders, mid, mod_down):
            at = positions.get(parent.get(candidate))
            if at is not None and (best_at is None or at < best_at):
                best, best_at = candidate, at
        return best

    def context(cid):
        """Guards, writes and resolution of every function a linearization holds."""
        if cid in contracts:
            lin = contracts[cid]["bases"]
            union = not contracts[cid]["deployable"]
        else:
            lin, union = [], False
        positions = {c: i for i, c in enumerate(lin)}
        members = [n for c in (lin or [None]) for n in by_contract.get(c, ()) if n in implemented]
        edges, applied, modifier_targets = {}, {}, {}
        reach, todo = set(members), list(members)
        while todo:
            g = todo.pop()
            owner = parent.get(g)
            eff = effects[g]
            targets, via_modifiers = set(), set()
            for ref in eff["internal"]:
                targets.update(resolve_call(ref, owner, positions, lin, ref in eff["super"],
                                            union))
            resolved = []
            for inv in invocations.get(g, ()):
                mid = resolve_modifier(inv["mid"], positions) if inv["mid"] in modifier_defs \
                    else inv["mid"]
                resolved.append((inv, mid))
                meff = modifier_effects.get(mid)
                if meff:
                    for ref in meff["internal"]:
                        via_modifiers.update(resolve_call(ref, parent.get(mid), positions, lin,
                                                          ref in meff["super"], union))
            edges[g] = targets | via_modifiers
            modifier_targets[g] = via_modifiers
            applied[g] = resolved
            for t in edges[g]:
                if t not in reach and t in effects:
                    reach.add(t)
                    todo.append(t)

        def callee_reads(ref, owner):
            found = set()
            for t in resolve_call(ref, owner, positions, lin, False, union):
                found |= set(funcs[t]["reads"])
            return found

        base_guard, base_write, modifier_write, base_reach = {}, {}, {}, {}
        own_checks = {}
        for g in reach:
            eff = effects[g]
            tokens = set(eff["guard_tokens"])
            for ref in eff["guard_callees"]:
                tokens |= callee_reads(ref, parent.get(g))
            writes, by_modifier = set(eff["writes"]), set()
            checks = []
            for inv, mid in applied[g]:
                tokens.add(inv["name"])
                if inv["token"]:
                    tokens.add(inv["token"])
                tokens |= inv["arg_decls"]
                meff = modifier_effects.get(mid)
                mine = set()
                if meff:
                    mine |= meff["guard_tokens"]
                    for ref in meff["guard_callees"]:
                        mine |= callee_reads(ref, parent.get(mid))
                    writes |= meff["writes"]
                    by_modifier |= meff["writes"]
                tokens |= mine
                checks.append((inv, mid, mine))
            base_guard[g] = tokens
            base_write[g] = writes
            modifier_write[g] = by_modifier
            base_reach[g] = set(edges[g]) | {"modifier:%s" % mid for _, mid in applied[g]}
            own_checks[g] = checks
        guards = _close_over(base_guard, edges)
        writes = _close_over(base_write, edges)
        reached = _close_over(base_reach, edges)
        values = {}
        for g in reach:
            via = set(modifier_write[g])
            for t in modifier_targets[g]:
                via |= writes.get(t, set())
            own = {}
            for inv, mid, mine in own_checks[g]:
                meff = modifier_effects.get(mid)
                checks = set(mine)
                if meff:
                    for ref in meff["internal"]:
                        for t in resolve_call(ref, parent.get(mid), positions, lin,
                                              ref in meff["super"], union):
                            checks |= guards.get(t, set())
                # A modifier's own checks: what its body and its helpers test. The bare name
                # does not carry the arguments; `onlyRole(MINTER_ROLE)` does.
                keyed = [(inv["name"], checks - {inv["name"]}),
                         (inv["token"], (checks | inv["arg_decls"]) - {inv["name"]})]
                for key, value in keyed:
                    if key:
                        own[key] = (own[key] & value) if key in own else set(value)
            values[g] = {"guards": sorted(guards[g]), "writes_transitive": sorted(writes[g]),
                         "writes_via_modifiers": sorted(via),
                         "internal_calls": sorted(funcs[t]["id"] for t in edges[g] if t in funcs),
                         "modifier_guards": {k: sorted(v) for k, v in sorted(own.items())},
                         "resolution": sorted(funcs[x]["id"] if x in funcs else str(x)
                                              for x in reached[g])}
        return values

    contexts = {}

    def values_in(cid, num):
        if cid not in contexts:
            contexts[cid] = context(cid)
        return contexts[cid].get(num)

    fields = ("guards", "writes_transitive", "writes_via_modifiers", "internal_calls",
              "modifier_guards", "resolution")
    for num in sorted(implemented):
        home = parent.get(num)
        found = values_in(home if home in contracts else None, num)
        if found:
            funcs[num].update({key: found[key] for key in fields})
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
    # Which deployable contracts deploy an abstract contract's entry points, inherited or
    # overridden: such a declaration is read through them, not as a surface of its own.
    deployers = defaultdict(list)
    for cid in sorted(contracts):
        if contracts[cid]["deployable"]:
            for base in contracts[cid]["bases"][1:]:
                deployers[base].append(contracts[cid]["path"] + ":" + contracts[cid]["name"])
    for num, f in funcs.items():
        home = parent.get(num)
        if f["entry"] and home in contracts and not contracts[home]["deployable"]:
            f["deployed_by"] = sorted(set(deployers.get(home, ())))
    # Heir symbols: the deployed surface of each deployable contract, resolved there.
    heir_symbols = []
    keys = {num: _function_key(nodes[num], types_of[num]) for num in funcs}
    for cid in sorted(contracts):
        info = contracts[cid]
        if not info["deployable"]:
            continue
        seen, hidden = set(), set()
        for owner_cid in info["bases"]:
            for num in by_contract.get(owner_cid, ()):
                f = funcs[num]
                if (not f["entry"] or f["function_kind"] == "constructor" or keys[num] in seen
                        or num in hidden):
                    continue
                seen.add(keys[num])
                hidden |= _transitive(bases_of, num, up)
                if owner_cid == cid:
                    continue
                found = values_in(cid, num) or {}
                f = dict(f)
                f.pop("deployed_by", None)
                heir = dict(f, id=f["id"] + "@" + str(cid), path=info["path"],
                            name=info["name"] + "." + f["short"], contract=info["name"],
                            contract_kind=info["kind"], contract_deployable=True,
                            writes=[], reads=[], calls=[], sink_details=[], inherited_by=[],
                            inherits=f["id"], inherited_from=f["contract"],
                            declaration_path=f["path"])
                heir.update({key: found.get(key, f[key]) for key in fields})
                heir["resolution_differs"] = heir["resolution"] != f["resolution"]
                heir_symbols.append(heir)
    out = list(funcs.values()) + heir_symbols
    for f in out:
        f.pop("short", None)
    return out


def _name_words(name):
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", str(name))
    return {w.lower() for w in re.split(r"[^A-Za-z0-9]+", spaced) if w}


def classify(names, eth_move=False, details=None, read_only=False):
    """Impact families of a function: from its own and called names, ETH movement and AST sink
    details. A view or pure function keeps only the AST families and a price read."""
    joined = " ".join(str(n).lower() for n in names)
    sinks = {key for key, words in SINK_TERMS.items() if any(w in joined for w in words)}
    words = set()
    for n in names:
        words |= _name_words(n)
    sinks |= {family for word, family in SINK_WORDS.items() if word in words}
    if read_only:
        sinks &= set(READ_ONLY_NAME_FAMILIES)
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
    raw = subprocess.run(["git", *GIT_HARDENING, "-C", str(root), "ls-files", "-z"],
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

def build(symbols, skipped_sources=None):
    symbols = sorted(symbols, key=lambda x: x["id"])
    known = {x["id"] for x in symbols}
    edges = []
    for s in symbols:
        for callee in s["calls"]:
            if callee in known:
                edges.append({"from": s["id"], "to": callee,
                              "kind": "static-call-reference", "confidence": "ast-reference"})
    call_edges = len(edges)
    # An heir symbol runs its declaration's code: one edge to it, so a path that ends at a
    # vendored declaration still reaches the in-scope contract that deploys it.
    for s in symbols:
        if s.get("inherits") in known:
            edges.append({"from": s["id"], "to": s["inherits"], "kind": "inherited-entry",
                          "confidence": "ast-reference"})
    inherited_edges = len(edges) - call_edges
    # The cap bounds the writer-reader overlaps only: a static reference is never dropped.
    budget = max(0, EDGE_CAP - len(edges))
    overlaps = 0
    truncated = False
    readers = defaultdict(list)
    for s in symbols:
        for name in s["reads"]:
            readers[name].append(s["id"])
    for s in symbols:
        for name in s["writes"]:
            for other in readers[name][:150]:
                if other == s["id"]:
                    continue
                if overlaps >= budget:
                    truncated = True
                    break
                edges.append({"from": s["id"], "to": other,
                              "kind": "writer-reader-overlap", "state": name,
                              "confidence": "candidate-only"})
                overlaps += 1
            if truncated:
                break
        if truncated:
            break
    heirs = sum(1 for s in symbols if s.get("inherits"))
    report = {"schema": 1, "method": "compiler-ast-plus-python-ast",
              "symbols": symbols, "edges": edges,
              "truncated": truncated,
              "edge_counts": {"total": len(edges), "static_call_reference": call_edges,
                              "inherited_entry": inherited_edges,
                              "writer_reader_overlap": overlaps, "cap": EDGE_CAP},
              "heir_symbols": heirs,
              "skipped_sources": list(skipped_sources or []),
              "semantic_scope": "Solidity compiler-resolved declarations and calls; Python syntax only",
              "reachable_verified": False,
              "warning": "Solidity calls are static references, not full dynamic dispatch. Writer-reader "
                         "overlap is NOT an executable path. Python entrypoints/calls can be unresolved. "
                         "No Rust/Move/Cairo semantics are claimed. A symbol carrying `inherits` is a "
                         "function a deployable contract inherits, resolved in that contract; a "
                         "declaration in an abstract contract follows every override of an "
                         "unresolved virtual call."
                         + (" Edge cap reached: graph is TRUNCATED and some overlaps are omitted."
                            if truncated else "")
                         + (" %d source file(s) were over the AST node cap and were NOT analysed: "
                            "see skipped_sources." % len(skipped_sources) if skipped_sources else "")}
    return report

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
        symbols, skipped = [], []
        if args.solc:
            trees = load_solc(args.solc, args.max_ast_mb * 1_000_000)
            skipped = getattr(trees, "skipped", [])
            symbols += solidity_symbols(trees)
        if args.repo:
            symbols += py_symbols(args.repo)
        report = build(symbols, skipped)
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
