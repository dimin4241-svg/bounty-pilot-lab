#!/usr/bin/env python3
"""Bounded compiler-AST data-flow leads from external inputs to sensitive operations.

These paths are source-reading aids. They do not prove control flow, authorization,
transaction ordering or exploitability; storage paths can span multiple transactions.
"""
from collections import defaultdict, deque
from bisect import bisect_right

MAX_FLOW_EDGES = 40_000
MAX_LEADS = 500
# Budget per sink. The total cap used to be enforced inside the walk, so whichever sink was
# enumerated first took every row: measured on a real build-info all 500 written leads pointed at
# one vendored SafeERC20 call and no in-scope sink reached the file.
MAX_LEADS_PER_SINK = 3
MAX_SINK_CANDIDATES = 12
MAX_SINKS = 2_000
MAX_PATH_DEPTH = 12
MAX_REVERSE_STEPS = 2_000
# Modifier names that read like an access check. A cue, never a proof: a modifier can be a
# no-op, its holder can be one key, and `nonReentrant` or `locked` is not authorization at all -
# which is why a gated sink is read later and never dropped.
AUTH_GUARD_CUES = ("only", "auth", "role", "owner", "admin", "governor", "permission",
                   "restricted", "whitelist", "allowlist", "guardian", "privileged")
_TEST_SEGMENTS = ("test", "tests", "spec", "mock", "mocks", "fixture", "fixtures",
                  "testing", "__tests__")
ENV_SOURCE_NAMES = {"msg.sender", "tx.origin", "msg.value", "block.timestamp", "block.number"}
SENSITIVE_STATE_TERMS = ("owner", "admin", "role", "implementation", "beacon", "guardian",
                         "operator", "signer", "oracle", "treasury", "pauser", "minter",
                         "upgrader", "authority", "validator", "fee")


def _stable(values):
    """A deterministic order for refs that mix declaration ids with environment/return keys.

    References are collected in a set, and a set holding both integers and strings iterates in an
    order that depends on `PYTHONHASHSEED`. That order reached `incoming`, so the same command on
    the same build-info wrote a different bounded queue on every run. Ids come first, ascending,
    then the string keys lexicographically.
    """
    return sorted(values, key=lambda value: (1, 0, str(value)) if isinstance(value, str)
                  else (0, value, ""))


def _in_scope(path, prefixes):
    """Whole-segment match, as bounty.path_in_scope does: `src` covers src/, never src-legacy/."""
    if not prefixes:
        return True
    text = str(path or "")
    for raw in prefixes:
        prefix = str(raw or "").strip().replace("\\", "/")
        while prefix.startswith("./"):
            prefix = prefix[2:]
        prefix = prefix.strip("/")
        if prefix == ".":
            prefix = ""
        if not prefix or text == prefix or text.startswith(prefix + "/"):
            return True
    return False


def _auth_guards(rows):
    """Modifier-style guards on these symbol rows whose name reads like an access check.

    `semantic_graph` records a function's modifiers and the values its requires read in one
    `guards` list, path-qualifying the variables and constants. Only the unqualified entries are
    modifier names, so a `src/Vault.sol:CONSOLIDATION_ROLE` constant is not read as a gate.
    """
    names = set()
    for row in rows or ():
        for token in row.get("guards") or ():
            text = str(token)
            if ":" in text:
                continue
            if any(cue in text.lower() for cue in AUTH_GUARD_CUES):
                names.add(text)
    return sorted(names)


def _is_test_path(path):
    """Tests, mocks and fixtures, by the cues `bounty._is_test_path` uses.

    They are kept - a mock is sometimes the only written statement of an assumption - but a
    bounded reading queue reads the production code first. `--scope src/` on a Foundry project
    whose tests live in `src/test` otherwise spends the budget on them: measured on Obol
    obol-splits, 17 of 151 rows sat in `src/test`, mocks included.
    """
    lowered = str(path or "").replace("\\", "/").lower()
    parts = [segment for segment in lowered.split("/") if segment]
    name = parts[-1] if parts else ""
    # Directory segments and the filename's own cues only. A substring test over the name would
    # read `Attestation.sol` as a test file.
    return (any(segment in _TEST_SEGMENTS for segment in parts[:-1])
            or "mock" in name or name.endswith((".t.sol", "test.sol", "tests.sol")))


def _src_key(node):
    return str(node.get("src") or "")


def _line_for(line_starts, path, src):
    """Best-effort line number from solc's byte offset when build-info includes source text."""
    starts = line_starts.get(str(path))
    if starts is None or not isinstance(src, str):
        return None
    try:
        offset = int(src.split(":", 1)[0])
    except ValueError:
        return None
    return bisect_right(starts, offset)


def _external_return_key(node, declaration, active, semantic):
    """Stable source key for a non-void call whose body is outside this AST model."""
    if node.get("nodeType") != "FunctionCall":
        return None
    target = _callee_target(node, semantic)
    expression = semantic._callee(node)
    if target in active or node.get("kind") == "typeConversion":
        return None
    if expression.get("nodeType") == "Identifier" and semantic._builtin(expression):
        return None
    base = expression.get("expression") or {}
    if (expression.get("nodeType") == "MemberAccess"
            and base.get("nodeType") == "Identifier" and semantic._builtin(base)
            and base.get("name") in ("abi", "bytes", "string")):
        return None
    type_string = str((node.get("typeDescriptions") or {}).get("typeString") or "")
    if not type_string or type_string in ("tuple()", "void"):
        return None
    return "external-return:%d:%s" % (declaration, _src_key(node))


def _variable_refs(expr, variable_ids, semantic, aliases=None, env_entries=None,
                   function_declaration=None, active=None):
    """Variable declarations and caller/environment values used by an expression."""
    aliases = aliases or {}
    refs = set()

    def add_environment(token):
        if not token:
            return
        if env_entries:
            refs.update("env:%s:%s" % (entry, token) for entry in env_entries)
        else:
            refs.add("env:" + token)

    for node in semantic.walk_json(expr or {}):
        kind = node.get("nodeType")
        if kind in ("Identifier", "MemberAccess"):
            ident = node.get("referencedDeclaration")
            if ident in variable_ids:
                refs.add(aliases.get(ident, ident))
        token = semantic._env_token(node)
        if token in ENV_SOURCE_NAMES:
            add_environment(token)
        if kind == "FunctionCall" and semantic._sender_call(node):
            add_environment("msg.sender")
        if function_declaration is not None and active is not None:
            external_return = _external_return_key(node, function_declaration,
                                                    active, semantic)
            if external_return:
                refs.add(external_return)
    return _stable(refs)


def _lhs_targets(expr, variable_ids, semantic, aliases=None):
    """Storage/local values written by an l-value; mapping keys are not destinations."""
    aliases = aliases or {}
    if not isinstance(expr, dict):
        return set()
    kind = expr.get("nodeType")
    if kind == "TupleExpression":
        result = set()
        for child in expr.get("components") or []:
            result |= _lhs_targets(child, variable_ids, semantic, aliases)
        return result
    if kind == "IndexAccess":
        return _lhs_targets(expr.get("baseExpression"), variable_ids, semantic, aliases)
    result = set()
    if kind in ("Identifier", "MemberAccess"):
        ident = expr.get("referencedDeclaration")
        if ident in variable_ids:
            result.add(aliases.get(ident, ident))
    if kind == "MemberAccess":
        result |= _lhs_targets(expr.get("expression"), variable_ids, semantic, aliases)
    return result


def _lhs_groups(expr, variable_ids, semantic, aliases=None):
    if isinstance(expr, dict) and expr.get("nodeType") == "TupleExpression":
        return [_lhs_targets(child, variable_ids, semantic, aliases)
                for child in expr.get("components") or []]
    return [_lhs_targets(expr, variable_ids, semantic, aliases)]


def _callee_target(call, semantic):
    expression = semantic._callee(call)
    return expression.get("referencedDeclaration")


def _function_label(symbols_by_decl, declaration, fallback):
    rows = symbols_by_decl.get(declaration) or []
    return str(rows[0].get("name") or fallback) if rows else fallback


def _sink_operands(call, semantic, params, state_info, libraries):
    """Sensitive values at a compiler-resolved sink, as (label, expression) pairs."""
    expression = semantic._callee(call)
    args = [a for a in call.get("arguments") or [] if isinstance(a, dict)]
    detail = semantic._call_sink(call, params, state_info, libraries)
    if detail:
        kind = detail.get("kind")
        if kind == "selfdestruct":
            return [("beneficiary", args[0])] if args else []
        if kind in ("low-level-call", "delegatecall", "callcode",
                    "address-functioncall", "address-functiondelegatecall"):
            base = expression.get("expression") or {}
            library = semantic._library_style(base, libraries)
            target = args[0] if library and args else base
            data = args[1:] if library else args[:1]
            result = [("target", target)] if isinstance(target, dict) else []
            result.extend(("calldata[%d]" % index, arg) for index, arg in enumerate(data))
            # solc wraps `addr.call{value: amount}` in FunctionCallOptions. The normal
            # callee helper unwraps that node, so read the option from the original call.
            option_node = call.get("expression") or {}
            while option_node.get("nodeType") == "FunctionCallOptions":
                names = option_node.get("names") or []
                values = option_node.get("options") or []
                result.extend(("native-value", value) for name, value in zip(names, values)
                              if name == "value" and isinstance(value, dict))
                option_node = option_node.get("expression") or {}
            if (library and expression.get("memberName") == "functionCallWithValue"
                    and len(args) > 2):
                result.append(("native-value", args[2]))
            return result
        if kind == "token-pull":
            base = expression.get("expression") or {}
            offset = 1 if semantic._library_style(base, libraries) else 0
            labels = ("from", "to", "amount", "data")
            token = args[0] if offset and args else base
            result = [("token", token)] if isinstance(token, dict) else []
            result.extend((labels[index] if index < len(labels) else "argument[%d]" % index, arg)
                          for index, arg in enumerate(args[offset:]))
            return result
        if kind == "permit":
            base = expression.get("expression") or {}
            offset = 1 if semantic._library_style(base, libraries) else 0
            token = args[0] if offset and args else base
            result = [("token", token)] if isinstance(token, dict) else []
            result.extend(("permit-argument[%d]" % index, arg)
                          for index, arg in enumerate(args[offset:]))
            return result

    # Native ETH sends expose both the recipient (the member-call base) and amount.
    # `transfer` is also an ERC-20 method, so classify it by the compiler's base type.
    if expression.get("nodeType") == "MemberAccess":
        member = expression.get("memberName")
        base = expression.get("expression") or {}
        base_type = str((base.get("typeDescriptions") or {}).get("typeString") or "")
        if member == "send" or (member == "transfer" and base_type.startswith("address")):
            result = [("recipient", base)] if isinstance(base, dict) else []
            if args:
                result.append(("amount", args[0]))
            return result
        if member in ("transfer", "safeTransfer"):
            library = semantic._library_style(base, libraries)
            offset = 1 if library else 0
            token = args[0] if offset and args else base
            labels = ("to", "amount", "data")
            result = [("token", token)] if isinstance(token, dict) else []
            result.extend((labels[index] if index < len(labels) else "argument[%d]" % index, arg)
                          for index, arg in enumerate(args[offset:]))
            return result

    # Existing impact families cover many named operations (withdraw, claim, upgrade, etc.).
    # Keep those as argument leads too, while the name is only a sink classifier.
    name = (expression.get("name") or expression.get("memberName") or "")
    normalized = str(name).lower().replace("_", "")
    terms = {term.replace("_", "") for values in semantic.SINK_TERMS.values() for term in values}
    if any(term in normalized for term in terms):
        return [("argument[%d]" % index, arg) for index, arg in enumerate(args)]
    return []


def _entry_symbols(symbols):
    """Compiler function declarations that can be reached as deployed public entries."""
    result = defaultdict(list)
    for symbol in symbols:
        declaration = symbol.get("declaration")
        if (symbol.get("language") != "solidity" or not isinstance(declaration, int)
                or not symbol.get("entry")):
            continue
        if symbol.get("scope_role") == "dependency" and not symbol.get("inherits"):
            continue
        if symbol.get("contract_deployable") or symbol.get("inherits"):
            result[declaration].append(symbol)
    return result


def analyze(trees, symbols, semantic, scope=None):
    """Trace bounded declaration-to-declaration flows in Solidity compiler ASTs.

    `scope` takes the same path prefixes as `impact-plan --scope`. Out-of-scope code is still
    traversed - a flow that passes through a vendored library and back into in-scope code is the
    interesting case - but a lead whose source and sink both sit outside the scope is counted and
    not written.
    """
    contents = getattr(trees, "contents", {})
    prefixes = [str(x) for x in (scope or []) if str(x).strip()]
    line_starts = {}
    for path, content in contents.items():
        encoded = content.encode("utf-8")
        starts, cursor = [0], 0
        while True:
            newline = encoded.find(b"\n", cursor)
            if newline < 0:
                break
            starts.append(newline + 1)
            cursor = newline + 1
        line_starts[str(path)] = starts
    function_nodes, function_paths, variable_info = {}, {}, {}
    state_ids, state_info, libraries = set(), {}, set()
    for path, tree in trees or []:
        for node in semantic.walk_json(tree):
            kind = node.get("nodeType")
            if kind == "ContractDefinition" and node.get("contractKind") == "library":
                if isinstance(node.get("id"), int):
                    libraries.add(node["id"])
            if kind == "VariableDeclaration" and isinstance(node.get("id"), int):
                ident = node["id"]
                variable_info[ident] = {"name": str(node.get("name") or "value_%d" % ident),
                                        "path": str(path),
                                        "state": bool(node.get("stateVariable")),
                                        "src": node.get("src")}
                if node.get("stateVariable"):
                    state_ids.add(ident)
                    mutability = node.get("mutability") or (
                        "constant" if node.get("constant") else "mutable")
                    state_info[ident] = (mutability if mutability in ("constant", "immutable")
                                         else "state")
            if kind == "FunctionDefinition" and isinstance(node.get("id"), int):
                declaration = node["id"]
                if node.get("implemented", True) and isinstance(node.get("body"), dict):
                    function_nodes[declaration] = node
                    function_paths[declaration] = str(path)

    symbols_by_decl = defaultdict(list)
    for symbol in symbols or []:
        declaration = symbol.get("declaration")
        if symbol.get("language") == "solidity" and isinstance(declaration, int):
            symbols_by_decl[declaration].append(symbol)
    for rows in symbols_by_decl.values():
        rows.sort(key=lambda row: not bool(row.get("contract_deployable")))
    active = set(function_nodes) & set(symbols_by_decl)
    entries = {ident: rows for ident, rows in _entry_symbols(symbols).items() if ident in active}
    if not active:
        return {"schema": 1, "method": "compiler-ast-declaration-flow", "status": "no-solidity-ast",
                "source_count": 0, "sink_count": 0, "lead_count": 0, "leads": [],
                "truncated": False, "scope_filter": prefixes or None,
                "sinks_with_leads": 0, "sinks_represented": 0,
                "sinks_in_test_paths": 0, "leads_in_test_paths": 0,
                "sinks_behind_an_access_modifier": 0, "leads_behind_an_access_modifier": 0,
                "leads_dropped_by_scope": 0, "leads_suppressed_by_sink_cap": 0,
                "notice": "No Solidity compiler AST functions were available; no taint analysis was run."}

    # Compiler declaration IDs are unique within the build-info output.
    variable_ids = set(variable_info)
    aliases = {}
    for declaration, function in function_nodes.items():
        if declaration not in active:
            continue
        for node in semantic.walk_json(function.get("body") or {}):
            if node.get("nodeType") != "VariableDeclarationStatement":
                continue
            value = node.get("initialValue") or {}
            for local in node.get("declarations") or []:
                if not isinstance(local, dict) or local.get("storageLocation") != "storage":
                    continue
                local_id = local.get("id")
                if not isinstance(local_id, int):
                    continue
                roots = set(_variable_refs(value, variable_ids, semantic, aliases)) & state_ids
                if roots:
                    aliases[local_id] = sorted(roots)[0]

    # Reachability is only a syntactic call-reference closure. It limits environmental sources;
    # it does not assert that runtime control flow or modifiers permit the call.
    calls_by_function = defaultdict(set)
    calls = {}
    for declaration in active:
        function = function_nodes[declaration]
        for node in semantic.walk_json(function.get("body") or {}):
            if node.get("nodeType") != "FunctionCall":
                continue
            target = _callee_target(node, semantic)
            if target in active:
                calls_by_function[declaration].add(target)
                calls[(declaration, _src_key(node))] = node
    reachable_entries = defaultdict(set)
    queue = deque()
    for declaration in entries:
        reachable_entries[declaration].add(declaration)
        queue.append(declaration)
    while queue:
        caller = queue.popleft()
        for callee in calls_by_function.get(caller, ()):
            added = reachable_entries[callee] | reachable_entries[caller]
            if added != reachable_entries[callee]:
                reachable_entries[callee] = added
                queue.append(callee)
    reachable = set(reachable_entries)

    # Seed public parameters and environment values at entry/reachable functions.
    seeds = defaultdict(list)
    seed_labels = {}
    for declaration, rows in entries.items():
        function = function_nodes[declaration]
        params = ((function.get("parameters") or {}).get("parameters") or [])
        for index, param in enumerate(params):
            ident = param.get("id") if isinstance(param, dict) else None
            if ident not in variable_ids:
                continue
            label = {"kind": "external-parameter", "function": _function_label(
                        symbols_by_decl, declaration, str(function.get("name") or "function")),
                     "parameter": str(param.get("name") or "arg_%d" % index),
                     "path": function_paths[declaration], "src": param.get("src"),
                     "line": _line_for(line_starts, function_paths[declaration], param.get("src")),
                     "entry": True}
            seeds[ident].append(label)
            seed_labels[ident] = variable_info.get(ident, {}).get("name", label["parameter"])

    for declaration in reachable:
        function = function_nodes[declaration]
        for node in semantic.walk_json(function.get("body") or {}):
            token = semantic._env_token(node)
            if token not in ENV_SOURCE_NAMES:
                if node.get("nodeType") == "FunctionCall" and semantic._sender_call(node):
                    token = "msg.sender"
                else:
                    continue
            entry_declarations = sorted(reachable_entries[declaration])
            entry_names = sorted({str(row.get("name")) for entry in reachable_entries[declaration]
                                  for row in entries.get(entry, [])})
            for entry in entry_declarations:
                key = "env:%s:%s" % (entry, token)
                label = {"kind": token, "function": _function_label(
                            symbols_by_decl, declaration,
                            str(function.get("name") or "function")),
                         "entry": _function_label(symbols_by_decl, entry, str(entry)),
                         "path": function_paths[declaration], "src": node.get("src"),
                         "line": _line_for(line_starts, function_paths[declaration],
                                           node.get("src")),
                         "reachable_entries": entry_names[:5]}
                # Environment values are shared only across functions reachable from the
                # same external entry. A msg.sender read in one public method must not become
                # an apparent source for a different method (or another transaction).
                seeds[key].append(label)
                seed_labels[key] = token

    # Every public entry that reaches a sink, and whether all of them read as access-checked.
    # Row one of two real queues was a call the deployment already restricts -
    # `ObolValidatorManager.consolidate` (`onlyOwnerOrRoles`) on Obol obol-splits,
    # `OUSDaiUtility.rescueETH` (`onlyAdmin`) on USDai - so a modifier-blind reading order spends
    # a reader's first minutes there.
    entry_guards = {declaration: _auth_guards(rows) for declaration, rows in entries.items()}

    def _gating(declaration):
        reached = sorted(set(reachable_entries[declaration]) & set(entry_guards))
        names = sorted({name for entry in reached for name in entry_guards[entry]})
        return (bool(reached) and all(entry_guards[entry] for entry in reached), names[:5])

    incoming = defaultdict(list)
    edge_count = 0
    graph_truncated = False

    def add_flow(source, target, kind, declaration, node):
        nonlocal edge_count, graph_truncated
        if source is None or target is None or source == target:
            return
        if edge_count >= MAX_FLOW_EDGES:
            graph_truncated = True
            return
        function = function_nodes[declaration]
        edge = {"from": source, "to": target, "kind": kind,
                "function": _function_label(symbols_by_decl, declaration,
                                            str(function.get("name") or "function")),
                "path": function_paths[declaration], "src": node.get("src"),
                "line": _line_for(line_starts, function_paths[declaration], node.get("src"))}
        incoming[target].append(edge)
        edge_count += 1

    sinks = []
    for declaration in sorted(reachable):
        function = function_nodes[declaration]
        params = {p.get("id") for p in ((function.get("parameters") or {}).get("parameters") or [])
                  if isinstance(p, dict)}
        body = function.get("body") or {}
        return_params = ((function.get("returnParameters") or {}).get("parameters") or [])

        for node in semantic.walk_json(body):
            kind = node.get("nodeType")
            if kind == "VariableDeclarationStatement":
                targets = [({aliases.get(d.get("id"), d.get("id"))}
                            if isinstance(d, dict) and d.get("id") in variable_ids else set())
                           for d in node.get("declarations") or []]
                value = node.get("initialValue") or {}
                sources = _variable_refs(value, variable_ids, semantic, aliases,
                                         reachable_entries[declaration], declaration, active)
                for target_set in targets:
                    for source in sources:
                        for target in target_set:
                            add_flow(source, target,
                                     "persistent-state-write" if target in state_ids else "assignment",
                                     declaration, node)
                if value.get("nodeType") == "FunctionCall":
                    callee = _callee_target(value, semantic)
                    callee_node = function_nodes.get(callee)
                    returns = ((callee_node.get("returnParameters") or {}).get("parameters") or []) \
                        if callee_node else []
                    for index, target_set in enumerate(targets):
                        if index < len(returns):
                            ret_id = returns[index].get("id")
                            for target in target_set:
                                add_flow(ret_id, target, "call-return", declaration, node)

            elif kind == "Assignment":
                targets = _lhs_targets(node.get("leftHandSide"), variable_ids, semantic, aliases)
                target_groups = _lhs_groups(node.get("leftHandSide"), variable_ids,
                                            semantic, aliases)
                sources = _variable_refs(node.get("rightHandSide"), variable_ids, semantic, aliases,
                                         reachable_entries[declaration], declaration, active)
                if node.get("operator") != "=":
                    # A compound assignment reads its own left side; merge through `_stable` so the
                    # union cannot reintroduce a hash-dependent order.
                    sources = _stable(set(sources) | set(_variable_refs(
                        node.get("leftHandSide"), variable_ids, semantic, aliases,
                        reachable_entries[declaration], declaration, active)))
                for source in sources:
                    for target in targets:
                        add_flow(source, target,
                                 "persistent-state-write" if target in state_ids else "assignment",
                                 declaration, node)
                for target in targets & state_ids:
                    state_name = variable_info.get(target, {}).get("name", "").lower().replace("_", "")
                    if sources and any(term in state_name for term in SENSITIVE_STATE_TERMS):
                        sinks.append({"function_id": declaration,
                                      "function": _function_label(symbols_by_decl, declaration,
                                          str(function.get("name") or "function")),
                                      "path": function_paths[declaration],
                                      "kind": "sensitive-state-write",
                                      "entries_all_gated": _gating(declaration)[0],
                                      "entry_auth_modifiers": _gating(declaration)[1],
                                      "member": variable_info.get(target, {}).get("name", "state"),
                                      "operand": "write:%s" % variable_info.get(target, {}).get("name", "state"),
                                      "src": node.get("src"),
                                      "line": _line_for(line_starts, function_paths[declaration],
                                                        node.get("src")),
                                      "references": [target],
                                      "reachable_entries": sorted({str(row.get("name"))
                                          for entry in reachable_entries[declaration]
                                          for row in entries.get(entry, [])})[:5]})
                value = node.get("rightHandSide") or {}
                if value.get("nodeType") == "FunctionCall":
                    callee = _callee_target(value, semantic)
                    callee_node = function_nodes.get(callee)
                    returns = ((callee_node.get("returnParameters") or {}).get("parameters") or []) \
                        if callee_node else []
                    for index, ret in enumerate(returns):
                        if index >= len(target_groups):
                            break
                        ret_id = ret.get("id")
                        for target in target_groups[index]:
                            add_flow(ret_id, target, "call-return", declaration, node)

            elif kind == "Return":
                values = node.get("expression") or {}
                value_groups = ([component for component in values.get("components") or []]
                                if values.get("nodeType") == "TupleExpression" else [values])
                for index, ret in enumerate(return_params):
                    if index >= len(value_groups):
                        break
                    ret_id = ret.get("id") if isinstance(ret, dict) else None
                    if ret_id in variable_ids:
                        sources = _variable_refs(value_groups[index], variable_ids,
                                                 semantic, aliases,
                                                 reachable_entries[declaration], declaration,
                                                 active)
                        for source in sources:
                            add_flow(source, ret_id, "return", declaration, node)

            elif kind == "FunctionCall":
                for operand, expr in _sink_operands(node, semantic, params, state_info, libraries):
                    refs = _variable_refs(expr, variable_ids, semantic, aliases,
                                          reachable_entries[declaration], declaration, active)
                    if refs:
                        expression = semantic._callee(node)
                        call_detail = semantic._call_sink(node, params, state_info, libraries)
                        member = semantic._callee(node).get("memberName")
                        base = (semantic._callee(node).get("expression") or {})
                        base_type = str((base.get("typeDescriptions") or {}).get("typeString") or "")
                        sink_kind = ((call_detail or {}).get("kind")
                                     or ("native-transfer" if member == "send" or
                                         (member == "transfer" and
                                          base_type.startswith("address")) else
                                         "token-transfer" if member in
                                         ("transfer", "safeTransfer") else "value-operation"))
                        sinks.append({"function_id": declaration,
                                      "function": _function_label(symbols_by_decl, declaration,
                                          str(function.get("name") or "function")),
                                      "path": function_paths[declaration],
                                      "kind": sink_kind,
                                      "entries_all_gated": _gating(declaration)[0],
                                      "entry_auth_modifiers": _gating(declaration)[1],
                                      "member": str(expression.get("memberName")
                                                    or expression.get("name") or "call"),
                                      "operand": operand, "src": node.get("src"),
                                      "line": _line_for(line_starts, function_paths[declaration],
                                                        node.get("src")),
                                      "references": _stable(refs),
                                      "reachable_entries": sorted({str(row.get("name"))
                                          for entry in reachable_entries[declaration]
                                          for row in entries.get(entry, [])})[:5]})

    # Link internal-call parameters after all bodies are indexed; these edges preserve the
    # call-site source span, so the reader can check the argument mapping in context.
    for (caller, _), call in calls.items():
        if caller not in reachable:
            continue
        callee = _callee_target(call, semantic)
        if callee not in reachable:
            continue
        target_params = ((function_nodes[callee].get("parameters") or {}).get("parameters") or [])
        for index, argument in enumerate(call.get("arguments") or []):
            if index >= len(target_params) or not isinstance(argument, dict):
                continue
            target = target_params[index].get("id")
            for source in _variable_refs(argument, variable_ids, semantic, aliases,
                                         reachable_entries[caller], caller, active):
                add_flow(source, target, "call-argument", caller, call)

    # External return values are an independent trust boundary, including when nested directly
    # inside an expression or passed to a sensitive operation without a temporary variable.
    for declaration in sorted(reachable):
        function = function_nodes[declaration]
        for node in semantic.walk_json(function.get("body") or {}):
            key = _external_return_key(node, declaration, active, semantic)
            if not key:
                continue
            expression = semantic._callee(node)
            seeds[key].append({"kind": "external-return", "function": _function_label(
                symbols_by_decl, declaration, str(function.get("name") or "function")),
                "path": function_paths[declaration], "src": node.get("src"),
                "line": _line_for(line_starts, function_paths[declaration], node.get("src")),
                "callee": str(semantic._callee(node).get("memberName")
                              or semantic._callee(node).get("name") or "external call")})
            seed_labels[key] = "external return value"

    # Control takeover ahead of an arbitrary call, an arbitrary call ahead of a token move. With
    # one rank for both, thousands of vendored `address-functioncall` rows outran the handful of
    # delegatecall and selfdestruct leads a 500-row window has to show.
    sink_rank = {"delegatecall": 0, "callcode": 0, "assembly-delegatecall": 0,
                 "address-functiondelegatecall": 0, "selfdestruct": 0,
                 "low-level-call": 1, "address-functioncall": 1, "native-transfer": 1,
                 "token-pull": 2, "permit": 2, "token-transfer": 2,
                 "sensitive-state-write": 2, "value-operation": 3}
    for row in sinks:
        row["scope_role"] = "in-scope" if _in_scope(row["path"], prefixes) else "dependency"
        row["test_path"] = _is_test_path(row["path"])
    # In-scope sinks are enumerated first. Ordering on the path alone put `@openzeppelin/...`
    # ahead of `contracts/...` and handed the whole budget to the vendored tree.
    sinks.sort(key=lambda row: (0 if row["scope_role"] == "in-scope" else 1,
                                1 if row["test_path"] else 0,
                                sink_rank.get(row["kind"], 3), row["path"],
                                str(row["src"] or ""), row["operand"]))
    leads = []
    lead_keys = set()
    sink_count = len(sinks)
    dropped_by_scope = 0
    per_sink = []
    if len(sinks) > MAX_SINKS:
        graph_truncated = True
    for sink in sinks[:MAX_SINKS]:
        candidates = []
        for destination in sink["references"]:
            if len(candidates) >= MAX_SINK_CANDIDATES:
                break
            queue = deque([(destination, [])])
            visited = {destination}
            steps = 0
            while queue:
                current, reversed_path = queue.popleft()
                steps += 1
                if steps > MAX_REVERSE_STEPS:
                    graph_truncated = True
                    break
                if current in seeds:
                    for source in seeds[current]:
                        key = (source.get("kind"), source.get("function"), source.get("src"),
                               source.get("entry"),
                               sink["function_id"], sink["src"], sink["operand"])
                        if key in lead_keys:
                            continue
                        source_role = ("in-scope" if _in_scope(source.get("path"), prefixes)
                                       else "dependency")
                        if (prefixes and source_role == "dependency"
                                and sink["scope_role"] == "dependency"):
                            # Neither end touches the declared scope: a vendored library calling
                            # itself, or a mock. Counted, never written.
                            dropped_by_scope += 1
                            continue
                        lead_keys.add(key)
                        path = list(reversed(reversed_path))
                        candidates.append({
                            "source": dict(source, value=seed_labels.get(current,
                                                       variable_info.get(current, {}).get("name", "value")),
                                           scope_role=source_role),
                            "sink": {name: sink[name] for name in (
                                "function", "path", "kind", "member", "operand", "src",
                                "line", "scope_role", "test_path", "entries_all_gated",
                                "entry_auth_modifiers", "reachable_entries")},
                            "flow": [{"from": _value_label(edge["from"], variable_info, seed_labels),
                                      "to": _value_label(edge["to"], variable_info, seed_labels),
                                      "kind": edge["kind"], "function": edge["function"],
                                      "path": edge["path"], "src": edge["src"],
                                      "line": edge["line"]}
                                     for edge in path],
                            "crosses_persistent_state": any(
                                edge["kind"] == "persistent-state-write" for edge in path),
                            "confidence": "static-taint-lead",
                            "review": ["confirm each assignment/call argument at its source span",
                                       "check guards, reachability, ordering and the protected control",
                                       "prove a violated invariant and third-party impact"]})
                        if len(candidates) >= MAX_SINK_CANDIDATES:
                            break
                    if len(candidates) >= MAX_SINK_CANDIDATES:
                        break
                    continue
                if len(reversed_path) >= MAX_PATH_DEPTH:
                    continue
                for edge in incoming.get(current, ()):
                    previous = edge["from"]
                    if previous in visited:
                        continue
                    visited.add(previous)
                    queue.append((previous, reversed_path + [edge]))
                if len(queue) > MAX_REVERSE_STEPS:
                    graph_truncated = True
                    break
        if candidates:
            candidates.sort(key=_lead_order)
            per_sink.append(candidates)

    # Round one gives every sink its single best lead, later rounds spend what is left. The cap
    # can no longer go entirely to whichever sink happened to be enumerated first.
    sinks_represented = 0
    suppressed_by_sink_cap = sum(max(0, len(rows) - MAX_LEADS_PER_SINK) for rows in per_sink)
    budget_spent = False
    for depth in range(MAX_LEADS_PER_SINK):
        if budget_spent:
            break
        for candidates in per_sink:
            if depth >= len(candidates):
                continue
            if len(leads) >= MAX_LEADS:
                budget_spent = graph_truncated = True
                break
            leads.append(candidates[depth])
            if depth == 0:
                sinks_represented += 1
    if suppressed_by_sink_cap:
        graph_truncated = True

    leads.sort(key=_lead_order)
    return {"schema": 1, "method": "compiler-ast-declaration-flow",
            "status": "analyzed", "source_count": len(seeds), "sink_count": sink_count,
            "flow_edge_count": edge_count, "lead_count": len(leads), "leads": leads,
            "truncated": graph_truncated, "scope_filter": prefixes or None,
            "sinks_with_leads": len(per_sink), "sinks_represented": sinks_represented,
            "sinks_in_test_paths": sum(1 for row in sinks if row.get("test_path")),
            "sinks_behind_an_access_modifier": sum(1 for row in sinks
                                                   if row.get("entries_all_gated")),
            "leads_behind_an_access_modifier": sum(1 for row in leads
                                                   if row["sink"].get("entries_all_gated")),
            "leads_in_test_paths": sum(1 for row in leads if row["sink"].get("test_path")),
            "leads_dropped_by_scope": dropped_by_scope,
            "leads_suppressed_by_sink_cap": suppressed_by_sink_cap,
            "limits": {"flow_edges": MAX_FLOW_EDGES, "leads": MAX_LEADS,
                       "leads_per_sink": MAX_LEADS_PER_SINK,
                       "sink_candidates": MAX_SINK_CANDIDATES, "sinks": MAX_SINKS,
                       "path_depth": MAX_PATH_DEPTH},
            "notice": "Static declaration-level flow hints only. No control-flow, modifier, "
                      "alias-completeness, arithmetic-safety, runtime reachability or exploit "
                      "claim is established. Rows are ordered for reading, not severity. "
                      "Persistent-state paths may require multiple transactions. External-call "
                      "operands are reported as boundaries; remote callee bodies and cross-contract "
                      "state are not traversed. Dynamic dispatch, assembly, external state and "
                      "unsupported compiler output can hide or distort paths; confirm every hop in "
                      "source. Each sink contributes at most `limits.leads_per_sink` rows and "
                      "in-scope sinks are read first; `sinks_with_leads`, `sinks_represented`, "
                      "`leads_dropped_by_scope` and `leads_suppressed_by_sink_cap` state what the "
                      "caps left out, and a lead whose source and sink both sit outside `scope_filter` "
                      "is never written. Tests, mocks and fixtures are kept but read last "
                      "within each scope role (`sink.test_path`, `sinks_in_test_paths`, "
                      "`leads_in_test_paths`; the two together are what a zero means - "
                      "`sinks_in_test_paths: 0` is a scope with no test material, while "
                      "`leads_in_test_paths: 0` beside a non-zero sink count means the cap bound "
                      "and production code took every row), and a sink every reaching entry gates with a "
                      "modifier that reads like an access check is read after the ungated ones "
                      "and counted (`sink.entries_all_gated`, `sink.entry_auth_modifiers`, "
                      "`sinks_behind_an_access_modifier`, `leads_behind_an_access_modifier`). "
                      "The gate changes the reading order only: it never decides which rows are "
                      "written. Both flags are cues - read the gate at its source span, and note "
                      "that one ungated entry added later un-gates the sink."}


def _value_label(value, variable_info, seed_labels):
    if value in variable_info:
        info = variable_info[value]
        return ("state:" if info["state"] else "value:") + info["name"]
    return seed_labels.get(value, str(value))


def _lead_order(row):
    # Control takeover ahead of an arbitrary call, an arbitrary call ahead of a token move. With
    # one rank for both, thousands of vendored `address-functioncall` rows outran the handful of
    # delegatecall and selfdestruct leads a 500-row window has to show.
    sink_rank = {"delegatecall": 0, "callcode": 0, "assembly-delegatecall": 0,
                 "address-functiondelegatecall": 0, "selfdestruct": 0,
                 "low-level-call": 1, "address-functioncall": 1, "native-transfer": 1,
                 "token-pull": 2, "permit": 2, "token-transfer": 2,
                 "sensitive-state-write": 2, "value-operation": 3}
    source_rank = {"external-parameter": 0, "msg.sender": 1, "tx.origin": 1,
                   "msg.value": 1, "external-return": 2,
                   "block.timestamp": 3, "block.number": 3}
    scope_rank = {"in-scope": 0, "dependency": 1}
    source = row["source"]
    sink = row["sink"]
    # The declared scope decides first: a lead that stays inside a vendored dependency is reading
    # material only once the in-scope ones are exhausted.
    return (scope_rank.get(sink.get("scope_role"), 0),
            1 if sink.get("test_path") else 0,
            # The gate ranks a row down and nothing else. It is deliberately absent from the sink
            # enumeration above, so which sinks get a row - and how many - is what it was without
            # it: on the unscoped Boson artifact round one already truncates at 500 of 714 sinks,
            # and demoting a gated sink there would have removed it from the file instead.
            1 if sink.get("entries_all_gated") else 0,
            scope_rank.get(source.get("scope_role"), 0),
            sink_rank.get(sink["kind"], 3), row["crosses_persistent_state"],
            source_rank.get(source["kind"], 4), len(row["flow"]), sink["path"],
            sink["line"] or 0, source.get("path", ""), source.get("line") or 0,
            # The keys above tie often - 40 of 151 obol-splits rows and 134 of 500 Boson rows
            # sit in a tied group - and `sort` is stable, so a tie left the row order to the
            # order the flow edges happened to be registered in. The rest of the row decides
            # it instead, which also makes candidate selection inside one sink total.
            str(sink.get("member") or ""), str(sink.get("operand") or ""),
            str(sink.get("src") or ""), str(source.get("function") or ""),
            str(source.get("entry") or ""), str(source.get("src") or ""),
            tuple((str(edge.get("kind") or ""), str(edge.get("src") or ""))
                  for edge in row["flow"]))
