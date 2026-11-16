#!/usr/bin/env python3
"""Offline Smali descriptor-bound static call review, not runtime evidence.

The parser supports only acyclic forward if-eqz/if-nez and goto joins;
backward jumps, exception edges and unrecognized instructions fail closed.
Only exact static String-typed call/return declarations in indexed source
can receive a tainted register. Sources and sinks are Android API descriptor
syntax cues, not verified caller control or effects.
"""
import hashlib
import re
from pathlib import Path

import mobile_lab

MAX_FILES = 500
MAX_BYTES = 8 * 1024 * 1024
MAX_FILE_BYTES = 350000
MAX_METHODS = 3000
MAX_STEPS = 12000
MAX_HOPS = 6
MAX_CALL_DEPTH = 3
MAX_LEADS = 120

CLASS = re.compile(r"(?m)^\.class\s+[^\n]*?\s+(L[A-Za-z0-9_/$-]+;)\s*$")
METHOD = re.compile(
    r"(?ms)^\.method\s+([^\n]*?)\s+([A-Za-z_$<>][\w$<>-]*)"
    r"\(([^)\n]*)\)(\S+)\s*\n(.*?)^\.end method\s*$"
)
INVOKE = re.compile(
    r"^invoke-(virtual|static|direct|super|interface)(/range)?"
    r"\s+\{([^}]*)\},\s*(L[A-Za-z0-9_/$-]+;)->"
    r"([A-Za-z_$<>][\w$<>-]*)\(([^)]*)\)(\S+)$"
)
REGISTER = r"[vp]\d+"
MOVE = re.compile(r"^move-object(?:/from16|/16)?\s+(" + REGISTER
                  + r"),\s*(" + REGISTER + r")$")
MOVE_RESULT = re.compile(r"^move-result-object\s+(" + REGISTER + r")$")
RETURN_OBJECT = re.compile(r"^return-object\s+(" + REGISTER + r")$")
KILL = re.compile(r"^(?:const(?:/4|/16|/high16|-wide(?:/16|/32|/high16)?|"
                  r"-string(?:/jumbo)?|-class)?|new-instance|move(?:/from16|/16)?)"
                  r"\s+(" + REGISTER + r")(?:\s*,|\s*$)")
SOURCE_METHODS = {
    ("Landroid/content/Intent;", "getDataString", "", "Ljava/lang/String;"),
    ("Landroid/content/Intent;", "getStringExtra",
     "Ljava/lang/String;", "Ljava/lang/String;"),
}
INTENT_METHODS = {
    ("Landroid/app/Activity;", "getIntent", "", "Landroid/content/Intent;"),
    ("Landroidx/activity/ComponentActivity;", "getIntent", "",
     "Landroid/content/Intent;"),
}
SINK_METHODS = {
    ("Landroid/webkit/WebView;", "loadUrl", "Ljava/lang/String;", "V"):
    "WEBVIEW_LOAD",
}
STATIC_PARAM = "Ljava/lang/String;"
BAD_CONTROL = re.compile(r"^(?:[:.]catch|:|if-|goto(?:/|$)|packed-switch|sparse-switch|"
                         r"monitor-|throw|fill-array-data|:try_|:catch_|move-exception)")
IGNORED = re.compile(r"^\.(?:locals|registers|line|prologue|epilogue|param|end param|"
                     r"local|end local|restart local|source|annotation|end annotation)\b")
SAFE_NOP = {"nop", "return-void"}
# Deliberately no switch, try/catch, arbitrary comparisons or loops.
CFG_LABEL = re.compile(r"^:([A-Za-z_$][\\w$]*)$")
CFG_IF = re.compile(r"^if-(?:eqz|nez)\\s+([vp]\\d+),\\s*:([A-Za-z_$][\\w$]*)$")
CFG_GOTO = re.compile(r"^goto(?:/16|/32)?\\s+:([A-Za-z_$][\\w$]*)$")
MAX_BRANCHES = 24


def _index(root):
    classes = {}
    duplicates = set()
    count = total = skipped = 0
    truncated = False
    for path in sorted(root.rglob("*.smali")):
        if path.is_symlink() or not path.is_file() or any(
                p.is_symlink() for p in path.parents if p != root):
            skipped += 1
            continue
        if count >= MAX_FILES or total >= MAX_BYTES:
            truncated = True
            break
        if path.stat().st_size > MAX_FILE_BYTES:
            truncated = True
            skipped += 1
            continue
        data = mobile_lab._regular_file(path, MAX_FILE_BYTES)
        if total + len(data) > MAX_BYTES:
            truncated = True
            break
        total += len(data)
        count += 1
        try:
            source = data.decode("utf-8")
        except UnicodeDecodeError:
            skipped += 1
            continue
        classes_found = CLASS.findall(source)
        if len(classes_found) != 1:
            skipped += 1
            continue
        descriptor = classes_found[0]
        if descriptor in classes:
            duplicates.add(descriptor)
            continue
        methods = {}
        for found in METHOD.finditer(source):
            signature = (found.group(2), found.group(3), found.group(4))
            if signature in methods:
                methods[signature] = None  # ambiguity: fail closed
                continue
            code = []
            line0 = source.count("\n", 0, found.start(5)) + 1
            for offset, raw in enumerate(found.group(5).splitlines()):
                text = raw.split("#", 1)[0].strip()
                if text:
                    code.append((line0 + offset, text))
            methods[signature] = {
                "name": found.group(2), "params": found.group(3),
                "return": found.group(4),
                "static": "static" in found.group(1).split(),
                "line": source.count("\n", 0, found.start()) + 1,
                "body": code,
                "signature": signature,
            }
            if sum(len(e["methods"]) for e in classes.values()) + len(methods) > MAX_METHODS:
                truncated = True
                break
        if truncated:
            break
        classes[descriptor] = {
            "file": path.relative_to(root).as_posix(),
            "sha256": hashlib.sha256(data).hexdigest(),
            "methods": methods,
        }
    for descriptor in duplicates:
        classes.pop(descriptor, None)
    return classes, {
        "files_scanned": count, "bytes_scanned": total,
        "indexed_classes": len(classes), "duplicate_class_descriptors": len(duplicates),
        "skipped_files": skipped, "truncated": truncated,
    }


def _registers(raw, is_range=False):
    if is_range:
        found = re.fullmatch(r"([vp])(\d+)\s*\.\.\s*([vp])(\d+)", raw.strip())
        if not found or found.group(1) != found.group(3):
            return None
        prefix, first, last = found.group(1), int(found.group(2)), int(found.group(4))
        if first > last or last - first > 7:
            return None
        return [f"{prefix}{n}" for n in range(first, last + 1)]
    values = [a.strip() for a in raw.split(",")] if raw.strip() else []
    if any(not re.fullmatch(REGISTER, x) for x in values):
        return None
    return values


def _method_descriptor(owner, method):
    name, params, ret = method["signature"]
    return owner + "->" + name + "(" + params + ")" + ret


def _return_summary(method, origin):
    """One pure String-to-String static helper with an exact final return.

    No loops, exceptions, calls, heap effects, check-casts, or registers
    outside explicit object moves and constant writes.
    """
    if (not method or not method["static"]
            or method["params"] != STATIC_PARAM
            or method["return"] != STATIC_PARAM
            or not _supported(method)):
        return None
    values = {"p0": origin}
    meaningful = [(line, op) for line, op in method["body"] if not IGNORED.match(op)]
    if not meaningful or len(meaningful) > 64:
        return None
    result = None
    for i, (line, op) in enumerate(meaningful):
        ret = RETURN_OBJECT.fullmatch(op)
        if ret:
            if i != len(meaningful) - 1:
                return None
            result = values.get(ret.group(1))
            return (result, line) if result is not None else None
        moved = MOVE.fullmatch(op)
        if moved:
            dst, src = moved.groups()
            if src in values:
                values[dst] = values[src]
            else:
                values.pop(dst, None)
            continue
        killed = KILL.match(op)
        if killed and op.startswith(("const", "move ")):
            values.pop(killed.group(1), None)
            continue
        return None
    return None


def _valid_route(route, sink_descriptor):
    if not route or len(route) > MAX_HOPS:
        return False
    stack = [route[0]["caller_descriptor"]]
    for edge in route:
        if edge["caller_descriptor"] != stack[-1]:
            return False
        target = edge["callee_descriptor"]
        if edge["edge_kind"] == "STATIC_CALL":
            stack.append(target)
        elif edge["edge_kind"] == "RETURN_TO_CALLER":
            if len(stack) < 2 or stack[-2] != target:
                return False
            stack.pop()
        else:
            return False
    return stack[-1] == sink_descriptor


def _supported(method):
    """Reject entire methods with branches or operations we cannot model."""
    code = method["body"]
    if len(code) > 300:
        return False
    for _, op in code:
        if IGNORED.match(op):
            continue
        if BAD_CONTROL.match(op) or op.startswith("."):
            return False
        if op in SAFE_NOP:
            continue
        if (INVOKE.fullmatch(op) or MOVE.fullmatch(op)
                or MOVE_RESULT.fullmatch(op) or RETURN_OBJECT.fullmatch(op)):
            continue
        if KILL.match(op):
            continue
        return False
    return True



def _cfg(method):
    """Validate and build a *forward-only* Smali instruction DAG.

    Edges must strictly increase the instruction index. All instructions in
    the method, including unreachable ones, must be from the supported subset.
    A branch target must be a unique in-method label. This never resolves a
    loop, switch, exception handler, synchronized block, or runtime path.
    """
    body = [(line, op) for line, op in method["body"] if not IGNORED.match(op)]
    if not body or len(body) > 300:
        return None
    labels = {}
    control = 0
    for i, (_, op) in enumerate(body):
        label = CFG_LABEL.fullmatch(op)
        if label:
            if label.group(1) in labels:
                return None
            labels[label.group(1)] = i
            continue
        if CFG_IF.fullmatch(op) or CFG_GOTO.fullmatch(op):
            control += 1
            if control > MAX_BRANCHES:
                return None
            continue
        if (BAD_CONTROL.match(op) or op.startswith(".")
                or op.startswith(":")):
            return None
        if (op in SAFE_NOP or INVOKE.fullmatch(op) or MOVE.fullmatch(op)
                or MOVE_RESULT.fullmatch(op) or RETURN_OBJECT.fullmatch(op)
                or KILL.match(op)):
            continue
        return None
    successors = []
    for i, (_, op) in enumerate(body):
        cond = CFG_IF.fullmatch(op)
        jump = CFG_GOTO.fullmatch(op)
        if cond or jump:
            label = (cond.group(2) if cond else jump.group(1))
            target = labels.get(label)
            if target is None or target <= i:  # no backward jumps or cycles
                return None
            following = [target]
            if cond and i + 1 < len(body):
                following.append(i + 1)
            successors.append(tuple(sorted(set(following))))
        elif op == "return-void" or RETURN_OBJECT.fullmatch(op):
            successors.append(())
        else:
            successors.append((i + 1,) if i + 1 < len(body) else ())
    return body, successors


def _must_join(left, right):
    """Intersect definite register origins at DAG joins, never union them."""
    a, pending_a = left
    b, pending_b = right
    common = {reg: origin for reg, origin in a.items()
              if reg in b and b[reg] == origin}
    pending = pending_a if pending_a == pending_b else None
    return common, pending

def analyze(sources, max_leads=MAX_LEADS):
    if type(max_leads) is not int or not 1 <= max_leads <= MAX_LEADS:
        raise ValueError("max_leads must be an integer between 1 and 120")
    supplied = Path(sources).expanduser().absolute()
    if supplied.is_symlink() or not supplied.is_dir():
        raise ValueError("Smali source root must be a non-symlink directory")
    root = supplied.resolve(strict=True)
    classes, coverage = _index(root)
    leads, seen = [], set()
    steps = 0
    unsupported = 0

    cfg_methods = 0
    cfg_joins = 0

    def walk(descriptor, method, origin_regs, hops, visited):
        nonlocal steps, unsupported, cfg_methods, cfg_joins
        owner = classes[descriptor]
        key = (descriptor, method["signature"])
        if key in visited or len(hops) > MAX_CALL_DEPTH:
            return
        plan = _cfg(method)
        if plan is None:
            unsupported += 1
            return
        body, successors = plan
        if any(CFG_IF.fullmatch(op) or CFG_GOTO.fullmatch(op) for _, op in body):
            cfg_methods += 1
        visited = visited | {key}
        # Every edge is forward, so ascending instruction order processes
        # ALL reachable predecessors before a join is evaluated.
        incoming = {0: (dict(origin_regs), None)}
        indegree = [0] * len(body)
        for successors_here in successors:
            for target in successors_here:
                indegree[target] += 1
        cfg_joins += sum(degree > 1 for degree in indegree)
        for index, (line, op) in enumerate(body):
            state = incoming.get(index)
            if state is None:
                continue
            steps += 1
            if steps >= MAX_STEPS or len(leads) >= max_leads:
                coverage["truncated"] = True
                return
            registers, pending = dict(state[0]), state[1]
            if (CFG_LABEL.fullmatch(op) or CFG_IF.fullmatch(op)
                    or CFG_GOTO.fullmatch(op) or op == "nop"):
                # No move-result after a branch, jump, label or executable NOP.
                pending = None
            elif op == "return-void" or RETURN_OBJECT.fullmatch(op):
                continue
            elif MOVE_RESULT.fullmatch(op):
                moved = MOVE_RESULT.fullmatch(op)
                if pending is None:
                    registers.pop(moved.group(1), None)
                else:
                    registers[moved.group(1)] = pending
                pending = None
            elif MOVE.fullmatch(op):
                pending = None
                dest, src = MOVE.fullmatch(op).groups()
                if src in registers:
                    registers[dest] = registers[src]
                else:
                    registers.pop(dest, None)
            elif KILL.match(op):
                pending = None
                registers.pop(KILL.match(op).group(1), None)
            else:
                pending = None
                call = INVOKE.fullmatch(op)
                if call is None:
                    return
                kind, range_mode, raw_args, callee_class, name, params, ret = call.groups()
                args = _registers(raw_args, bool(range_mode))
                if args is None:
                    return
                signature = (callee_class, name, params, ret)
                if (kind in ("virtual", "super")
                        and signature in INTENT_METHODS and len(args) == 1):
                    pending = ("INTENT", None)
                elif kind == "virtual" and signature in SOURCE_METHODS:
                    required = 1 + (1 if params == "Ljava/lang/String;" else 0)
                    if (len(args) == required
                            and registers.get(args[0], (None,))[0] == "INTENT"):
                        pending = ("INPUT", (owner["file"], line, owner["sha256"],
                                             "ANDROID_INTENT_DESCRIPTOR_SOURCE_CUE"), ())
                else:
                    sink = SINK_METHODS.get(signature) if kind == "virtual" else None
                    if sink and len(args) == 2:
                        value = registers.get(args[1])
                        route = value[2] if value and len(value) > 2 else ()
                        if (value and value[0] == "INPUT" and owner["file"] != value[1][0]
                                and _valid_route(route, _method_descriptor(descriptor, method))):
                            origin = value[1]
                            identifier = (origin[0], origin[1], owner["file"], line,
                                          tuple((h["caller_file"], h["call_line"],
                                                 h["callee_file"], h["callee_descriptor"],
                                                 h["edge_kind"]) for h in route))
                            if identifier not in seen:
                                seen.add(identifier)
                                leads.append({
                                    "id": "MSCF-" + hashlib.sha256(
                                        repr(identifier).encode()).hexdigest()[:16],
                                    "status": "UNVERIFIED_SMALI_EXACT_STATIC_DESCRIPTOR_PATH",
                                    "platform": "android",
                                    "severity": "unassessed",
                                    "reachability": "UNKNOWN", "impact": "NOT_ESTABLISHED",
                                    "source": {"file": origin[0], "line": origin[1],
                                               "sha256": origin[2], "kind": origin[3]},
                                    "sink": {"file": owner["file"], "line": line,
                                             "sha256": owner["sha256"], "kind": sink,
                                             "api_descriptor": callee_class + "->" + name +
                                                               "(" + params + ")" + ret},
                                    "hops": list(route),
                                    "runtime_effect_verified": False,
                                    "attacker_origin_verified": False,
                                    "branch_feasibility_verified": False,
                                    "missing_evidence": [
                                        "Android entrypoint/exported/permission checks",
                                        "DEX call target class loading and runtime behavior",
                                        "branch and exception handling",
                                        "candidate/negative native reproduction",
                                        "actual protected resource or effect",
                                    ],
                                })
                    elif kind == "static" and params == STATIC_PARAM and len(args) == 1:
                        callee_owner = classes.get(callee_class)
                        target = (callee_owner["methods"].get((name, params, ret))
                                  if callee_owner else None)
                        input_value = registers.get(args[0])
                        if (target and target["static"] and input_value
                                and input_value[0] == "INPUT"):
                            edge = {
                                "caller_file": owner["file"], "caller_sha256": owner["sha256"],
                                "caller_method": method["name"], "call_line": line,
                                "caller_descriptor": _method_descriptor(descriptor, method),
                                "callee_file": callee_owner["file"],
                                "callee_sha256": callee_owner["sha256"],
                                "callee_method": name,
                                "callee_declaration_line": target["line"],
                                "callee_descriptor": _method_descriptor(callee_class, target),
                                "edge_kind": "STATIC_CALL",
                                "binding": "DEX_LEXICAL_EXACT_STATIC_DESCRIPTOR",
                            }
                            route = input_value[2] if len(input_value) > 2 else ()
                            if (ret == "V" and len(hops) < MAX_CALL_DEPTH
                                    and len(route) < MAX_HOPS):
                                child_origin = ("INPUT", input_value[1], route + (edge,))
                                walk(callee_class, target, {"p0": child_origin},
                                     hops + [edge], visited)
                            elif ret == STATIC_PARAM and len(route) + 2 <= MAX_HOPS:
                                summary = _return_summary(target, input_value)
                                if summary is not None:
                                    returned, return_line = summary
                                    reverse = {
                                        "caller_file": callee_owner["file"],
                                        "caller_sha256": callee_owner["sha256"],
                                        "caller_method": target["name"],
                                        "call_line": return_line,
                                        "caller_descriptor": _method_descriptor(callee_class, target),
                                        "callee_file": owner["file"],
                                        "callee_sha256": owner["sha256"],
                                        "callee_method": method["name"],
                                        "callee_declaration_line": method["line"],
                                        "callee_descriptor": _method_descriptor(descriptor, method),
                                        "edge_kind": "RETURN_TO_CALLER",
                                        "binding": "DEX_LEXICAL_EXACT_STATIC_RETURN",
                                    }
                                    pending = ("INPUT", returned[1],
                                               route + (edge, reverse))
                                    registers.clear()
                                    # The pending result is consumed ONLY by
                                    # the immediately following move-result.
                                    # Any other operation drops it.
                                    for target_index in successors[index]:
                                        next_state = (dict(registers), pending)
                                        prior = incoming.get(target_index)
                                        incoming[target_index] = (
                                            next_state if prior is None
                                            else _must_join(prior, next_state))
                                    continue
                            registers.clear()
                    else:
                        # Any unmodeled invoked method may mutate state.
                        registers.clear()
            for target_index in successors[index]:
                next_state = (dict(registers), pending)
                prior = incoming.get(target_index)
                incoming[target_index] = (next_state if prior is None
                                          else _must_join(prior, next_state))

    for descriptor, owner in sorted(classes.items()):
        for key, method in sorted(owner["methods"].items()):
            if len(leads) >= max_leads or steps >= MAX_STEPS:
                coverage["truncated"] = True
                break
            if method:
                walk(descriptor, method, {}, [], set())
    coverage["acyclic_cfg_methods_visited"] = cfg_methods
    coverage["acyclic_cfg_join_nodes"] = cfg_joins
    coverage["unsupported_method_visits"] = unsupported
    coverage["instruction_steps"] = steps
    return {
        "schema_version": 1,
        "engine": "mobile-smali-descriptor-crossfile",
        "mode": "offline-exact-static-descriptor-acyclic-cfg-must-join-flow",
        "platform": "android",
        "source_root": "operator-provided",
        "assurance": "STATIC_DESCRIPTOR_CALL_REVIEW_ONLY_NOT_RUNTIME_PROOF",
        "coverage": coverage,
        "leads": leads,
        "lead_count": len(leads),
        "limits": {"max_provenance_edges": MAX_HOPS,
                   "max_call_depth": MAX_CALL_DEPTH, "max_leads": MAX_LEADS,
                   "only_exact_static_string_void_or_pure_string_return": True,
                   "supported_range_width": "one String arg or exactly two receiver+String registers",
                   "not_implemented": [
                       "invoke-virtual/interface dispatch or dynamic class loading",
                       "only forward if-eqz/if-nez and goto DAG joins; no loops",
                       "switches, try/catch, exceptions and branch feasibility",
                       "wide and mixed-prefix range registers",
                       "returns with arbitrary calls, fields, heap and callbacks",
                       "cross-language Kotlin/Java/Smali symbol equivalence",
                       "Android permissions, real reachability and execution",
                   ]},
    }
