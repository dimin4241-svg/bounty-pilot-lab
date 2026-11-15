#!/usr/bin/env python3
"""Bounded offline function-level mobile lexical def-use tracing.

It traces explicit source-call/entrypoint-parameter -> assignment -> sensitive
call, including one unambiguous same-file helper call. It is NOT a compiler
AST, control-flow graph, platform call graph, symbolic executor or proof.
"""
import hashlib
import re
from collections import defaultdict
from pathlib import Path

import mobile_lab

MAX_FILES = 1000
MAX_FILE_SIZE = 350000
MAX_BYTES = 8 * 1024 * 1024
MAX_FUNCTIONS = 4000
MAX_EVENTS = 500
MAX_LEADS = 120
MAX_METHOD_BYTES = 120000
MAX_CALL_DEPTH = 2

SUFFIXES = {
    "android": {".java", ".kt", ".kts", ".smali"},
    "ios": {".swift", ".m", ".mm"},
}
KEYWORDS = {"if", "for", "while", "switch", "catch", "when", "synchronized",
            "try", "else", "do", "return", "throw", "new", "guard"}
# Only source APIs that are plausibly derived from a mobile entry boundary.
SOURCE = {
    "android": re.compile(
        r"\b(?:getIntent|getStringExtra|getParcelableExtra|getDataString|getData|getExtras|"
        r"getClipData)\s*\(|\b(?:intent\.(?:data|extras)|getIntent\s*\(\s*\)\.data)", re.I),
    "ios": re.compile(r"\b(?:openURLContexts|incomingURL|userActivity\.webpageURL)\b"),
}
SINKS = {
    "android": {
        "WEBVIEW_LOAD": r"\b(?:loadUrl|loadDataWithBaseURL|loadData)\s*\(",
        "IPC_FORWARD": r"\b(?:startActivity|sendBroadcast|startService)\s*\(",
        "ACTIVITY_RESULT": r"\bsetResult\s*\(",
        "FILE_WRITE": r"\b(?:FileOutputStream|openFileOutput|openOutputStream|Files\.copy)\s*\(",
        "DYNAMIC_CODE": r"\b(?:DexClassLoader|PathClassLoader)\s*\(",
    },
    "ios": {
        "WEBVIEW_LOAD": r"\b(?:loadHTMLString|loadRequest|evaluateJavaScript|loadFileURL|load)\s*\(",
        "FILE_WRITE": r"\b(?:writeToURL|writeToFile|copyItem|createFile)\s*\(",
        "API_REQUEST": r"\b(?:dataTask|uploadTask)\s*\(",
    }
}
SINK_PATTERNS = {
    p: {k: re.compile(v) for k, v in kinds.items()} for p, kinds in SINKS.items()
}
JAVA_METHOD = re.compile(r"\b([A-Za-z_$][\w$]*)\s*\(([^()]{0,1200})\)\s*"
                         r"(?:throws\s+[^{]{1,120})?\{", re.M)
SWIFT_METHOD = re.compile(r"\bfunc\s+([A-Za-z_][\w]*)\s*\(([^()]{0,1200})\)"
                          r"(?:\s*(?:async|throws|rethrows))*"
                          r"(?:\s*->\s*[\w?.<>, \[\]]{1,100})?\s*\{", re.M)
ASSIGN = re.compile(
    r"(?:\b(?:val|var|let|final|const|String|Uri|Intent|URL|NSString|NSURL)\s+)?"
    r"(?P<name>[A-Za-z_$][\w$]*)(?:\s*:\s*[\w?.<>]+)?\s*=(?!=)\s*(?P<value>.*)$"
)
NAME = re.compile(r"(?<![\w$])([A-Za-z_$][\w$]*)(?![\w$])")
CALL = re.compile(r"\b([A-Za-z_$][\w$]*)\s*\(([^()]{0,400})\)")


def _mask(source):
    """Remove comments and string *content* while preserving lengths/newlines."""
    out = list(source)
    pos = 0
    mode = ""
    while pos < len(source):
        char = source[pos]
        following = source[pos:pos + 2]
        if mode == "line":
            if char == "\n":
                mode = ""
            else:
                out[pos] = " "
        elif mode == "block":
            if following == "*/":
                out[pos:pos + 2] = [" ", " "]
                mode = ""
                pos += 1
            elif char != "\n":
                out[pos] = " "
        elif mode in ("'", '"', "\x60"):
            if char == "\\" and pos + 1 < len(source):
                out[pos] = " "
                pos += 1
                if source[pos] != "\n":
                    out[pos] = " "
            elif char == mode:
                out[pos] = " "
                mode = ""
            elif char != "\n":
                out[pos] = " "
        elif following == "//":
            out[pos:pos + 2] = [" ", " "]
            mode = "line"
            pos += 1
        elif following == "/*":
            out[pos:pos + 2] = [" ", " "]
            mode = "block"
            pos += 1
        elif char in ("'", '"', "\x60"):
            out[pos] = " "
            mode = char
        pos += 1
    return "".join(out)


def _split_args(value):
    args, buffer, depth = [], [], 0
    for char in value:
        if char in "([<":
            depth += 1
        elif char in ")]>":
            depth = max(0, depth - 1)
        if char == "," and depth == 0:
            args.append("".join(buffer).strip())
            buffer = []
        else:
            buffer.append(char)
    tail = "".join(buffer).strip()
    if tail:
        args.append(tail)
    return args


def _params(signature, platform):
    result = []
    for part in _split_args(signature):
        if platform == "ios":
            before = part.split(":")[0].split()
            name = before[-1] if before else ""
        elif ":" in part and not part.strip().startswith("@"):
            name = part.split(":")[0].strip().split()[-1]
        else:
            name = part.strip().split()[-1] if part.strip().split() else ""
        name = name.replace("...", "")
        if re.fullmatch(r"[A-Za-z_$][\w$]*", name):
            result.append(name)
        else:
            return None
    return result


def _balanced_end(content, brace):
    depth = 0
    for pos in range(brace, min(len(content), brace + MAX_METHOD_BYTES)):
        if content[pos] == "{":
            depth += 1
        elif content[pos] == "}":
            depth -= 1
            if depth == 0:
                return pos
    return None


def _functions(source, platform):
    clean = _mask(source)
    regex = SWIFT_METHOD if platform == "ios" else JAVA_METHOD
    methods = []
    covered_to = -1
    for found in regex.finditer(clean):
        if found.start() < covered_to:
            continue
        name = found.group(1)
        if name in KEYWORDS:
            continue
        if platform == "android":
            # Avoid mistaking an expression or lambda for a declaration.
            prior = clean[max(0, found.start() - 120): found.start()].split("\n")[-1]
            if not re.search(r"\b(?:fun|void|public|private|protected|static|final|override|"
                             r"internal|suspend|[A-Za-z_$][\w$<>?.]*)\s+$", prior):
                continue
        params = _params(found.group(2), platform)
        if params is None:
            continue
        brace = found.end() - 1
        end = _balanced_end(clean, brace)
        if end is None:
            continue
        methods.append({"name": name, "params": params,
                        "body": clean[brace + 1:end],
                        "start": brace + 1,
                        "line": source.count("\n", 0, found.start()) + 1})
        covered_to = end + 1
        if len(methods) >= MAX_FUNCTIONS:
            break
    return methods, clean


def _statements(body, offset, full):
    # Bounded simple statement segmentation. Language expressions, branches and
    # closures are not resolved. Semicolons/newlines delimiting lexical facts.
    for found in re.finditer(r"[^;\n]+", body):
        candidate = found.group(0).strip()
        if candidate:
            absolute = offset + found.start()
            yield full.count("\n", 0, absolute) + 1, candidate


def _seed_parameters(fn, platform):
    name, params = fn["name"].lower(), fn["params"]
    if platform == "android":
        if name in ("onnewintent",):
            return {p: ("ENTRY_PARAMETER", fn["line"]) for p in params[:1]}
        return {}
    if name in ("application", "scene", "onopenurl", "continueuseractivity"):
        return {p: ("ENTRY_PARAMETER", fn["line"]) for p in params
                if p.lower() in ("url", "urls", "contexts", "useractivity", "activity")}
    return {}


def _uses_any(expression, variables):
    found = set(NAME.findall(expression))
    return [name for name in variables if name in found]


def _trace(fn, platform, defs, source, file_digest, path, seeds, visited=(), depth=0):
    if depth > MAX_CALL_DEPTH or (fn["name"], fn["line"]) in visited:
        return []
    visited = visited + ((fn["name"], fn["line"]),)
    tainted = dict(seeds)
    flows = []
    for line, statement in _statements(fn["body"], fn["start"], source):
        direct_source = bool(SOURCE[platform].search(statement))
        match = ASSIGN.search(statement)
        rhs = match.group("value") if match else None
        if match:
            dest = match.group("name")
            incoming = _uses_any(rhs, tainted)
            if SOURCE[platform].search(rhs):
                tainted[dest] = ("SOURCE_API", line)
            elif incoming:
                tainted[dest] = tainted[incoming[0]]
            else:
                # Definite lexical assignment with no tainted RHS resets a name.
                tainted.pop(dest, None)
        for kind, expression in SINK_PATTERNS[platform].items():
            found = expression.search(statement)
            if not found:
                continue
            # Consider arguments only, not a similarly-named source elsewhere
            # in the statement. Does NOT claim the control-flow condition holds.
            arguments = statement[found.end():]
            active = _uses_any(arguments, tainted)
            if active or SOURCE[platform].search(arguments):
                origin = tainted[active[0]] if active else ("SOURCE_API", line)
                flows.append({"sink": kind, "source_kind": origin[0],
                              "source_line": origin[1], "sink_line": line,
                              "method": fn["name"], "hops": []})
        if depth >= MAX_CALL_DEPTH:
            continue
        # Single same-file unambiguous helper call. Call graph is deliberately
        # conservative: no overload resolution, dynamic dispatch or reflection.
        for call in CALL.finditer(statement):
            helper = call.group(1)
            args = _split_args(call.group(2))
            candidates = defs.get((helper, len(args)), [])
            if len(candidates) != 1 or candidates[0] is fn:
                continue
            selected = {p: tainted[name] for p, arg in zip(candidates[0]["params"], args)
                        for name in _uses_any(arg, tainted)}
            if not selected:
                continue
            children = _trace(candidates[0], platform, defs, source,
                              file_digest, path, selected, visited, depth + 1)
            for child in children:
                child["hops"] = [{"method": fn["name"], "line": line}] + child["hops"]
                flows.append(child)
    return flows


def _smali_flows(source):
    flows = []
    methods = list(re.finditer(r"(?m)^\s*\.method\s+([^\n]+)\n(.*?)^\s*\.end method",
                               source, re.S | re.M))
    for method in methods[:MAX_FUNCTIONS]:
        registers = {}
        pending = None
        method_name = method.group(1).split("(")[0].split()[-1]
        for i, text in enumerate(method.group(2).splitlines()):
            line = source.count("\n", 0, method.start(2)) + i + 1
            code = text.split("#", 1)[0].strip()
            invoke = re.search(r"invoke-[^\s]+\s+\{([^}]+)\},\s+L[^;]+;->([\w$]+)\(", code)
            if invoke:
                args = [x.strip() for x in invoke.group(1).split(",")]
                api = invoke.group(2)
                if api in {"getIntent", "getStringExtra", "getParcelableExtra",
                           "getData", "getDataString", "getExtras"}:
                    pending = ("SOURCE_API", line)
                else:
                    pending = None
                    target = {
                        "loadUrl": "WEBVIEW_LOAD", "setResult": "ACTIVITY_RESULT",
                        "startActivity": "IPC_FORWARD", "openFileOutput": "FILE_WRITE",
                    }.get(api)
                    if target:
                        active = [registers[v] for v in args if v in registers]
                        if active:
                            flows.append({"sink": target, "source_kind": active[0][0],
                                          "source_line": active[0][1], "sink_line": line,
                                          "method": method_name, "hops": [],
                                          "representation": "smali-register"})
            moved = re.match(r"move-result-object\s+([vp]\d+)", code)
            if moved:
                if pending:
                    registers[moved.group(1)] = pending
                else:
                    registers.pop(moved.group(1), None)
                pending = None
            alias = re.match(r"move-object(?:/from16|/16)?\s+([vp]\d+),\s*([vp]\d+)", code)
            if alias:
                if alias.group(2) in registers:
                    registers[alias.group(1)] = registers[alias.group(2)]
                else:
                    registers.pop(alias.group(1), None)
            clear = re.match(r"const(?:-string(?:/jumbo)?|-class)?\s+([vp]\d+)[,\s]", code)
            if clear:
                registers.pop(clear.group(1), None)
    return flows


def analyze(sources, platform, max_leads=MAX_LEADS):
    if platform not in SUFFIXES:
        raise ValueError("platform must be android or ios")
    if type(max_leads) is not int or not 1 <= max_leads <= MAX_LEADS:
        raise ValueError("max_leads must be 1..120")
    root = Path(sources).expanduser().resolve(strict=True)
    if not root.is_dir() or root.is_symlink():
        raise ValueError("source root must be a non-symlink directory")
    leads = []
    # A component-to-filename join is a candidate only: neither class loading
    # nor platform permission checks nor runtime entrypoint reachability is
    # established by this lightweight source inventory.
    manifest_status = "not-applicable"
    components = []
    if platform == "android":
        try:
            inventory = mobile_lab._inspect_decoded_manifest(root, platform)
            components = inventory.get("components", [])
            manifest_status = ("present" if components else "no-component-metadata")
        except (ValueError, OSError):
            manifest_status = "unreadable"
    scanned = 0
    bytes_read = 0
    skipped = 0
    truncated = False
    for path in sorted(root.rglob("*")):
        if path.suffix.lower() not in SUFFIXES[platform] or not path.is_file():
            continue
        if path.is_symlink() or any(p.is_symlink() for p in path.parents if p != root):
            skipped += 1
            continue
        if scanned >= MAX_FILES or bytes_read >= MAX_BYTES or len(leads) >= max_leads:
            truncated = True
            break
        size = path.stat().st_size
        if size > MAX_FILE_SIZE or bytes_read + size > MAX_BYTES:
            skipped += 1
            truncated = True
            continue
        data = mobile_lab._regular_file(path, MAX_FILE_SIZE)
        scanned += 1
        bytes_read += len(data)
        try:
            source = data.decode("utf-8")
        except UnicodeDecodeError:
            skipped += 1
            continue
        rel = path.relative_to(root).as_posix()
        simple = path.stem
        possible_components = [
            {"name": item["name"], "exposure": item["exposure"],
             "permission": item["permission"]}
            for item in components if item["name"].rsplit(".", 1)[-1] == simple
        ][:12]
        digest = hashlib.sha256(data).hexdigest()
        if path.suffix == ".smali":
            flows = _smali_flows(source)
        else:
            fns, _ = _functions(source, platform)
            defs = defaultdict(list)
            for fn in fns:
                defs[(fn["name"], len(fn["params"]))].append(fn)
            flows = []
            for fn in fns:
                flows.extend(_trace(fn, platform, defs, source, digest, rel,
                                    _seed_parameters(fn, platform)))
        seen = set()
        for flow in flows:
            signature = (flow["source_line"], flow["sink_line"], flow["sink"],
                         tuple((h["method"], h["line"]) for h in flow["hops"]))
            if signature in seen:
                continue
            seen.add(signature)
            if len(leads) >= max_leads:
                truncated = True
                break
            identity = (rel + "\0" + digest + "\0" + str(signature)).encode("utf-8")
            leads.append({
                "id": "MFL-" + hashlib.sha256(identity).hexdigest()[:14],
                "platform": platform, "file": rel, "file_sha256": digest,
                "method": flow["method"], "source_line": flow["source_line"],
                "sink_line": flow["sink_line"], "sink_kind": flow["sink"],
                "source_kind": flow["source_kind"], "hops": flow["hops"],
                "component_filename_matches": possible_components,
                "component_binding": "UNVERIFIED_FILENAME_HEURISTIC",
                "status": "LEXICAL_DEF_USE_REVIEW_UNVERIFIED",
                "reachability": "UNKNOWN", "impact": "NOT_ESTABLISHED",
                "severity": "unassessed",
                "unproven": ["control flow", "caller identity", "permissions",
                             "real native execution", "authorization", "impact"],
            })
    return {
        "schema_version": 1, "engine": "mobile-function-flow",
        "platform": platform, "source_root": "operator-provided",
        "assurance": "STATIC_LEXICAL_FLOW_NOT_A_VULNERABILITY",
        "limits": {"same_file_only": True, "max_helper_depth": MAX_CALL_DEPTH,
                   "unsupported": ["compiler AST", "SSA", "branch feasibility",
                                   "overloaded/dynamic dispatch", "cross-file calls",
                                   "full Smali ranges", "Swift closures", "ObjC messages"]},
        "manifest_status": manifest_status,
        "coverage": {"files_read": scanned, "bytes_read": bytes_read,
                     "skipped_files": skipped, "truncated": truncated},
        "leads": leads, "lead_count": len(leads),
    }
