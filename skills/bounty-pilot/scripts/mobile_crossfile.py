#!/usr/bin/env python3
"""Bounded cross-file mobile lexical call graph for reviewer leads, not proof.

Only explicit, uniquely resolved class/receiver calls are followed. No runtime
execution, network, compiler AST, dispatch modelling or authorization claims.
"""
import hashlib
import re
from collections import defaultdict
from pathlib import Path

import mobile_flow
import mobile_lab

MAX_FILES = 800
MAX_TOTAL_BYTES = 8 * 1024 * 1024
MAX_FILE_BYTES = 350000
MAX_METHODS = 3500
MAX_HOPS = 3
MAX_CALLS_PER_METHOD = 80
MAX_LEADS = 120

FILE_TYPES = {"android": {".java", ".kt", ".kts"}, "ios": {".swift"}}
DECL = re.compile(r"\b(?:class|object|struct|enum)\s+([A-Za-z_][\w]*)\b")
PACKAGE = re.compile(r"(?m)^\s*package\s+([A-Za-z_][\w.]*)\s*;?")
IMPORT = re.compile(r"(?m)^\s*import\s+(?:static\s+)?([A-Za-z_][\w.]*)\s*;?")
QUALIFIED_CALL = re.compile(r"(?<![\w.])(?P<receiver>[A-Za-z_]\w*)\s*\.\s*"
                            r"(?P<name>[A-Za-z_]\w*)\s*\((?P<args>[^()]*)\)")
UNQUALIFIED_CALL = re.compile(r"(?<![\w.])(?P<name>[A-Za-z_]\w*)\s*"
                              r"\((?P<args>[^()]*)\)")
LOCAL_NEW = re.compile(r"\b(?:val|var|let)?\s*(?P<variable>[A-Za-z_]\w*)\s*"
                       r"=\s*(?:new\s+)?(?P<class>[A-Za-z_]\w*)\s*\(\s*\)")
JAVA_NEW = re.compile(r"\b(?P<class>[A-Za-z_]\w*)\s+"
                      r"(?P<variable>[A-Za-z_]\w*)\s*=\s*new\s+"
                      r"(?P<constructor>[A-Za-z_]\w*)\s*\(\s*\)")
IGNORE_METHODS = {"if", "while", "for", "switch", "return", "catch", "throw",
                  "getIntent", "getDataString", "getStringExtra", "getData"}


def _index(root, platform):
    entries = []
    total_bytes = 0
    skipped = 0
    truncated = False
    functions_count = 0
    root = Path(root)
    # Explicit path safety: never read symlink source files or their parents.
    for path in sorted(root.rglob("*")):
        if path.suffix.lower() not in FILE_TYPES[platform] or not path.is_file():
            continue
        if path.is_symlink() or any(part.is_symlink() for part in path.parents
                                   if part != root):
            skipped += 1
            continue
        size = path.stat().st_size
        if (len(entries) >= MAX_FILES or total_bytes >= MAX_TOTAL_BYTES
                or functions_count >= MAX_METHODS):
            truncated = True
            break
        if size > MAX_FILE_BYTES or total_bytes + size > MAX_TOTAL_BYTES:
            truncated = True
            skipped += 1
            continue
        data = mobile_lab._regular_file(path, MAX_FILE_BYTES)
        total_bytes += len(data)
        try:
            original = data.decode("utf-8")
        except UnicodeDecodeError:
            skipped += 1
            continue
        masked = mobile_flow._mask(original)
        classes = [m.group(1) for m in DECL.finditer(masked)]
        stem = path.stem
        # Skip ambiguous/multi-class lexical files. A class declaration alone
        # is not a reliable Java/Kotlin/Swift symbol binding.
        if classes.count(stem) != 1:
            skipped += 1
            continue
        fns, _ = mobile_flow._functions(original, platform)
        if not fns:
            continue
        if functions_count + len(fns) > MAX_METHODS:
            truncated = True
            break
        functions_count += len(fns)
        package = PACKAGE.search(masked) if platform == "android" else None
        import_names = {m.group(1) for m in IMPORT.finditer(masked)}
        package_name = package.group(1) if package else ""
        language = ("kotlin" if path.suffix.lower() in {".kt", ".kts"}
                    else "java" if path.suffix.lower() == ".java"
                    else "swift")
        kotlin_kind = None
        if language == "kotlin":
            # An 'object' has a singleton receiver. Ordinary classes are
            # final by default, but open/abstract/sealed declarations are not
            # safe to bind as a unique instance implementation.
            escaped_stem = re.escape(stem)
            if re.search(r"\bobject\s+" + escaped_stem + r"\b", masked):
                kotlin_kind = "object"
            elif (re.search(r"\bclass\s+" + escaped_stem + r"\b", masked)
                  and not re.search(
                      r"\b(?:open|abstract|sealed)\s+class\s+" +
                      escaped_stem + r"\b", masked)):
                kotlin_kind = "final-class"
            else:
                kotlin_kind = "unsupported"
        entry = {
            "path": path.relative_to(root).as_posix(),
            "language": language, "kotlin_kind": kotlin_kind,
            "sha256": hashlib.sha256(data).hexdigest(),
            "class": stem, "package": package_name,
            "symbol": (package_name + "." + stem if package_name else stem),
            "imports": import_names, "source": original, "functions": fns,
            "methods": defaultdict(list),
        }
        for fn in fns:
            fn["owner"] = entry
            entry["methods"][(fn["name"], len(fn["params"]))].append(fn)
        entries.append(entry)
    symbols = defaultdict(list)
    for entry in entries:
        symbols[entry["symbol"]].append(entry)
    return entries, symbols, {
        "files_indexed": len(entries), "source_bytes": total_bytes,
        "functions_indexed": functions_count, "skipped_files": skipped,
        "truncated": truncated,
    }


def _class_lookup(caller, receiver, symbols, platform):
    if platform == "ios":
        # Swift uses an unqualified module type in this bounded approximation.
        target = receiver
    else:
        direct = caller["package"] + "." + receiver if caller["package"] else receiver
        imported = [x for x in caller["imports"] if x.rsplit(".", 1)[-1] == receiver]
        if len(imported) > 1:
            return None
        if len(imported) == 1:
            target = imported[0]
            # Do not guess if same-name local type also exists.
            if direct != target and symbols.get(direct):
                return None
        else:
            target = direct
    matches = symbols.get(target, [])
    return matches[0] if len(matches) == 1 else None


def _receiver_types(statement, caller, symbols, platform, binding):
    # Binding is local to the function, not to a whole file.
    direct = LOCAL_NEW.search(statement)
    if direct:
        target = _class_lookup(caller, direct.group("class"), symbols, platform)
        if target:
            binding[direct.group("variable")] = target
        else:
            binding.pop(direct.group("variable"), None)
    typed = JAVA_NEW.search(statement)
    if typed:
        if typed.group("class") == typed.group("constructor"):
            target = _class_lookup(caller, typed.group("class"), symbols, platform)
            if target:
                binding[typed.group("variable")] = target
    assign = mobile_flow.ASSIGN.search(statement)
    if assign and not direct and not typed:
        binding.pop(assign.group("name"), None)


def _resolve_method(entry, name, arity):
    candidates = entry["methods"].get((name, arity), [])
    return candidates[0] if len(candidates) == 1 else None


def _calls(statement, owner, symbols, platform, binding):
    result = []
    for match in QUALIFIED_CALL.finditer(statement):
        receiver, name = match.group("receiver"), match.group("name")
        args = mobile_flow._split_args(match.group("args"))
        instance = receiver in binding
        target = binding.get(receiver) or _class_lookup(owner, receiver, symbols, platform)
        if target is None:
            continue
        if owner["language"] == "kotlin":
            # A Kotlin class name is not an object instance; a Java-like
            # class-qualified call must not be treated as static without
            # compiler/bytecode evidence. Instance calls require a visibly
            # constructed final class, singleton calls an explicit object.
            if target["language"] != "kotlin":
                continue
            if instance and target["kotlin_kind"] != "final-class":
                continue
            if not instance and target["kotlin_kind"] != "object":
                continue
        if target is owner:  # same-file resolution is delegated to mobile_flow.
            continue
        method = _resolve_method(target, name, len(args))
        if method is None:
            continue
        resolution = ("kotlin-explicit-final-instance" if instance else
                      "kotlin-explicit-object-singleton") if owner["language"] == "kotlin" else (
                      "explicit-class-or-local-instance")
        result.append((target, method, args, resolution))
    # Unqualified method calls are handled only within the current source file,
    # where the existing bounded lexical engine already has this behavior.
    # No global search by same method name is ever performed.
    return result[:MAX_CALLS_PER_METHOD]


def _trace_ordered(fn, owner, symbols, platform, initial, trail=(), depth=0):
    """Statement-order sensitive tracer for one explicit cross-file path."""
    identity = (owner["path"], fn["line"], fn["name"])
    if depth > MAX_HOPS or identity in trail:
        return []
    trail = trail + (identity,)
    tainted = dict(initial)
    receiver_types = {}
    found = []
    followed = 0
    for line, statement in mobile_flow._statements(
            fn["body"], fn["start"], owner["source"]):
        _receiver_types(statement, owner, symbols, platform, receiver_types)
        assignment = mobile_flow.ASSIGN.search(statement)
        if assignment:
            name, expr = assignment.group("name"), assignment.group("value")
            used = mobile_flow._uses_any(expr, tainted)
            if mobile_flow.SOURCE[platform].search(expr):
                tainted[name] = (owner["path"], line, owner["sha256"], "SOURCE_API")
            elif used:
                tainted[name] = tainted[used[0]]
            else:
                tainted.pop(name, None)
        if depth:
            for sink_type, sink in mobile_flow.SINK_PATTERNS[platform].items():
                result = sink.search(statement)
                if result:
                    active = mobile_flow._uses_any(statement[result.end():], tainted)
                    if active:
                        origin = tainted[active[0]]
                        found.append({
                            "source_file": origin[0],
                            "source_line": origin[1],
                            "source_sha256": origin[2],
                            "source_kind": origin[3],
                            "sink_file": owner["path"], "sink_line": line,
                            "sink_sha256": owner["sha256"],
                            "sink_method": fn["name"],
                            "sink_kind": sink_type,
                            "hops": [],
                        })
        if depth >= MAX_HOPS:
            continue
        for target, helper, args, resolution in _calls(
                statement, owner, symbols, platform, receiver_types):
            if followed >= MAX_CALLS_PER_METHOD:
                break
            followed += 1
            inherited = {}
            for param, arg in zip(helper["params"], args):
                used = mobile_flow._uses_any(arg, tainted)
                if used:
                    inherited[param] = tainted[used[0]]
            if not inherited:
                continue
            for child in _trace_ordered(
                    helper, target, symbols, platform, inherited, trail, depth + 1):
                child["hops"].insert(0, {
                    "caller_file": owner["path"], "caller_line": line,
                    "caller_method": fn["name"], "callee_file": target["path"],
                    "callee_method": helper["name"],
                    "callee_declaration_line": helper["line"],
                    "resolution": resolution,
                })
                found.append(child)
    return found



def _compiler_support(report, compiler_graph, root):
    """Compare independent Java AST method targets to lexical taint *leads*.

    Caller/callee declarations, invocation line, source digest and method names
    must agree. Compiler binding never validates caller inputs, taint or effects.
    """
    if (not isinstance(compiler_graph, dict)
            or compiler_graph.get("schema_version") != 1
            or compiler_graph.get("engine") != "mobile-java-compiler-graph"
            or compiler_graph.get("platform") != "android"):
        raise ValueError("expected mobile-java-compiler-graph JSON, schema version 1")
    digests = compiler_graph.get("source_digests")
    edges = compiler_graph.get("edges")
    coverage = compiler_graph.get("coverage")
    if (not isinstance(digests, dict) or len(digests) > 350
            or not isinstance(edges, list) or len(edges) > 3000
            or not isinstance(coverage, dict)
            or type(coverage.get("diagnostic_errors")) is not int
            or coverage["diagnostic_errors"] < 0):
        raise ValueError("malformed Java compiler graph")
    for relative, digest in digests.items():
        if (not isinstance(relative, str) or not relative
                or Path(relative).is_absolute()
                or ".." in Path(relative).parts
                or not isinstance(digest, str) or len(digest) != 64):
            raise ValueError("unsafe Java source fingerprint")
        path = root / relative
        if (path.is_symlink()
                or any(p.is_symlink() for p in path.parents if p != root)):
            raise ValueError("compiler source points through a symlink")
        data = mobile_lab._regular_file(path, MAX_FILE_BYTES)
        if hashlib.sha256(data).hexdigest() != digest:
            raise ValueError("compiler graph has stale Java source hashes")
    supported = set()
    for edge in edges:
        if not isinstance(edge, dict):
            raise ValueError("invalid compiler edge")
        a, b = edge.get("caller_file"), edge.get("callee_file")
        if (a not in digests or b not in digests
                or edge.get("caller_sha256") != digests[a]
                or edge.get("callee_sha256") != digests[b]
                or edge.get("binding_source") != "JDK_COMPILER_SYMBOL"):
            raise ValueError("compiler edge has inconsistent source fingerprint")
        key = (a, edge.get("caller_method"), edge.get("call_line"),
               b, edge.get("callee_method"), edge.get("callee_declaration_line"))
        supported.add(key)
    matched = 0
    unaligned = 0
    non_java = 0
    for lead in report["leads"]:
        hops = lead["hops"]
        if any(not (h["caller_file"].endswith(".java")
                    and h["callee_file"].endswith(".java")) for h in hops):
            status = "JAVA_ONLY_NOT_APPLICABLE"
            count = 0
            non_java += 1
        else:
            count = sum(
                (h["caller_file"], h["caller_method"], h["caller_line"],
                 h["callee_file"], h["callee_method"],
                 h["callee_declaration_line"]) in supported
                for h in hops)
            status = ("ALL_HOPS_AST_SYMBOL_ALIGNED" if count == len(hops)
                      else "SOME_HOPS_NOT_AST_ALIGNED")
            if count == len(hops):
                matched += 1
            else:
                unaligned += 1
        lead["compiler_alignment"] = {
            "status": status, "matched_hops": count,
            "total_hops": len(hops),
            "compilation_errors": coverage["diagnostic_errors"],
            "compiler_edge_truncated": bool(
                coverage.get("compiler_edge_truncated", False)),
            "runtime_effect_verified": False,
            "taint_validated_by_compiler": False,
        }
    report["compiler_comparison"] = {
        "aligned_leads": matched, "unaligned_java_leads": unaligned,
        "non_java_leads": non_java,
        "compiler_diagnostic_errors": coverage["diagnostic_errors"],
        "symbol_graph_complete": bool(
            coverage.get("complete_file_coverage")
            and coverage["diagnostic_errors"] == 0),
        "meaning": "compiled call-target alignment only; no taint or runtime proof",
    }
    return report


def analyze(sources, platform, max_leads=MAX_LEADS, compiler_graph=None,
            jvm_classes=None):
    if platform not in FILE_TYPES:
        raise ValueError("cross-file analysis supports android or ios")
    if type(max_leads) is not int or not 1 <= max_leads <= MAX_LEADS:
        raise ValueError("max_leads must be an integer from 1 to 120")
    supplied = Path(sources).expanduser().absolute()
    if supplied.is_symlink() or not supplied.is_dir():
        raise ValueError("source root must be a non-symlink directory")
    root = supplied.resolve(strict=True)
    entries, symbols, coverage = _index(root, platform)
    leads, duplicates = [], set()
    for entry in entries:
        for fn in entry["functions"]:
            if len(leads) >= max_leads:
                coverage["truncated"] = True
                break
            seeds = mobile_flow._seed_parameters(fn, platform)
            initial = {name: (entry["path"], token[1], entry["sha256"], token[0])
                       for name, token in seeds.items()}
            for item in _trace_ordered(fn, entry, symbols, platform, initial):
                # Reject same-file paths and incompletely anchored chains.
                if not item["hops"] or item["source_file"] == item["sink_file"]:
                    continue
                signature = (item["source_file"], item["source_line"],
                             item["sink_file"], item["sink_line"], item["sink_kind"],
                             tuple((h["caller_file"], h["caller_line"],
                                    h["callee_file"]) for h in item["hops"]))
                if signature in duplicates:
                    continue
                duplicates.add(signature)
                if len(leads) >= max_leads:
                    coverage["truncated"] = True
                    break
                token = repr(signature).encode("utf-8")
                leads.append({
                    "id": "MCF-" + hashlib.sha256(token).hexdigest()[:16],
                    "status": "UNVERIFIED_EXPLICIT_CROSSFILE_LEXICAL_PATH",
                    "platform": platform, "severity": "unassessed",
                    "reachability": "UNKNOWN", "impact": "NOT_ESTABLISHED",
                    "source": {"file": item["source_file"],
                               "line": item["source_line"],
                               "sha256": item["source_sha256"],
                               "kind": item["source_kind"]},
                    "sink": {"file": item["sink_file"], "line": item["sink_line"],
                             "sha256": item["sink_sha256"],
                             "method": item["sink_method"],
                             "kind": item["sink_kind"]},
                    "hops": item["hops"],
                    "missing_evidence": ["compiler symbol binding", "branch feasibility",
                                         "caller identity/permission", "native execution",
                                         "negative control", "actual impact"],
                })
    graph_edges = {}
    graph_nodes = {}
    for lead in leads:
        for hop in lead["hops"]:
            caller = hop["caller_file"] + "::" + hop["caller_method"]
            callee = hop["callee_file"] + "::" + hop["callee_method"]
            graph_nodes[caller] = {"id": caller, "kind": "method",
                                   "file": hop["caller_file"],
                                   "method": hop["caller_method"]}
            graph_nodes[callee] = {"id": callee, "kind": "method",
                                   "file": hop["callee_file"],
                                   "method": hop["callee_method"]}
            key = (caller, callee, hop["caller_line"])
            graph_edges[key] = {"from": caller, "to": callee,
                                "call_line": hop["caller_line"],
                                "resolution": hop["resolution"],
                                "verified_runtime": False}
    result = {
        "schema_version": 1,
        "engine": "mobile-crossfile",
        "mode": "offline-explicit-unique-symbol-lexical",
        "platform": platform, "source_root": "operator-provided",
        "coverage": coverage,
        "graph": {"nodes": [graph_nodes[k] for k in sorted(graph_nodes)],
                  "edges": [graph_edges[k] for k in sorted(graph_edges)],
                  "interpretation": "lexically resolved review edges, not verified runtime calls"},
        "leads": leads, "lead_count": len(leads),
        "assurance": "STATIC_LEADS_ONLY_NOT_COMPILER_VERIFIED",
        "limits": {
            "max_interfile_hops": MAX_HOPS,
            "only_explicit_resolved_class_or_local_instance_calls": True,
            "supported_sources": sorted(FILE_TYPES[platform]),
            "not_implemented": ["true Java/Kotlin/Swift type resolution",
                                "overload resolution", "interface dispatch",
                                "nested expression calls", "cross-file returns",
                                "implicit callbacks", "Smali interfile calls",
                                "ObjC message dispatch", "native runtime proof"],
        },
    }
    if compiler_graph is not None:
        if platform != "android":
            raise ValueError("Java compiler graph is supported only with android")
        result = _compiler_support(result, compiler_graph, root)
    if jvm_classes is not None:
        if platform != "android":
            raise ValueError("Kotlin JVM alignment is supported only with android")
        import mobile_kotlin_jvm
        result = mobile_kotlin_jvm.align_kotlin_leads(result, entries, jvm_classes)
    return result
