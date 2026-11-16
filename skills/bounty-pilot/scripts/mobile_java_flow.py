#!/usr/bin/env python3
"""Bounded Java AST flow review; neither runtime verification nor an exploit.

A trusted JDK helper analyzes ordered locals, pure return summaries,
private current-object fields, and narrow assignment-only joins.
Calls require fixed dispatch. Intent sources and sinks remain syntax/name
cues, not authenticated Android framework objects. No target classes execute.
"""
import hashlib
import shutil
import tempfile
from pathlib import Path

import mobile_java_compiler
import mobile_lab

HELPER = Path(__file__).resolve().parents[1] / "java" / "MobileCompilerFlow.java"
MAX_HOPS = 3
MAX_FLOWS = 120
MAX_LINE = 10000000
MAX_OUTPUT_BYTES = 6 * 1024 * 1024


def _positive(value, label):
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid compiler " + label) from exc
    if not 1 <= parsed <= MAX_LINE:
        raise ValueError("out-of-range compiler " + label)
    return parsed


def _parse(payload, digests):
    if len(payload.encode("utf-8")) > MAX_OUTPUT_BYTES:
        raise ValueError("Java compiler flow report is too large")
    lines = payload.splitlines()
    if not lines:
        raise ValueError("compiler flow metadata missing")
    meta = lines[0].split("\t")
    if len(meta) != 7 or meta[0] != "META":
        raise ValueError("unexpected Java compiler flow header")
    try:
        files, errors, declarations, count, unsupported = map(int, meta[1:6])
    except ValueError as exc:
        raise ValueError("invalid Java compiler flow summary") from exc
    if (files != len(digests) or errors < 0 or declarations < 0
            or count < 0 or count > MAX_FLOWS or unsupported < 0
            or meta[6] not in ("0", "1")):
        raise ValueError("invalid or truncated Java compiler flow summary")
    leads = []
    seen = set()
    for line in lines[1:]:
        fields = line.split("\t")
        if not fields or fields[0] != "FLOW" or len(fields) < 10:
            raise ValueError("unrecognized compiler flow record")
        values = [mobile_java_compiler._decode(value) for value in fields[1:]]
        if len(values) < 9:
            raise ValueError("missing compiler flow anchors")
        (source_file, source_line, source_kind, sink_file, sink_line,
         sink_method, sink_signature, sink_cue, hop_count) = values[:9]
        hops = _positive(hop_count, "hop count")
        if hops > MAX_HOPS or len(fields) not in (10 + 8 * hops, 10 + 9 * hops):
            raise ValueError("compiler flow hop count inconsistent")
        stride = 9 if len(fields) == 10 + 9 * hops else 8
        if source_file not in digests or sink_file not in digests:
            raise ValueError("flow mentions a source outside pinned snapshot")
        if source_kind not in ("ANDROID_INTENT_SOURCE_SYNTAX_CUE",
                               "ONNEWINTENT_PARAMETER_NAME_CUE"):
            raise ValueError("unsupported source cue")
        if sink_cue not in (
                "loadUrl", "loadDataWithBaseURL", "setResult",
                "openFileOutput", "openOutputStream", "sendBroadcast",
                "startActivity", "startService"):
            raise ValueError("unsupported sink cue")
        chain = []
        data = values[9:]
        for i in range(0, len(data), stride):
            segments = data[i:i + stride]
            (caller_file, caller_method, caller_signature, call_line,
             callee_file, callee_method, callee_line, callee_signature) = segments[:8]
            kind = segments[8] if stride == 9 else "METHOD_CALL"
            if kind not in ("METHOD_CALL", "RETURN_TO_CALLER"):
                raise ValueError("unknown compiler flow edge kind")
            if caller_file not in digests or callee_file not in digests:
                raise ValueError("flow hop refers to unknown source")
            chain.append({
                "caller_file": caller_file, "caller_sha256": digests[caller_file],
                "caller_method": caller_method,
                "caller_signature": caller_signature,
                "call_line": _positive(call_line, "call line"),
                "callee_file": callee_file, "callee_sha256": digests[callee_file],
                "callee_method": callee_method,
                "callee_signature": callee_signature,
                "callee_declaration_line": _positive(callee_line, "declaration line"),
                "edge_kind": kind,
                "method_binding": ("JDK_EXECUTABLE_ELEMENT"
                                   if kind == "METHOD_CALL"
                                   else "JDK_BOUND_RETURN_TO_CALLER"),
            })
        if not chain or chain[0]["caller_file"] != source_file:
            raise ValueError("flow source/hops do not connect")
        if chain[-1]["callee_file"] != sink_file:
            raise ValueError("flow hop/sink do not connect")
        # A return must restore precisely the active call frame.
        stack = [(chain[0]["caller_file"], chain[0]["caller_signature"])]
        for edge in chain:
            if (edge["caller_file"], edge["caller_signature"]) != stack[-1]:
                raise ValueError("non-contiguous compiler flow method chain")
            target = (edge["callee_file"], edge["callee_signature"])
            if edge["edge_kind"] == "METHOD_CALL":
                stack.append(target)
            else:
                if len(stack) < 2 or target != stack[-2]:
                    raise ValueError("return does not match compiler call frame")
                stack.pop()
        if stack[-1] != (sink_file, sink_signature):
            raise ValueError("compiler flow terminates outside sink method")
        result = {
            "source": {"file": source_file,
                       "line": _positive(source_line, "source line"),
                       "sha256": digests[source_file], "kind": source_kind},
            "sink": {"file": sink_file,
                     "line": _positive(sink_line, "sink line"),
                     "sha256": digests[sink_file],
                     "method": sink_method,
                     "method_signature": sink_signature,
                     "api_name_cue": sink_cue},
            "hops": chain,
            "status": "JAVA_AST_BOUNDED_ARGUMENT_RETURN_FIELD_FLOW_REVIEW",
            "severity": "unassessed",
            "reachability": "UNKNOWN",
            "impact": "NOT_ESTABLISHED",
            "attacker_origin_verified": False,
            "branch_feasibility_verified": False,
            "sink_effect_verified": False,
            "limitations": [
                "Android source API recognition is name/syntax-based",
                "sink API recognition is name-based, not OS-side authenticated",
                "parameter binding resolved by Java compiler",
                "pure fixed-dispatch return helpers only; return hops are explicit",
                "private this.field accesses only within the current method",
                "unmodeled aliases, cross-method heap, complex branches and virtual dispatch",
            ],
        }
        identity = (source_file, result["source"]["line"], sink_file,
                    result["sink"]["line"],
                    tuple((hop["caller_file"], hop["call_line"],
                           hop["callee_signature"], hop["edge_kind"]) for hop in chain))
        if identity in seen:
            continue
        seen.add(identity)
        result["id"] = ("MCFA-" + hashlib.sha256(
            repr(identity).encode("utf-8")).hexdigest()[:16])
        leads.append(result)
    if len(lines) - 1 != count:
        raise ValueError("compiler emitted inconsistent flow count")
    return {
        "declarations": declarations,
        "diagnostic_errors": errors,
        "unsupported_control_flow_statements": unsupported,
        "truncated": meta[6] == "1",
        "leads": leads,
    }


def analyze(sources):
    supplied = Path(sources).expanduser().absolute()
    if supplied.is_symlink() or not supplied.is_dir():
        raise ValueError("Java source root must be a non-symlink directory")
    root = supplied.resolve(strict=True)
    files, digests, coverage = mobile_java_compiler._sources(root)
    if not files:
        raise ValueError("no eligible Java sources for compiler flow")
    if not HELPER.is_file() or HELPER.is_symlink():
        raise ValueError("trusted JDK flow helper unavailable")
    javac, java = shutil.which("javac"), shutil.which("java")
    if not javac or not java:
        raise ValueError("local JDK 17+ javac and java required")
    with tempfile.TemporaryDirectory(prefix="bpilot-java-flow-") as scratch:
        compiled = Path(scratch) / "helpers"
        empty = Path(scratch) / "classpath"
        compiled.mkdir(mode=0o700)
        empty.mkdir(mode=0o700)
        mobile_java_compiler._execute([
            javac, "-proc:none", "-encoding", "UTF-8",
            "-d", str(compiled), str(HELPER)], timeout=35)
        output = mobile_java_compiler._execute([
            java, "-Xmx384m", "-cp", str(compiled), "MobileCompilerFlow",
            str(root), str(empty)] + [str(path) for path in files], timeout=100)
    for relative, original in digests.items():
        path = root / relative
        if hashlib.sha256(
                mobile_lab._regular_file(path, mobile_java_compiler.MAX_SOURCE_BYTES)
        ).hexdigest() != original:
            raise ValueError("Java source changed during compiler flow analysis")
    results = _parse(output, digests)
    return {
        "schema_version": 1,
        "engine": "mobile-java-compiler-flow",
        "platform": "android",
        "mode": "JDK_AST_FIXED_DISPATCH_ARGUMENT_PURE_RETURN_AND_PRIVATE_FIELD_FLOW",
        "assurance": "STATIC_ARGUMENT_FLOW_CANDIDATES_ONLY_NO_RUNTIME_VERIFICATION",
        "coverage": {
            **coverage,
            "method_declarations": results["declarations"],
            "diagnostic_errors": results["diagnostic_errors"],
            "unsupported_control_flow_statements": results[
                "unsupported_control_flow_statements"],
            "flow_truncated": results["truncated"],
            "complete_file_coverage": (
                not coverage["truncated"] and not results["truncated"]
                and results["diagnostic_errors"] == 0),
        },
        "source_digests": dict(sorted(digests.items())),
        "leads": results["leads"],
        "lead_count": len(results["leads"]),
        "engine_does_not_execute_target_classes": True,
        "limitations": [
            "ordered local Java variables, private this.fields and conditional joins only",
            "only statically dispatched intra/inter-file Java method calls (three hops maximum)",
            "complex conditions, branch bodies, loops and try/catch clear taint rather than speculate",
            "pure direct returns only; no cross-method fields, aliases or full provenance",
            "Android Intent source and sink names are syntax cues, not verified APIs",
            "not Kotlin, Swift, native code, Smali or runtime callback dispatch",
            "no proof of authorization, user control, exploitability or harm",
            "compiler diagnostics and incomplete SDK classpaths reduce coverage",
            "JDK not OS-network-sandboxed; use a disposable isolated environment",
        ],
    }
