#!/usr/bin/env python3
"""Source-only JDK 17 compiler call graph, not taint, reachability or an exploit.

Compiles a trusted helper; parses/analyzes operator-supplied Java in javac
with annotation processing off, isolated classpath and no target classfiles.
It does not explicitly OS-sandbox the compiler or forbid Java networking.
"""
import base64
import binascii
import hashlib
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import mobile_lab

MAX_FILES = 350
MAX_PATHS = 30000
MAX_TOTAL_BYTES = 8 * 1024 * 1024
MAX_SOURCE_BYTES = 350000
MAX_EDGES = 3000
MAX_STDOUT_BYTES = 6 * 1024 * 1024
HELPER = Path(__file__).resolve().parents[1] / "java" / "MobileCompilerGraph.java"


def _sources(root):
    selected, digests, total = [], {}, 0
    coverage = {"skipped_files": 0, "truncated": False,
                "source_bytes": 0, "paths_scanned": 0}
    for path in sorted(root.rglob("*")):
        coverage["paths_scanned"] += 1
        if coverage["paths_scanned"] > MAX_PATHS:
            coverage["truncated"] = True
            break
        if path.suffix.lower() != ".java" or not path.is_file():
            continue
        if (path.is_symlink()
                or any(part.is_symlink() for part in path.parents if part != root)):
            coverage["skipped_files"] += 1
            continue
        size = path.stat().st_size
        if (len(selected) >= MAX_FILES or total + size > MAX_TOTAL_BYTES):
            coverage["truncated"] = True
            break
        if size > MAX_SOURCE_BYTES:
            coverage["truncated"] = True
            coverage["skipped_files"] += 1
            continue
        data = mobile_lab._regular_file(path, MAX_SOURCE_BYTES)
        try:
            data.decode("utf-8")
        except UnicodeDecodeError:
            coverage["skipped_files"] += 1
            continue
        relative = path.relative_to(root).as_posix()
        digests[relative] = hashlib.sha256(data).hexdigest()
        total += len(data)
        selected.append(path)
    coverage["source_bytes"] = total
    coverage["source_files"] = len(selected)
    return selected, digests, coverage


def _execute(argv, timeout):
    try:
        process = subprocess.run(
            argv, capture_output=True, stdin=subprocess.DEVNULL,
            check=False, timeout=timeout,
            env={k: v for k, v in os.environ.items() if k in
                 ("HOME", "PATH", "LANG", "LC_ALL", "TMPDIR", "JAVA_HOME")},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError("JDK helper unavailable or exceeded time bound") from exc
    if process.returncode != 0:
        raise ValueError("isolated-classpath compiler helper exited unsuccessfully")
    if len(process.stdout) > MAX_STDOUT_BYTES:
        raise ValueError("compiler edge output exceeded byte limit")
    return process.stdout.decode("utf-8")


def _decode(raw):
    try:
        value = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
        return value.decode("utf-8", "strict")
    except (binascii.Error, UnicodeDecodeError, ValueError) as exc:
        raise ValueError("invalid encoded compiler field") from exc


def _parse(output, digests):
    lines = output.splitlines()
    if not lines:
        raise ValueError("compiler emitted no metadata")
    meta = lines[0].split("\t")
    if len(meta) != 5 or meta[0] != "META":
        raise ValueError("unexpected compiler metadata")
    try:
        files, errors, declarations = map(int, meta[1:4])
    except ValueError as exc:
        raise ValueError("invalid compiler metadata numbers") from exc
    if (files != len(digests) or errors < 0 or declarations < 0
            or meta[4] not in ("0", "1")):
        raise ValueError("compiler metadata inconsistent with source selection")
    edges, seen = [], set()
    for line in lines[1:]:
        fields = line.split("\t")
        if len(fields) != 10 or fields[0] != "EDGE":
            raise ValueError("unexpected compiler edge record")
        (caller_file, caller_method, caller_line, callee_file, callee_method,
         callee_line, call_line, caller_signature, callee_signature) = [
            _decode(s) for s in fields[1:]]
        if caller_file not in digests or callee_file not in digests:
            raise ValueError("compiler edge references an undeclared source")
        try:
            declaration_line, target_line, invocation_line = (
                int(caller_line), int(callee_line), int(call_line))
        except ValueError as exc:
            raise ValueError("invalid compiler line number") from exc
        if min(declaration_line, target_line, invocation_line) < 1:
            raise ValueError("compiler line anchors must be positive")
        key = (caller_file, caller_method, declaration_line,
               callee_file, callee_method, target_line,
               invocation_line, caller_signature, callee_signature)
        if key in seen:
            continue
        seen.add(key)
        if len(edges) >= MAX_EDGES:
            raise ValueError("compiler output exceeds edge cap")
        edges.append({
            "caller_file": caller_file, "caller_sha256": digests[caller_file],
            "caller_method": caller_method,
            "caller_declaration_line": declaration_line,
            "call_line": invocation_line,
            "callee_file": callee_file, "callee_sha256": digests[callee_file],
            "callee_method": callee_method,
            "callee_declaration_line": target_line,
            "caller_signature": caller_signature,
            "callee_signature": callee_signature,
            "binding_source": "JDK_COMPILER_SYMBOL",
            "runtime_invocation_verified": False,
        })
    return {
        "java_files_supplied_to_compiler": files,
        "java_declarations_resolved": declarations,
        "diagnostic_errors": errors,
        "compiler_edge_truncated": meta[4] == "1",
        "edges": sorted(edges, key=lambda edge: (
            edge["caller_file"], edge["call_line"],
            edge["callee_file"], edge["callee_declaration_line"],
            edge["callee_signature"])),
    }


def analyze(sources, javac="javac", java="java"):
    given = Path(sources).expanduser().absolute()
    if not given.is_dir() or given.is_symlink():
        raise ValueError("Java source root must be a non-symlink directory")
    root = given.resolve(strict=True)
    selected, digests, coverage = _sources(root)
    if not selected:
        raise ValueError("no eligible Java sources to analyze")
    if not HELPER.is_file() or HELPER.is_symlink():
        raise ValueError("shipped Java compiler helper unavailable")
    if javac != "javac" or java != "java":
        raise ValueError("only local JDK executables from PATH are supported")
    javac_bin, java_bin = shutil.which(javac), shutil.which(java)
    if not javac_bin or not java_bin:
        raise ValueError("JDK 17+ javac/java must be installed")
    with tempfile.TemporaryDirectory(prefix="bpilot-java-graph-") as scratch:
        build_dir = Path(scratch) / "compiled-helper"
        empty_cp = Path(scratch) / "empty-classpath"
        build_dir.mkdir(mode=0o700)
        empty_cp.mkdir(mode=0o700)
        _execute([javac_bin, "-encoding", "UTF-8", "-proc:none",
                  "-d", str(build_dir), str(HELPER)], timeout=35)
        output = _execute(
            [java_bin, "-Xmx384m", "-cp", str(build_dir),
             "MobileCompilerGraph", str(root), str(empty_cp)]
            + [str(path) for path in selected], timeout=100)
    parsed = _parse(output, digests)
    complete = not coverage["truncated"] and not parsed["compiler_edge_truncated"]
    return {
        "schema_version": 1, "engine": "mobile-java-compiler-graph",
        "platform": "android", "mode": "JDK_AST_SYMBOL_RESOLUTION",
        "source_root": "operator-provided",
        "coverage": {**coverage,
                     "java_declarations_resolved": parsed["java_declarations_resolved"],
                     "diagnostic_errors": parsed["diagnostic_errors"],
                     "compiler_edge_truncated": parsed["compiler_edge_truncated"],
                     "complete_file_coverage": complete},
        "edges": parsed["edges"], "edge_count": len(parsed["edges"]),
        "source_digests": dict(sorted(digests.items())),
        "assurance": (
            "COMPILER_BINDINGS_WITH_DIAGNOSTIC_ERRORS"
            if parsed["diagnostic_errors"]
            else "COMPILER_BINDINGS_UNDER_ISOLATED_CLASSPATH"),
        "limitations": [
            "binding is compiler-resolved only for available Java source symbols",
            "Java, not Kotlin, Swift, Objective-C or Smali",
            "no Android SDK or app-dependency classpath is loaded",
            "compiler diagnostics can make binding coverage incomplete",
            "reflection, runtime polymorphism and callback dispatch not evaluated",
            "no taint, branch feasibility, permissions or protected effect proven",
            "no OS-level network sandbox imposed; use trusted local JDK and isolation",
        ],
    }
