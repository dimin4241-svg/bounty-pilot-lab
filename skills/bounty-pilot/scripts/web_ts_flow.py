#!/usr/bin/env python3
"""Bounded cross-file JS/TS syntax flow through ESM imports to sensitive calls.

Does not execute target source, send HTTP requests, prove authorization bypass,
or perform compiler type-checker/whole-program taint analysis. File sources
are parsed with an operator-vetted SHA-pinned TypeScript compiler on a local,
isolated runner. All reported paths are unverified reading candidates.
"""
import argparse
import hashlib
import json
import os
import posixpath
import re
import shutil
import subprocess
import sys
from collections import deque
from pathlib import Path

EXTENSIONS = (".ts", ".tsx", ".js", ".jsx", ".mts", ".cts", ".mjs", ".cjs")
SKIP = frozenset((".git", "node_modules", ".next", "dist", "build", "coverage", ".turbo",
                  ".cache", ".venv", "__pycache__"))
MAX_FILES = 120
MAX_FILE_BYTES = 180_000
MAX_TOTAL_BYTES = 4_000_000
MAX_STEPS = 2500
MAX_HOPS = 5
MAX_LEADS = 150
SHA = re.compile(r"^[0-9a-f]{64}$")
IDENT = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]{0,100}$")
GUARD = re.compile(r"(auth|permission|verify|guard|owner|tenant|role|access|policy|session)", re.I)
SINK = re.compile(
    r"(^|\.)(?:findUnique|findFirst|findMany|update|updateMany|delete|deleteMany|"
    r"create|createMany|execute|queryRaw|save|charge|refund|transfer|withdraw|"
    r"sendTransaction|writeContract|signTypedData|publish|enqueue)$", re.I)
SINK_ROOT = re.compile(r"^(db|prisma|repository|repo|store|stripe|billing|payment|queue)\.", re.I)
SOURCE_PARAMS = frozenset(("req", "request", "context", "ctx", "event", "payload", "input", "body"))

# DOM sinks. innerHTML/outerHTML/dangerouslySetInnerHTML are distinctive property names in their
# own right (an object literally named `.innerHTML` is almost never anything else), so they match
# regardless of what the receiver expression is - a DOM element is referenced through an arbitrary
# local variable name, unlike the backend ORM calls above that are rooted at a known object name.
DOM_SINK_PROPERTY = re.compile(r"(^|\.)(?:innerHTML|outerHTML|dangerouslySetInnerHTML)$")
DOM_SINK_GLOBAL = re.compile(r"^(?:eval|Function)$")
# write/writeln/open/href/assign/replace/cookie are common, generic names on unrelated objects
# (String.prototype.replace, any object's .open()); only count them rooted at document/window/
# location/history, parsed from the full `object.property` chain web_ts_flow_parser.cjs builds.
DOM_SINK_ROOTED = re.compile(
    r"^(?:document\.(?:write|writeln|cookie)|window\.open|location\.(?:href|assign|replace))$", re.I)
# A cue, never a proof: a sanitizer call present in the chain does not establish it is applied to
# this exact value, configured safely, or not itself bypassed; its absence does not establish an
# unsanitized sink either - sanitization can happen in a wrapper component this scan never visits.
SANITIZER = re.compile(r"(sanitiz|purify|dompurify|escape|striptags|strip_tags)", re.I)
# Flow-insensitive: these identifiers are treated as attacker-influenceable wherever they appear in
# any function's call arguments or variable initializers, the same bag-of-identifiers model the
# existing alias/argument taint tracking already uses. A local variable or parameter that happens
# to share one of these names is indistinguishable from the real DOM API and will false-positive;
# that is the same trade-off SOURCE_PARAMS already makes for backend request parameter names.
DOM_SOURCE_IDENT = frozenset(("location", "referrer", "localStorage", "sessionStorage", "cookie"))
MAX_DOM_ENTRY_STEPS = 4000


def _dom_sink_kind(name):
    if not isinstance(name, str) or len(name) > 150:
        return None
    if DOM_SINK_PROPERTY.search(name):
        return "DOM_XSS_CANDIDATE_FLOW"
    if DOM_SINK_GLOBAL.fullmatch(name) or DOM_SINK_ROOTED.fullmatch(name):
        return "DOM_XSS_CANDIDATE_FLOW"
    return None


def _digest(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":"),
                                    ensure_ascii=True).encode("ascii")).hexdigest()


def _root(path):
    root = Path(path).expanduser()
    if root.is_symlink() or not root.is_dir():
        raise ValueError("source root must be a non-symlink directory")
    return root.resolve()


def _parser(path, sha):
    parser = Path(path)
    if (not parser.is_absolute() or parser.is_symlink() or not parser.is_file() or
            parser.name != "typescript.js" or parser.stat().st_size > 20_000_000 or
            not isinstance(sha, str) or not SHA.fullmatch(sha)):
        raise ValueError("absolute vetted typescript.js and pinned SHA-256 required")
    if hashlib.sha256(parser.read_bytes()).hexdigest() != sha:
        raise ValueError("pinned TypeScript parser SHA-256 mismatch")
    return str(parser.resolve())


def _collect(root, prefixes=None):
    if prefixes is None:
        prefixes = ["."]
    if not isinstance(prefixes, list) or len(prefixes) > 20:
        raise ValueError("bounded scope prefixes required")
    validated = []
    for prefix in prefixes:
        if (not isinstance(prefix, str) or not prefix or prefix.startswith("/") or
                "\\" in prefix or ".." in Path(prefix).parts or
                any(ord(c) < 32 for c in prefix)):
            raise ValueError("invalid source scope prefix")
        validated.append(prefix.rstrip("/"))
    found = []
    omitted = {"oversized": 0, "symlinked": 0, "excluded": 0}
    size = 0
    for file in sorted(root.rglob("*")):
        if file.suffix.lower() not in EXTENSIONS:
            continue
        rel = file.relative_to(root)
        if any(part in SKIP for part in rel.parts):
            continue
        relname = rel.as_posix()
        if not any(pre == "." or relname == pre or relname.startswith(pre + "/")
                   for pre in validated):
            omitted["excluded"] += 1
            continue
        # Test only components *inside* the checkout. Absolute parents
        # above the root may be OS-managed aliases (macOS /var -> /private/var)
        # and must not silently eliminate every otherwise normal source file.
        if file.is_symlink() or any(
                (root / Path(*rel.parts[:depth])).is_symlink()
                for depth in range(1, len(rel.parts))):
            omitted["symlinked"] += 1
            continue
        if not file.is_file():
            continue
        byte_size = file.stat().st_size
        if byte_size > MAX_FILE_BYTES:
            omitted["oversized"] += 1
            continue
        if len(found) >= MAX_FILES or size + byte_size > MAX_TOTAL_BYTES:
            raise ValueError("source budget exhausted; narrow --scope")
        size += byte_size
        found.append({"path": relname, "content": file.read_text(
            encoding="utf-8", errors="replace")})
    return found, omitted, size


def _resolve_import(from_path, spec, available):
    if not isinstance(spec, str) or not spec.startswith("."):
        return None
    base = posixpath.normpath(posixpath.join(posixpath.dirname(from_path), spec))
    if base == ".." or base.startswith("../") or base.startswith("/"):
        return None
    candidates = [base]
    candidates.extend(base + suffix for suffix in EXTENSIONS)
    candidates.extend(posixpath.join(base, "index" + suffix) for suffix in EXTENSIONS)
    for item in candidates:
        if item in available:
            return item
    return None


def _check_index(index):
    if not isinstance(index, dict) or index.get("schema_version") != 1:
        raise ValueError("invalid parser index")
    rows = index.get("files")
    if not isinstance(rows, list) or len(rows) > MAX_FILES:
        raise ValueError("invalid parsed file set")
    return rows


def analyze_index(index, parser_sha, source_bytes, omitted):
    rows = _check_index(index)
    symbols = {}
    imports = {}
    routes = []
    available = set()
    parse_problems = []
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("path"), str):
            raise ValueError("invalid indexed file")
        path = row["path"]
        if path in available or path.startswith("/") or ".." in path.split("/"):
            raise ValueError("duplicate or unsafe indexed file")
        available.add(path)
    for row in rows:
        path = row["path"]
        if row.get("parse_diagnostics"):
            parse_problems.append({"file": path, "kind": "PARSER_DIAGNOSTIC"})
            continue
        aliases = {}
        for imp in row.get("imports", [])[:150]:
            dest = _resolve_import(path, imp.get("specifier"), available)
            if dest:
                for item in imp.get("names", [])[:50]:
                    local, remote = item.get("local"), item.get("exported")
                    if isinstance(local, str) and IDENT.fullmatch(local) and (
                            isinstance(remote, str) and
                            (IDENT.fullmatch(remote) or remote == "default")):
                        aliases[local] = (dest, remote)
        imports[path] = aliases
        for item in row.get("functions", [])[:300]:
            name = item.get("name")
            if not isinstance(name, str) or not IDENT.fullmatch(name):
                continue
            key = (path, name)
            if key not in symbols:
                symbols[key] = item
        for r in row.get("routes", [])[:500]:
            if not isinstance(r, dict) or not isinstance(r.get("path"), str):
                continue
            if not r["path"].startswith("/") or len(r["path"]) > 420:
                continue
            if r.get("method") not in ("GET", "POST", "PUT", "PATCH", "DELETE"):
                continue
            handler = r.get("handler")
            if not isinstance(handler, str) or not IDENT.fullmatch(handler):
                continue
            routes.append({
                "file": path, "line": r.get("line"), "method": r["method"],
                "path": r["path"], "handler": handler,
                "middleware_cues": [x for x in r.get("middleware", [])[:30]
                                    if isinstance(x, str) and GUARD.search(x)]
            })

    def resolve(path, callee):
        if not isinstance(callee, str) or not IDENT.fullmatch(callee):
            return None
        if (path, callee) in symbols:
            return path, callee
        mapped = imports.get(path, {}).get(callee)
        if mapped and mapped in symbols and symbols[mapped].get("exported") is True:
            return mapped
        return None

    flows, unresolved = [], []
    seen_flows = set()
    budget = {"steps": 0, "dom_steps": 0}

    def _trace(entry, starting_names, initial_guards, origin, sink_kind_of, step_key, step_cap):
        queue = deque([(entry, frozenset(starting_names), [], initial_guards)])
        seen = set()
        while queue and budget[step_key] < step_cap and len(flows) < MAX_LEADS:
            key, taints, chain, guards = queue.popleft()
            state = (key, tuple(sorted(taints)))
            if state in seen or len(chain) >= MAX_HOPS:
                continue
            seen.add(state)
            budget[step_key] += 1
            definition = symbols[key]
            taints = set(taints)
            for _ in range(4):
                for alias in definition.get("aliases", [])[:100]:
                    if (isinstance(alias.get("name"), str) and
                            any(x in taints for x in alias.get("from", []))):
                        taints.add(alias["name"])
            local_guards = set(guards)
            sanitizer_cues = set()
            for c in definition.get("calls", [])[:150]:
                name = c.get("callee")
                if not isinstance(name, str) or len(name) > 150:
                    continue
                if GUARD.search(name):
                    local_guards.add(name[:100])
                if SANITIZER.search(name):
                    sanitizer_cues.add(name[:100])
                arg_flags = [
                    any(identifier in taints for identifier in identifiers)
                    if isinstance(identifiers, list) else False
                    for identifiers in c.get("args", [])[:15]]
                if not any(arg_flags):
                    continue
                hop = {"file": key[0], "function": key[1],
                       "callee": name, "line": c.get("line")}
                callee = resolve(key[0], name)
                sink_kind = sink_kind_of(name)
                if callee and not sink_kind:
                    target_params = symbols[callee].get("params", [])
                    next_names = {target_params[i] for i, tainted in enumerate(arg_flags)
                                 if tainted and i < len(target_params) and target_params[i]}
                    if next_names:
                        queue.append((callee, frozenset(next_names),
                                      chain + [hop], sorted(local_guards)[:40]))
                elif sink_kind:
                    fingerprint = (origin["fingerprint"], key[0], key[1], name)
                    if fingerprint in seen_flows:
                        continue
                    seen_flows.add(fingerprint)
                    evidence = chain + [hop]
                    flows.append({
                        "id": _digest(fingerprint)[:18],
                        "kind": sink_kind,
                        "entry": origin["entry"],
                        "sink": {"file": key[0], "function": key[1], "call": name,
                                 "line": c.get("line")},
                        "call_chain": evidence,
                        "cross_file": len({x["file"] for x in evidence}) > 1,
                        "guard_name_cues": sorted(local_guards)[:40],
                        "sanitizer_name_cues": sorted(sanitizer_cues)[:40],
                        "classification": "UNVERIFIED_STATIC_ARGUMENT_FLOW",
                        "review": origin["review"]
                    })

    def _backend_sink(name):
        if SINK.search(name) and (SINK_ROOT.search(name) or "." not in name):
            return "SYNTACTIC_REQUEST_ARGUMENT_TO_SENSITIVE_CALL"
        # eval/new Function fed by a request parameter is server-side code injection, not DOM
        # XSS, but the same bare-global sink shape; worth the same one-line check here so a
        # request argument reaching eval is not silently uncovered by either pass.
        if DOM_SINK_GLOBAL.fullmatch(name):
            return "SYNTACTIC_REQUEST_ARGUMENT_TO_CODE_EVALUATION"
        return None

    for route in routes:
        entry = resolve(route["file"], route["handler"])
        if entry is None:
            unresolved.append({"file": route["file"], "line": route["line"],
                               "reason": "HANDLER_UNRESOLVED"})
            continue
        definition = symbols[entry]
        starting = frozenset(name for name in definition.get("params", []) if name in SOURCE_PARAMS)
        if not starting:
            continue
        origin = {"fingerprint": (route["file"], route["line"]),
                  "entry": {"file": route["file"], "line": route["line"],
                           "method": route["method"], "path": route["path"]},
                  "review": ("Manually trace runtime input, sanitizers, middleware, "
                            "authorization and actual side effect; syntax alone "
                            "cannot prove a vulnerability.")}
        _trace(entry, starting, list(route["middleware_cues"]), origin, _backend_sink,
              "steps", MAX_STEPS)

    # Second, independent pass: a DOM-source identifier (location, document.referrer,
    # localStorage, sessionStorage, document.cookie) reaching a DOM sink. Unlike the backend
    # pass above, this does not start from a route handler - a React/Vue component or any other
    # browser-side function is normally never called from a server route at all, so every
    # function is its own entry point, seeded with the fixed DOM-source identifier set rather
    # than a resolved parameter name. The same flow-insensitive alias/argument taint mechanics
    # as the backend pass apply unchanged; only the seed and the sink pattern differ.
    for key in sorted(symbols):
        origin = {"fingerprint": ("DOM_SOURCE", key[0], key[1]),
                  "entry": {"file": key[0], "function": key[1], "line": symbols[key].get("line")},
                  "review": ("Manually confirm the source is actually reachable from an "
                            "attacker-controlled browser context, that no sanitizer is applied "
                            "between source and sink, and the eligible dApp impact class "
                            "(signing/redirect) before reporting; syntax alone proves nothing.")}
        _trace(key, DOM_SOURCE_IDENT, [], origin, _dom_sink_kind, "dom_steps", MAX_DOM_ENTRY_STEPS)
        if len(flows) >= MAX_LEADS:
            break

    flows.sort(key=lambda x: (-int(x["cross_file"]), x["id"]))
    return {
        "schema_version": 1, "mode": "web-ts-cross-file-flow",
        "parser_sha256": parser_sha,
        "source_bytes": source_bytes, "files_scanned": len(rows),
        "functions_indexed": len(symbols), "routes_indexed": len(routes),
        "unresolved_routes": unresolved[:100],
        "parse_problems": parse_problems,
        "omitted": omitted, "flows": flows[:MAX_LEADS],
        "truncated": len(flows) >= MAX_LEADS,
        "network_requests": 0, "confirmed_vulnerabilities": 0,
        "limitations": ("Bounded, syntactic ESM named imports and simple call-argument "
                        "propagation only. Aliasing is flow-insensitive. No type checker, "
                        "cross-function return taint, class dispatch, imported namespaces, "
                        "full middleware inheritance or runtime guard verification. "
                        "Guard-name cues never establish presence/absence of authorization. "
                        "DOM_XSS_CANDIDATE_FLOW seeds every function with a fixed identifier "
                        "set (location, referrer, localStorage, sessionStorage, cookie); a "
                        "local variable or parameter sharing one of those names, not the real "
                        "DOM API, will false-positive the same way SOURCE_PARAMS already can "
                        "for backend flows. A sanitizer_name_cues entry is a call name seen "
                        "in the chain, never proof it runs on this value or is configured safely.")
    }


def inspect(repo, parser_path, parser_sha256, prefixes=None):
    root = _root(repo)
    parser = _parser(parser_path, parser_sha256)
    files, omitted, source_bytes = _collect(root, prefixes)
    if not files:
        raise ValueError("no in-scope JS/TS files selected")
    payload = {"schema_version": 1, "files": files}
    cmd = [shutil.which("node") or "node", "--max-old-space-size=256",
           str(Path(__file__).with_name("web_ts_flow_parser.cjs").resolve()), parser]
    try:
        proc = subprocess.run(cmd, input=json.dumps(payload), text=True,
                              capture_output=True, timeout=35, check=False,
                              cwd=str(Path(__file__).resolve().parent),
                              env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                                   "NODE_OPTIONS": ""})
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError("pinned local TypeScript parser unavailable/timeout") from exc
    if proc.returncode or len(proc.stdout) > 8_000_000:
        raise ValueError("TypeScript parser failed; check local isolated installation")
    try:
        index = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise ValueError("TypeScript parser emitted invalid JSON") from exc
    result = analyze_index(index, parser_sha256, source_bytes, omitted)
    result["source_fingerprint_sha256"] = _digest([
        [f["path"], hashlib.sha256(f["content"].encode("utf-8")).hexdigest()]
        for f in files])
    return result


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--repo", required=True, help="local scope-approved source directory")
    p.add_argument("--scope", action="append", help="optional bounded relative source prefix")
    p.add_argument("--typescript-parser", required=True)
    p.add_argument("--parser-sha256", required=True)
    p.add_argument("--out", required=True, help="new private JSON output, never overwrite")
    a = p.parse_args(argv)
    try:
        result = inspect(a.repo, a.typescript_parser, a.parser_sha256, a.scope)
        path = Path(a.out)
        if path.exists() or path.is_symlink():
            raise ValueError("output must not exist")
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(result, stream, sort_keys=True, ensure_ascii=False, indent=2)
            stream.write("\n")
    except (OSError, ValueError, TypeError) as exc:
        p.error(str(exc))
    print(json.dumps({"out": a.out, "mode": result["mode"], "flows": len(result["flows"]),
                      "routes": result["routes_indexed"]}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
