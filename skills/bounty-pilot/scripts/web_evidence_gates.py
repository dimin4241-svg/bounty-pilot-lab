#!/usr/bin/env python3
"""Offline evidence preflights for argument binding and specification-to-code mapping.

These gates verify pinned local snippets, not dataflow correctness, target execution,
authorization, deployed behavior, credential exposure or a vulnerability. No network.
Only Python's standard library is used.
"""
import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit

MAX_INPUT = 262144
MAX_FILE = 1048576
CASE_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,80}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
SHA40 = re.compile(r"^[0-9a-f]{40}$")
MODES = ("argument-binding", "spec-implementation")


def _unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def _regular_bytes(path, limit):
    path = Path(path)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
        raise ValueError("regular non-symlink file within size limit required")
    fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        with os.fdopen(fd, "rb") as stream:
            data = stream.read(limit + 1)
    except Exception:
        raise
    if len(data) > limit:
        raise ValueError("file exceeds size limit")
    return data


def _load(path):
    return json.loads(_regular_bytes(path, MAX_INPUT).decode("utf-8"),
                      object_pairs_hook=_unique)


def _head(repo):
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_PAGER="cat")
    command = ["git", "--no-optional-locks", "-c", "core.fsmonitor=false",
               "-c", "core.hooksPath=/dev/null", "-c", "core.pager=cat",
               "-C", str(repo), "rev-parse", "HEAD"]
    done = subprocess.run(command, capture_output=True, timeout=20, env=env,
                          check=True)
    return done.stdout.decode("ascii").strip()


def _root(path):
    root = Path(path).expanduser().resolve(strict=True)
    if not root.is_dir():
        raise ValueError("root must be a directory")
    return root


def _anchor(root, anchor):
    if not isinstance(anchor, dict):
        raise ValueError("anchor must be an object")
    relative = anchor.get("path")
    digest = anchor.get("sha256")
    line = anchor.get("line")
    excerpt = anchor.get("text")
    if (not isinstance(relative, str) or not relative or
            Path(relative).is_absolute() or "\\" in relative or
            ".." in Path(relative).parts or
            not isinstance(digest, str) or not SHA256.fullmatch(digest) or
            type(line) is not int or line < 1 or
            not isinstance(excerpt, str) or not excerpt.strip() or len(excerpt) > 2000):
        raise ValueError("invalid anchored path/hash/line/text")
    path = root / relative
    data = _regular_bytes(path, MAX_FILE)
    if hashlib.sha256(data).hexdigest() != digest:
        raise ValueError("anchor file digest differs from pinned bytes")
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise ValueError("anchor file must be UTF-8") from exc
    if line > len(lines) or excerpt not in lines[line - 1]:
        raise ValueError("exact anchored excerpt not found on line")
    return excerpt


def _block(root, anchor):
    # A parse region is bounded, anchored by an exact first line and full-file SHA.
    excerpt = _anchor(root, anchor)
    relative = anchor["path"]
    lines = _regular_bytes(root / relative, MAX_FILE).decode("utf-8").splitlines()
    count = anchor.get("span", 1)
    if type(count) is not int or not 1 <= count <= 40:
        raise ValueError("anchor span must be 1..40")
    start = anchor["line"] - 1
    return "\n".join(lines[start:start + count])


def _split_parameters(text):
    result, start, depth, quoted, escaped = [], 0, 0, False, False
    for i, char in enumerate(text):
        if char == '"' and not escaped:
            quoted = not quoted
        if not quoted:
            if char in "([<":
                depth += 1
            elif char in ")]>":
                depth -= 1
            elif char == "," and depth == 0:
                result.append(text[start:i].strip())
                start = i + 1
        escaped = (char == "\\" and not escaped)
        if char != "\\":
            escaped = False
    result.append(text[start:].strip())
    return result if result != [""] else []


def _parens(text, method):
    match = re.search(r"\b" + re.escape(method) + r"\s*\(", text)
    if not match:
        raise ValueError("method invocation/declaration not found in anchored region")
    start = match.end()
    depth, quoted, escaped = 1, False, False
    for pos in range(start, len(text)):
        ch = text[pos]
        if ch == '"' and not escaped:
            quoted = not quoted
        if not quoted:
            if ch == "(":
                depth += 1
            if ch == ")":
                depth -= 1
                if depth == 0:
                    return text[start:pos]
        escaped = ch == "\\" and not escaped
        if ch != "\\":
            escaped = False
    raise ValueError("unbalanced declaration/invocation; manual review required")


def _annotations(block, method, syntax):
    if syntax == "java":
        params = _split_parameters(_parens(block, method))
        result = []
        for param in params:
            if re.search(r"@Url\b", param):
                result.append({"kind": "url"})
            else:
                header = re.search(r'@Header\s*\(\s*"([^"]{1,80})"\s*\)', param)
                result.append({"kind": "header", "name": header.group(1)}
                              if header else {"kind": "other"})
        return result
    if syntax == "smali":
        if not re.search(r"\.method\b[^\n]*\b" + re.escape(method) + r"\(", block):
            raise ValueError("smali method declaration missing")
        result = []
        parts = re.findall(r"\.param\s+p(\d+)\b([\s\S]*?)\.end param\b", block)
        for position, content in parts:
            if "Lretrofit2/http/Url;" in content:
                kind = {"kind": "url"}
            elif "Lretrofit2/http/Header;" in content:
                match = re.search(r'\bvalue\s*=\s*"([^"]{1,80})"', content)
                kind = {"kind": "header", "name": match.group(1)} if match else {"kind": "other"}
            else:
                kind = {"kind": "other"}
            result.append((int(position), kind))
        if not result or [p for p, _ in result] != list(range(1, len(result) + 1)):
            raise ValueError("incomplete ordered smali parameter annotations")
        return [kind for _, kind in result]
    raise ValueError("syntax must be java or smali")


def _arguments(block, method, syntax):
    if syntax == "java":
        return _split_parameters(_parens(block, method))
    match = re.search(r"invoke-(?:interface|virtual)(?:/range)?\s+\{([^}]*)\},"
                      r"[^\n]*->" + re.escape(method) + r"\(", block)
    if not match or ".." in match.group(1):
        raise ValueError("smali invoke register list unresolved")
    registers = [item.strip() for item in match.group(1).split(",")]
    return registers[1:]  # receiver register is first


def _routing(value):
    if not isinstance(value, str) or len(value) > 800 or any(ord(c) < 32 for c in value):
        return "unknown"
    if value.startswith("//"):
        parsed = urlsplit("https:" + value)
        return "dynamic" if parsed.hostname else "unknown"
    parsed = urlsplit(value)
    if parsed.scheme:
        return "dynamic" if parsed.scheme in ("https", "http") and parsed.hostname else "unknown"
    if parsed.netloc or "\\" in value:
        return "unknown"
    return "base"  # root relative, relative, query-only, and empty values


def argument_binding(data, repo, _documents=None, _evidence=None):
    cases = []
    for item in data["cases"]:
        case_id = item.get("id")
        if not isinstance(case_id, str) or not CASE_ID.fullmatch(case_id):
            raise ValueError("invalid case id")
        try:
            method = item["method"]
            name = method["name"]
            syntax = method["syntax"]
            if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z_$][\w$]{0,80}", name):
                raise ValueError("invalid method name")
            declared = _annotations(_block(repo, method["declaration"]), name, syntax)
            invoked = _arguments(_block(repo, item["invocation"]), name, syntax)
            if not declared or len(declared) != len(invoked):
                raise ValueError("method arity is not bound to invocation")
            url_positions = [i for i, x in enumerate(declared) if x["kind"] == "url"]
            if len(url_positions) != 1:
                raise ValueError("exactly one @Url parameter required")
            wanted = item["claim"]["header"]
            indices = [i for i, x in enumerate(declared)
                       if x["kind"] == "header" and x.get("name") == wanted]
            if len(indices) != 1:
                raise ValueError("claimed header is not at the declared position")
            examples = item["url_examples"]
            if not isinstance(examples, list) or not 1 <= len(examples) <= 15:
                raise ValueError("url_examples must contain 1..15 local model values")
            routes = []
            for example in examples:
                label = example["label"]
                if not isinstance(label, str) or not CASE_ID.fullmatch(label):
                    raise ValueError("invalid example label")
                routes.append({"label": label, "route_source": _routing(example["value"])})
            route_set = {r["route_source"] for r in routes}
            status = ("DESTINATION_CLAIM_CONTRADICTED" if route_set == {"dynamic"}
                      else "CONDITIONAL_ROUTING_ONLY" if route_set != {"base"}
                      else "STATIC_ROUTING_ONLY")
            cases.append({"id": case_id, "status": status,
                          "url_parameter_index": url_positions[0],
                          "url_argument": invoked[url_positions[0]],
                          "header_parameter_index": indices[0],
                          "header_argument": invoked[indices[0]],
                          "routing": routes,
                          "unverified": ["runtime reachability", "URL value provenance",
                                         "header value provenance", "simultaneous session state",
                                         "server-side validation", "protected effect"]})
        except (ValueError, KeyError, TypeError, OSError) as exc:
            cases.append({"id": case_id, "status": "BLOCKED_UNRESOLVED_BINDING",
                          "reason_code": type(exc).__name__})
    return {"schema_version": 1, "mode": "argument-binding", "cases": cases,
            "ready_for_vulnerability_claim": False,
            "notice": "Static bindings and RFC-style URL classes only; not a dataflow or network proof."}


def _receipt(root, obj):
    if not isinstance(obj, dict) or not isinstance(obj.get("file"), str):
        raise ValueError("missing evidence receipt")
    path = obj["file"]
    if Path(path).is_absolute() or ".." in Path(path).parts:
        raise ValueError("evidence file must be relative")
    digest = obj.get("sha256")
    if not isinstance(digest, str) or not SHA256.fullmatch(digest):
        raise ValueError("invalid evidence digest")
    contents = _regular_bytes(root / path, MAX_FILE)
    if hashlib.sha256(contents).hexdigest() != digest:
        raise ValueError("evidence hash mismatch")
    if obj.get("exit_code") != 0 or obj.get("executed") is not True:
        raise ValueError("not a claimed successful execution receipt")
    return digest


def spec_implementation(data, repo, documents, evidence):
    if documents is None:
        raise ValueError("--documents required for spec-implementation")
    cases = []
    for item in data["cases"]:
        case_id = item.get("id")
        if not isinstance(case_id, str) or not CASE_ID.fullmatch(case_id):
            raise ValueError("invalid case id")
        try:
            requirement = item["requirement"]
            if requirement["type"] not in ("SPEC_CONFIRMED", "DESIGN_INFERRED",
                                            "RESEARCH_HYPOTHESIS"):
                raise ValueError("unknown requirement class")
            _anchor(documents, requirement["anchor"])
            _anchor(repo, item["implementation"]["anchor"])
            version = requirement.get("version")
            if not isinstance(version, str) or not version.strip():
                raise ValueError("missing spec version")
            status = ("SPEC_SOURCE_LINK_ONLY" if requirement["type"] == "SPEC_CONFIRMED"
                      else "HYPOTHESIS_NOT_SPEC")
            receipt_pair = item.get("experiment")
            if receipt_pair:
                if evidence is None:
                    raise ValueError("--evidence root required for receipts")
                if receipt_pair.get("source_revision") != data["source_revision"]:
                    raise ValueError("experiment revision differs")
                a = _receipt(evidence, receipt_pair["candidate"])
                b = _receipt(evidence, receipt_pair["control"])
                if a == b or receipt_pair["candidate"]["file"] == receipt_pair["control"]["file"]:
                    raise ValueError("candidate/control evidence cannot be the same")
                status = ("REVIEW_PACKET_UNAUTHENTICATED" if status == "SPEC_SOURCE_LINK_ONLY"
                          else "HYPOTHESIS_WITH_RECEIPTS")
            cases.append({"id": case_id, "status": status,
                          "requirement_type": requirement["type"],
                          "ready_for_vulnerability_claim": False,
                          "unverified": ["semantic correctness of test assertions",
                                         "native effect", "deployed version",
                                         "authorization and scope", "reviewer adjudication"]})
        except (ValueError, KeyError, TypeError, OSError) as exc:
            cases.append({"id": case_id, "status": "BLOCKED_MISSING_EVIDENCE",
                          "reason_code": type(exc).__name__,
                          "ready_for_vulnerability_claim": False})
    return {"schema_version": 1, "mode": "spec-implementation", "cases": cases,
            "ready_for_vulnerability_claim": False,
            "notice": "Anchored documents, source and user-supplied receipts are not a vulnerability proof."}


def _write_new(path, value, protected):
    dest = Path(path).expanduser().resolve()
    for root in protected:
        if dest == root or root in dest.parents:
            raise ValueError("output must be outside source/documents/evidence roots")
    if dest.exists():
        raise ValueError("output must be a new file")
    dest.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(dest), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, ensure_ascii=False, sort_keys=True)
        stream.write("\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=MODES)
    parser.add_argument("--input", required=True, help="private local manifest JSON")
    parser.add_argument("--repo", required=True, help="exact pinned local source checkout")
    parser.add_argument("--documents", help="local plain-text specification snapshot directory")
    parser.add_argument("--evidence", help="local operator-held execution receipt directory")
    parser.add_argument("--out", required=True, help="new private output file outside source")
    parser.add_argument("--gate", action="store_true",
                        help="exit 1 unless each case has reviewed structural evidence")
    args = parser.parse_args(argv)
    try:
        repo = _root(args.repo)
        documents = _root(args.documents) if args.documents else None
        evidence = _root(args.evidence) if args.evidence else None
        data = _load(args.input)
        if (not isinstance(data, dict) or data.get("schema_version") != 1 or
                not isinstance(data.get("source_revision"), str) or
                not SHA40.fullmatch(data["source_revision"]) or
                not isinstance(data.get("cases"), list) or
                not 1 <= len(data["cases"]) <= 50):
            raise ValueError("invalid manifest schema or bounded cases")
        if _head(repo) != data["source_revision"]:
            raise ValueError("source_revision differs from local HEAD")
        if args.mode == "argument-binding":
            result = argument_binding(data, repo)
            passing = all(row["status"] == "STATIC_ROUTING_ONLY"
                          for row in result["cases"])
        else:
            result = spec_implementation(data, repo, documents, evidence)
            passing = all(row["status"] == "REVIEW_PACKET_UNAUTHENTICATED"
                          for row in result["cases"])
        _write_new(args.out, result, [x for x in (repo, documents, evidence) if x])
        print(json.dumps({"output": args.out, "mode": args.mode, "cases": len(result["cases"]),
                          "gate_passed_structurally": passing,
                          "production_verified": False}, sort_keys=True))
        return 1 if args.gate and not passing else 0
    except (ValueError, KeyError, OSError, subprocess.SubprocessError,
            UnicodeError, json.JSONDecodeError) as exc:
        print("evidence gate error: " + type(exc).__name__, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
