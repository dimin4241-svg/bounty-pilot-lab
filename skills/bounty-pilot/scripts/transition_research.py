#!/usr/bin/env python3
"""Low-confidence, local-only research leads for state transitions and trust handoffs.

This module deliberately emits observations rather than findings. It does not fetch source,
resolve call graphs, execute target code, contact services, validate credentials, or read a chain.
"""
import hashlib
import re
from pathlib import Path


MAX_FUNCTIONS = 20_000
MAX_CANDIDATES = 250
MAX_PAIRS_PER_FILE = 2_000
MAX_POLICY_PAIRS = 10_000
SOURCE_SUFFIXES = {".sol", ".vy", ".rs", ".move", ".cairo", ".go", ".ts", ".tsx",
                   ".js", ".jsx", ".py", ".java", ".kt", ".swift", ".php", ".rb",
                   ".c", ".h", ".cc", ".cpp", ".hpp", ".cs"}

_FUNCTION_PATTERNS = (
    re.compile(r"(?m)^[ \t]*(?:(?:export|default|async|pub|unsafe|inline|public|private|"
               r"protected|internal|static|virtual|override|external|view|pure|payable)\s+)*"
               r"(?:function|fn|def)\s+([A-Za-z_$][\w$]*)\b"),
    re.compile(r"(?m)^[ \t]*func\s+(?:\([^\n)]*\)\s*)?([A-Za-z_][\w$]*)\s*\("),
    re.compile(r"(?m)^[ \t]*(?:(?:export|default|async|public|private|protected|static|"
               r"override|virtual|readonly)\s+)*([A-Za-z_$][\w$]*)\s*\([^;\n]*\)"
               r"\s*(?::[^{}\n]+)?\s*\{"),
    re.compile(r"(?m)^[ \t]*(?:(?:export|default|async)\s+)*(?:const|let|var)\s+"
               r"([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:\([^;\n]*\)|[A-Za-z_$][\w$]*)"
               r"\s*=>\s*\{"),
)
_NON_FUNCTION_NAMES = {"if", "for", "while", "switch", "catch", "return", "require",
                       "assert", "match", "loop", "where", "sizeof"}
_WRITE_RE = re.compile(
    r"(?<![=!<>])\b([A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)?)"
    r"(?:\s*\[[^\]\n]{1,120}\])?\s*(?:\+\+|--|(?:[+*/%&|^-])?=(?!=))")
_MUTATING_CALL_RE = re.compile(
    r"\b([A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)?)\s*\.\s*"
    r"(?:set|insert|put|remove|delete|add|grant|revoke|mint|burn|transfer|approve|push|"
    r"append|clear|update|save|store|enqueue|disable|invalidate)\s*\(")
_AUTH_GUARDS = {
    "owner_or_admin": re.compile(r"(?i)\b(?:onlyOwner|onlyAdmin|assertAdmin|requireAdmin|"
                                  r"isAdmin|ownerOf|adminOnly)\b|\b(?:owner|admin)\b.{0,50}"
                                  r"(?:==|!=|is|require|assert)|(?:==|!=|is|require|assert).{0,50}"
                                  r"\b(?:owner|admin)\b"),
    "role_check": re.compile(r"(?i)\b(?:onlyRole|hasRole|requireRole|checkRole|roleRequired|"
                             r"has_permission)\s*\(|\brole\s*(?:==|!=|in\b)"),
    "principal_or_tenant_binding": re.compile(r"(?i)\b(?:msg\.sender|caller|principal|"
                                               r"current_user|request\.user|tenant_owner)\b"),
    "auth_middleware_or_decorator": re.compile(r"(?i)@(?:login_required|requires?_auth|"
                                               r"permission_required)\b|\b(?:Depends|middleware)"
                                               r"\s*\([^\n)]*(?:auth|principal|current_user)"),
    "explicit_authorization": re.compile(r"(?i)\b(?:authorize|isAuthorized|checkPermission|"
                                         r"requirePermission|assertAuthorized|accessControl)\s*\("),
}
_REVOCATION_CHECK = re.compile(r"(?i)\b(?:is_?revoked|revoked\w*|revocation\w*|"
                               r"token_version|permission_epoch|auth_epoch|is_disabled|"
                               r"disabled_at|invalidated_at)\b")
_IDENTITY_TERMS = re.compile(r"(?i)\b(token|session|device|pairing|role|permission|identity|"
                             r"credential|signer|capability|principal|tenant|account)\b")
_ALT_OPS = {"restore", "recover", "import", "clone", "copy", "replicate", "migrate",
            "reconnect", "pair", "refresh", "renew", "rebuild", "repair", "retry",
            "fallback", "rescue", "resume", "reissue", "replay", "rollback", "reset"}
_PRIMARY_OPS = {"create", "register", "provision", "issue", "grant", "add", "set", "update",
                "deploy", "initialize", "init", "enroll", "connect", "authorize", "approve"}
_REVOKE_OPS = {"revoke", "disable", "deauthorize", "deauth", "remove", "delete", "logout",
               "expire", "invalidate", "rotate", "unpair", "disconnect", "retire"}
_RESTORE_OPS = {"restore", "recover", "import", "clone", "reconnect", "pair", "refresh", "renew",
                "resume", "reissue", "recreate", "enable", "reset"}
_DELETE_OPS = {"delete", "remove", "destroy", "purge", "release", "terminate", "deprovision"}
_ASYNC_OPS = {"process", "consume", "retry", "cleanup", "drain", "reconcile", "expire", "cache",
              "snapshot", "worker", "queue", "handle", "load", "fetch", "read"}
_POLICY_MARKER = re.compile(r"(?i)\b(?:authoriz\w*|permission\w*|security[_ -]?policy|"
                            r"policy[_ -]?(?:version|epoch)|auth[_ -]?epoch|revocation\w*|"
                            r"role\w*|trust[_ -]?config)\b")
_UNTRUSTED_INPUT = re.compile(r"(?i)pull_request_target|workflow_run|issue_comment|github\.event|"
                              r"issue[_ .-]?body|comment\.body|external[_ .-]?input|untrusted|"
                              r"fork[_ .-]?pr|webhook[_ .-]?payload")
_ELEVATED_CAPABILITY = re.compile(r"(?im)^\s*(?:contents|pull-requests|actions|packages|"
                                  r"id-token|deployments):\s*(?:write|write-all)\b|"
                                  r"permissions:\s*write-all|secrets\.[A-Za-z_]|"
                                  r"\b(?:run_command|execute_command|shell|terminal|apply_patch|"
                                  r"write_file|push_to_repo)\b")
_ARTIFACT_CACHE = re.compile(r"(?i)actions/(?:cache|upload-artifact|download-artifact)|"
                             r"restore-keys|cache[_ -]?key|artifact[_ -]?(?:name|path|id)|"
                             r"download[_ -]?artifact|upload[_ -]?artifact")
_RELEASE_ACTION = re.compile(r"(?i)\b(?:release|publish|deploy|npm\s+publish|docker\s+push|"
                             r"gh\s+release|upload[_ -]?url|registry)\b")
_AGENT_MARKER = re.compile(r"(?i)\b(?:claude|copilot|openai|llm|mcp|ai[_ -]?agent|"
                           r"agent[_ -]?(?:tool|action|runner|prompt))\b")
_LOWER_LAYER = re.compile(r"(?i)(?:^|[/_. -])(?:hypervisor|kernel|kvm|qemu|firecracker|"
                          r"containerd|sandbox|cgroup|ebpf|bpf|virtio|storage[_ -]?pool|"
                          r"block[_ -]?device|snapshot|wasm[_ -]?runtime)(?:[/_. -]|$)")
_ARCH_BRANCH = re.compile(r"(?i)(?:target_pointer_width\s*=|target_arch\s*=|"
                          r"sizeof\s*\(\s*void\s*\*\s*\)|"
                          r"#\s*if\s+(?:defined\s*\()?\s*(?:_WIN64|__LP64__|__x86_64__|"
                          r"__aarch64__))")
_ARCH_32 = re.compile(r"(?i)(?:target_pointer_width\s*=\s*[\"']?32|target_arch\s*=\s*[\"']?(?:x86|i[3-6]86|arm)|\b_WIN32\b|\b__i386__\b|\b__arm__\b)")
_ARCH_64 = re.compile(r"(?i)(?:target_pointer_width\s*=\s*[\"']?64|target_arch\s*=\s*[\"']?(?:x86_64|aarch64|powerpc64)|\b_WIN64\b|\b__LP64__\b|\b__x86_64__\b|\b__aarch64__\b)")
_WIDTH_MARKERS = re.compile(r"(?i)\b(?:usize|isize|size_t|intptr_t|uintptr_t|u32|u64|i32|i64|"
                            r"uint32|uint64|int32|int64|from_le_bytes|from_be_bytes|decode|"
                            r"serialize|deserialize|cast|truncate|overflow|wrapping)\b")


def _mask_comments_and_strings(text, path=""):
    """Blank comments/string literals but retain offsets and newlines for source anchors."""
    chars = list(text)
    hash_comments = Path(path).suffix.lower() in {".py", ".yml", ".yaml", ".toml", ".sh"}
    i, state, quote_end = 0, "code", None
    while i < len(chars):
        ch = chars[i]
        nxt = chars[i + 1] if i + 1 < len(chars) else ""
        if state == "code":
            if ch == "/" and nxt == "/":
                chars[i] = chars[i + 1] = " "
                i += 2
                state = "line"
                continue
            if ch == "/" and nxt == "*":
                chars[i] = chars[i + 1] = " "
                i += 2
                state = "block"
                continue
            if hash_comments and ch == "#" and (
                    i == 0 or text[text.rfind("\n", 0, i) + 1:i].strip() == ""):
                chars[i] = " "
                i += 1
                state = "line"
                continue
            if ch in "\"'`":
                state = "string"
                quote_end = ch * (3 if ch in "\"'" and text[i:i + 3] == ch * 3 else 1)
                for j in range(len(quote_end)):
                    chars[i + j] = " "
                i += len(quote_end)
                continue
        elif state == "line":
            if ch == "\n":
                state = "code"
            else:
                chars[i] = " "
        elif state == "block":
            if ch == "*" and nxt == "/":
                chars[i] = chars[i + 1] = " "
                i += 2
                state = "code"
                continue
            if ch != "\n":
                chars[i] = " "
        elif state == "string":
            if ch == "\\":
                if ch != "\n":
                    chars[i] = " "
                if i + 1 < len(chars) and chars[i + 1] != "\n":
                    chars[i + 1] = " "
                i += 2
                continue
            if text.startswith(quote_end, i):
                for j in range(len(quote_end)):
                    if chars[i + j] != "\n":
                        chars[i + j] = " "
                i += len(quote_end)
                state = "code"
                continue
            if ch != "\n":
                chars[i] = " "
        i += 1
    return "".join(chars)


def _mask_hash_comments_keep_values(text):
    """Mask YAML/TOML/Python-style comments while retaining quoted config values."""
    output = []
    for line in text.splitlines(keepends=True):
        content = line.rstrip("\r\n")
        newline = line[len(content):]
        quote, escaped, end = None, False, len(content)
        for index, char in enumerate(content):
            if quote:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    quote = None
            elif char in ("'", '"'):
                quote = char
            elif char == "#":
                end = index
                break
        if end < len(content):
            content = content[:end] + " " * (len(content) - end)
        output.append(content + newline)
    return "".join(output)


def _function_windows(path, text):
    if Path(path).suffix.lower() not in SOURCE_SUFFIXES:
        return []
    code = _mask_comments_and_strings(text, path)
    headers = {}
    for pattern in _FUNCTION_PATTERNS:
        for match in pattern.finditer(code):
            name = match.group(1)
            if name.lower() not in _NON_FUNCTION_NAMES:
                headers[match.start()] = (name, match.end())
    found = sorted(headers.items())[:MAX_FUNCTIONS]
    rows = []
    for index, (start, (name, after_name)) in enumerate(found):
        next_start = found[index + 1][0] if index + 1 < len(found) else len(code)
        header_start = start
        line_start = code.rfind("\n", 0, start) + 1
        line = code.count("\n", 0, start) + 1
        # Include line-level modifiers such as Solidity onlyOwner and Java visibility annotations.
        start = line_start
        if Path(path).suffix.lower() == ".py":
            indent = len(code[line_start:header_start])
            end = next_start
            cursor = code.find("\n", after_name)
            cursor = len(code) if cursor < 0 else cursor + 1
            while cursor < next_start:
                newline = code.find("\n", cursor)
                stop = len(code) if newline < 0 else newline
                row = code[cursor:stop]
                if row.strip() and len(row) - len(row.lstrip(" \t")) <= indent:
                    end = cursor
                    break
                cursor = stop + 1
        else:
            opening = code.find("{", after_name, min(next_start, after_name + 2500))
            if opening < 0:
                continue
            depth, end = 0, None
            for pos in range(opening, next_start):
                if code[pos] == "{":
                    depth += 1
                elif code[pos] == "}":
                    depth -= 1
                    if depth == 0:
                        end = pos + 1
                        break
            if end is None:
                continue
        if end and end > start:
            rows.append({"path": path, "name": name, "line": line, "start": start,
                         "end": end, "text": text[start:end], "code": code[start:end],
                         "language": Path(path).suffix.lower().lstrip(".")})
    return rows


def _symbols(code):
    ignored = {"self", "this", "ctx", "context", "i", "j", "k", "idx", "index", "result",
               "success", "error", "err", "tmp", "value", "data", "key", "id", "owner"}
    values = set()
    for match in _WRITE_RE.finditer(code):
        target = re.sub(r"\s+", "", match.group(1)).strip(".")
        if target:
            values.add(target.lower())
            values.add(target.rsplit(".", 1)[-1].lower())
    for match in _MUTATING_CALL_RE.finditer(code):
        target = re.sub(r"\s+", "", match.group(1)).strip(".")
        if target:
            values.add(target.lower())
            values.add(target.rsplit(".", 1)[-1].lower())
    for match in re.finditer(r"(?i)\bdelete\s+([A-Za-z_$][\w$]*)", code):
        values.add(match.group(1).lower())
    return sorted(x for x in values if x not in ignored)


def _guard_families(code):
    return sorted(name for name, pattern in _AUTH_GUARDS.items() if pattern.search(code))


def _ops(name):
    words = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name).lower().replace("-", "_").split("_")
    return set(re.findall(r"[a-z0-9]+", " ".join(words)))


def _evidence(path, text, start, end, redact):
    line = text.count("\n", 0, start) + 1
    excerpt = " ".join(text[max(0, start - 40):min(len(text), end + 80)].split())
    return {"path": path, "line": line, "excerpt": redact(excerpt)[:220]}


def _id(kind, values):
    payload = "\0".join(str(x) for x in values)
    return kind.upper() + "-" + hashlib.sha256(payload.encode("utf-8", "replace")).hexdigest()[:10].upper()


def _candidate(kind, path, left, right, symbols, guards_left, guards_right,
               redact, extra=None):
    first = {"path": path, "line": left["line"],
             "excerpt": redact(" ".join(left["text"].split())[:220])}
    second = {"path": path, "line": right["line"],
              "excerpt": redact(" ".join(right["text"].split())[:220])}
    row = {"id": _id(kind, (path, left["name"], right["name"])), "type": kind,
           "status": "hypothesis", "confidence": "low", "path": path,
           "shared_state_symbols": sorted(symbols),
           "operation_paths": [{"name": left["name"], "line": left["line"],
                                "guard_families": guards_left, "source": first},
                               {"name": right["name"], "line": right["line"],
                                "guard_families": guards_right, "source": second}],
           "disconfirming_evidence": [
               "Names and shared writes are lexical clues, not a resolved call/data-flow proof.",
               "Authorization may be enforced by a caller, inherited modifier, middleware, library, or deployment policy outside this function.",
               "No target path was executed and no unauthorized transition or impact was observed."],
           "notice": "Review lead only; do not report as a vulnerability without a reachable, reproduced path."}
    if extra:
        row.update(extra)
    return row


def _operation_pairs(functions, redact):
    alternatives, revivals, lifecycle = [], [], []
    examined_pairs = 0
    by_path = {}
    for function in functions:
        by_path.setdefault(function["path"], []).append(function)
    for path, rows in by_path.items():
        per_file_pairs = 0
        enriched = []
        for row in rows:
            ops = _ops(row["name"])
            row = {**row, "ops": ops, "writes": set(_symbols(row["code"])),
                   "guards": _guard_families(row["code"]),
                   "identity_terms": {m.group(1).lower() for m in _IDENTITY_TERMS.finditer(row["code"])},
                   "revoke_marker": bool(_REVOCATION_CHECK.search(row["code"]))}
            enriched.append(row)
        for i, left in enumerate(enriched):
            for right in enriched[i + 1:]:
                per_file_pairs += 1
                examined_pairs += 1
                if per_file_pairs > MAX_PAIRS_PER_FILE:
                    break
                shared = left["writes"] & right["writes"]
                if not shared:
                    continue
                left_primary = bool(left["ops"] & _PRIMARY_OPS)
                right_primary = bool(right["ops"] & _PRIMARY_OPS)
                left_alt = bool(left["ops"] & _ALT_OPS)
                right_alt = bool(right["ops"] & _ALT_OPS)
                if ((left_primary and right_alt) or (right_primary and left_alt)):
                    normal, alt = (left, right) if left_primary else (right, left)
                    if set(normal["guards"]) != set(alt["guards"]):
                        row = _candidate("alternative_path_auth_parity", path, normal, alt, shared,
                                         normal["guards"], alt["guards"], redact,
                                         {"primary_operation": normal["name"],
                                          "alternate_operation": alt["name"],
                                          "missing_guard_families": sorted(set(normal["guards"]) - set(alt["guards"])),
                                          "alternate_only_guard_families": sorted(set(alt["guards"]) - set(normal["guards"]))})
                        alternatives.append(row)
                revoke_side = left if left["ops"] & _REVOKE_OPS else right if right["ops"] & _REVOKE_OPS else None
                restore_side = right if revoke_side is left else left if revoke_side is right else None
                if (revoke_side and restore_side and restore_side["ops"] & _RESTORE_OPS
                        and not restore_side["revoke_marker"]):
                    revivals.append(_candidate(
                        "revocation_resurrection", path, revoke_side, restore_side, shared,
                        revoke_side["guards"], restore_side["guards"], redact,
                        {"revocation_state_check_in_restore_path": False,
                         "shared_identity_terms": sorted(revoke_side["identity_terms"] & restore_side["identity_terms"])}))
                delete_side = left if left["ops"] & _DELETE_OPS else right if right["ops"] & _DELETE_OPS else None
                async_side = right if delete_side is left else left if delete_side is right else None
                if (delete_side and async_side and async_side["ops"] & _ASYNC_OPS
                        and shared):
                    lifecycle.append(_candidate(
                        "deleted_object_residual_path", path, delete_side, async_side, shared,
                        delete_side["guards"], async_side["guards"], redact,
                        {"lifecycle_path": "delete-to-async/cache/queue/worker candidate"}))
            if per_file_pairs > MAX_PAIRS_PER_FILE:
                break
    return alternatives[:MAX_CANDIDATES], revivals[:MAX_CANDIDATES], lifecycle[:MAX_CANDIDATES], examined_pairs


def _line_hits(path, original, code, pattern, redact, limit=3):
    rows = []
    for line_number, (code_line, original_line) in enumerate(
            zip(code.splitlines(), original.splitlines()), 1):
        if pattern.search(code_line):
            rows.append({"path": path, "line": line_number,
                         "excerpt": redact(" ".join(original_line.split()))[:220]})
            if len(rows) >= limit:
                break
    return rows


def _workflow_and_agent_analysis(files, redact):
    workflows, agents = [], []
    workflows_examined = 0
    agent_configs_examined = 0
    workflow_path = re.compile(r"(?i)(?:^|/)(?:\.github/workflows/[^/]+|\.circleci/[^/]+|"
                               r"\.buildkite/[^/]+|Jenkinsfile|azure-pipelines\.ya?ml)$")
    for path, original in files.items():
        if len(original) > 1_000_000:
            continue
        code = _mask_hash_comments_keep_values(original)
        is_workflow = bool(workflow_path.search(path))
        has_agent = bool(_AGENT_MARKER.search(code) or re.search(r"(?i)(?:^|/)(?:agents?|mcp|ai)(?:/|[._-])", path))
        if not (is_workflow or has_agent):
            continue
        workflows_examined += int(is_workflow)
        agent_configs_examined += int(has_agent)
        input_rows = _line_hits(path, original, code, _UNTRUSTED_INPUT, redact)
        capability_rows = _line_hits(path, original, code, _ELEVATED_CAPABILITY, redact)
        artifact_rows = _line_hits(path, original, code, _ARTIFACT_CACHE, redact)
        release_rows = _line_hits(path, original, code, _RELEASE_ACTION, redact)
        agent_rows = _line_hits(path, original, code, _AGENT_MARKER, redact)
        summary = {"id": "WORKFLOW-" + hashlib.sha256(path.encode()).hexdigest()[:10].upper(),
                   "path": path, "untrusted_input_evidence": input_rows,
                   "elevated_capability_evidence": capability_rows,
                   "artifact_or_cache_evidence": artifact_rows,
                   "release_evidence": release_rows,
                   "agent_evidence": agent_rows}
        if is_workflow:
            summary["type"] = "workflow_provenance_observation"
            summary["status"] = "review_candidate" if input_rows and capability_rows and (artifact_rows or release_rows) else "no_combined_signal"
            summary["notice"] = "Workflow text is not an evaluated GitHub Actions permission graph; reusable workflows and repository settings may change effective authority."
            workflows.append(summary)
        if has_agent and input_rows and capability_rows:
            summary = {**summary, "type": "agentic_trust_boundary", "status": "hypothesis",
                       "confidence": "low",
                       "notice": "Textual co-occurrence does not establish that untrusted input reaches the agent or that the tool is callable in this event."}
            agents.append(summary)
    return workflows[:MAX_CANDIDATES], agents[:MAX_CANDIDATES], workflows_examined, agent_configs_examined


def _policy_replica_drift(functions, redact):
    """Find same-named policy paths whose local guard/config markers differ across files."""
    grouped = {}
    for function in functions:
        grouped.setdefault(function["name"].lower(), []).append(function)
    candidates = []
    examined = 0
    for name, rows in grouped.items():
        if len(rows) < 2:
            continue
        for index, left in enumerate(rows):
            for right in rows[index + 1:]:
                if left["path"] == right["path"]:
                    continue
                if examined >= MAX_POLICY_PAIRS:
                    return candidates, examined
                examined += 1
                left_code, right_code = left["code"], right["code"]
                if not (_POLICY_MARKER.search(left_code) and _POLICY_MARKER.search(right_code)):
                    continue
                left_guards, right_guards = _guard_families(left_code), _guard_families(right_code)
                if left_guards == right_guards:
                    continue
                left_evidence = {"path": left["path"], "line": left["line"],
                                 "excerpt": redact(" ".join(left["text"].split())[:220])}
                right_evidence = {"path": right["path"], "line": right["line"],
                                  "excerpt": redact(" ".join(right["text"].split())[:220])}
                candidates.append({
                    "id": _id("policy-drift", (left["path"], right["path"], name)),
                    "type": "security_policy_replica_drift", "status": "hypothesis",
                    "confidence": "low", "path": left["path"] + " <-> " + right["path"],
                    "operation_paths": [{"name": left["name"], "line": left["line"],
                                         "guard_families": left_guards, "source": left_evidence},
                                        {"name": right["name"], "line": right["line"],
                                         "guard_families": right_guards, "source": right_evidence}],
                    "policy_markers": sorted(set(x.group(0).lower() for x in _POLICY_MARKER.finditer(left_code + "\n" + right_code))),
                    "disconfirming_evidence": [
                        "Same-named functions may be unrelated or intentionally enforce different policies.",
                        "A caller, deployment config, shared library, or version negotiation may make the effective rules equivalent.",
                        "No call graph, deployed node matrix, or cross-service request was inspected."],
                    "notice": "Cross-file policy comparison is lexical and does not establish that both implementations serve the same request."})
                if len(candidates) >= MAX_CANDIDATES:
                    return candidates, examined
    return candidates, examined


def _architecture_and_lower_layer(files, redact):
    architecture, lower_layer = [], []
    for path, original in files.items():
        code = _mask_comments_and_strings(original, path)
        suffix = Path(path).suffix.lower()
        if suffix in SOURCE_SUFFIXES:
            if (_ARCH_BRANCH.search(code) and _ARCH_32.search(original) and
                    _ARCH_64.search(original) and _WIDTH_MARKERS.search(code)):
                pattern = re.compile(r"(?i)target_pointer_width|target_arch|sizeof\s*\(|#\s*if\s+.*(?:WIN64|LP64|x86_64|aarch64)")
                architecture.append({"type": "architecture_semantics_candidate", "status": "hypothesis",
                                     "confidence": "low", "path": path,
                                     "architecture_evidence": _line_hits(path, original, code, pattern, redact),
                                     "width_or_codec_evidence": _line_hits(path, original, code, _WIDTH_MARKERS, redact),
                                     "safe_test": "Compare native 32-bit and 64-bit candidate/control outputs in isolated builds; record compiler, target triple, and serialized bytes.",
                                     "notice": "Architecture markers do not establish divergent semantics or exploitability."})
        if _LOWER_LAYER.search(path) or _LOWER_LAYER.search(code[:20_000]):
            pattern = _LOWER_LAYER
            lower_layer.append({"type": "lower_layer_dependency_surface", "status": "surface_only",
                                "confidence": "low", "path": path,
                                "evidence": _line_hits(path, original, code, pattern, redact),
                                "requires_component_scope_confirmation": True,
                                "safe_test": "Only use a project-owned local VM/container/fork explicitly allowed by the program; no host escape or cross-tenant test.",
                                "notice": "A path or dependency name is not proof of a boundary weakness or a bounty-eligible target."})
    return architecture[:MAX_CANDIDATES], lower_layer[:MAX_CANDIDATES]


def analyze(files, redact):
    """Return local static research observations, each anchored and explicitly unverified."""
    functions = []
    for path, text in files.items():
        functions.extend(_function_windows(path, text))
        if len(functions) >= MAX_FUNCTIONS:
            functions = functions[:MAX_FUNCTIONS]
            break
    alternatives, revivals, lifecycle, pair_count = _operation_pairs(functions, redact)
    policy_drift, policy_pairs = _policy_replica_drift(functions, redact)
    workflows, agents, workflow_files, agent_configs = _workflow_and_agent_analysis(files, redact)
    architecture, lower_layer = _architecture_and_lower_layer(files, redact)
    return {
        "alternative_path_discovery": {
            "candidates": alternatives, "functions_parsed": len(functions),
            "function_pairs_examined": pair_count,
            "notice": "Compares only same-file functions with lexically shared mutation symbols and different guard markers; no AST or interprocedural data flow is resolved."},
        "revocation_resurrection": {
            "candidates": revivals,
            "notice": "Pairs revoke-like and restore/reconnect-like functions only when they lexically mutate a shared symbol; absence of a revocation marker is not proof that revocation is bypassed."},
        "deleted_object_lifecycle": {
            "candidates": lifecycle,
            "notice": "Same-file delete/async pairs are candidates only; queues, caches, storage ownership, and runtime ordering are not resolved."},
        "security_policy_drift": {
            "candidates": policy_drift, "function_pairs_examined": policy_pairs,
            "notice": "Same-named cross-file policy functions with differing local guard markers are leads; service wiring and deployed version distribution are not known."},
        "ci_release_provenance": {
            "workflows_examined": workflow_files, "observations": workflows,
            "notice": "Passive text triage only. It does not calculate effective GitHub permissions, protected environments, action pinning, or artifact attestations."},
        "agentic_trust": {
            "configurations_examined": agent_configs, "candidates": agents,
            "notice": "Does not follow prompt instructions or execute tools. An input/capability co-occurrence is not proof of prompt injection or data access."},
        "architecture_divergence": {
            "candidates": architecture,
            "notice": "Architecture and codec markers nominate local differential tests; target-specific build and runtime semantics remain unverified."},
        "lower_layer_surfaces": {
            "surfaces": lower_layer,
            "notice": "Inventory only. Deep kernel, hypervisor, storage, or sandbox tests require explicit program scope and an isolated authorized environment."},
        "caps": {"functions": MAX_FUNCTIONS, "candidates_per_category": MAX_CANDIDATES,
                 "function_pairs_per_file": MAX_PAIRS_PER_FILE,
                 "cross_file_policy_pairs": MAX_POLICY_PAIRS},
    }

