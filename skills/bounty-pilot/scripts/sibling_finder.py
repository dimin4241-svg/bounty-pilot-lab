#!/usr/bin/env python3
"""Offline structural near-duplicate function finder; leads, NOT a clone verdict.

The same mistake is nearly always copied: the paired function, the second market,
the other collateral, four adapters with one hook (see references/misses.md #9).
This is a bounded heuristic lexical/structural similarity scan over a tracked git
checkout, NOT a parser, sound AST differ or semantic clone detector. It flags two
things for human review:

  - STRUCTURAL_SIBLING_LEAD: two functions whose normalized token shape is very
    similar (same control flow and operator skeleton, identifiers/literals erased).
  - ASYMMETRIC_GUARD_SIBLING_LEAD: the same, but exactly one of the pair contains
    an access-check-like cue term (see GUARD_CUES) that the other lacks.

A high similarity score can mean two correct, intentionally parallel
implementations. A missing cue term can mean the guard is spelled differently,
inherited from a modifier, or genuinely absent. Read both bodies before
reporting a mismatch as a vulnerability. Never executes target code.
"""
import argparse
import hashlib
import json
import re
import subprocess
import sys
from collections import defaultdict
from difflib import SequenceMatcher
from pathlib import Path

GIT_OPTS = ("--no-optional-locks", "-c", "core.fsmonitor=false",
            "-c", "core.hooksPath=/dev/null", "-c", "core.pager=cat")
EXCLUDED = {"node_modules", "vendor", "dist", "build", "target", ".git", "test", "tests"}
MAX_FILE = 400_000
MAX_FUNCTIONS = 4000
MAX_FUNCTION_LINES = 400
MAX_BUCKET = 60
MAX_COMPARISONS = 40_000
MAX_LEADS = 200
DEFAULT_MIN_RATIO = 0.82

# A cue, never a proof: a modifier or condition can read like a check and not be one,
# or be named unlike every term here and still be one. See taint_paths.py's AUTH_CUE
# for the same caveat; this list is kept separately so the two tools stay independent.
# Deliberately excludes generic validation terms ("require", "assert", "check"): those
# fire on ordinary input validation in both siblings and would mask the asymmetry this
# tool exists to find.
GUARD_CUES = ("only", "auth", "access", "restrict", "whitelist",
              "allowlist", "guardian", "privileged", "role", "owner", "permit",
              "authorized", "isadmin", "has_permission", "haspermission")

BRACE_SUFFIX = {".sol", ".rs", ".go", ".ts", ".tsx", ".js", ".jsx", ".move", ".cairo", ".java", ".c", ".cpp"}
PY_SUFFIX = {".py"}
CODE_SUFFIX = BRACE_SUFFIX | PY_SUFFIX

BRACE_DEF = re.compile(r"\b(?:function|fn|func)\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")
PY_DEF = re.compile(r"^(\s*)def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")
STRING_LIT = re.compile(r'"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'')
LINE_COMMENT = re.compile(r"//.*$|#.*$")
TOKEN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*|[0-9]+(?:\.[0-9]+)?|\S")
IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
NUMBER = re.compile(r"^[0-9]+(?:\.[0-9]+)?$")


def _repo(value):
    root = Path(value).resolve()
    if not (root / ".git").exists():
        raise ValueError("a local git checkout is required")
    return root


def _tracked(root):
    cp = subprocess.run(["git", *GIT_OPTS, "-C", str(root), "ls-files", "-z"],
                        capture_output=True, check=True, timeout=20)
    names = [n for n in cp.stdout.decode("utf-8", "replace").split("\x00") if n]
    if len(names) > 50000:
        raise ValueError("tracked file inventory exceeds safety cap")
    return names


def _read(root, name):
    p = root / name
    if p.is_symlink() or not p.is_file() or not p.resolve().is_relative_to(root):
        return None
    if p.stat().st_size > MAX_FILE:
        return None
    try:
        return p.read_text(encoding="utf-8", errors="replace").splitlines()
    except (OSError, UnicodeError):
        return None


def _in_excluded(name):
    return any(part in EXCLUDED for part in Path(name).parts)


def _extract_brace_functions(path, lines):
    found = []
    i = 0
    n = len(lines)
    while i < n and len(found) < 300:
        m = BRACE_DEF.search(lines[i])
        if not m:
            i += 1
            continue
        name = m.group(1)
        start = i
        brace_line = None
        for j in range(i, min(i + 5, n)):
            if "{" in lines[j]:
                brace_line = j
                break
        if brace_line is None:
            i += 1
            continue
        depth = 0
        end = None
        for j in range(brace_line, min(brace_line + MAX_FUNCTION_LINES, n)):
            depth += lines[j].count("{") - lines[j].count("}")
            if depth <= 0 and j >= brace_line:
                end = j
                break
        if end is None:
            i += 1
            continue
        body = lines[start:end + 1]
        if len(body) >= 1:
            found.append((name, start + 1, body))
        i = end + 1
    return found


def _extract_py_functions(path, lines):
    found = []
    i = 0
    n = len(lines)
    while i < n and len(found) < 300:
        m = PY_DEF.match(lines[i])
        if not m:
            i += 1
            continue
        indent, name = len(m.group(1)), m.group(2)
        start = i
        end = i
        for j in range(i + 1, min(i + MAX_FUNCTION_LINES, n)):
            stripped = lines[j].strip()
            if stripped == "" or lines[j].startswith(" " * (indent + 1)) or lines[j].startswith("\t"):
                end = j
                continue
            break
        body = lines[start:end + 1]
        if len(body) >= 1:
            found.append((name, start + 1, body))
        i = end + 1
    return found


def _shape_and_cues(body, own_name):
    # The function's own declared name is not a condition it evaluates; a function
    # called `getOrderAsOwner` or `onlyOwnerCanCall` must not be credited with a
    # guard it never actually checks.
    own_low = own_name.lower()
    cues = set()
    tokens = []
    for raw in body:
        line = LINE_COMMENT.sub("", STRING_LIT.sub(" STR ", raw))
        for tok in TOKEN.findall(line):
            if IDENT.fullmatch(tok):
                low = tok.lower()
                if low != own_low and any(cue in low for cue in GUARD_CUES):
                    cues.add(low)
                tokens.append("ID")
            elif NUMBER.fullmatch(tok):
                tokens.append("NUM")
            else:
                tokens.append(tok)
    return tokens, cues


def collect(root, scope_prefixes=None):
    tracked = _tracked(root)
    functions = []
    for name in sorted(tracked):
        if _in_excluded(name):
            continue
        suffix = Path(name).suffix.lower()
        if suffix not in CODE_SUFFIX:
            continue
        if scope_prefixes and not any(name == p or name.startswith(p + "/") for p in scope_prefixes):
            continue
        lines = _read(root, name)
        if lines is None:
            continue
        extracted = (_extract_py_functions(name, lines) if suffix in PY_SUFFIX
                    else _extract_brace_functions(name, lines))
        for fn_name, line, body in extracted:
            if len(functions) >= MAX_FUNCTIONS:
                return functions, True
            tokens, cues = _shape_and_cues(body, fn_name)
            if len(tokens) < 6:
                continue
            functions.append({"path": name, "name": fn_name, "line": line,
                              "tokens": tokens, "cues": cues,
                              "body_sha256": hashlib.sha256(
                                  "\n".join(body).encode("utf-8", "replace")).hexdigest()})
    return functions, False


def find_siblings(functions, min_ratio=DEFAULT_MIN_RATIO):
    buckets = defaultdict(list)
    for idx, fn in enumerate(functions):
        buckets[len(fn["tokens"]) // 20].append(idx)
    leads = []
    comparisons = 0
    truncated_buckets = 0
    for key in sorted(buckets):
        members = buckets[key]
        for neighbor_key in (key, key + 1):
            neighbors = buckets.get(neighbor_key, [])
            if neighbor_key == key:
                pairs = [(members[a], members[b]) for a in range(len(members))
                        for b in range(a + 1, len(members))]
            else:
                pairs = [(a, b) for a in members for b in neighbors]
            if len(pairs) > MAX_BUCKET * MAX_BUCKET:
                truncated_buckets += 1
                pairs = pairs[:MAX_BUCKET * MAX_BUCKET]
            for a, b in pairs:
                if comparisons >= MAX_COMPARISONS:
                    break
                comparisons += 1
                fa, fb = functions[a], functions[b]
                if fa["path"] == fb["path"] and fa["name"] == fb["name"] and fa["line"] == fb["line"]:
                    continue
                if fa["body_sha256"] == fb["body_sha256"]:
                    ratio = 1.0
                else:
                    ratio = SequenceMatcher(None, fa["tokens"], fb["tokens"], autojunk=False).ratio()
                if ratio < min_ratio:
                    continue
                only_a = bool(fa["cues"]) and not fb["cues"]
                only_b = bool(fb["cues"]) and not fa["cues"]
                classification = ("ASYMMETRIC_GUARD_SIBLING_LEAD" if (only_a or only_b)
                                 else "STRUCTURAL_SIBLING_LEAD")
                leads.append({
                    "classification": classification,
                    "similarity": round(ratio, 3),
                    "a": {"path": fa["path"], "name": fa["name"], "line": fa["line"],
                         "guard_cues": sorted(fa["cues"])},
                    "b": {"path": fb["path"], "name": fb["name"], "line": fb["line"],
                         "guard_cues": sorted(fb["cues"])},
                })
            if comparisons >= MAX_COMPARISONS:
                break
        if comparisons >= MAX_COMPARISONS:
            break
    leads.sort(key=lambda row: (row["classification"] != "ASYMMETRIC_GUARD_SIBLING_LEAD",
                                -row["similarity"]))
    return leads[:MAX_LEADS], len(leads) > MAX_LEADS, truncated_buckets, comparisons


def run(repository, min_ratio=DEFAULT_MIN_RATIO, scope=None):
    if not isinstance(min_ratio, (int, float)) or not 0.5 <= min_ratio <= 1.0:
        raise ValueError("min_ratio must be 0.5..1.0")
    root = _repo(repository)
    functions, truncated_functions = collect(root, scope)
    leads, truncated_leads, truncated_buckets, comparisons = find_siblings(functions, min_ratio)
    return {
        "schema_version": 1, "classification": "STRUCTURAL_SIBLING_LEADS",
        "functions_scanned": len(functions),
        "function_cap_reached": truncated_functions,
        "comparisons_made": comparisons,
        "bucket_caps_reached": truncated_buckets,
        "min_ratio": min_ratio,
        "leads": leads,
        "lead_cap_reached": truncated_leads,
        "notice": ("A heuristic token-shape comparison over a bounded line/brace extraction, "
                   "not a parser or semantic clone detector. Read both bodies before concluding "
                   "a guard is actually missing: a cue can be a false friend, and a real guard "
                   "can use no cue term here at all. Missing from this list is not evidence a "
                   "function has no sibling; it may have been skipped by a size or scan cap.")
    }


def main(argv=None):
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--repo", required=True)
    cli.add_argument("--min-ratio", type=float, default=DEFAULT_MIN_RATIO)
    cli.add_argument("--scope", action="append",
                     help="bounded relative directory/file prefix; repeatable")
    cli.add_argument("--out")
    args = cli.parse_args(argv)
    try:
        result = run(args.repo, args.min_ratio, args.scope)
        text = json.dumps(result, indent=2, ensure_ascii=False)
        if args.out:
            out = Path(args.out)
            if out.exists():
                raise ValueError("refusing to overwrite an existing output file")
            out.write_text(text, encoding="utf-8")
        else:
            print(text)
        return 0
    except (ValueError, OSError, subprocess.SubprocessError, UnicodeError) as exc:
        print("Error: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
