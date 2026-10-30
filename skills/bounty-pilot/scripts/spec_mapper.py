#!/usr/bin/env python3
"""Source-anchored specification-to-code coverage leads; NOT a compliance verdict.

Read-only, tracked checkout, bounded exact-symbol matching. Never executes target code.
Missing a local lexical symbol is not evidence that a requirement is unenforced.
"""
import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

GIT_OPTS = ("--no-optional-locks", "-c", "core.fsmonitor=false",
            "-c", "core.hooksPath=/dev/null", "-c", "core.pager=cat")
CODE_SUFFIX = {".sol", ".vy", ".rs", ".go", ".py", ".ts", ".js", ".move", ".cairo"}
EXCLUDED = {"node_modules", "vendor", "dist", "build", "target", ".git", "test", "tests"}
IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{2,79}$")
REQ_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{1,79}$")
MAX_FILE = 200_000
MAX_SYMBOL_HITS = 40
# A test fixture mentions the same symbols as the code it exercises, and sorts
# before it. Read production code first so the hit budget is never spent on
# fixtures while the enforcement sites go unread.
TEST_NAME = re.compile(r"(?i)(?:^|/)(?:test_[^/]+|[^/]*(?:_test|\.test|\.spec|\.t))\.[a-z]+$")


def _path(value):
    if not isinstance(value, str) or not value or len(value) > 240:
        raise ValueError("path must be a short relative checkout path")
    p = Path(value)
    if p.is_absolute() or ".." in p.parts or "\\" in value or "\x00" in value or not p.parts or p.as_posix() == ".":
        raise ValueError("path traversal or unsupported relative path")
    if any(x in EXCLUDED or x.startswith(".env") or "secret" in x.lower()
           for x in p.parts):
        raise ValueError("excluded or sensitive path")
    return p.as_posix()


def _text(value, name, cap=500):
    if not isinstance(value, str) or not value.strip() or len(value) > cap:
        raise ValueError(name + " must be nonempty bounded text")
    if any(ord(c) < 32 for c in value):
        raise ValueError(name + " contains control characters")
    value.encode("utf-8")
    return value


def _files(root):
    cp = subprocess.run(["git", *GIT_OPTS, "-C", str(root), "ls-files", "-z"],
                        capture_output=True, check=True, timeout=15)
    names = cp.stdout.decode("utf-8", "replace").split("\x00")
    if len(names) > 30000:
        raise ValueError("tracked file inventory exceeds safety cap")
    return {n for n in names if n}


def _read(root, name, tracked):
    if name not in tracked:
        raise ValueError("path is not tracked in checkout: " + name)
    p = root / name
    if p.is_symlink() or not p.is_file() or not p.resolve().is_relative_to(root):
        raise ValueError("path is not a safe regular tracked file")
    if p.stat().st_size > MAX_FILE:
        raise ValueError("file exceeds 200 kB cap")
    return p.read_text(encoding="utf-8", errors="replace").splitlines()


def map_spec(spec, repository):
    if (not isinstance(spec, dict) or type(spec.get("schema_version")) is not int
            or spec["schema_version"] != 1):
        raise ValueError("schema_version 1 required")
    requirements = spec.get("requirements")
    if not isinstance(requirements, list) or not 1 <= len(requirements) <= 40:
        raise ValueError("requirements must contain 1..40 entries")
    root = Path(repository).resolve()
    if not (root / ".git").exists():
        raise ValueError("a local git checkout is required")
    tracked = _files(root)
    head = subprocess.run(["git", *GIT_OPTS, "-C", str(root), "rev-parse", "HEAD"],
                          capture_output=True, text=True, check=True, timeout=10).stdout.strip()
    if not re.fullmatch(r"[a-f0-9]{40,64}", head):
        raise ValueError("unable to pin a checkout revision")
    dirty = bool(subprocess.run(
        ["git", *GIT_OPTS, "-C", str(root), "status", "--porcelain"],
        capture_output=True, check=True, timeout=10).stdout.strip())
    seen = set()
    report = []
    for req in requirements:
        if not isinstance(req, dict):
            raise ValueError("requirement must be an object")
        ident = req.get("id")
        if not isinstance(ident, str) or not REQ_ID.fullmatch(ident) or ident in seen:
            raise ValueError("invalid or duplicate requirement id")
        seen.add(ident)
        doc = _path(req.get("source_path"))
        line = req.get("source_line")
        quote = _text(req.get("quote"), "quote", 300)
        if type(line) is not int or line < 1:
            raise ValueError("source_line must be a positive integer")
        doc_lines = _read(root, doc, tracked)
        if line > len(doc_lines) or quote not in doc_lines[line - 1]:
            raise ValueError("quoted specification text does not match source_path:source_line")
        symbols = req.get("symbols")
        if (not isinstance(symbols, list) or not 1 <= len(symbols) <= 8
                or any(not isinstance(x, str) or not IDENT.fullmatch(x) for x in symbols)):
            raise ValueError("1..8 explicit code symbols required")
        scopes = req.get("code_scope")
        if not isinstance(scopes, list) or not 1 <= len(scopes) <= 8:
            raise ValueError("code_scope must list 1..8 relative directories or files")
        prefixes = [_path(x).rstrip("/") for x in scopes]
        names = [n for n in sorted(tracked)
                 if any(n == p or n.startswith(p + "/") for p in prefixes)
                 and Path(n).suffix.lower() in CODE_SUFFIX
                 and not EXCLUDED.intersection(Path(n).parts)]
        names.sort(key=lambda n: (bool(TEST_NAME.search(n)), n))
        if len(names) > 500:
            raise ValueError("spec mapping scope exceeds 500 code files")
        coverage = []
        readable = 0
        for name in names:
            try:
                lines = _read(root, name, tracked)
            except (ValueError, OSError, UnicodeError):
                continue
            readable += 1
            for n, body in enumerate(lines, 1):
                for symbol in symbols:
                    if re.search(r"(?<![A-Za-z0-9_])" + re.escape(symbol) +
                                 r"(?![A-Za-z0-9_])", body):
                        coverage.append({"path": name, "line": n, "symbol": symbol,
                                         "line_sha256": hashlib.sha256(
                                             body.encode("utf-8")).hexdigest()})
                        if len(coverage) >= MAX_SYMBOL_HITS:
                            break
                if len(coverage) >= MAX_SYMBOL_HITS:
                    break
            if len(coverage) >= MAX_SYMBOL_HITS:
                break
        truncated = len(coverage) >= MAX_SYMBOL_HITS
        notice = ("Lexical presence does not prove enforcement; lexical absence "
                  "does not establish a vulnerability or code coverage.")
        if truncated:
            notice += (" The hit budget was reached, so this is a bounded sample and not "
                       "a map: %d of %d scoped files were read and %d were never opened. "
                       "Narrow code_scope or declare fewer symbols before reading the "
                       "distribution of these hits."
                       % (readable, len(names), max(0, len(names) - readable)))
        report.append({
            "id": ident, "spec_anchor": {"path": doc, "line": line,
                       "quote_sha256": hashlib.sha256(quote.encode()).hexdigest()},
            "declared_symbols": symbols, "scoped_code_files": len(names),
            "readable_code_files": readable,
            "unread_code_files": max(0, len(names) - readable),
            "symbol_hit_cap": MAX_SYMBOL_HITS, "truncated": truncated,
            "symbol_hits": coverage,
            "classification": "LEXICAL_MAPPING_LEAD" if coverage else "UNMAPPED_LEAD",
            "next_experiment": "Trace reachable implementation and independently test the "
                               "stated property with candidate and control in native tests.",
            "notice": notice})
    return {"schema_version": 1, "classification": "RESEARCH_LEADS",
            "source_revision": head, "working_tree_dirty": dirty,
            "requirements": report, "confirmed_vulnerabilities": 0,
            "notice": "No target code executed. An explicit documented requirement and "
                      "an independent native experiment are mandatory for a finding."}


def main(argv=None):
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--repo", required=True)
    cli.add_argument("--spec", required=True)
    args = cli.parse_args(argv)
    try:
        p = Path(args.spec)
        if p.is_symlink() or p.stat().st_size > 100_000:
            raise ValueError("spec file must be regular and under 100 kB")
        result = map_spec(json.loads(p.read_text(encoding="utf-8")), args.repo)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0
    except (ValueError, OSError, subprocess.SubprocessError, UnicodeError) as exc:
        print("Error: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
