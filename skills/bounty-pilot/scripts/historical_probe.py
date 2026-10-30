#!/usr/bin/env python3
"""Read-only historical source scanner A/B diagnostic; NOT a blind AI audit.

Both scanners see the exact same pinned checkout and scope. Reports count only
lexical research leads, never rediscoveries, impact, native PoCs or payout odds.
No target code is executed and no ground-truth file is read.
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

HEX40 = re.compile(r"^[0-9a-fA-F]{40}$")
GIT = ("--no-optional-locks", "-c", "core.fsmonitor=false",
       "-c", "core.hooksPath=/dev/null", "-c", "core.pager=cat")
ENV_KEEP = {"PATH", "LANG", "LC_ALL", "PYTHONHOME", "SYSTEMROOT", "TMPDIR"}


def _git(root, *args):
    result = subprocess.run(
        ["git", *GIT, "-C", str(root), *args],
        env={**{k: v for k, v in os.environ.items() if k in ENV_KEEP},
             "GIT_TERMINAL_PROMPT": "0"},
        capture_output=True, timeout=25, check=True)
    return result.stdout.decode("utf-8", "replace").strip()


def _source_snapshot(repo, pinned):
    if not isinstance(pinned, str) or not HEX40.fullmatch(pinned):
        raise ValueError("must supply the full pinned 40-hex historical commit")
    root = Path(repo).resolve()
    if not (root / ".git").exists():
        raise ValueError("historical target must be an already checked out git repository")
    actual = _git(root, "rev-parse", "HEAD")
    if actual.lower() != pinned.lower():
        raise ValueError("target checkout HEAD does not match historical commit")
    if _git(root, "status", "--porcelain", "--untracked-files=no"):
        raise ValueError("historical source has modified tracked files")
    return root, actual


def _validate_scope(scopes):
    if not isinstance(scopes, list) or not 1 <= len(scopes) <= 30:
        raise ValueError("1..30 declared top-level scopes are required")
    clean = []
    for scope in scopes:
        if not isinstance(scope, str) or not re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9_.-]{1,110}", scope):
            raise ValueError("only explicit, top-level source directory names are accepted")
        if scope in clean:
            raise ValueError("duplicate scope")
        clean.append(scope)
    return sorted(clean)


def _run_scanner(script, root, scopes, timeout):
    raw = Path(script)
    if raw.is_symlink():
        raise ValueError("scanner source must not be a symlink")
    source = raw.resolve()
    if not source.is_file() or source.stat().st_size > 200_000:
        raise ValueError("scanner must be a regular Python source file under 200kB")
    argv = [sys.executable, str(source), "scan", "--repo", str(root)]
    for scope in scopes:
        argv.extend(("--scope", scope))
    env = {k: v for k, v in os.environ.items() if k in ENV_KEEP}
    env.update({"PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1",
                "GIT_TERMINAL_PROMPT": "0"})
    cp = subprocess.run(argv, env=env, capture_output=True, timeout=timeout)
    if cp.returncode:
        raise ValueError("scanner failed (status %s): %s" % (
            cp.returncode, cp.stderr.decode("utf-8", "replace")[-400:]))
    if len(cp.stdout) > 2_000_000:
        raise ValueError("scanner output exceeds 2MB")
    data = json.loads(cp.stdout)
    if (not isinstance(data, dict) or data.get("mode") != "source-scan"
            or data.get("classification") != "RESEARCH_LEADS"
            or data.get("confirmed_vulnerabilities") != 0
            or not isinstance(data.get("leads"), list)):
        raise ValueError("scanner did not return passive, unverified source leads")
    leads = data["leads"]
    if any(not isinstance(v, dict)
           or v.get("classification") != "LEXICAL_LEAD"
           or not isinstance(v.get("signal"), str)
           or not isinstance(v.get("path"), str)
           or type(v.get("line")) is not int or v["line"] < 1 for v in leads):
        raise ValueError("invalid passive lead")
    keys = sorted({(v["signal"], v["path"], v["line"]) for v in leads})
    return {"source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            "scanned_files": data.get("scanned_files"), "capped": bool(data.get("truncated")),
            "count": len(leads), "unique": len(keys),
            "keys_sha256": hashlib.sha256(
                json.dumps(keys, separators=(",", ":")).encode()).hexdigest(),
            "keys": keys}


def compare_probe(repo, pinned, baseline_script, candidate_script, scopes, timeout=120):
    root, commit = _source_snapshot(repo, pinned)
    scopes = _validate_scope(scopes)
    if type(timeout) is not int or not 5 <= timeout <= 240:
        raise ValueError("timeout must be a bounded integer")
    prior = _run_scanner(baseline_script, root, scopes, timeout)
    future = _run_scanner(candidate_script, root, scopes, timeout)
    if _git(root, "rev-parse", "HEAD") != commit or _git(
            root, "status", "--porcelain", "--untracked-files=no"):
        raise ValueError("historical checkout changed during source-only scan")
    before, after = set(map(tuple, prior.pop("keys"))), set(map(tuple, future.pop("keys")))
    return {"schema_version": 1, "kind": "NONBLIND_TOOL_ONLY_DIAGNOSTIC",
            "target_revision": commit, "scope": scopes,
            "baseline": prior, "candidate": future,
            "common_leads": len(before & after),
            "new_lexical_leads": len(after - before),
            "lost_lexical_leads": len(before - after),
            "native_pocs": None, "verified_rediscoveries": None,
            "blind_ai_comparison": False, "model_used": False,
            "finding_quality_conclusion": "NOT_MEASURED",
            "notice": "No historical ground truth or answer key was accessed. "
                      "Changes in lexical hits do not establish valid security bugs "
                      "or a measured improvement in autonomous AI discovery."}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--pinned", required=True)
    parser.add_argument("--baseline-script", required=True)
    parser.add_argument("--candidate-script", required=True)
    parser.add_argument("--scope", action="append", required=True)
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--out", help="new report JSON file; never overwrite")
    args = parser.parse_args(argv)
    try:
        data = compare_probe(args.repo, args.pinned,
                             args.baseline_script, args.candidate_script,
                             args.scope, args.timeout)
        body = json.dumps(data, sort_keys=True, indent=2) + "\n"
        if args.out:
            p = Path(args.out)
            if p.exists() or p.is_symlink():
                raise ValueError("refuse overwriting historical diagnostic")
            fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(body)
        print(body, end="")
        return 0
    except (OSError, ValueError, subprocess.SubprocessError,
            UnicodeError, json.JSONDecodeError) as exc:
        print("error: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
