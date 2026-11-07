#!/usr/bin/env python3
"""Offline historical source A/B replay: real pinned source, equal budgets, no model calls.

The 0.46 API lexical inventory and 0.47 augmented JS cues are compared
against actual public Git snapshots. These are source READING CUES only.
No candidate is accepted as a vulnerability without a native PoC and
independent adjudication. A clean zero is reported as zero confirmed finds.
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path, PurePosixPath

import web3_research
import web3_advanced
import web_historical_bench as hist

# Controls are independent of bug labels, advisory URLs and affected paths.
REPO_SCOPES = {
    "https://github.com/vercel/next.js": ("packages/next/src/server/web",),
    "https://github.com/brix/crypto-js": ("",),
}
BUDGET = {"max_files": 120, "max_lines": 6000, "max_bytes": 1_000_000,
          "per_file_bytes": 100_000, "time_limit_seconds": 60}
EXTENSIONS = {".js", ".cjs", ".mjs", ".jsx", ".ts", ".tsx", ".py"}
GIT_ARGS = ("--no-optional-locks", "-c", "core.fsmonitor=false",
            "-c", "core.hooksPath=/dev/null", "-c", "core.pager=cat")
REV = re.compile(r"[0-9a-f]{40}\Z")


def git(root, *args, timeout=120):
    p = subprocess.run(["git", *GIT_ARGS, "-C", str(root), *args],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       check=True, timeout=timeout)
    return p.stdout.decode("utf-8", "replace").strip()


def fetch_official_snapshot(task, root):
    url = task["repository_url"]
    if url not in REPO_SCOPES:
        raise ValueError("repository not in preapproved public benchmark source set")
    sha = task["source_revision"]
    if not REV.fullmatch(sha):
        raise ValueError("full pinned Git revision required")
    root.mkdir(parents=True, exist_ok=False)
    git(root, "init", "-q")
    git(root, "remote", "add", "origin", url)
    git(root, "fetch", "--quiet", "--no-tags", "--depth", "1",
        "--filter=blob:none", "origin", sha, timeout=180)
    if REPO_SCOPES[url][0]:
        git(root, "sparse-checkout", "init", "--cone")
        git(root, "sparse-checkout", "set", *REPO_SCOPES[url])
    git(root, "checkout", "-q", "--detach", "FETCH_HEAD", timeout=180)
    if git(root, "rev-parse", "HEAD") != sha:
        raise ValueError("fetched HEAD differs from opaque queue commit")
    if git(root, "status", "--porcelain"):
        raise ValueError("fetched snapshot checkout dirty")
    return root


def source_window(root, url):
    """Canonical identical source bytes for both arms; hard caps, no code execution."""
    prefix = REPO_SCOPES[url][0]
    listed = git(root, "ls-files", "-z", timeout=60).split("\0")
    files, lines, size, digest = 0, 0, 0, hashlib.sha256()
    snippets = []
    for rel in sorted(set(listed)):
        if not rel or (prefix and not rel.startswith(prefix + "/")):
            continue
        p = PurePosixPath(rel)
        if p.suffix.lower() not in EXTENSIONS or any(z in ("node_modules", "dist", "test", "tests", ".git") for z in p.parts):
            continue
        target = root / rel
        if target.is_symlink() or not target.is_file() or target.stat().st_size > BUDGET["per_file_bytes"]:
            continue
        raw = target.read_bytes()
        text = raw.decode("utf-8", "replace")
        rows = text.splitlines()
        if files >= BUDGET["max_files"] or lines + len(rows) > BUDGET["max_lines"] or size + len(raw) > BUDGET["max_bytes"]:
            break
        files += 1
        lines += len(rows)
        size += len(raw)
        digest.update(rel.encode("utf-8") + b"\0")
        digest.update(hashlib.sha256(raw).digest())
        # Only code text: no published report, labels, control roles or review mappings.
        snippets.append((rel, rows))
    if not snippets:
        raise ValueError("no source files in fixed, generic code scope")
    return {"source_file_count": files, "source_lines": lines,
            "source_bytes": size, "source_digest": digest.hexdigest()}, snippets


def one_arm(snippets, arm):
    if arm not in ("baseline", "extended"):
        raise ValueError("unknown heuristic arm")
    expressions = dict(web3_research.SIGNALS)
    if arm == "extended":
        expressions.update({"runtime-" + key: rx for key, rx in web3_advanced.SOURCE_CUES.items()})
    counts = {name: 0 for name in expressions}
    anchors = []
    start = time.monotonic()
    for path, rows in snippets:
        if time.monotonic() - start > BUDGET['time_limit_seconds']:
            raise ValueError('fixed per-arm wall-clock budget exceeded')
        for number, line in enumerate(rows, 1):
            if number % 256 == 0 and time.monotonic() - start > BUDGET['time_limit_seconds']:
                raise ValueError('fixed per-arm wall-clock budget exceeded')
            if len(line) > 5000:
                continue
            for label, rx in expressions.items():
                if rx.search(line):
                    counts[label] += 1
                    if len(anchors) < 40:
                        anchors.append({"path": path, "line": number, "cue": label})
    return {"arm": arm, "counts": counts,
            "lexical_cues": sum(counts.values()), "sample_anchors": anchors,
            "elapsed_seconds": round(time.monotonic() - start, 6),
            "finding_count": 0, "verified_root_causes": 0,
            "classification": "SOURCE_TRIAGE_NOT_VULNERABILITY_FINDINGS"}


def replay(seed, workdir):
    """Real source replay; evaluator truth enters only *after* source scans are fixed."""
    workdir = Path(workdir).expanduser().resolve()
    workdir.mkdir(mode=0o700, parents=False, exist_ok=False)
    hunter = workdir / "hunter"
    evaluator = workdir / "evaluator"
    hist.prepare(seed, hunter, evaluator)
    queue = json.loads((hunter / "blind-queue.json").read_text(encoding="utf-8"))
    rows = []
    predictions = {"baseline": [], "extended": []}
    for task in queue["tasks"]:
        tid = task["task_id"]
        checkout = workdir / ("snapshot-" + tid)
        fetch_official_snapshot(task, checkout)
        verified = hist.verify_checkout(queue, tid, checkout)
        meta, snippets = source_window(checkout, task["repository_url"])
        arms = {name: one_arm(snippets, name) for name in ("baseline", "extended")}
        rows.append({"task_id": tid, "revision_verified": verified["pinned_git_revision_verified"],
                     "scope": list(REPO_SCOPES[task["repository_url"]]),
                     "source": meta, "arms": arms})
        for name in predictions:
            predictions[name].append({
                "task_id": tid, "source_revision": task["source_revision"],
                "findings": []  # Lexical cues cannot be promoted to vulnerability claims.
            })
        # Download is limited to public source. Remove the checkout after extracting
        # the hashes and bounded cues, before any evaluator results are examined.
        shutil.rmtree(checkout)
    # Commit predictions before reading evaluator map.
    reports = {}
    for name in ("baseline", "extended"):
        sub = workdir / ("evaluator-" + name)
        sub.mkdir(mode=0o700)
        key_data = (evaluator / "answer-map.json").read_bytes()
        key_dest = sub / "answer-map.json"
        fd = os.open(str(key_dest), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(key_data)
        p = {"schema_version": 1, "tasks": predictions[name]}
        sealed = hist.seal(queue, p, sub)
        score = hist.score(sub, {"schema_version": 1,
                                  "reviewer": "no-claim-automatic-evaluator",
                                  "judgments": []})
        reports[name] = {"seal_sha256": sealed["predictions_sha256"], "score": score}
    summary = {
        "schema_version": 1, "classification": "EXECUTED_OFFLINE_SOURCE_CUE_A_B_ONLY",
        "strategy_a": "Bounty Pilot 0.46 API-map generic source signals",
        "strategy_b": "Bounty Pilot 0.47 API-map signals plus generic JS runtime cues",
        "not_a_model_trial": True,
        "source_policy": "official public GitHub repositories, pinned Git SHAs, no target code executed",
        "same_budget_per_arm": BUDGET,
        "queue_sha256": hist._sha(queue),
        "snapshots_executed": len(rows), "cases_in_reference": len(seed["cases"]),
        "source_windows_identical_between_arms": True,
        "snapshots": rows, "arms": reports,
        "measured_verified_rediscoveries": 0,
        "independent_human_review": False,
        "notice": "Real immutable historical source snapshots were scanned with two existing "
                  "offline LEXICAL algorithms under identical source budgets. These tools "
                  "cannot assert a security root cause and generated ZERO reportable findings. "
                  "The historical scoring is zero for each arm with no claims to adjudicate; "
                  "it is not evidence of model performance, blind human validation or payout uplift."
    }
    hist._write(workdir / "diagnostic-report.json", summary)
    return summary


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", required=True, help="nonexisting private report directory")
    ap.add_argument("--catalog", default=str(hist.SEED),
                    help="published evaluator-only public seed catalog")
    args = ap.parse_args(argv)
    try:
        report = replay(web3_advanced.json_file(args.catalog), args.out)
        print(json.dumps({
            "status": report["classification"], "snapshots": report["snapshots_executed"],
            "verified_rediscoveries": report["measured_verified_rediscoveries"],
            "baseline": report["arms"]["baseline"]["score"],
            "extended": report["arms"]["extended"]["score"],
            "report": str(Path(args.out).resolve() / "diagnostic-report.json")
        }, indent=2))
        return 0
    except (ValueError, OSError, subprocess.SubprocessError) as e:
        ap.error(str(e))


if __name__ == "__main__":
    sys.exit(main())
