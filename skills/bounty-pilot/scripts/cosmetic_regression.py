#!/usr/bin/env python3
"""Commits that promised a cosmetic change and replaced a semantic check with a rendered string.

The shape, from the live case in `references/blind-spots.md` section 4: a team gets a complaint
that an amount is displayed twice, and the fix drops the predicate that decided *why* the field
was the transaction's own value - the field's declared path and its formatter - in favour of
comparing the text the two fields happen to render to. Two values with opposite meanings that
stringify alike then suppress each other, and the device signs what it never displayed.

Every row is a lead to read, never a finding. A rendered comparison is often exactly what the
author wanted; what makes a row worth reading is that the predicate it replaced carried
provenance the string cannot.

The sweep refuses to run on a checkout with no history, because an empty answer from a depth-1
clone is indistinguishable from a clean one - see `guard_history`.
"""
import argparse
import json
import os
import re
import subprocess
from pathlib import Path

# The commit-message funnel is cheap and weak: on trezor-firmware it passed 1168 of 2559
# commits (46%). It exists to keep the diff work bounded, never as evidence - `--all-commits`
# drops it, and the output always reports both counts so the funnel stays visible.
MESSAGE_FUNNEL = re.compile(
    r"double display|duplicat|cosmetic|redundant|wording|polish|typo|nit\b"
    r"|clean ?up|simplif|refactor|visual|only (a )?display|display only"
    r"|no changelog|rendered string|compare .*string|string compar", re.I)

# A predicate that knows *what a value is* - its declared source, its type, its tag.
SEMANTIC_REMOVED = (
    ("isinstance", re.compile(r"\bisinstance\s*\(")),
    ("type-check", re.compile(r"\b(type|issubclass)\s*\(")),
    ("enum/const cmp", re.compile(r"(==|!=|\bis\b)\s*[A-Z][A-Za-z0-9_]*\.[A-Z][A-Za-z0-9_]*")),
    ("path/tag field", re.compile(r"\.(path|kind|tag|variant|discriminant|type)\b\s*(==|!=)")),
    ("formatter probe", re.compile(r"get_formatter\s*\(|\bformatter\b")),
)
# A comparison against text a human was meant to read.
RENDERED_ADDED = (
    ("rendered var cmp", re.compile(
        r"(==|!=)\s*\w*(formatted|rendered|_str|text|label|title|display)\w*"
        r"|\w*(formatted|rendered|_str|text|label|title|display)\w*\s*(==|!=)")),
    ("format() in cmp", re.compile(
        r"(==|!=)\s*\w*format\w*\s*\(|\w*format\w*\s*\([^)]*\)\s*(==|!=)")),
    ("str() in cmp", re.compile(r"(==|!=)\s*str\s*\(|\bstr\s*\([^)]*\)\s*(==|!=)")),
)
DEFAULT_MAX_COMMITS = 5000


def git(repo, *args, check=False):
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_PAGER="cat")
    done = subprocess.run(["git", "-C", str(repo), *args], check=check, env=env, timeout=600,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return done.stdout.decode("utf-8", "replace")


def history_surface(repo):
    """What history this checkout actually has. `commits` is None when HEAD does not resolve."""
    count = git(repo, "rev-list", "--count", "HEAD").strip()
    return {
        "commits": int(count) if count.isdigit() else None,
        "shallow": git(repo, "rev-parse", "--is-shallow-repository").strip() == "true",
        "grafted": "grafted" in git(repo, "log", "-1", "--format=%D"),
        "blobless_partial_clone": bool(
            git(repo, "config", "--get", "remote.origin.partialclonefilter").strip()),
    }


def guard_history(history):
    """The blocker this sweep must report instead of an empty candidate list, or None.

    A pass over a depth-1 checkout of trezor-firmware closed the target with "0 submittable"
    while the defect its own reading pass had open was live in `main`; the introducing commit
    was not in the clone at all. Nothing in that run was wrong except that a history lens was
    allowed to answer with silence.
    """
    if history["commits"] is not None and history["commits"] > 1 \
            and not history["shallow"] and not history["grafted"]:
        return None
    had = "no readable history" if history["commits"] is None \
        else f"{history['commits']} commit(s) from HEAD"
    why = [had]
    if history["shallow"]:
        why.append("the clone is shallow")
    if history["grafted"]:
        why.append("HEAD is grafted")
    return {
        "claim": "this sweep cannot run on this checkout",
        "command": "git rev-list --count HEAD; git rev-parse --is-shallow-repository",
        "output_excerpt": "; ".join(why),
        "remedy": "reclone with full history - `git clone --filter=blob:none --bare` keeps "
                  "every commit for a fraction of the size (trezor-firmware: 19,288 commits "
                  "in 23 MB) - then rerun. An empty result from this checkout is not a clean "
                  "result and must not be recorded as coverage.",
    }


def classify(message, diff):
    """Which signals this one commit carries. Pure: the test feeds it a stored patch."""
    removed = [line[1:] for line in diff.splitlines()
               if line.startswith("-") and not line.startswith("---")]
    added = [line[1:] for line in diff.splitlines()
             if line.startswith("+") and not line.startswith("+++")]
    lost = sorted({name for name, rx in SEMANTIC_REMOVED for line in removed if rx.search(line)})
    gained = sorted({name for name, rx in RENDERED_ADDED for line in added if rx.search(line)})
    funnel = MESSAGE_FUNNEL.search(message or "")
    return {
        "message_funnel": funnel.group(0) if funnel else None,
        "semantic_removed": lost,
        "rendered_added": gained,
        "removed_anchor": next((line.strip() for line in removed
                                if any(rx.search(line) for _, rx in SEMANTIC_REMOVED)), None),
        "added_anchor": next((line.strip() for line in added
                              if any(rx.search(line) for _, rx in RENDERED_ADDED)), None),
        "is_candidate": bool(lost and gained),
    }


def sweep(repo, paths=None, funnel=True, max_commits=DEFAULT_MAX_COMMITS):
    repo = Path(repo).resolve()
    history = history_surface(repo)
    blocker = guard_history(history)
    if blocker:
        return {"state": "blocked", "history": history, "blocker": blocker, "candidates": []}
    pathspec = ["--", *paths] if paths else []
    log = git(repo, "log", f"--max-count={max_commits}", "--format=%H%x01%s%x02%b%x03", *pathspec)
    commits = []
    for record in log.split("\x03"):
        if "\x01" not in record:
            continue
        sha, rest = record.strip().split("\x01", 1)
        subject, body = rest.split("\x02", 1)
        commits.append((sha, subject, body))
    looked_at = [c for c in commits if not funnel or MESSAGE_FUNNEL.search(c[1] + "\n" + c[2])]
    candidates = []
    for sha, subject, body in looked_at:
        verdict = classify(subject + "\n" + body, git(repo, "show", "--unified=0", "--format=",
                                                      sha, *pathspec))
        if verdict["is_candidate"]:
            candidates.append(dict(verdict, commit=sha[:12], subject=subject.strip(),
                                   date=git(repo, "log", "-1", "--format=%ci", sha).strip()))
    return {
        "state": "swept",
        "history": history,
        "commits_touching_paths": len(commits),
        "message_funnel_applied": bool(funnel),
        "commits_diffed": len(looked_at),
        "candidates": candidates,
        "notice": "Leads, not findings. For each row read what the removed predicate proved "
                  "that the added string cannot, then ask whether two fields with opposite "
                  "meanings can render alike. The message funnel is a cost control, not "
                  "evidence: it passed 46% of commits on the calibration target.",
    }


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--repo", required=True, help="checkout with full commit history")
    p.add_argument("--path", action="append", default=None,
                   help="limit to this path; repeatable. Aim it at the confirmation, display "
                        "and signing layers")
    p.add_argument("--all-commits", action="store_true",
                   help="diff every commit instead of only those whose message promises "
                        "cosmetics; slower and the honest default for a small path set")
    p.add_argument("--max-commits", type=int, default=DEFAULT_MAX_COMMITS)
    p.add_argument("--out")
    a = p.parse_args(argv)
    try:
        report = sweep(a.repo, a.path, funnel=not a.all_commits, max_commits=a.max_commits)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        p.error(str(exc))
    payload = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if a.out:
        Path(a.out).write_text(payload, encoding="utf-8")
        print(json.dumps({"out": a.out, "state": report["state"],
                          "candidates": len(report["candidates"])}))
    else:
        print(payload, end="")
    return 1 if report["state"] == "blocked" else 0


if __name__ == "__main__":
    raise SystemExit(main())
