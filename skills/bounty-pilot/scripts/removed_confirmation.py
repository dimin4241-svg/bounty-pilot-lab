#!/usr/bin/env python3
"""A redesign that deleted a confirmation, and the string catalogue that proves it.

The inverse of the cosmetic-regression sweep: that one looks for a predicate replaced by rendered
text, this one for a screen that simply stopped existing. A flow is reworked, the commit says it
improves the UX, and a field nobody is thinking about leaves with the old layout. Nothing is
broken; something is just no longer shown.

The calibration case, Trezor's Stellar signing flow. `6dc393af6`, "refactor(core): improve Stellar
signing UX", dropped sixteen display labels; eight of them were also deleted from the translation
catalogue in the same commit, and **four of those eight were the network display** -
`stellar__confirm_network`, `stellar__on_network_template`, `stellar__private_network`,
`stellar__testnet_network`. Thirteen months later `7e4bbee93` put the network back, saying it "was
intentionally omitted from the confirmation flow during a recent redesign" and that the rationale
"somewhat overlooked users that wish to interact with multiple networks": for an account on both
mainnet and testnet, not being able to tell them apart is the whole risk.

The string catalogue is what makes this precise. A label that disappears from the code may have
been renamed or moved; a label deleted from the code **and** from the catalogue in the same commit
is a string the product no longer has. That is rank 0. Code-only losses are rank 1, where the
renames live.

The label and key patterns default to Trezor's shapes (`TR.module__key` in code, `"module__key"`
in `translations/*.json`) and are options: any project with a string catalogue - gettext, a locale
JSON, a resource file - has the same pair of facts.
"""
import argparse
import importlib.util
import json
import os
import re
import subprocess
from pathlib import Path

LABEL_IN_CODE = r"TR\.([A-Za-z0-9_]+)"
KEY_IN_CATALOGUE = r"\"([a-z0-9_]+__[a-z0-9_]+)\""
CATALOGUE_HINT = "translations/,locales/,/locale/,.po,messages/"
# A commit that reworks a flow. Deliberate removals are excluded below: when a message says it
# removes a confirmation, somebody decided to, and that decision is not this generator's business.
REDESIGN = re.compile(r"redesign|refactor|improve[sd]? (the )?ux|\bux\b|rework|unify|simplif"
                      r"|new (layout|flow|design)|revamp|modernis|cleanup|clean up", re.I)
# Two exclusions, both of which say "the string did not stop being shown":
# a message that announces the removal - somebody decided, and that decision is not this sweep's
# business - and one that announces a key rename, where the catalogue loses the old key and gains
# a differently-named one. Over `core/src/apps` the second accounts for every rank-0 commit except
# the calibration case.
DELIBERATE = re.compile(r"\b(remove|removing|removed|drop|dropping|dropped|delete|deleting|"
                        r"deleted|stop showing|no longer show)\b", re.I)
RENAMED = re.compile(r"\b(renam\w+|generali[sz]\w+|merg\w+)\b.{0,40}\b(key|keys|string|strings"
                     r"|translation\w*)\b|\b(key|keys|string|strings|translation\w*)\b.{0,40}"
                     r"\b(renam\w+|generali[sz]\w+|merg\w+)\b|^\w+\(translations\)", re.I)
DEFAULT_MAX_COMMITS = 5000


def _guard():
    """Reuse the history guard, so one checkout rule covers every history lens."""
    path = Path(__file__).resolve().parent / "cosmetic_regression.py"
    spec = importlib.util.spec_from_file_location("bp_cosmetic_regression", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def git(repo, *args):
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_PAGER="cat")
    done = subprocess.run(["git", "-C", str(repo), *args], check=False, env=env, timeout=600,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return done.stdout.decode("utf-8", "replace")


def _is_catalogue(path, hints):
    return any(hint in path for hint in hints)


def labels_lost(diff, hints, label_pattern=LABEL_IN_CODE, key_pattern=KEY_IN_CATALOGUE):
    """`(lost from code, deleted from the catalogue)` for one commit's diff.

    Both are computed as removed-minus-added, so a label moved to another screen inside the same
    commit, or a key merely reindented, does not count as lost.
    """
    label = re.compile(label_pattern)
    key = re.compile(key_pattern)
    code_removed, code_added, catalogue_removed, catalogue_added = set(), set(), set(), set()
    path, catalogue = None, False
    for line in diff.splitlines():
        header = re.match(r"^diff --git a/(\S+) b/(\S+)", line)
        if header:
            path = header.group(2)
            catalogue = _is_catalogue(path, hints)
            continue
        if path is None:
            continue
        if line.startswith("-") and not line.startswith("---"):
            if catalogue:
                catalogue_removed |= set(key.findall(line))
            else:
                code_removed |= set(label.findall(line))
        elif line.startswith("+") and not line.startswith("+++"):
            if catalogue:
                catalogue_added |= set(key.findall(line))
            else:
                code_added |= set(label.findall(line))
    return code_removed - code_added, catalogue_removed - catalogue_added


def catalogue_texts(diff, hints, key_pattern=KEY_IN_CATALOGUE):
    """`({key: {text}} removed, {key: {text}} added)` from the catalogue side of a diff.

    Two forms are read, because Trezor's catalogue uses both: a flat `"key": "text"` and a nested
    `"key": {"Bolt": "text", ...}` with one variant per device. Empty variants are ignored.
    """
    key = re.compile(key_pattern)
    nested_open = re.compile(key_pattern + r"\s*:\s*\{")
    flat = re.compile(key_pattern + r"\s*:\s*\"((?:[^\"\\\\]|\\\\.)*)\"")
    variant = re.compile(r"\"[A-Za-z][A-Za-z0-9_]*\"\s*:\s*\"((?:[^\"\\\\]|\\\\.)*)\"")
    sides = {"-": {}, "+": {}}
    current = {"-": None, "+": None}
    path, catalogue = None, False
    for line in diff.splitlines():
        header = re.match(r"^diff --git a/(\S+) b/(\S+)", line)
        if header:
            path = header.group(2)
            catalogue = _is_catalogue(path, hints)
            current = {"-": None, "+": None}
            continue
        if path is None or not catalogue or not line:
            continue
        side = line[0]
        if side not in sides or line.startswith("---") or line.startswith("+++"):
            continue
        body = line[1:]
        if body.strip() in ("}", "},"):
            current[side] = None
            continue
        opened = nested_open.search(body)
        if opened:
            current[side] = opened.group(1)
            continue
        hit = flat.search(body)
        if hit:
            if hit.group(2):
                sides[side].setdefault(hit.group(1), set()).add(hit.group(2))
            current[side] = None
            continue
        if current[side]:
            inner = variant.search(body)
            if inner and inner.group(1):
                sides[side].setdefault(current[side], set()).add(inner.group(1))
    return sides["-"], sides["+"]


def _moved_or_title(lost, removed_texts, added_texts):
    """Which lost labels say, from their own text, that nothing stopped being shown.

    - **moved**: a deleted key's text reappears under a key added in the same commit. That is a
      rename or a namespace move, and it does not depend on the commit message saying so - which
      matters, because the one in the calibration run said only "boilerplate support".
    - **title**: the text is a single word, or ends in a colon, and carries no placeholder. A
      screen title, not a field's value.

    Nothing here can separate a two-word title from a two-word field label - "Confirm Stellar" from
    "Confirm network" - and this deliberately does not try.
    """
    everything_added = {text for texts in added_texts.values() for text in texts}
    moved, titles = set(), set()
    for name in lost:
        texts = removed_texts.get(name) or set()
        if texts & everything_added:
            moved.add(name)
            continue
        if texts and all("{" not in text
                         and (text.strip().endswith(":") or len(text.split()) == 1)
                         for text in texts):
            titles.add(name)
    return moved, titles


def sweep(repo, paths=None, hints=None, funnel=True, max_commits=DEFAULT_MAX_COMMITS,
          label_pattern=LABEL_IN_CODE, key_pattern=KEY_IN_CATALOGUE):
    guard = _guard()
    repo = Path(repo).resolve()
    history = guard.history_surface(repo)
    blocker = guard.guard_history(history)
    if blocker:
        return {"state": "blocked", "history": history, "blocker": blocker,
                "leads": [], "notes": []}
    hints = hints or [hint for hint in CATALOGUE_HINT.split(",") if hint]
    pathspec = ["--", *paths] if paths else []
    log = git(repo, "log", f"--max-count={max_commits}", "--format=%H%x01%s%x02%b%x03", *pathspec)
    commits = []
    for record in log.split("\x03"):
        if "\x01" not in record:
            continue
        sha, rest = record.strip().split("\x01", 1)
        subject, body = rest.split("\x02", 1)
        commits.append((sha, subject, body))
    looked_at = []
    for sha, subject, body in commits:
        message = subject + "\n" + body
        if funnel and not REDESIGN.search(message):
            continue
        if funnel and DELIBERATE.search(message):
            continue
        if funnel and RENAMED.search(message):
            continue
        looked_at.append((sha, subject, body))
    leads, notes = [], []
    for sha, subject, body in looked_at:
        # the whole commit, so the catalogue counts even when --path narrows the code
        lost, gone = labels_lost(git(repo, "show", "--unified=0", "--format=", sha),
                                hints, label_pattern, key_pattern)
        if paths:
            in_paths, _ = labels_lost(
                git(repo, "show", "--unified=0", "--format=", sha, *pathspec),
                hints, label_pattern, key_pattern)
            lost &= in_paths
        whole = git(repo, "show", "--unified=0", "--format=", sha)
        removed_texts, added_texts = catalogue_texts(whole, hints, key_pattern)
        moved, titles = _moved_or_title(lost, removed_texts, added_texts)
        for name in sorted(moved):
            notes.append({"commit": sha[:12], "label": name, "subject": subject.strip(),
                          "note": "its text reappears under a key added in the same commit: a "
                                  "rename or a namespace move, whatever the message says",
                          "text": sorted(removed_texts.get(name) or [])})
        for name in sorted(titles):
            notes.append({"commit": sha[:12], "label": name, "subject": subject.strip(),
                          "note": "a single word or a trailing colon and no placeholder: a screen "
                                  "title rather than a field's value",
                          "text": sorted(removed_texts.get(name) or [])})
        for name in sorted(lost - moved - titles):
            leads.append({
                "commit": sha[:12], "date": git(repo, "log", "-1", "--format=%ci", sha).strip(),
                "subject": subject.strip(), "label": name,
                "also_deleted_from_the_catalogue": name in gone,
                "why": f"`{name}` left the code in a commit that announces a rework, and "
                       + ("its string was deleted from the catalogue in the same commit, so the "
                          "product no longer has it at all"
                          if name in gone else
                          "may have been renamed or moved: check whether an equivalent screen "
                          "exists now"),
                "rank": 0 if name in gone else 1})
    leads.sort(key=lambda row: (row["rank"], row["date"], row["label"]))
    return {
        "state": "swept", "history": history,
        "commits_touching_paths": len(commits), "commits_diffed": len(looked_at),
        "message_funnel_applied": bool(funnel),
        "leads": leads, "notes": notes,
        "counts": {"lost-confirmation-label": len(leads),
                   "gone-from-the-catalogue-too": sum(1 for row in leads if row["rank"] == 0)},
        "notice": "Leads, not findings. For each rank-0 row, read the flow as it is now and ask "
                  "what the user used to be told and is not. A redesign may legitimately drop a "
                  "screen; the question is whether anybody decided to drop *this* one.",
    }


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--repo", required=True, help="checkout with full commit history")
    p.add_argument("--path", action="append", default=None,
                   help="limit the code side to this path; repeatable")
    p.add_argument("--catalogue", action="append", default=None,
                   help=f"substring identifying string-catalogue files (default: {CATALOGUE_HINT})")
    p.add_argument("--all-commits", action="store_true",
                   help="diff every commit instead of only those whose message announces a rework")
    p.add_argument("--max-commits", type=int, default=DEFAULT_MAX_COMMITS)
    p.add_argument("--label-pattern", default=LABEL_IN_CODE)
    p.add_argument("--key-pattern", default=KEY_IN_CATALOGUE)
    p.add_argument("--out")
    a = p.parse_args(argv)
    try:
        report = sweep(a.repo, a.path, a.catalogue, funnel=not a.all_commits,
                       max_commits=a.max_commits, label_pattern=a.label_pattern,
                       key_pattern=a.key_pattern)
    except (OSError, ValueError, re.error, subprocess.SubprocessError) as exc:
        p.error(str(exc))
    payload = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if a.out:
        Path(a.out).write_text(payload, encoding="utf-8")
        print(json.dumps({"out": a.out, "state": report["state"],
                          "counts": report.get("counts", {})}))
    else:
        print(payload, end="")
    return 1 if report["state"] == "blocked" else 0


if __name__ == "__main__":
    raise SystemExit(main())
