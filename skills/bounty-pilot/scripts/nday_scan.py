#!/usr/bin/env python3
"""Upstream fixes the target never took: an offline N-day lead list for forks and vendored code.

The `upstream-diff` lens reads what a fork CHANGED versus its upstream. Nothing in the workflow
listed the other direction: the security fixes upstream SHIPPED AFTER the revision the target
pinned, which the target never merged. For a fork, a submodule or a vendored library, every one
of those is a candidate N-day in the target - and it is public the moment the fix is pushed.

The motivating incidents:

- **Cosmos EVM, August 2026.** A fix was pushed to the public repository on 19 August without an
  advisory. Between 20 and 25 August six chains that ran the unpatched module (MANTRA, TAC,
  KiiChain, Nesa and others) were exploited, roughly $14.8M realized. The patch itself was the
  disclosure; the chains that lost money were the ones whose pin predated it.
- **Cetus, May 2025 (~$223M).** The bug was an overflow check in `integer-mate`, a math library
  the protocol depended on. The target's own code was not where the bug lived.
- **Liquid / Elements, September 2026.** A bug in mature upstream node software, inherited by
  everything built on it.

How the pin is found, per `--upstream NAME=PATH` (a LOCAL clone the user fetched; this script
never touches the network):

1. **submodule** - a `.gitmodules` entry whose path is the `--map` target directory, or whose URL
   or path basename is NAME, or whose URL is the clone's `origin`; the pin is the gitlink commit
   from `git ls-tree HEAD <path>`.
2. **vendored** - with `--map NAME=TARGET_SUBDIR:UPSTREAM_SUBDIR`, the blob hashes of the target's
   committed files are compared with `git ls-tree -r` of upstream commits that touched the
   subdirectory; the commit matching the most files is the pin, with its match fraction and a
   confidence. The walk is capped and says so when it hits the cap.
3. **shared-history** - the target is a fork that shares commits with the clone; the newest target
   commit that exists in the clone is the fork point.
4. **go.mod / Cargo.lock** - a Go module version (tag or pseudo-version hash) or a Cargo git
   source `#<sha>` that resolves in the clone. A `replace` to another module is reported, not
   followed: the fork is the thing to clone.
5. otherwise **unresolved**, with the reason. An upstream is never silently dropped.

Then `git log --cherry-pick --right-only --no-merges pinned...REF` lists upstream commits the pin
does not contain (a backport with the same patch-id is dropped as already present), restricted to
commits touching files present in the target's copy. Each is scored by message keywords and diff
shape (an added require/assert/revert, a changed comparison operator, an added bounds or checked
arithmetic check) and labelled `fix_absent`, `fix_present` or `undetermined` by comparing the
target's blobs with the commit's pre- and post-fix blobs, then by `git apply --check` forward and
reverse against a temporary copy of the target's files. Anything over `--limit` is counted and
named under `omitted`, never dropped.

Every row is a lead, not a finding. A keyword is not a vulnerability, and an unmerged fix is
harmless when the target never reaches the changed path. The output is sensitive: a public fix
the target has not merged is reported privately to the program, never posted. This is not the
patch-variant search - `ecosystem_intelligence.py` reads the target's OWN history for sibling
paths a fix missed; this reads the upstream history the target never received.

Git on both checkouts runs hardened (no fsmonitor, no hooks, no optional locks, literal
pathspecs, no external diff or textconv): the target and the clone are untrusted.
"""
import argparse
import json
import os
import re
import subprocess
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

SCHEMA_VERSION = 1
GIT_HARDENING = ("--no-optional-locks", "-c", "core.fsmonitor=false",
                 "-c", "core.hooksPath=/dev/null", "-c", "core.pager=cat",
                 "-c", "log.showSignature=false", "-c", "diff.noprefix=false")
GIT_ENV = {"GIT_TERMINAL_PROMPT": "0", "GIT_LITERAL_PATHSPECS": "1", "GIT_PAGER": "cat",
           "GIT_OPTIONAL_LOCKS": "0", "GIT_CONFIG_NOSYSTEM": "1"}
SHA = re.compile(r"^[0-9a-f]{40}([0-9a-f]{24})?$")
DEFAULT_WALK_CAP = 2000
DEFAULT_LIMIT = 200

# Message keywords. A prefix match on a word start: `reentr` covers reentrancy and reentrant.
KEYWORDS = (
    (3, "cve", r"\bCVE-\d"), (3, "ghsa", r"\bGHSA-"), (3, "security", r"\bsecurity"),
    (3, "vuln", r"\bvuln"), (3, "exploit", r"\bexploit"),
    (2, "overflow", r"overflow"), (2, "underflow", r"underflow"), (2, "reentr", r"\breentr"),
    (2, "bypass", r"\bbypass"), (2, "dos", r"\bDoS\b|denial.of.service"),
    (2, "panic", r"\bpanic"), (2, "auth", r"\bauth"), (2, "silent", r"\bsilent"),
    (1, "fix", r"\bfix"), (1, "validate", r"\bvalidat"), (1, "check", r"\bcheck"),
    (1, "bound", r"\bbound"), (1, "sanitize", r"\bsaniti[sz]"), (1, "audit", r"\baudit"),
)
KEYWORDS = tuple((w, n, re.compile(p, re.I)) for w, n, p in KEYWORDS)
ADDS_GUARD = re.compile(r"\b(require|assert|ensure|revert)\s*!?\s*\(|\brevert\s+\w|"
                        r"\bassert!|\bensure!|\bpanic!?\s*\(|\babort\b|\bassert_\w+!?\s*\(")
ADDS_ERROR_RETURN = re.compile(r"\breturn\b[^\n]*\b(err|Err\(|error|errors\.|errorsmod\.|"
                               r"fmt\.Errorf|Error\()|\?\s*;\s*$|\bthrow\b")
ADDS_BOUNDS = re.compile(r"\b(len\(|\.len\(\)|\.length\b|max\w*|min\w*|MAX\w*|MIN\w*|"
                         r"limit|bound|cap\b|IsNegative|IsZero|IsNil|IsValid|"
                         r"\w+\s*(<=?|>=?)\s*\w+)", re.I)
CHECKED_MATH = re.compile(r"\b(checked_(add|sub|mul|div|pow|shl|shr)|overflowing_\w+|"
                          r"saturating_\w+|SafeAdd|SafeSub|SafeMul|SafeMath|mulDiv|"
                          r"AddOverflow|SubUnderflow|MulOverflow|\.Overflows?\b)", re.I)
COMPARISON = re.compile(r"<=|>=|==|!=|<|>")
TEST_OR_DOC = re.compile(r"(^|/)(tests?|testdata|testutil|mocks?|docs?|examples?)/|"
                         r"_test\.go$|\.t\.sol$|test_[^/]*\.py$|\.md$|\.rst$|\.txt$|"
                         r"(^|/)CHANGELOG", re.I)

NOTICE = (
    "Every listed commit and advisory is a LEAD, not a finding. Message keywords and diff shape "
    "are not proof of a vulnerability: a commit titled 'fix' can be cosmetic and a silent "
    "security fix can be titled anything. The target may be unaffected because it never "
    "reaches the changed code path, configures it away, or patched it differently; confirm "
    "reachability in the target and write a native candidate test with a negative control "
    "before claiming impact. fix_status compares files only: 'fix_absent' means the target's "
    "copy still has the pre-fix text, not that the bug is exploitable there. A pin resolved "
    "with less than high confidence can be wrong. A public upstream fix that the target has "
    "not merged is sensitive: report it PRIVATELY to the program, never publicly, and never "
    "probe a live deployment with it. Check the program's scope (some exclude known or "
    "upstream issues, or issues already public) and the dup-map before writing it up. "
    "Commits are compared against the local clone's ref only; fetch the clone first and pick "
    "the branch the fixes land on.")


class GitError(RuntimeError):
    pass


def _git(root, *args, check=True, input_bytes=None, text=True, timeout=300, cwd=None,
         env_extra=None):
    env = dict(os.environ)
    env.update(GIT_ENV)
    env.update(env_extra or {})
    command = ["git", *GIT_HARDENING]
    if root is not None:
        command += ["-C", str(root)]
    done = subprocess.run(command + list(args), input=input_bytes, cwd=cwd, env=env,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    if check and done.returncode != 0:
        raise GitError(f"git {' '.join(args[:3])}: "
                       + done.stderr.decode("utf-8", "replace").strip()[:300])
    if text:
        return done.stdout.decode("utf-8", "replace")
    return done


def _ok(root, *args):
    return _git(root, *args, check=False, text=False).returncode == 0


def _resolve(root, rev):
    out = _git(root, "rev-parse", "--verify", "--quiet", rev + "^{commit}", check=False).strip()
    return out if SHA.match(out) else None


def _object_format(root):
    out = _git(root, "rev-parse", "--show-object-format", check=False).strip()
    return out or "sha1"


def _norm(value):
    return re.sub(r"[^a-z0-9]+", "-", str(value).lower()).strip("-")


def _url_key(url):
    """`git@github.com:a/b.git`, `https://github.com/a/b` -> `github.com/a/b`."""
    url = (url or "").strip()
    url = re.sub(r"^[a-z+]+://", "", url, flags=re.I)
    url = re.sub(r"^[^@/]+@", "", url)
    url = url.replace(":", "/", 1) if re.match(r"^[^/]+:[^/]", url) else url
    url = re.sub(r"\.git/?$", "", url).rstrip("/")
    return url.lower()


def _subdir(value):
    value = (value or "").strip().strip("/")
    return "" if value in ("", ".") else value


def _join(prefix, rel):
    return f"{prefix}/{rel}" if prefix else rel


def _tree(root, rev, *paths):
    """{path: blob} for regular files under `paths` (default: everything) at rev."""
    args = ["ls-tree", "-r", "-z", "--full-tree", rev]
    paths = [p for p in paths if p]
    if paths:
        args += ["--", *paths]
    out = _git(root, *args, check=False)
    files = {}
    for entry in out.split("\0"):
        if not entry or "\t" not in entry:
            continue
        meta, path = entry.split("\t", 1)
        mode, kind, blob = meta.split()
        if kind == "blob" and mode in ("100644", "100755"):
            files[path] = blob
    return files


def _blob(root, sha):
    done = _git(root, "cat-file", "blob", sha, check=False, text=False)
    return done.stdout if done.returncode == 0 else None


# --- pin resolution -------------------------------------------------------------------------


def _gitmodules(repo, head):
    raw = _git(repo, "show", f"{head}:.gitmodules", check=False, text=False)
    if raw.returncode != 0:
        return []
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "gitmodules"
        path.write_bytes(raw.stdout)
        out = _git(None, "config", "--no-includes", "-f", str(path), "--get-regexp",
                   r"^submodule\..*\.(path|url)$", check=False)
    modules = {}
    for line in out.splitlines():
        key, _, value = line.partition(" ")
        name, _, field = key[len("submodule."):].rpartition(".")
        modules.setdefault(name, {})[field] = value.strip()
    return [m for m in modules.values() if m.get("path")]


def _gitlink(repo, head, path):
    out = _git(repo, "ls-tree", "-z", head, "--", path, check=False)
    for entry in out.split("\0"):
        if entry.startswith("160000 commit "):
            return entry.split()[2].split("\t")[0]
    return None


def _view_from_upstream(upstream, pinned, up_sub):
    tree = _tree(upstream, pinned, up_sub)
    return {path: {"repo": str(upstream), "blob": blob, "target_path": None}
            for path, blob in tree.items()}


def _try_submodule(spec, repo, head, origin_key):
    mapping = spec.get("map")
    for module in _gitmodules(repo, head):
        path, url = module["path"].strip("/"), module.get("url", "")
        hit = (mapping and _subdir(mapping[0]) == path) or \
            _norm(Path(path).name) == _norm(spec["name"]) or \
            (url and _norm(Path(_url_key(url)).name) == _norm(spec["name"])) or \
            (url and origin_key and _url_key(url) == origin_key)
        if not hit:
            continue
        sha = _gitlink(repo, head, path)
        if not sha:
            return {"resolution": "unresolved",
                    "reason": f".gitmodules names {path!r} but HEAD has no gitlink there"}
        if not _resolve(spec["path"], sha):
            return {"resolution": "unresolved", "pinned": sha,
                    "reason": f"submodule {path!r} pins {sha}, which is not in the local "
                              "upstream clone; fetch it (git fetch --all) and re-run"}
        up_sub = _subdir(mapping[1]) if mapping else ""
        view = _view_from_upstream(spec["path"], sha, up_sub)
        for upath, row in view.items():
            row["target_path"] = _join(path, upath[len(up_sub) + 1:] if up_sub else upath)
        return {"resolution": "submodule", "pinned": sha, "confidence": "high",
                "basis": f"gitlink at {path!r} in the target's HEAD", "submodule_path": path,
                "view": view, "upstream_subdir": up_sub}
    return None


def _try_vendored(spec, repo, head, walk_cap):
    target_sub, up_sub = _subdir(spec["map"][0]), _subdir(spec["map"][1])
    upstream = spec["path"]
    if _object_format(repo) != _object_format(upstream):
        return {"resolution": "unresolved",
                "reason": "target and upstream clone use different object formats "
                          "(sha1 vs sha256); blob hashes cannot be compared"}
    target = _tree(repo, head, target_sub)
    rel = {}
    for path, blob in target.items():
        suffix = path[len(target_sub) + 1:] if target_sub else path
        rel[_join(up_sub, suffix)] = (path, blob)
    if not rel:
        return {"resolution": "unresolved",
                "reason": f"the target's HEAD has no files under {target_sub or '.'!r}"}
    walk = ["rev-list", f"--max-count={walk_cap + 1}", spec["ref_sha"]]
    if up_sub:
        walk += ["--", up_sub]
    commits = [c for c in _git(upstream, *walk).split() if SHA.match(c)]
    capped = len(commits) > walk_cap
    commits = commits[:walk_cap]
    best, best_score, ties = None, -1, 0
    for commit in commits:
        tree = _tree(upstream, commit, up_sub)
        score = sum(1 for path, (_, blob) in rel.items() if tree.get(path) == blob)
        # Newest first, so on a tie the OLDER commit wins. That is the conservative pin: a
        # target that matches both c1 and c3 on its unchanged files, with a local edit in the
        # file c3 fixed, must still see c3 listed - fix_status then says whether it took it.
        if score > best_score:
            best, best_score, ties = commit, score, 1
        elif score == best_score:
            best, ties = commit, ties + 1
    match = {"target_files": len(rel), "matching_files": max(best_score, 0),
             "fraction": round(max(best_score, 0) / len(rel), 4),
             "commits_walked": len(commits), "walk_capped": capped,
             "commits_with_the_same_score": ties}
    if capped:
        match["walk_cap_note"] = (f"only the newest {walk_cap} upstream commits touching the "
                                  "subdirectory were compared; an older pin may match better "
                                  "(raise --walk-cap)")
    if not best or best_score <= 0:
        return {"resolution": "unresolved", "match": match,
                "reason": "no walked upstream commit shares a single file blob with the "
                          "target's copy; check the --map directories"}
    fraction = match["fraction"]
    confidence = "high" if fraction >= 0.95 else "medium" if fraction >= 0.6 else "low"
    if capped and confidence == "high" and fraction < 1:
        confidence = "medium"
    view = {path: {"repo": str(repo), "blob": blob, "target_path": tpath}
            for path, (tpath, blob) in rel.items()}
    return {"resolution": "vendored", "pinned": best, "confidence": confidence,
            "basis": "oldest walked upstream commit whose tree matches the most target "
                     "file blobs (ties resolve to the older commit, so more is listed)",
            "match": match, "view": view, "upstream_subdir": up_sub,
            "target_subdir": target_sub}


def _try_shared_history(spec, repo, head, walk_cap):
    commits = [c for c in _git(repo, "rev-list", f"--max-count={walk_cap}", head).split()
               if SHA.match(c)]
    if not commits:
        return None
    done = _git(spec["path"], "cat-file", "--batch-check", check=False,
                input_bytes=("\n".join(commits) + "\n").encode(), text=False)
    lines = done.stdout.decode("utf-8", "replace").splitlines()
    for commit, line in zip(commits, lines):
        if line.split()[:2] == [commit, "commit"]:
            target = _tree(repo, head)
            view = {path: {"repo": str(repo), "blob": blob, "target_path": path}
                    for path, blob in target.items()}
            return {"resolution": "shared-history", "pinned": commit,
                    "confidence": "high",
                    "basis": "newest commit in the target's history that also exists in the "
                             "upstream clone (fork point); fixes the fork cherry-picked later "
                             "are caught by fix_status",
                    "view": view, "upstream_subdir": "", "target_subdir": ""}
    return None


def _go_version_commit(upstream, version):
    version = version.replace("+incompatible", "")
    pseudo = re.search(r"-(?:\d+\.)?\d{14}-([0-9a-f]{12})$", version)
    if pseudo:
        return _resolve(upstream, pseudo.group(1)), f"pseudo-version hash {pseudo.group(1)}"
    for tag in (version, version.lstrip("v")):
        sha = _resolve(upstream, f"refs/tags/{tag}")
        if sha:
            return sha, f"tag {tag}"
    return None, f"no tag {version} in the clone"


def _try_manifests(spec, repo, head, origin_key):
    names = [p for p in _git(repo, "ls-tree", "-r", "-z", "--name-only", head).split("\0")
             if Path(p).name in ("go.mod", "Cargo.lock")]
    wanted = _norm(spec["name"])

    def matches(module):
        key = _norm(module)
        return key == wanted or key.endswith("-" + wanted) or \
            (origin_key and _url_key(module).startswith(origin_key))

    notes = []
    for path in sorted(names, key=lambda p: (p.count("/"), p)):
        text = _git(repo, "show", f"{head}:{path}", check=False)
        if Path(path).name == "go.mod":
            replaces = re.findall(r"(?m)^\s*(?:replace\s+)?(\S+)(?:\s+v\S+)?\s+=>\s+(\S+)"
                                  r"(?:\s+(v\S+))?", text)
            for old, new, _ in replaces:
                if matches(old):
                    notes.append(f"{path} replaces {old} with {new}: the target runs that "
                                 "replacement, so scan it (a fork clone as --repo, or a local "
                                 "path with --map) against this upstream")
            for module, version in re.findall(r"(?m)^\s*(?:require\s+)?([a-z0-9.\-]+\.[a-z]+/"
                                               r"\S+)\s+(v\S+)", text):
                if not matches(module) or any(matches(o) for o, _, _ in replaces):
                    continue
                sha, how = _go_version_commit(spec["path"], version)
                if not sha:
                    notes.append(f"{path} requires {module} {version} but {how}")
                    continue
                return {"resolution": "go-module", "pinned": sha, "confidence": "high",
                        "basis": f"{path}: {module} {version} ({how})",
                        "view": _view_from_upstream(spec["path"], sha, ""),
                        "upstream_subdir": ""}
        else:
            for block in text.split("[[package]]"):
                name = re.search(r'(?m)^name\s*=\s*"([^"]+)"', block)
                source = re.search(r'(?m)^source\s*=\s*"git\+([^"#?]+)[^"#]*#([0-9a-f]{7,64})"',
                                   block)
                if not (name and source):
                    continue
                if not (matches(name.group(1)) or matches(_url_key(source.group(1)))):
                    continue
                sha = _resolve(spec["path"], source.group(2))
                if not sha:
                    notes.append(f"{path}: {name.group(1)} pins {source.group(2)}, not in the "
                                 "local clone; fetch it")
                    continue
                return {"resolution": "cargo-git", "pinned": sha, "confidence": "high",
                        "basis": f"{path}: {name.group(1)} git source #{source.group(2)}",
                        "view": _view_from_upstream(spec["path"], sha, ""),
                        "upstream_subdir": ""}
    return {"notes": notes} if notes else None


def _resolve_pin(spec, repo, head, walk_cap):
    origin = _git(spec["path"], "config", "--get", "remote.origin.url", check=False).strip()
    origin_key = _url_key(origin) if origin else ""
    found = _try_submodule(spec, repo, head, origin_key)
    if found:
        return found
    if spec.get("map"):
        return _try_vendored(spec, repo, head, walk_cap)
    found = _try_shared_history(spec, repo, head, walk_cap)
    if found:
        return found
    found = _try_manifests(spec, repo, head, origin_key)
    if found and "resolution" in found:
        return found
    reason = ("no submodule, shared history, go.mod or Cargo.lock git pin links the target to "
              "this clone; for a vendored copy pass --map NAME=TARGET_SUBDIR:UPSTREAM_SUBDIR")
    if found:
        reason += ". " + " ".join(found["notes"])
    return {"resolution": "unresolved", "reason": reason}


# --- candidates -----------------------------------------------------------------------------


def _log(upstream, pinned, ref, since_days):
    args = ["log", "--no-merges", "--cherry-pick", "--right-only", "-z", "--name-only",
            "--no-renames", "--format=%x1e%H%x1f%cI%x1f%B%x1f"]
    if since_days is not None:
        since = datetime.now(timezone.utc) - timedelta(days=since_days)
        args.append("--since=" + since.strftime("%Y-%m-%dT%H:%M:%SZ"))
    args.append(f"{pinned}...{ref}")
    out = _git(upstream, *args)
    rows = []
    for chunk in out.split("\x1e"):
        if not chunk.strip():
            continue
        parts = chunk.split("\x1f", 3)
        if len(parts) != 4 or not SHA.match(parts[0]):
            continue
        files = [f.strip("\n") for f in parts[3].split("\0")]
        rows.append({"commit": parts[0], "date": parts[1], "message": parts[2].strip(),
                     "touched": [f for f in files if f]})
    return rows


def _patch(upstream, commit, paths):
    return _git(upstream, "diff-tree", "-p", "-r", "--root", "--no-renames", "--no-color",
                "--no-ext-diff", "--no-textconv", "--full-index", "--src-prefix=a/",
                "--dst-prefix=b/", "--no-commit-id", commit, "--", *paths, check=False)


def _signals(message, patch, files):
    score, signals = 0, []
    for weight, name, pattern in KEYWORDS:
        if pattern.search(message):
            score += weight
            signals.append(f"keyword:{name}")
    added, removed = [], []
    for line in patch.splitlines():
        if line.startswith("+") and not line.startswith("+++"):
            added.append(line[1:].strip())
        elif line.startswith("-") and not line.startswith("---"):
            removed.append(line[1:].strip())
    removed_set = set(removed)
    new = [line for line in added if line and line not in removed_set
           and not line.startswith(("//", "#", "*", "/*", "--"))]
    shape = (
        (3, "adds-require-assert-revert", any(ADDS_GUARD.search(x) for x in new)),
        (2, "adds-error-return", any(ADDS_ERROR_RETURN.search(x) for x in new)),
        (2, "adds-checked-arithmetic", any(CHECKED_MATH.search(x) for x in new)),
        (1, "adds-bounds-check", any(re.match(r"(if|else if|require|assert|ensure|"
                                              r"if\s*\()", x) and ADDS_BOUNDS.search(x)
                                     for x in new)),
    )
    for weight, name, hit in shape:
        if hit:
            score += weight
            signals.append(f"diff:{name}")
    strip = lambda s: COMPARISON.sub("<op>", s)  # noqa: E731
    removed_shapes = {strip(x): x for x in removed if COMPARISON.search(x)}
    if any(COMPARISON.search(x) and strip(x) in removed_shapes and removed_shapes[strip(x)] != x
           for x in added):
        score += 3
        signals.append("diff:changes-comparison-operator")
    if files and all(TEST_OR_DOC.search(f) for f in files):
        score //= 2
        signals.append("only-tests-or-docs-in-target-files")
    return score, signals


def _fix_status(upstream, commit, paths, view):
    """Compare the target's copy of `paths` with the commit's pre- and post-fix blobs."""
    parent = _resolve(upstream, commit + "^")
    pre = _tree(upstream, parent, *paths) if parent else {}
    post = _tree(upstream, commit, *paths)
    states = []
    for path in paths:
        mine = view[path]["blob"]
        if mine == post.get(path) and mine != pre.get(path):
            states.append("post")
        elif mine == pre.get(path) and mine != post.get(path):
            states.append("pre")
        else:
            states.append("other")
    if states and all(s == "post" for s in states):
        return "fix_present", "every touched file in the target equals the post-fix blob"
    if states and all(s == "pre" for s in states):
        return "fix_absent", "every touched file in the target equals the pre-fix blob"
    patch = _patch(upstream, commit, paths)
    if not patch.strip() or "Binary files" in patch:
        return "undetermined", "no textual diff to apply"
    with tempfile.TemporaryDirectory() as tmp:
        for path in paths:
            data = _blob(view[path]["repo"], view[path]["blob"])
            if data is None:
                return "undetermined", f"could not read the target's copy of {path}"
            dest = Path(tmp, path)
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
        # Outside any repository `git apply` behaves like patch(1) on the files in cwd; the
        # ceiling stops it from discovering a repository above the temporary directory.
        apply = ["apply", "--check", "--whitespace=nowarn"]
        data = patch.encode("utf-8")
        forward = _git(None, *apply, check=False, text=False, cwd=tmp, input_bytes=data,
                       env_extra={"GIT_CEILING_DIRECTORIES": str(Path(tmp).parent)})
        if forward.returncode == 0:
            return "fix_absent", ("the upstream diff applies cleanly to the target's copy "
                                  "(git apply --check), so the pre-fix text is still there")
        reverse = _git(None, *apply, "-R", check=False, text=False, cwd=tmp, input_bytes=data,
                       env_extra={"GIT_CEILING_DIRECTORIES": str(Path(tmp).parent)})
        if reverse.returncode == 0:
            return "fix_present", ("the upstream diff reverse-applies to the target's copy, "
                                   "so the post-fix text is already there")
    return "undetermined", ("the target's copy has diverged: the diff neither applies nor "
                            "reverse-applies; read the hunks by hand")


def _candidates(spec, pin, since_days, limit):
    upstream, view = spec["path"], pin["view"]
    rows, untouched = [], 0
    for row in _log(upstream, pin["pinned"], spec["ref_sha"], since_days):
        present = [f for f in row["touched"] if f in view]
        if not present:
            untouched += 1
            continue
        patch = _patch(upstream, row["commit"], present)
        score, signals = _signals(row["message"], patch, present)
        subject = row["message"].splitlines()[0] if row["message"] else ""
        rows.append({"commit": row["commit"], "date": row["date"], "subject": subject[:200],
                     "score": score, "signals": signals, "files": present,
                     "files_not_in_target": len(row["touched"]) - len(present)})
    rows.sort(key=lambda r: r["date"], reverse=True)
    rows.sort(key=lambda r: -r["score"])  # stable: newest first within a score
    kept, rest = rows[:limit], rows[limit:]
    for row in kept:
        status, basis = _fix_status(upstream, row["commit"], row["files"], view)
        row["fix_status"], row["fix_status_basis"] = status, basis
        mapped = [view[f]["target_path"] for f in row["files"] if view[f]["target_path"]]
        if mapped and mapped != row["files"]:
            row["target_files"] = mapped
    omitted = {"count": len(rest), "max_score": max((r["score"] for r in rest), default=None),
               "commits": [r["commit"] for r in rest],
               "note": (f"{len(rest)} lower-ranked candidate(s) over --limit {limit} were not "
                        "labelled; raise --limit to see them") if rest else ""}
    return kept, omitted, untouched


# --- advisories -----------------------------------------------------------------------------


def _load_advisories(advisories):
    if advisories is None:
        return []
    if isinstance(advisories, (str, Path)):
        advisories = json.loads(Path(advisories).read_text(encoding="utf-8"))
    if isinstance(advisories, dict):
        advisories = advisories.get("advisories", [advisories])
    if not isinstance(advisories, list):
        raise ValueError("advisories must be a JSON list of objects")
    return [a for a in advisories if isinstance(a, dict)]


def _listify(value):
    if value is None:
        return []
    return [str(v) for v in value] if isinstance(value, (list, tuple)) else [str(value)]


def _advisory_matches(adv, spec):
    if adv.get("upstream"):
        return _norm(adv["upstream"]) == _norm(spec["name"])
    wanted = _norm(spec["name"])
    for value in _listify(adv.get("package")) + _listify(adv.get("name")):
        key = _norm(value.split(":")[-1])
        if key == wanted or key.endswith("-" + wanted) or wanted.endswith("-" + key):
            return True
    return False


def _advisory(adv, results, specs):
    row = {"id": adv.get("id") or adv.get("ghsa_id") or adv.get("cve") or "unnamed",
           "package": adv.get("package") or adv.get("name"),
           "summary": str(adv.get("summary", ""))[:300], "url": adv.get("url")}
    hits = [(spec, res) for spec, res in zip(specs, results) if _advisory_matches(adv, spec)]
    if not hits:
        return dict(row, status="no_matching_upstream",
                    basis="no --upstream NAME matches this advisory's package/name (or its "
                          "'upstream' field); it was not evaluated")
    spec, res = hits[0]
    row["upstream"] = spec["name"]
    pinned = res.get("pinned")
    if res["resolution"] == "unresolved" or not pinned:
        return dict(row, status="undetermined", basis="the upstream's pin is unresolved")
    row["pinned"] = pinned
    upstream = spec["path"]
    patched = _listify(adv.get("patched_commit") or adv.get("patched_commits"))
    versions = _listify(adv.get("fixed_versions") or adv.get("patched_versions"))
    fixes, missing = [], []
    for value in patched:
        sha = _resolve(upstream, value)
        (fixes if sha else missing).append(sha or value)
    for version in versions:
        sha = None
        for tag in (version, "v" + version.lstrip("v"), version.lstrip("v")):
            sha = _resolve(upstream, f"refs/tags/{tag}")
            if sha:
                break
        (fixes if sha else missing).append(sha or f"version {version}")
    row["patched_revisions"] = fixes
    if missing:
        row["not_in_local_clone"] = missing
    if not fixes:
        return dict(row, status="undetermined",
                    basis="no patched commit or fixed-version tag resolves in the local clone")
    contained = [sha for sha in fixes if _ok(upstream, "merge-base", "--is-ancestor", sha,
                                             pinned)]
    if contained:
        return dict(row, status="patched_at_pin", patched_by=contained[0],
                    basis="a patched revision is an ancestor of the pin")
    row["status"] = "advisory_unpatched"
    row["basis"] = ("no patched commit or fixed-version tag is an ancestor of the pin. A "
                    "backport with different history is not seen by this test; read "
                    "fix_status, then confirm by hand")
    commits = [sha for sha in (_resolve(upstream, value) for value in patched) if sha]
    if commits and res.get("view"):
        sha = commits[0]
        changed = _git(upstream, "diff-tree", "-r", "--root", "--no-commit-id", "--no-renames",
                       "--name-only", "-z", sha).split("\0")
        present = sorted(p for p in changed if p and p in res["view"])
        if present:
            row["fix_status"], row["fix_status_basis"] = _fix_status(upstream, sha, present,
                                                                     res["view"])
        else:
            row["fix_status"] = "undetermined"
            row["fix_status_basis"] = "the patched commit touches no file in the target's copy"
    return row


# --- entry points ---------------------------------------------------------------------------


def _normalize_upstreams(upstreams):
    if isinstance(upstreams, dict):
        upstreams = [{"name": k, "path": v} for k, v in upstreams.items()]
    specs = []
    for item in upstreams:
        spec = dict(item)
        spec["path"] = str(Path(spec["path"]).resolve())
        mapping = spec.get("map")
        if isinstance(mapping, str):
            target_sub, _, up_sub = mapping.partition(":")
            mapping = (target_sub, up_sub)
        spec["map"] = tuple(mapping) if mapping else None
        specs.append(spec)
    return specs


def analyze(repo, upstreams, advisories=None, since_days=None, limit=DEFAULT_LIMIT,
            walk_cap=DEFAULT_WALK_CAP):
    """Upstreams: {name: path} or [{name, path, map: (target_subdir, upstream_subdir), ref}]."""
    repo = str(Path(repo).resolve())
    head = _resolve(repo, "HEAD")
    if not head:
        raise ValueError(f"{repo} has no resolvable HEAD commit")
    specs = _normalize_upstreams(upstreams)
    results = []
    for spec in specs:
        entry = {"name": spec["name"], "path": spec["path"], "ref": spec.get("ref") or "HEAD",
                 "map": list(spec["map"]) if spec["map"] else None, "warnings": []}
        try:
            spec["ref_sha"] = _resolve(spec["path"], entry["ref"])
            if not spec["ref_sha"]:
                raise GitError(f"ref {entry['ref']!r} does not resolve in the upstream clone")
            entry["upstream_head"] = spec["ref_sha"]
            if _git(spec["path"], "rev-parse", "--is-shallow-repository",
                    check=False).strip() == "true":
                entry["warnings"].append("the upstream clone is shallow: history before the "
                                         "graft is invisible and the pin may not resolve")
            pin = _resolve_pin(spec, repo, head, walk_cap)
        except (GitError, subprocess.TimeoutExpired, OSError) as exc:
            pin = {"resolution": "unresolved", "reason": f"{type(exc).__name__}: {exc}"}
        entry.update({k: v for k, v in pin.items() if k != "view"})
        entry.setdefault("pinned", None)
        entry.setdefault("confidence", None)
        entry["candidates"], entry["omitted"] = [], {"count": 0, "max_score": None,
                                                     "commits": [], "note": ""}
        if pin["resolution"] != "unresolved":
            try:
                kept, omitted, untouched = _candidates(spec, pin, since_days, limit)
                entry["candidates"], entry["omitted"] = kept, omitted
                entry["commits_not_touching_target_files"] = untouched
            except (GitError, subprocess.TimeoutExpired) as exc:
                entry["warnings"].append(f"candidate listing failed: {exc}")
        if since_days is not None:
            entry["warnings"].append(f"only upstream commits from the last {since_days} days "
                                     "were listed; older unmerged fixes are not shown")
        results.append(entry)
        spec["_pin"] = pin
    adv_rows = [_advisory(adv, [dict(s["_pin"]) for s in specs], specs)
                for adv in _load_advisories(advisories)]
    counts = {
        "upstreams": len(results),
        "unresolved": sum(1 for r in results if r["resolution"] == "unresolved"),
        "candidates": sum(len(r["candidates"]) for r in results),
        "fix_absent": sum(1 for r in results for c in r["candidates"]
                          if c["fix_status"] == "fix_absent"),
        "omitted": sum(r["omitted"]["count"] for r in results),
        "advisory_unpatched": sum(1 for a in adv_rows if a["status"] == "advisory_unpatched"),
    }
    return {"schema_version": SCHEMA_VERSION, "tool": "nday-scan", "repo": repo,
            "repo_commit": head, "since_days": since_days, "limit": limit,
            "upstreams": results, "advisories": adv_rows, "counts": counts, "notice": NOTICE}


def _pairs(values, parser, flag):
    out = {}
    for value in values or []:
        name, sep, rest = value.partition("=")
        if not sep or not name or not rest:
            parser.error(f"{flag} expects NAME=VALUE, got {value!r}")
        out[name] = rest
    return out


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="nday-scan",
        description="List upstream commits after the target's pinned revision that the target "
                    "never took, ranked for security relevance. Offline; leads only.")
    p.add_argument("--repo", required=True, help="target checkout (untrusted; read only)")
    p.add_argument("--upstream", action="append", required=True, metavar="NAME=PATH",
                   help="local clone of an upstream project, fetched by you; repeatable")
    p.add_argument("--map", action="append", metavar="NAME=TARGET_SUBDIR:UPSTREAM_SUBDIR",
                   help="where a vendored copy (or submodule) of NAME lives; repeatable")
    p.add_argument("--ref", action="append", metavar="NAME=REF",
                   help="upstream branch/tag to compare against (default: the clone's HEAD)")
    p.add_argument("--advisories", help="JSON list of advisories you exported "
                                        "({id, package|name, summary, patched_commit | "
                                        "fixed_versions, url})")
    p.add_argument("--since-days", type=int, help="only upstream commits from the last N days")
    p.add_argument("--limit", type=int, default=DEFAULT_LIMIT,
                   help="candidates labelled per upstream; the rest are counted as omitted")
    p.add_argument("--walk-cap", type=int, default=DEFAULT_WALK_CAP,
                   help="upstream commits compared when locating a vendored copy's pin")
    p.add_argument("--out", help="write the full JSON report here")
    a = p.parse_args(argv)
    if a.limit < 0 or a.walk_cap < 1 or (a.since_days is not None and a.since_days < 0):
        p.error("--limit, --walk-cap and --since-days must be non-negative")
    if not Path(a.repo).is_dir():
        p.error(f"--repo {a.repo!r} is not a directory")
    upstreams = _pairs(a.upstream, p, "--upstream")
    maps = _pairs(a.map, p, "--map")
    refs = _pairs(a.ref, p, "--ref")
    for name in list(maps) + list(refs):
        if name not in upstreams:
            p.error(f"{name!r} is not named by any --upstream")
    for name, mapping in maps.items():
        if ":" not in mapping:
            p.error(f"--map {name}= expects TARGET_SUBDIR:UPSTREAM_SUBDIR")
    for name, path in upstreams.items():
        if not Path(path).is_dir():
            p.error(f"--upstream {name}={path!r} is not a directory")
    specs = [{"name": n, "path": path, "map": maps.get(n), "ref": refs.get(n)}
             for n, path in upstreams.items()]
    try:
        report = analyze(a.repo, specs, a.advisories, a.since_days, a.limit, a.walk_cap)
    except (ValueError, OSError, GitError) as exc:
        p.error(str(exc))
    payload = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    summary = {"repo_commit": report["repo_commit"], "counts": report["counts"],
               "upstreams": [{"name": u["name"], "resolution": u["resolution"],
                              "pinned": u["pinned"], "confidence": u["confidence"],
                              "candidates": len(u["candidates"]),
                              "omitted": u["omitted"]["count"]} for u in report["upstreams"]],
               "notice": "leads only; report unmerged public fixes privately"}
    if a.out:
        Path(a.out).write_text(payload, encoding="utf-8")
        summary["out"] = a.out
        print(json.dumps(summary, indent=2))
    else:
        print(payload, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
