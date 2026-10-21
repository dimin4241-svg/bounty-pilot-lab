#!/usr/bin/env python3
"""Evidence-first gate: attest that decisive paired experiments ran before more reading.

This is a workflow gate, NOT exploit verification. Only a native PoC against
unchanged production source can establish the factual claim.
"""
import argparse
import json
import os
import posixpath
import re
import subprocess
import sys
from pathlib import Path

FINDING_ID = re.compile(r"BP-[0-9]{3,}$")
OPEN = {"hypothesis", "needs-evidence"}
RANK = {"critical": 0, "high": 1, "unassessed": 2, "medium": 3,
        "low": 4, "informational": 5}
# A commit is named by 7 to 64 hex characters, compared case-insensitively by prefix - the same
# rule the structural check applies to a finding's `revision`.
HEX_REVISION = re.compile(r"[0-9a-f]{7,64}")
# What a failure looks like in an excerpt whose command still exited 0. bounty.py holds the
# same two patterns for next_experiment.blocker; a test keeps them identical.
FAILURE_OUTPUT = re.compile(
    r'(?i)\b(?:error|errors|errored|fail|failed|failure|fatal|panic|panicked|exception|traceback|'
    r'denied|forbidden|unauthori[sz]ed|not found|no such|unsupported|not supported|'
    r'not available|unavailable|refused|timed out|timeout|rate[ -]?limit(?:ed)?|'
    r'too many requests|reverted|cannot|can\'t|could not|couldn\'t|unable to|not allowed|'
    r'insufficient|aborted|killed)\b|\bHTTP/[\d.]+ [45]\d\d\b|'
    r'\b(?:status|code)\W{1,3}[45]\d\d\b|"error"\s*:')
SUCCESS_COUNTS = re.compile(r'(?i)\b(?:0|no|zero|without)\s+(?:errors?|failures?|failed)\b')
GIT_TIMEOUT = 30


def revision_of(value):
    """A commit hash, lowercased, or None when the value is not 7 to 64 hex characters."""
    if not isinstance(value, str):
        return None
    text = value.strip().lower()
    return text if HEX_REVISION.fullmatch(text) else None


def same_revision(left, right):
    """Two hex revisions name one commit when one is a prefix of the other."""
    a, b = revision_of(left), revision_of(right)
    return bool(a and b and (a.startswith(b) or b.startswith(a)))


GIT_HARDENING = ["--no-optional-locks", "-c", "core.fsmonitor=false",
                 "-c", "core.hooksPath=/dev/null"]


def _git_out(target_root, *args):
    done = subprocess.run(["git", *GIT_HARDENING, "-C", str(target_root), *args],
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=GIT_TIMEOUT,
                          env=dict(os.environ, GIT_TERMINAL_PROMPT="0"))
    return done.returncode, done.stdout.decode("utf-8", "replace").strip()


def _known_commit(target_root, revision):
    """Whether the run's target checkout holds this commit (one fetched, not made locally).

    Existing in the checkout is not enough: a commit made in the target checkout itself - one
    that deletes the require under test - exists there too. Where the checkout has remote
    refs or tags, the commit must be reachable from one of them. A checkout with neither
    has nothing published to compare against, and is read by existence alone.
    """
    if not target_root or not Path(target_root).is_dir():
        return False
    try:
        code, full = _git_out(target_root, "rev-parse", "--verify", "--quiet",
                              revision + "^{commit}")
        full = full.lower()
        if code != 0 or not full.startswith(revision):
            return False
        code, published = _git_out(target_root, "for-each-ref", "--format=%(refname)",
                                   "refs/remotes", "refs/tags")
        if code != 0:
            return False
        if not published:
            return True
        code, containing = _git_out(target_root, "for-each-ref", "--contains", full,
                                    "--format=%(refname)", "refs/remotes", "refs/tags")
        return code == 0 and bool(containing)
    except (OSError, subprocess.SubprocessError):
        return False


def blocker_evidence_reason(blocker):
    """Why a blocker is not a reproduced failure, or '' when it is one.

    Reproduced means a command, the integer it exited with, and what it printed: a non-zero
    exit, or exit 0 with output that shows the error (curl exits 0 on a 403).
    """
    command, excerpt, code = (blocker.get("command"), blocker.get("output_excerpt"),
                              blocker.get("exit_code"))
    if not (isinstance(command, str) and command.strip() and isinstance(excerpt, str)
            and excerpt.strip()):
        return "no command and output_excerpt: nobody can tell whether the obstacle is real"
    if type(code) is not int:
        return "no exit_code: record the integer the command returned"
    if code != 0 or FAILURE_OUTPUT.search(SUCCESS_COUNTS.sub("", excerpt)):
        return ""
    return ("the command exited 0 and its output shows no error: a blocker is a failure "
            "somebody observed, and this run succeeded")


def _case_cwd(case):
    """The directory a case ran in, normalised; older results carry only the typed `cwd`."""
    resolved = case.get("cwd_resolved")
    if isinstance(resolved, str) and resolved:
        return resolved
    typed = case.get("cwd", ".")
    return posixpath.normpath(typed) if isinstance(typed, str) and typed else "."


def candidate_signatures(data):
    """(argv, cwd) of each candidate a runner result executed, as comparable strings."""
    cases = data.get("cases") if isinstance(data, dict) else None
    found = set()
    for case in cases if isinstance(cases, list) else []:
        if isinstance(case, dict) and case.get("role") == "candidate" and \
                isinstance(case.get("argv"), list):
            found.add(json.dumps([case["argv"], _case_cwd(case)], sort_keys=True))
    return found


def _read(path):
    with path.open(encoding="utf-8") as stream:
        return json.load(stream)


def _within_run(run, relative):
    if not isinstance(relative, str) or not relative or Path(relative).is_absolute():
        raise ValueError("result_path must be a nonempty run-relative path")
    raw = run / relative
    if raw.is_symlink() or any(part.is_symlink() for part in raw.parents if part != run):
        raise ValueError("result_path must not contain symlinks")
    path = raw.resolve()
    if run not in path.parents or not path.is_file():
        raise ValueError("result_path missing or outside private run directory")
    if path.stat().st_size > 2_000_000:
        raise ValueError("experiment result file is too large")
    return path


def read_result(run, relative):
    """The runner output a ledger entry cites, refused unless it is a regular file in the run."""
    return _read(_within_run(Path(run).resolve(), relative))


def _paired_result(data):
    if not isinstance(data, dict) or data.get("mode") != "executed":
        return False, "runner was not executed"
    cases = data.get("cases")
    if not isinstance(cases, list) or not cases:
        return False, "runner has no cases"
    pairs, commands = {}, {}
    for case in cases:
        if not isinstance(case, dict):
            return False, "malformed runner case"
        ident, role = case.get("pair_id"), case.get("role")
        if not isinstance(ident, str) or not ident or role not in ("candidate", "negative-control"):
            return False, "missing pair or role"
        if (case.get("executed") is not True or case.get("tests_ran") is not True or
                case.get("timed_out") is True or case.get("status") != "ran"):
            if case.get("status") == "unknown-runner":
                return False, ("the runner could not read this command's output (unknown-runner), "
                               "so nothing shows a test executed; use a recognised test command or "
                               "set expect_tests_marker on the case")
            return False, "test was skipped, timed out, or matched zero tests"
        if not isinstance(case.get("exit_code"), int) or isinstance(case["exit_code"], bool):
            return False, "missing observed exit code"
        if case.get("matched_expected_exit") is not True:
            return False, "actual exit code disagrees with expected"
        if not isinstance(case.get("argv"), list) or not case["argv"]:
            return False, "missing executed argv"
        pairs.setdefault(ident, []).append(role)
        # The resolved directory, not its spelling: "." and "./" are the same place.
        commands.setdefault(ident, []).append(
            json.dumps([case["argv"], _case_cwd(case)], sort_keys=True))
    if not pairs or any(sorted(roles) != ["candidate", "negative-control"]
                        for roles in pairs.values()):
        return False, "candidate and negative-control must both run exactly once per pair"
    # A control that runs the very command the candidate ran contrasts nothing: both `true`,
    # or the same test twice, conform on exit codes and test no property at all.
    same = sorted(ident for ident, runs in commands.items() if len(set(runs)) == 1)
    if same:
        return False, ("candidate and negative-control ran the same command in the same "
                       "directory (pair " + ", ".join(same) + "); the control must exercise "
                       "the contrasting case")
    if data.get("result") != "experiments-conformed":
        return False, "runner did not finish in conformed status"
    return True, "paired native commands executed; assertions still require human review"


def load_ledger(run):
    """Read experiments.json as (final entry by finding id, errors); a missing file is empty."""
    run = Path(run)
    ledger_path = run / "experiments.json"
    ledger = _read(ledger_path) if ledger_path.exists() else {"version": 1, "experiments": []}
    if not isinstance(ledger, dict) or ledger.get("version") != 1 or not isinstance(ledger.get("experiments"), list):
        raise ValueError("experiments.json requires version=1 and experiments array")
    by_id, errors = {}, []
    for entry in ledger["experiments"]:
        if not isinstance(entry, dict) or not FINDING_ID.fullmatch(str(entry.get("finding_id", ""))):
            errors.append("experiment entry has invalid finding_id")
            continue
        key = entry["finding_id"]
        if key in by_id:
            errors.append(key + ": multiple final experiment records; keep only the latest")
        by_id[key] = entry
    return by_id, errors


def shared_results(run, by_id):
    """Errors for one paired run standing behind more than one executed finding.

    The same file cited twice is one case. The other is the same candidate - argv, directory
    and observed commit - rerun under a second finding_id: two results, one experiment.
    """
    run = Path(run).resolve()
    cited, signatures = {}, {}
    for key, entry in sorted(by_id.items()):
        if entry.get("status") != "executed" or not isinstance(entry.get("result_path"), str):
            continue
        try:
            path = (run / entry["result_path"]).resolve()
        except (OSError, RuntimeError, ValueError):
            continue
        cited.setdefault(path, []).append(key)
        try:
            data = read_result(run, entry["result_path"])
        except (OSError, ValueError):
            continue
        observed = revision_of(data.get("source_revision")) if isinstance(data, dict) else None
        for signature in candidate_signatures(data):
            signatures.setdefault((signature, observed), set()).add(key)
    errors = []
    for path, keys in sorted(cited.items()):
        if len(keys) > 1:
            errors.append(", ".join(keys) + ": cite the same result_path; one paired run is the "
                          "evidence for one finding, so run and record each finding's own pair")
    reported = set()
    for (signature, _), keys in sorted(signatures.items()):
        group = tuple(sorted(keys))
        if len(group) > 1 and group not in reported:
            reported.add(group)
            argv = json.loads(signature)[0]
            errors.append(", ".join(group) + ": their results ran the same candidate command ("
                          + " ".join(str(word) for word in argv)[:160] + ") in the same directory "
                          "at the same commit; one experiment is the evidence for one finding")
    return errors


def check_entry(run, meta, finding, entry):
    """Validate one finding's ledger entry as (state, reason, runner result or None).

    The experiment gate and the submission gate both call this, so a record can
    never be held to a weaker standard at submission than it was between passes.
    """
    run = Path(run).resolve()
    ident = finding.get("id", "<missing-id>")
    status = entry.get("status")
    if status == "blocked":
        reason, alternative = entry.get("reason"), entry.get("attempted_alternative")
        if (not isinstance(reason, str) or len(reason.strip()) < 20 or
                not isinstance(alternative, str) or len(alternative.strip()) < 20):
            return "unsubstantiated-blocker", "blocker needs specific reason and attempted alternative", None
        # A blocker is a claim every later pass reads as closed ground, so it carries the
        # same evidence as next_experiment.blocker: the command, its exit code, its output.
        missing = blocker_evidence_reason(entry)
        if missing:
            return ("unsubstantiated-blocker", "blocked entry is not a reproduced failure: " + missing
                    + ". Record command, exit_code and output_excerpt as the shell printed them",
                    None)
        return "blocked", reason, None
    if status != "executed":
        return "invalid", "status must be executed or blocked", None
    entry_revision, finding_revision = revision_of(entry.get("revision")), \
        revision_of(finding.get("revision"))
    if not entry_revision or not finding_revision or \
            not same_revision(entry_revision, finding_revision):
        return ("stale-revision", "experiment revision differs from the finding's revision (each is "
                "7 to 64 hex characters naming the same commit)", None)
    if not isinstance(entry.get("observation"), str) or len(entry["observation"].strip()) < 20:
        return "missing-observation", "execution requires a concrete observed outcome", None
    result = None
    try:
        result = read_result(run, entry.get("result_path"))
        valid, reason = _paired_result(result)
        observed = revision_of(result.get("source_revision")) if isinstance(result, dict) else None
        if valid and not (observed and same_revision(observed, entry_revision)
                          and same_revision(observed, finding_revision)):
            valid, reason = False, 'runner-observed checkout commit differs from pinned revision'
        elif valid and not same_revision(observed, meta.get("commit")):
            # The PoC ran at another commit than the one the run was opened at - the deployed
            # revision, typically. The finding names it; it must be a commit the target
            # checkout knows, not one made in the disposable copy.
            if not _known_commit(meta.get("target_root"), observed):
                valid, reason = False, ("the paired run observed commit " + observed[:12] + ", which "
                                        "is neither the run's commit nor a commit in the target "
                                        "checkout; run the PoC at a revision the project published")
            else:
                reason = (reason + "; ran at " + observed[:12] + ", the finding's revision, not the "
                          "run's commit " + str(meta.get("commit"))[:12])
        bound = result.get("finding_id") if isinstance(result, dict) else None
        if valid and bound != ident:
            # A result names the finding it tests, or one passing pair would satisfy any record.
            valid = False
            if isinstance(bound, str) and bound:
                reason = "runner result is bound to " + bound + ", not " + ident
            else:
                reason = ("runner result names no finding_id; set finding_id in the plan so the "
                          "result is bound to its finding, and rerun scenario_runner.py")
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        valid, reason = False, str(exc)
    return ("executed" if valid else "incomplete"), reason, result


def review(run, limit=3):
    run = Path(run).resolve()
    if limit < 1 or limit > 20:
        raise ValueError("limit must be between 1 and 20")
    meta, findings = _read(run / "run.json"), _read(run / "findings.json")
    by_id, errors = load_ledger(run)
    if not isinstance(findings, list):
        raise ValueError("findings.json must be an array")
    ids = {f.get("id") for f in findings if isinstance(f, dict)}
    for key in by_id:
        if key not in ids:
            errors.append(key + ": experiment has no matching finding")
    errors.extend(shared_results(run, by_id))
    queue = sorted((f for f in findings if isinstance(f, dict) and f.get("status") in OPEN),
                   key=lambda f: (RANK.get(f.get("severity"), 6),
                                  0 if f.get("status") == "needs-evidence" else 1,
                                  str(f.get("id", ""))))
    selected, deferred = queue[:limit], queue[limit:]
    details, unverified = [], []
    for finding in selected:
        ident = finding.get("id", "<missing-id>")
        entry = by_id.get(ident)
        if entry is None:
            errors.append(ident + ": no executed experiment or explicit blocker recorded")
            details.append({"finding_id": ident, "state": "unattempted"})
            continue
        state, reason, _ = check_entry(run, meta, finding, entry)
        if state == "unsubstantiated-blocker":
            unverified.append({"finding_id": ident, "source": "experiments.json",
                               "reason": reason})
        if state == "blocked":
            details.append({"finding_id": ident, "state": state, "reason": reason})
        elif state in ("executed", "incomplete"):
            if state == "incomplete":
                errors.append(ident + ": paired execution incomplete: " + reason)
            details.append({"finding_id": ident, "state": state, "review_note": reason})
        else:
            errors.append(ident + ": " + reason)
            details.append({"finding_id": ident, "state": state})
    return {"gate": "before-reporting", "result": "failed" if errors else "passed",
            "selected": details, "deferred": [f.get("id") for f in deferred],
            "errors": errors, "checked": len(selected), "unverified_blockers": unverified,
            "notice": "This gate verifies recorded local test execution, not bug truth, economic impact, "
                      "eligibility, or novelty. Inspect unchanged source and test assertions separately."}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", required=True)
    parser.add_argument("--limit", type=int, default=3)
    parser.add_argument("--gate", action="store_true", help="return nonzero for uncovered experiments")
    args = parser.parse_args(argv)
    try:
        report = review(args.run, args.limit)
    except (OSError, ValueError, json.JSONDecodeError, KeyError) as exc:
        print("Error: " + str(exc), file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2))
    return 1 if args.gate and report["errors"] else 0


if __name__ == "__main__":
    sys.exit(main())
