#!/usr/bin/env python3
"""Two-pass native candidate/control experiment using Pilot's existing runner.

No test is invented, no network sandbox is provided, and no exploit is proven.
Execution is opt-in, requires an explicitly confirmed disposable workspace.
"""
import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

import experimenter
import scenario_runner

GIT_OPTS = ("--no-optional-locks", "-c", "core.fsmonitor=false",
            "-c", "core.hooksPath=/dev/null", "-c", "core.pager=cat")
SHA = re.compile(r"^[0-9a-fA-F]{40}$")


def _git(root, *args):
    cp = subprocess.run(["git", *GIT_OPTS, "-C", str(root), *args],
                        capture_output=True, check=True, timeout=15)
    return cp.stdout.decode("utf-8", "replace").strip()


def plan_native(spec, stack, root):
    if not isinstance(spec, dict):
        raise ValueError("native spec must be an object")
    revision = spec.get("source_revision")
    if not isinstance(revision, str) or not SHA.fullmatch(revision):
        raise ValueError("full 40-hex source_revision required for native cycle")
    checkout = Path(root).resolve()
    if not (checkout / ".git").exists():
        raise ValueError("native experiments require a local git checkout")
    head = _git(checkout, "rev-parse", "HEAD")
    if head.lower() != revision.lower():
        raise ValueError("native checkout HEAD differs from spec.source_revision")
    plan = experimenter.plan(spec, stack)
    plan["source_revision"] = head
    plan["execution_policy"] = "DISPOSABLE_ISOLATED_WORKSPACE_REQUIRED"
    return plan


def cycle(spec, stack, repository, allow_exec=False, isolated_confirmed=False):
    checkout = Path(repository).resolve()
    plan = plan_native(spec, stack, checkout)
    if allow_exec and not isolated_confirmed:
        raise ValueError("execution needs --isolated-workspace-confirmed; "
                         "the Pilot runner is not a network sandbox")
    if allow_exec and (checkout == Path.home().resolve() or checkout == Path("/")):
        raise ValueError("refusing execution from home directory or filesystem root")
    before = _git(checkout, "status", "--porcelain", "--untracked-files=no")
    snapshots = []
    for round_number in range(1, 3 if allow_exec else 2):
        report = scenario_runner.execute(plan, checkout, allow_exec=allow_exec)
        case_results = []
        for case in report["cases"]:
            case_results.append({
                "pair_id": case["pair_id"], "role": case["role"],
                "executed": bool(case.get("executed")),
                "tests_ran": case.get("tests_ran"),
                "status": case.get("status", "not-executed"),
                "matched_expected_exit": bool(case.get("matched_expected_exit")),
                "log_sha256": hashlib.sha256(
                    (case.get("stdout", "") + "\n" + case.get("stderr", "")).encode()
                ).hexdigest() if case.get("executed") else None,
            })
        snapshots.append({"round": round_number, "result": report["result"],
                          "cases": case_results})
        if _git(checkout, "rev-parse", "HEAD") != plan["source_revision"]:
            raise ValueError("checkout revision changed during experiment")
    after = _git(checkout, "status", "--porcelain", "--untracked-files=no")
    unchanged = before == after
    performed = allow_exec and len(snapshots) == 2
    conforming = (performed and unchanged and
                  all(row["result"] == "experiments-conformed" for row in snapshots))
    fingerprint = [tuple((x["pair_id"], x["role"], x["matched_expected_exit"],
                           x["tests_ran"], x["status"]) for x in round_["cases"])
                   for round_ in snapshots]
    deterministic = len(fingerprint) == 2 and fingerprint[0] == fingerprint[1]
    return {"schema_version": 1, "finding_id": plan.get("finding_id"),
            "revision": plan["source_revision"], "mode": "executed" if performed else "dry-run",
            "status": ("NATIVE_PAIR_RAN_NEEDS_INDEPENDENT_REVIEW"
                       if conforming and deterministic else "INCOMPLETE_OR_NOT_EXECUTED"),
            "rounds": snapshots, "tracked_files_unchanged": unchanged,
            "repeatable_execution_status": deterministic, "confirmed_vulnerabilities": 0,
            "notice": "No network or filesystem isolation is enforced here. Test results "
                      "are harness evidence only; source integrity, attack preconditions, "
                      "impact, assertions and bounty eligibility need independent review."}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", required=True)
    parser.add_argument("--stack", required=True,
                        choices=("foundry", "cargo", "pytest", "go"))
    parser.add_argument("--repo", required=True)
    parser.add_argument("--allow-exec", action="store_true")
    parser.add_argument("--isolated-workspace-confirmed", action="store_true")
    parser.add_argument("--out", help="private result JSON; must not already exist")
    args = parser.parse_args(argv)
    try:
        p = Path(args.spec)
        if p.is_symlink() or not p.is_file() or p.stat().st_size > 100_000:
            raise ValueError("spec must be regular and under 100kB")
        result = cycle(json.loads(p.read_text(encoding="utf-8")), args.stack,
                       args.repo, args.allow_exec, args.isolated_workspace_confirmed)
        if args.out:
            dest = Path(args.out)
            if dest.exists() or dest.is_symlink():
                raise ValueError("refusing to overwrite experiment output")
            dest.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(result, indent=2))
        return 0 if not args.allow_exec or result["status"].startswith("NATIVE_PAIR") else 1
    except (ValueError, OSError, subprocess.SubprocessError, UnicodeError) as exc:
        print("Error: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
