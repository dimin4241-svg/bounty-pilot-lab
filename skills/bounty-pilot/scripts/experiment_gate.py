#!/usr/bin/env python3
"""Evidence-first gate: attest that decisive paired experiments ran before more reading.

This is a workflow gate, NOT exploit verification. Only a native PoC against
unchanged production source can establish the factual claim.
"""
import argparse
import json
import re
import sys
from pathlib import Path

FINDING_ID = re.compile(r"BP-[0-9]{3,}$")
OPEN = {"hypothesis", "needs-evidence"}
RANK = {"critical": 0, "high": 1, "unassessed": 2, "medium": 3,
        "low": 4, "informational": 5}


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


def _paired_result(data):
    if not isinstance(data, dict) or data.get("mode") != "executed":
        return False, "runner was not executed"
    cases = data.get("cases")
    if not isinstance(cases, list) or not cases:
        return False, "runner has no cases"
    pairs = {}
    for case in cases:
        if not isinstance(case, dict):
            return False, "malformed runner case"
        ident, role = case.get("pair_id"), case.get("role")
        if not isinstance(ident, str) or not ident or role not in ("candidate", "negative-control"):
            return False, "missing pair or role"
        if (case.get("executed") is not True or case.get("tests_ran") is not True or
                case.get("timed_out") is True or case.get("status") != "ran"):
            return False, "test was skipped, timed out, or matched zero tests"
        if not isinstance(case.get("exit_code"), int) or isinstance(case["exit_code"], bool):
            return False, "missing observed exit code"
        if case.get("matched_expected_exit") is not True:
            return False, "actual exit code disagrees with expected"
        if not isinstance(case.get("argv"), list) or not case["argv"]:
            return False, "missing executed argv"
        pairs.setdefault(ident, []).append(role)
    if not pairs or any(sorted(roles) != ["candidate", "negative-control"]
                        for roles in pairs.values()):
        return False, "candidate and negative-control must both run exactly once per pair"
    if data.get("result") != "experiments-conformed":
        return False, "runner did not finish in conformed status"
    return True, "paired native commands executed; assertions still require human review"


def review(run, limit=3):
    run = Path(run).resolve()
    if limit < 1 or limit > 20:
        raise ValueError("limit must be between 1 and 20")
    meta, findings = _read(run / "run.json"), _read(run / "findings.json")
    ledger_path = run / "experiments.json"
    ledger = _read(ledger_path) if ledger_path.exists() else {"version": 1, "experiments": []}
    if not isinstance(ledger, dict) or ledger.get("version") != 1 or not isinstance(ledger.get("experiments"), list):
        raise ValueError("experiments.json requires version=1 and experiments array")
    if not isinstance(findings, list):
        raise ValueError("findings.json must be an array")
    by_id, errors = {}, []
    for entry in ledger["experiments"]:
        if not isinstance(entry, dict) or not FINDING_ID.fullmatch(str(entry.get("finding_id", ""))):
            errors.append("experiment entry has invalid finding_id")
            continue
        key = entry["finding_id"]
        if key in by_id:
            errors.append(key + ": multiple final experiment records; keep only the latest")
        by_id[key] = entry
    ids = {f.get("id") for f in findings if isinstance(f, dict)}
    for key in by_id:
        if key not in ids:
            errors.append(key + ": experiment has no matching finding")
    queue = sorted((f for f in findings if isinstance(f, dict) and f.get("status") in OPEN),
                   key=lambda f: (RANK.get(f.get("severity"), 6),
                                  0 if f.get("status") == "needs-evidence" else 1,
                                  str(f.get("id", ""))))
    selected, deferred = queue[:limit], queue[limit:]
    details = []
    for finding in selected:
        ident = finding.get("id", "<missing-id>")
        entry = by_id.get(ident)
        if entry is None:
            errors.append(ident + ": no executed experiment or explicit blocker recorded")
            details.append({"finding_id": ident, "state": "unattempted"})
            continue
        status = entry.get("status")
        if status == "blocked":
            reason, alternative = entry.get("reason"), entry.get("attempted_alternative")
            if (not isinstance(reason, str) or len(reason.strip()) < 20 or
                    not isinstance(alternative, str) or len(alternative.strip()) < 20):
                errors.append(ident + ": blocker needs specific reason and attempted alternative")
                details.append({"finding_id": ident, "state": "unsubstantiated-blocker"})
            else:
                details.append({"finding_id": ident, "state": "blocked", "reason": reason})
            continue
        if status != "executed":
            errors.append(ident + ": status must be executed or blocked")
            details.append({"finding_id": ident, "state": "invalid"})
            continue
        if entry.get("revision") != meta.get("commit") or entry.get("revision") != finding.get("revision"):
            errors.append(ident + ": experiment revision differs from pinned run/finding revision")
            details.append({"finding_id": ident, "state": "stale-revision"})
            continue
        if not isinstance(entry.get("observation"), str) or len(entry["observation"].strip()) < 20:
            errors.append(ident + ": execution requires a concrete observed outcome")
            details.append({"finding_id": ident, "state": "missing-observation"})
            continue
        try:
            result = _read(_within_run(run, entry.get("result_path")))
            valid, reason = _paired_result(result)
            if valid and result.get('source_revision') != entry['revision']:
                valid, reason = False, 'runner-observed checkout commit differs from pinned revision'
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            valid, reason = False, str(exc)
        if not valid:
            errors.append(ident + ": paired execution incomplete: " + reason)
        details.append({"finding_id": ident, "state": "executed" if valid else "incomplete",
                        "review_note": reason})
    return {"gate": "before-next-reading-pass", "result": "failed" if errors else "passed",
            "selected": details, "deferred": [f.get("id") for f in deferred],
            "errors": errors, "checked": len(selected),
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
