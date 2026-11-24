#!/usr/bin/env python3
"""Offline scorecard for paired, independently reviewed local benchmark receipts.

No agent dispatch, network, target access or report promotion. Inputs are
operator-supplied aggregates, not independently authenticated observations.
"""
import argparse
import json
import math
import os
import re
from pathlib import Path

IDENT = re.compile(r"[A-Za-z0-9_-]{1,64}")
SHA = re.compile(r"[0-9a-f]{40}")
ARMS = ("baseline", "candidate")


def require(ok, message):
    if not ok:
        raise ValueError(message)


def fields(obj, expected):
    require(isinstance(obj, dict) and set(obj) == set(expected.split()),
            "unexpected or missing fields")


def integer(value):
    return type(value) is int and 0 <= value <= 100_000_000


def number(value):
    return type(value) in (float, int) and 0 <= value <= 1_000_000 and math.isfinite(value)


def identifier(value):
    return isinstance(value, str) and IDENT.fullmatch(value) is not None


def ratio(a, b):
    return round(a / b, 6) if b else None


def summarize(doc):
    fields(doc, "schema_version model baseline_revision candidate_revision budget tasks receipts")
    require(type(doc["schema_version"]) is int and doc["schema_version"] == 1,
            "unsupported schema")
    require(identifier(doc["model"]), "use an opaque model build ID")
    for key in ("baseline_revision", "candidate_revision"):
        require(isinstance(doc[key], str) and SHA.fullmatch(doc[key]), "pin revisions")
    require(doc["baseline_revision"] != doc["candidate_revision"], "distinct revisions required")
    budget = doc["budget"]
    fields(budget, "usd seconds input_tokens output_tokens")
    require(number(budget["usd"]) and budget["usd"] > 0, "invalid USD budget")
    require(all(integer(budget[k]) and budget[k] > 0 for k in
                ("seconds", "input_tokens", "output_tokens")), "invalid limits")
    tasks = doc["tasks"]
    require(isinstance(tasks, list) and 1 <= len(tasks) <= 1000, "invalid task cohort")
    expected = {}
    for task in tasks:
        fields(task, "id kind")
        ident = task["id"]
        require(identifier(ident) and ident not in expected, "duplicate/invalid task ID")
        require(task["kind"] in ("positive", "negative"), "invalid task kind")
        expected[ident] = task["kind"]

    receipts = doc["receipts"]
    require(isinstance(receipts, list) and len(receipts) == 2 * len(expected),
            "each arm needs a receipt for every task, including failures")
    rows = {}
    for row in receipts:
        fields(row, "arm task_id status oracle_solved confirmed rejected unresolved usage")
        arm, ident = row["arm"], row["task_id"]
        require(arm in ARMS and identifier(ident) and ident in expected,
                "unknown arm/task")
        require((arm, ident) not in rows, "duplicate receipt")
        require(row["status"] in ("completed", "error", "timeout"), "invalid status")
        for key in ("confirmed", "rejected", "unresolved"):
            require(integer(row[key]), "invalid adjudicated count")
        if expected[ident] == "negative":
            require(row["oracle_solved"] is None and row["confirmed"] == 0,
                    "negative control cannot have a known positive solution")
        else:
            require(type(row["oracle_solved"]) is bool, "positive case needs boolean oracle")
            if row["oracle_solved"]:
                require(row["status"] == "completed" and row["confirmed"] > 0,
                        "solved requires completed run and reviewed confirmation")
        if row["status"] != "completed":
            require(row["confirmed"] == 0, "failed run cannot claim a confirmed result")
        usage = row["usage"]
        if usage is not None:
            fields(usage, "usd seconds input_tokens output_tokens context_tokens")
            require(number(usage["usd"]), "invalid cost")
            require(all(integer(usage[k]) for k in ("seconds", "input_tokens", "output_tokens",
                                                     "context_tokens")), "invalid usage")
            require(usage["context_tokens"] <= usage["input_tokens"],
                    "context tokens cannot exceed input tokens")
        rows[arm, ident] = row

    result = {}
    positives = sum(kind == "positive" for kind in expected.values())
    negatives = len(expected) - positives
    for arm in ARMS:
        cohort = [rows[arm, ident] for ident in expected]
        solved = sum(r["oracle_solved"] is True for r in cohort)
        confirmed = sum(r["confirmed"] for r in cohort)
        rejected = sum(r["rejected"] for r in cohort)
        unresolved = sum(r["unresolved"] for r in cohort)
        usage = [r["usage"] for r in cohort if r["usage"] is not None]
        complete = len(usage) == len(cohort)
        totals = {k: round(sum(u[k] for u in usage), 6) for k in
                  ("usd", "seconds", "input_tokens", "output_tokens", "context_tokens")} if complete else None
        exceeded = sum(any(u[k] > budget[k] for k in budget) for u in usage)
        clean_completed = sum(r["status"] == "completed" and
                              r["rejected"] == r["unresolved"] == 0
                              for r in cohort if expected[r["task_id"]] == "negative")
        result[arm] = {
            "positive_solved": solved, "positive_solve_rate": ratio(solved, positives),
            "clean_negative_completed": clean_completed,
            "clean_negative_rate": ratio(clean_completed, negatives),
            "failed_runs": sum(r["status"] != "completed" for r in cohort),
            "confirmed_claims": confirmed, "rejected_claims": rejected,
            "unresolved_claims": unresolved,
            "reviewed_claim_precision": ratio(confirmed, confirmed + rejected),
            "usage_receipts": len(usage), "usage_totals": totals,
            "known_budget_exceedances": exceeded,
            "usd_per_confirmed_claim": ratio(totals["usd"], confirmed) if complete else None,
            "input_tokens_per_confirmed_claim": ratio(totals["input_tokens"], confirmed) if complete else None,
            "context_share": ratio(totals["context_tokens"], totals["input_tokens"]) if complete else None,
        }
    wins = losses = 0
    for ident, kind in expected.items():
        if kind == "positive":
            a = rows["baseline", ident]["oracle_solved"]
            b = rows["candidate", ident]["oracle_solved"]
            wins += int(b and not a)
            losses += int(a and not b)
    return {
        "schema_version": 1, "status": "OPERATOR_SUPPLIED_AGGREGATES_NOT_ATTESTED",
        "positive_tasks": positives, "negative_tasks": negatives,
        "arms": result, "candidate_only_solves": wins, "baseline_only_solves": losses,
        "public_uplift_claim_allowed": False,
        "notice": "No runs executed. Counts are per-task adjudicated claims, not globally unique "
                  "bugs. Missing usage is unknown, not zero. Unresolved claims are excluded from "
                  "reviewed precision. Budget exceedances are retained, not silently dropped. "
                  "Model identity, isolation, oracle and reviewer independence require external verification.",
    }


def unique(items):
    result = {}
    for k, v in items:
        require(k not in result, "duplicate JSON key")
        result[k] = v
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    try:
        require(args.input.is_file() and not args.input.is_symlink() and
                args.input.stat().st_size <= 3_000_000, "invalid input file")
        report = summarize(json.loads(args.input.read_text(encoding="utf-8"),
                                      object_pairs_hook=unique))
        fd = os.open(args.out, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2, allow_nan=False)
            handle.write("\n")
    except (OSError, ValueError, TypeError, KeyError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
