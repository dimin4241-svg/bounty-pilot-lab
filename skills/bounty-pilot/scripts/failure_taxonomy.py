#!/usr/bin/env python3
"""Categorize why research did not yield payable, independently proven bugs.

Reads only a researcher-supplied **structured** case ledger and optionally
an existing discovery_doctor JSON. Never infers "model missed a real bug"
from an empty model response. No emails, model sessions, target calls or
publication. Case descriptions are never copied to output.
"""
import argparse
import json
import sys
from collections import Counter
from pathlib import Path

FIELDS = {
    "reading": {"not-run", "failed", "completed"},
    "candidate": {"none", "hypothesis", "proven-poc", "refuted"},
    "poc": {"not-run", "setup-failed", "candidate-failed",
            "control-failed", "reported-paired-pass"},
    "impact": {"not-assessed", "capital-unrealistic", "no-measured-loss",
               "measured-researcher-supplied"},
    "eligibility": {"not-checked", "in-scope", "out-of-scope", "duplicate"},
    "disposition": {"not-submitted", "pending", "rejected", "accepted",
                    "rewarded-researcher-supplied"},
}
STAGES = [
    ("reading", "not-run", "dispatch-unstarted", "Run a bounded, scoped agent reading."),
    ("reading", "failed", "dispatch-or-format-failure", "Inspect agent logs, bundles and parser drift."),
    ("candidate", "none", "no-candidate-unproven-negative", "Inspect uncovered code; do not claim the model missed a known bug without independently pinned truth."),
    ("candidate", "refuted", "hypothesis-refuted", "Record falsifying trace and pursue independent mechanisms."),
    ("poc", "not-run", "poc-missing", "Build native candidate + same-state control in an isolated checkout."),
    ("poc", "setup-failed", "native-harness-setup", "Resolve toolchain and fixtures without altering target behavior."),
    ("poc", "candidate-failed", "candidate-not-reproduced", "Check reachability, actor capability and sequence assumptions."),
    ("poc", "control-failed", "invalid-negative-control", "Fix honest control before promoting a candidate."),
    ("impact", "not-assessed", "economic-impact-unknown", "Measure asset deltas and all obligations/costs with actual receipts."),
    ("impact", "capital-unrealistic", "economically-unreachable", "Minimize real attacker capital and verify liquidity."),
    ("impact", "no-measured-loss", "no-demonstrated-economic-loss", "Look for a separate credible impact or record as informational."),
    ("eligibility", "not-checked", "program-scope-unverified", "Check published scope and deployed revision."),
    ("eligibility", "out-of-scope", "ineligible-out-of-scope", "Do not submit or expand testing on an excluded asset."),
    ("eligibility", "duplicate", "already-known-duplicate", "Stop resubmitting the same root cause; compare against fixes."),
]
ACTIONS = {
    "awaiting-triage": "Await official confirmation or request clarification once; do not assume payout.",
    "reported-accepted": "Reconcile accepted severity and independently verify fix/award status.",
    "reported-reward": "Verify payout receipt separately; a local ledger is not financial proof.",
    "reported-rejection": "Compare concrete objections against same-state native evidence.",
    "not-submitted": "Independently review scope, duplicate risk, PoC and impact before private submission.",
}


def evaluate(doc, doctor=None):
    if not isinstance(doc, dict) or doc.get("schema_version") != 1:
        raise ValueError("case ledger must use schema_version=1")
    rows = doc.get("cases")
    if not isinstance(rows, list) or not 1 <= len(rows) <= 500:
        raise ValueError("cases must be array of 1..500")
    if doctor is not None and (
            not isinstance(doctor, dict) or doctor.get("schema_version") != 1):
        raise ValueError("doctor report must use schema_version=1")
    result, seen = [], set()
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("case must be object")
        ident = row.get("id")
        if not isinstance(ident, str) or not 1 <= len(ident) <= 120 or ident in seen:
            raise ValueError("case ID invalid or duplicate")
        seen.add(ident)
        for name, allowed in FIELDS.items():
            if row.get(name) not in allowed:
                raise ValueError("%s has invalid %s" % (ident, name))
        reason = None
        action = None
        for field, target, diagnosis, recommended in STAGES:
            if row[field] == target:
                reason, action = diagnosis, recommended
                break
        if reason is None:
            outcome = row["disposition"]
            reason = {
                "not-submitted": "not-submitted",
                "pending": "awaiting-triage",
                "rejected": "reported-rejection",
                "accepted": "reported-accepted",
                "rewarded-researcher-supplied": "reported-reward",
            }[outcome]
            action = ACTIONS[reason]
        # Some combinations are internally contradictory; fail closed.
        if row["poc"] == "reported-paired-pass" and row["candidate"] == "none":
            raise ValueError("cannot pass a PoC without a candidate")
        if row["disposition"] != "not-submitted" and (
                row["reading"] != "completed" or row["candidate"] == "none"):
            raise ValueError("disposition inconsistent with no completed investigation")
        if row["disposition"] in ("accepted", "rewarded-researcher-supplied") and (
                row["poc"] != "reported-paired-pass" or row["impact"] == "not-assessed"):
            raise ValueError("cannot mark accepted/rewarded without recorded PoC and impact")
        result.append({"id": ident, "bottleneck": reason,
                       "recommended_action": action,
                       "status": "operator-ledger-unverified"})
    by = dict(sorted(Counter(x["bottleneck"] for x in result).items()))
    hints = []
    if doctor:
        stats = doctor.get("reading_counts", {})
        jobs = doctor.get("agent_jobs", {})
        if isinstance(jobs, dict) and (jobs.get("failed", 0) or jobs.get("queued", 0)):
            hints.append("agent-dispatch-incomplete")
        if isinstance(stats, dict) and stats.get("unparsed_candidate_headers", 0):
            hints.append("parser-dropped-candidate-like-headers")
        if doctor.get("oversized_bundles"):
            hints.append("prompt-context-oversized")
    return {"schema_version": 1, "execution": "offline-read-only-categorization",
            "case_count": len(result), "bottlenecks": by,
            "cases": result, "pipeline_warnings": hints,
            "notice": ("Do not infer a real missed vulnerability, confirmed PoC, accepted "
                       "severity or payout from this ledger. Assertions require independent "
                       "native evidence and a trusted external triage receipt.")}


def _pairs(items):
    out = {}
    for k, v in items:
        if k in out:
            raise ValueError("duplicate JSON key")
        out[k] = v
    return out


def read(path):
    p = Path(path).expanduser()
    if p.is_symlink() or not p.is_file() or p.stat().st_size > 2_000_000:
        raise ValueError("input must be local regular JSON <=2MB")
    return json.loads(p.read_text(encoding="utf-8"), object_pairs_hook=_pairs)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--ledger", required=True)
    p.add_argument("--doctor-report")
    p.add_argument("--out", help="optional new JSON file")
    a = p.parse_args(argv)
    try:
        data = evaluate(read(a.ledger),
                        read(a.doctor_report) if a.doctor_report else None)
        encoded = json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        if a.out:
            dest = Path(a.out).expanduser()
            if dest.exists() or dest.is_symlink():
                raise ValueError("output already exists")
            dest.parent.mkdir(parents=True, exist_ok=True)
            with dest.open("x", encoding="utf-8") as f:
                f.write(encoded)
            print(json.dumps({"out": a.out, "case_count": data["case_count"]}))
        else:
            print(encoded, end="")
    except (ValueError, KeyError, TypeError, OSError) as exc:
        p.error(str(exc))
    return 0


if __name__ == "__main__":
    sys.exit(main())
