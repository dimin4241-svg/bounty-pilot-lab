#!/usr/bin/env python3
"""Prepare truly separated blind A/B audit tasks and compare sealed results.

No model is launched, target code copied, reports read or benchmarks scored by
"prepare". Real run/score requires separately approved Mac and independent
review using existing backtest + bench_compare tools. No public uplift claim.
"""
import argparse
import importlib.util
import json
import os
import re
import secrets
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
_SHA = re.compile(r"^[0-9a-f]{40}$")
_MAX_INPUT = 1024 * 1024


def _read(path):
    p = Path(path).expanduser()
    if p.is_symlink() or not p.is_file() or p.stat().st_size > _MAX_INPUT:
        raise ValueError("JSON must be regular non-symlink <=1MB")
    return json.loads(p.read_text(encoding="utf-8"), object_pairs_hook=_unique)


def _unique(items):
    o = {}
    for k, v in items:
        if k in o:
            raise ValueError("duplicate key " + k[:80])
        o[k] = v
    return o


def _sha(v, key):
    if not isinstance(v, str) or not _SHA.fullmatch(v):
        raise ValueError(key + " must be an exact 40-hex git SHA")
    return v


def _cap(v, key, limit=200):
    if not isinstance(v, str) or not 1 <= len(v) <= limit:
        raise ValueError(key + " missing or too long")
    return v


def _validate(doc):
    if not isinstance(doc, dict) or doc.get("schema_version") != 1:
        raise ValueError("campaign schema_version=1 required")
    baseline = _sha(doc.get("baseline_skill_sha"), "baseline_skill_sha")
    candidate = _sha(doc.get("candidate_skill_sha"), "candidate_skill_sha")
    if baseline == candidate:
        raise ValueError("must compare two distinct skill revisions")
    name = _cap(doc.get("model"), "model", 100)
    if type(doc.get("budget_usd")) not in (int, float) or not 0 < doc["budget_usd"] <= 1000:
        raise ValueError("bounded positive budget_usd required")
    minutes = doc.get("minutes_per_case")
    if type(minutes) is not int or not 5 <= minutes <= 240:
        raise ValueError("minutes_per_case must be 5..240")
    cases = doc.get("cases")
    if not isinstance(cases, list) or not 1 <= len(cases) <= 30:
        raise ValueError("1..30 cases required")
    names = set()
    for c in cases:
        if not isinstance(c, dict) or (
                set(c) != {"case", "repo_url", "pinned_commit", "scope_paths"}):
            raise ValueError("cases may contain only case/repo_url/pinned_commit/scope_paths; NO truth")
        ident = _cap(c.get("case"), "case", 100)
        if ident in names:
            raise ValueError("case names must be unique")
        names.add(ident)
        _sha(c.get("pinned_commit"), "pinned_commit")
        url = _cap(c.get("repo_url"), "repo_url", 500)
        if not (url.startswith("https://github.com/") and
                re.fullmatch(r"https://github\.com/[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+(?:\.git)?", url)):
            raise ValueError("repo_url must be simple public GitHub repo HTTPS URL")
        scopes = c.get("scope_paths")
        if not isinstance(scopes, list) or not 1 <= len(scopes) <= 15:
            raise ValueError("scope_paths need explicit 1..15 paths")
        for path in scopes:
            if not isinstance(path, str) or not 1 <= len(path) <= 160:
                raise ValueError("invalid scope")
            p = Path(path)
            if p.is_absolute() or ".." in p.parts or "\\" in path or path.startswith("."):
                raise ValueError("unsafe scope path")
    return baseline, candidate, name, minutes, cases


def _write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as out:
        json.dump(data, out, indent=2, sort_keys=True)
        out.write("\n")


def prepare(doc, target):
    baseline, candidate, name, minutes, cases = _validate(doc)
    dest = Path(target).expanduser().absolute()
    if dest.exists() or dest.is_symlink():
        raise ValueError("campaign output must not already exist")
    dest.mkdir(parents=True, exist_ok=False, mode=0o700)
    private = {"schema_version": 1, "mode": "offline-blind-preparation",
               "comparison_ready": False,
               "baseline_skill_sha": baseline, "candidate_skill_sha": candidate,
               "model": name, "budget_usd": doc["budget_usd"],
               "minutes_per_case": minutes, "cases": []}
    # Shuffle arm order per case using independent private entropy; no task is
    # given the other arm, judging truth, known bug count or mechanism.
    for c in cases:
        opaque = secrets.token_hex(12)
        private["cases"].append({"opaque_id": opaque, "case": c["case"],
                                 "pinned_commit": c["pinned_commit"]})
        for arm, skill_sha in (("baseline", baseline), ("candidate", candidate)):
            task = {"schema_version": 1, "opaque_task": opaque,
                    "scope_paths": c["scope_paths"], "repo_url": c["repo_url"],
                    "pinned_commit": c["pinned_commit"], "skill_commit": skill_sha,
                    "model": name, "budget_limit_usd": doc["budget_usd"],
                    "minutes": minutes,
                    "prompt_policy": ("No historical reports/ground truth, code changes, "
                                      "user secrets or access to judge. Pin exact source, "
                                      "commit findings and seal BEFORE scoring."),
                    "execution": "NOT_STARTED_REQUIRES_SEPARATE_APPROVED_MAC"}
            _write_json(dest / "jobs" / arm / opaque / "TASK.json", task)
    _write_json(dest / "private-judge-ledger.json", private)
    return {"status": "prepared-only-not-run", "cases": len(cases),
            "comparisons": len(cases) * 2, "blind_claim_allowed": False,
            "public_accuracy_claim_allowed": False, "location": str(dest),
            "notice": ("Store private-judge-ledger.json outside BOTH hunter sandboxes. "
                       "Do not mount rival arm jobs or published reports.")}


def compare_scored(baseline, candidate, campaign):
    _, _, _, _, expected = _validate(campaign)
    if not isinstance(baseline, list) or not isinstance(candidate, list):
        raise ValueError("scored arms must be arrays from backtest score")
    keys = {(c["case"], c["pinned_commit"]) for c in expected}
    # Normalize and score only through existing verified scoring logic. A
    # closed-form accuracy number without scored ground truth is forbidden.
    spec = importlib.util.spec_from_file_location("bp_bench_compare",
                                                  SCRIPTS / "bench_compare.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    for arm in (baseline, candidate):
        observed = {(x.get("case"), x.get("pinned_commit")) for x in arm if isinstance(x, dict)}
        if observed != keys:
            raise ValueError("scored cases must match pinned campaign exactly")
    summary = mod.compare(baseline, candidate)
    summary["evaluation_status"] = "unverified-operator-scored-private-comparison"
    summary["public_claim_allowed"] = False
    summary["reasons"] = [
        "Independent case pin and ground truth review not verified by this command.",
        "No external model launch, budget equality or blinded filesystem confirmed.",
        "At least five independent sealed cases needed before considering a rate report.",
    ]
    summary["case_count"] = len(keys)
    return summary


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="action", required=True)
    create = sub.add_parser("prepare")
    create.add_argument("--campaign", required=True)
    create.add_argument("--out-dir", required=True)
    score = sub.add_parser("compare")
    score.add_argument("--campaign", required=True)
    score.add_argument("--baseline-scored", required=True)
    score.add_argument("--candidate-scored", required=True)
    score.add_argument("--out", required=True)
    args = p.parse_args(argv)
    try:
        campaign = _read(args.campaign)
        if args.action == "prepare":
            out = prepare(campaign, args.out_dir)
        else:
            result = compare_scored(_read(args.baseline_scored),
                                    _read(args.candidate_scored), campaign)
            path = Path(args.out).expanduser()
            if path.exists() or path.is_symlink():
                raise ValueError("comparison report path exists")
            _write_json(path, result)
            out = {"status": result["evaluation_status"], "out": str(path)}
    except (OSError, ValueError, TypeError, KeyError) as exc:
        p.error(str(exc))
    print(json.dumps(out, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
