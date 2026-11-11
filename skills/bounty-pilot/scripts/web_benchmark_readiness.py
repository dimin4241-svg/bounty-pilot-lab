#!/usr/bin/env python3
"""Strict 30–50 case historical Web benchmark provenance gate.

This checks catalog structure, repository/family diversity and independently
supplied vulnerable/patched control evidence digests. It does NOT fetch, build,
verify advisory details, certify independent reviewers, run models, score
findings or make any uplift claim. Public cases can be memorized by a model.
"""
import argparse
import hashlib
import json
import os
import re
from pathlib import Path

SHA = re.compile(r"^[a-f0-9]{64}$")
IDENT = re.compile(r"^[A-Za-z0-9_.:-]{1,120}$")
MAX_BYTES = 3_000_000
MIN_CASES = 30
MAX_CASES = 50
MIN_REPOS = 5
MIN_FAMILIES = 5


def _unique(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise ValueError("duplicate JSON key")
        d[k] = v
    return d


def _read(path):
    p = Path(path)
    if p.is_symlink() or not p.is_file() or p.stat().st_size > MAX_BYTES:
        raise ValueError("bounded regular JSON input required")
    return json.loads(p.read_text(encoding="utf-8"), object_pairs_hook=_unique)


def _write(path, value):
    p = Path(path)
    if p.exists() or p.is_symlink():
        raise ValueError("report already exists")
    p.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(p), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(value, f, indent=2, sort_keys=True, ensure_ascii=False)
        f.write("\n")


def _digest(obj):
    return hashlib.sha256(json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")).hexdigest()


def assess(catalog, reviews):
    spec = __import__("importlib.util").util.spec_from_file_location(
        "bp_historical_gate",
        Path(__file__).with_name("web_historical_bench.py"))
    module = __import__("importlib.util").util.module_from_spec(spec)
    spec.loader.exec_module(module)
    cases = module._catalog(catalog)
    if (not isinstance(reviews, dict) or set(reviews) != {
            "schema_version", "reviewer_role", "cases"} or
            type(reviews["schema_version"]) is not int or
            reviews["schema_version"] != 1):
        raise ValueError("exact evaluator-only review format required")
    if reviews["reviewer_role"] != "external_independent_reviewer":
        raise ValueError("separate reviewer role must be declared")
    rows = reviews["cases"]
    if not isinstance(rows, list) or len(rows) > MAX_CASES:
        raise ValueError("at most 50 reviewer evidence records")
    ids = set()
    reviewed = {}
    for row in rows:
        if not isinstance(row, dict) or set(row) != {
                "id", "reproduced_vulnerable_sha256",
                "reproduced_patched_sha256", "revision_chain_checked",
                "distinct_negative_control", "reviewer_id",
                "independent_review_asserted"}:
            raise ValueError("invalid evaluator-only review fields")
        ident = row["id"]
        if not isinstance(ident, str) or not IDENT.fullmatch(ident) or ident in ids:
            raise ValueError("invalid or duplicate review ID")
        ids.add(ident)
        for k in ("reproduced_vulnerable_sha256", "reproduced_patched_sha256"):
            if row[k] is not None and (not isinstance(row[k], str) or
                                        not SHA.fullmatch(row[k])):
                raise ValueError("review digest must be SHA-256 or null")
        if not isinstance(row["reviewer_id"], str) or not IDENT.fullmatch(row["reviewer_id"]):
            raise ValueError("reviewer ID must be bounded label")
        for k in ("revision_chain_checked", "distinct_negative_control",
                  "independent_review_asserted"):
            if type(row[k]) is not bool:
                raise ValueError("review attestations must be explicit boolean")
        reviewed[ident] = row
    expected = {c["id"] for c in cases}
    if set(reviewed) - expected:
        raise ValueError("evidence for unknown catalog case")
    good = set()
    for c in cases:
        row = reviewed.get(c["id"])
        if row and row["revision_chain_checked"] and row["distinct_negative_control"] and (
                row["independent_review_asserted"] and
                row["reproduced_vulnerable_sha256"] and
                row["reproduced_patched_sha256"] and
                row["reproduced_vulnerable_sha256"] != row["reproduced_patched_sha256"]):
            good.add(c["id"])
    family_set = {c["family"] for c in cases}
    repos = {c["repository_url"] for c in cases}
    reasons = []
    if not MIN_CASES <= len(cases) <= MAX_CASES:
        reasons.append("NEED_30_TO_50_INDEPENDENT_HISTORICAL_CASES")
    if len(repos) < MIN_REPOS:
        reasons.append("INSUFFICIENT_REPOSITORY_DIVERSITY")
    if len(family_set) < MIN_FAMILIES:
        reasons.append("INSUFFICIENT_MECHANISM_DIVERSITY")
    if len(good) != len(cases):
        reasons.append("MISSING_SEPARATELY_REVIEWED_VULNERABLE_AND_PATCHED_CONTROLS")
    if any(
        ("synthetic" in c["id"].lower() or
         "placeholder" in c["source_revisions"].lower() or
         "/example/" in c["repository_url"].lower())
        for c in cases
    ):
        reasons.append("SYNTHETIC_OR_PLACEHOLDER_CASES_NOT_HISTORICAL")
    # A verified corpus may still be public and memorized. This tool never
    # declares truly unseen holdouts or public uplift from self-attestations.
    return {"schema_version": 1, "mode": "web-benchmark-readiness",
            "status": ("OPERATOR_ATTESTED_REPLAY_READY_NOT_VERIFIED" if
                       not reasons else "BLOCKED_INSUFFICIENT_HISTORICAL_EVIDENCE"),
            "catalog_sha256": _digest(catalog),
            "review_record_sha256": _digest(reviews),
            "case_count": len(cases), "repository_count": len(repos),
            "mechanism_families": len(family_set),
            "cases_with_operator_attested_controls": len(good),
            "blocking_reasons": reasons,
            "can_prepare_private_operator_replay": not reasons,
            "ground_truth_independently_verified_by_tool": False,
            "real_model_runs": 0, "public_uplift_claim_allowed": False,
            "limitations": ("Review attestations and reproduction hashes are user-supplied "
                            "and not cryptographically verified; public vulnerabilities "
                            "may already be in model training data. This tool cannot "
                            "claim blinded rediscovery, revenue or performance gain.")}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--catalog", required=True)
    p.add_argument("--evaluator-reviews", required=True)
    p.add_argument("--out", required=True)
    a = p.parse_args(argv)
    try:
        report = assess(_read(a.catalog), _read(a.evaluator_reviews))
        _write(a.out, report)
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        p.error(str(exc))
    print(json.dumps({"out": a.out, "status": report["status"],
                      "case_count": report["case_count"],
                      "blocking_reasons": report["blocking_reasons"]}))
    return 0 if report["can_prepare_private_operator_replay"] else 2


if __name__ == "__main__":
    sys.exit(main())
