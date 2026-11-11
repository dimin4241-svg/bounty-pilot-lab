#!/usr/bin/env python3
"""Offline controlled business-effect oracle for researcher-owned lab traces.

Requires pre/post state evidence, repeated candidate observations, and a
matched negative control. An HTTP status, changed display counter or
model-written claim alone can never satisfy the effect gate. Observations are
operator supplied, not independently verified; zero production claims.
"""
import argparse
import json
import os
import re
import sys
from pathlib import Path

ID = re.compile(r"^[A-Za-z0-9_.:-]{1,100}$")
SHA = re.compile(r"^[a-f0-9]{64}$")
REL = frozenset(("increased", "decreased", "equals", "changed", "unchanged"))
MAX_CASES = 100


def _load(path):
    p = Path(path).expanduser()
    if p.is_symlink() or not p.is_file() or p.stat().st_size > 2_000_000:
        raise ValueError("bounded regular JSON <=2MB required")
    return json.loads(p.read_text(encoding="utf-8"), object_pairs_hook=_unique)


def _unique(pairs):
    obj = {}
    for k, v in pairs:
        if k in obj:
            raise ValueError("duplicate JSON key")
        obj[k] = v
    return obj


def _write(path, obj):
    p = Path(path).expanduser()
    if p.is_symlink() or p.exists():
        raise ValueError("output exists")
    p.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(p), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, sort_keys=True, indent=2)
        f.write("\n")


def _state(value):
    if not isinstance(value, dict) or not 1 <= len(value) <= 30:
        raise ValueError("state must contain 1..30 safe scalar facts")
    for k, v in value.items():
        if (not isinstance(k, str) or not ID.fullmatch(k) or
                type(v) not in (int, float, bool, str, type(None)) or
                (isinstance(v, str) and len(v) > 120) or
                (type(v) is float and (abs(v) > 1e15 or v != v))):
            raise ValueError("state values must be bounded scalar observations")
    return value


def _observation(record):
    if (not isinstance(record, dict) or set(record) != {
            "before", "after", "evidence_sha256", "effect_observed_at_step"}):
        raise ValueError("observation requires before/after/digest/timing")
    before, after = _state(record["before"]), _state(record["after"])
    if set(before) != set(after):
        raise ValueError("before and after state keys differ")
    if (not isinstance(record["evidence_sha256"], str) or
            not SHA.fullmatch(record["evidence_sha256"])):
        raise ValueError("independently saved observation digest required")
    step = record["effect_observed_at_step"]
    if type(step) is not int or not 0 <= step <= 50:
        raise ValueError("bounded observation step required")
    return before, after


def _predicate(before, after, rule):
    field = rule["field"]
    relation = rule["relation"]
    a, b = before[field], after[field]
    if relation == "changed":
        return a != b
    if relation == "unchanged":
        return a == b
    if relation == "equals":
        return b == rule["value"]
    if type(a) not in (int, float) or type(b) not in (int, float):
        return False
    return b > a if relation == "increased" else b < a


def analyze(doc):
    if (not isinstance(doc, dict) or set(doc) != {
            "schema_version", "environment", "cases"} or
            type(doc["schema_version"]) is not int or doc["schema_version"] != 1 or
            doc["environment"] != "researcher_owned_lab"):
        raise ValueError("lab schema version 1 required")
    cases = doc["cases"]
    if not isinstance(cases, list) or not 1 <= len(cases) <= MAX_CASES:
        raise ValueError("1..100 effect cases required")
    ids, results = set(), []
    for row in cases:
        if not isinstance(row, dict) or set(row) != {
                "id", "resource_kind", "business_effect", "predicate",
                "candidate_repetitions", "negative_control"}:
            raise ValueError("invalid case fields")
        ident = row["id"]
        if not isinstance(ident, str) or not ID.fullmatch(ident) or ident in ids:
            raise ValueError("duplicate or invalid case id")
        ids.add(ident)
        if row["resource_kind"] not in (
                "payment-sandbox", "subscription", "export", "approval",
                "job", "object", "refund-sandbox", "other"):
            raise ValueError("unsupported resource kind")
        if (not isinstance(row["business_effect"], str) or
                not ID.fullmatch(row["business_effect"])):
            raise ValueError("effect must have explicit opaque identifier")
        rule = row["predicate"]
        if (not isinstance(rule, dict) or set(rule) != {"field", "relation", "value"} or
                not isinstance(rule["field"], str) or not ID.fullmatch(rule["field"]) or
                rule["relation"] not in REL or
                type(rule["value"]) not in (int, float, bool, str, type(None))):
            raise ValueError("invalid effect assertion")
        repeats = row["candidate_repetitions"]
        if not isinstance(repeats, list) or not 2 <= len(repeats) <= 5:
            raise ValueError("two to five independent candidate repetitions required")
        controls = row["negative_control"]
        if not isinstance(controls, list) or len(controls) != len(repeats):
            raise ValueError("matched negative control required for every repetition")
        candidate_ok, control_ok = [], []
        hashes = set()
        for candidate, control in zip(repeats, controls):
            c_pre, c_post = _observation(candidate)
            n_pre, n_post = _observation(control)
            for pair in (candidate, control):
                if pair["evidence_sha256"] in hashes:
                    raise ValueError("repeated evidence digest does not establish independent observations")
                hashes.add(pair["evidence_sha256"])
            field = rule["field"]
            if field not in c_pre or field not in n_pre:
                raise ValueError("predicate field not observed")
            if c_pre[field] != n_pre[field]:
                raise ValueError("candidate/control initial state must match")
            candidate_ok.append(_predicate(c_pre, c_post, rule))
            control_ok.append(_predicate(n_pre, n_post, rule))
        if all(candidate_ok) and not any(control_ok):
            status = "CONTROLLED_EFFECT_IN_OPERATOR_SUPPLIED_LAB_DATA"
        elif any(control_ok):
            status = "INCONCLUSIVE_NEGATIVE_CONTROL_CHANGED"
        elif any(candidate_ok):
            status = "INCONCLUSIVE_INCONSISTENT_REPETITIONS"
        else:
            status = "NO_BUSINESS_EFFECT_OBSERVED"
        results.append({"case_id": ident, "resource_kind": row["resource_kind"],
                        "effect": row["business_effect"], "status": status,
                        "candidate_effect_repetitions": sum(candidate_ok),
                        "negative_control_effect_repetitions": sum(control_ok),
                        "evidence_digest_count": len(hashes),
                        "confirmed_vulnerability": False})
    return {"schema_version": 1, "mode": "web-business-effect-oracle",
            "cases_reviewed": len(cases), "results": results,
            "controlled_effect_leads": sum(
                x["status"] == "CONTROLLED_EFFECT_IN_OPERATOR_SUPPLIED_LAB_DATA"
                for x in results),
            "network_requests": 0, "confirmed_vulnerabilities": 0,
            "limitations": ("Requires independently saved state facts and matched "
                            "negative controls, but does not authenticate the "
                            "capturing service, verify payments or infer a live exploit. "
                            "A controlled business effect alone is not necessarily "
                            "an unauthorized effect; join with explicit policy facts.")}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--input", required=True)
    p.add_argument("--out", required=True)
    a = p.parse_args(argv)
    try:
        result = analyze(_load(a.input))
        _write(a.out, result)
    except (ValueError, OSError, TypeError, KeyError, json.JSONDecodeError) as exc:
        p.error(str(exc))
    print(json.dumps({"out": a.out, "controlled_effect_leads":
                      result["controlled_effect_leads"],
                      "confirmed_vulnerabilities": 0}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
