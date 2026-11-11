#!/usr/bin/env python3
"""Offline conservative root-cause grouping and evidence-based review queue.

Never conflates distinct business invariants based on keyword similarity.
Exact group keys require same pinned project/revision, trust boundary, violated
invariant, and concrete code/fix anchor (or human-reviewed root cause ID).
Related but non-identical leads are only suggestions for manual review.
"""
import argparse
import hashlib
import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path

ID = re.compile(r"^[A-Za-z0-9_.:/-]{1,160}$")
SHA40 = re.compile(r"^[a-f0-9]{40}$")
FIELDS = ("reachability", "trust_boundary", "business_effect", "novelty", "testability")
MAX_CANDIDATES = 1500


def _unique(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise ValueError("duplicate JSON key")
        d[k] = v
    return d


def _load(path):
    p = Path(path)
    if p.is_symlink() or not p.is_file() or p.stat().st_size > 3_000_000:
        raise ValueError("input JSON must be <=3MB, regular, non-symlink")
    return json.loads(p.read_text(encoding="utf-8"), object_pairs_hook=_unique)


def _write(path, data):
    p = Path(path)
    if p.is_symlink() or p.exists():
        raise ValueError("output must be new")
    p.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True, ensure_ascii=False)
        f.write("\n")


def _id(value, label):
    if not isinstance(value, str) or not ID.fullmatch(value):
        raise ValueError(label + ": bounded opaque ID required")
    return value


def _key(row):
    if row["reviewed_root_cause_id"] is not None:
        return ["reviewed", row["reviewed_root_cause_id"]]
    return ["structural", row["source_file"], row["invariant_id"],
            row["trust_boundary_id"], row["code_anchor"]]


def rank(row):
    quality = row["evidence"]
    if not isinstance(quality, dict) or set(quality) != set(FIELDS):
        raise ValueError("five evidence dimensions required")
    for key in FIELDS:
        if type(quality[key]) is not int or quality[key] not in (0, 1, 2):
            raise ValueError("evidence dimensions require strict 0/1/2 integer")
    # Useful but bounded: 0..10, not an estimated vulnerability probability.
    return sum(quality.values())


def analyze(doc):
    if (not isinstance(doc, dict) or set(doc) != {
            "schema_version", "project", "pinned_revision", "candidates"} or
            type(doc["schema_version"]) is not int or doc["schema_version"] != 1):
        raise ValueError("exact versioned root cause queue required")
    project = _id(doc["project"], "project")
    rev = doc["pinned_revision"]
    if not isinstance(rev, str) or not SHA40.fullmatch(rev):
        raise ValueError("exact 40-hex pinned revision required")
    entries = doc["candidates"]
    if not isinstance(entries, list) or not 1 <= len(entries) <= MAX_CANDIDATES:
        raise ValueError("bounded nonempty candidate set required")
    seen, groups, related = set(), defaultdict(list), defaultdict(list)
    for row in entries:
        if not isinstance(row, dict) or set(row) != {
                "id", "source_file", "code_anchor", "invariant_id",
                "trust_boundary_id", "reviewed_root_cause_id",
                "claimed_effect_id", "evidence", "evidence_digest",
                "disposition"}:
            raise ValueError("candidate fields invalid")
        ident = _id(row["id"], "id")
        if ident in seen:
            raise ValueError("duplicate candidate")
        seen.add(ident)
        for field in ("source_file", "code_anchor", "invariant_id",
                      "trust_boundary_id", "claimed_effect_id"):
            _id(row[field], field)
        cause = row["reviewed_root_cause_id"]
        if cause is not None:
            _id(cause, "reviewed root cause")
        if row["disposition"] not in ("unreviewed", "refuted", "parked", "confirmed-local"):
            raise ValueError("invalid candidate disposition")
        digest = row["evidence_digest"]
        if digest is not None and (
                not isinstance(digest, str) or
                not re.fullmatch(r"[a-f0-9]{64}", digest)):
            raise ValueError("evidence digest invalid")
        score = rank(row)
        if row["disposition"] == "refuted":
            score = 0
        if row["disposition"] == "parked":
            score = min(score, 2)
        # Separate origin keys prevent a single broad textual "auth bypass"
        # category from merging unrelated effects.
        grouping = json.dumps([project, rev, _key(row)], sort_keys=True)
        groups[grouping].append({"id": ident, "score": score,
                                 "disposition": row["disposition"],
                                 "evidence_digest": digest})
        related[(row["source_file"], row["code_anchor"])].append(
            {"id": ident, "invariant": row["invariant_id"],
             "boundary": row["trust_boundary_id"]})
    out = []
    for gkey, rows in sorted(groups.items()):
        ranked = sorted(rows, key=lambda x: (-x["score"], x["id"]))
        out.append({"group_id": hashlib.sha256(gkey.encode()).hexdigest()[:20],
                    "member_ids": [x["id"] for x in ranked],
                    "preferred_review_id": ranked[0]["id"],
                    "top_evidence_score_0_to_10": ranked[0]["score"],
                    "member_count": len(rows),
                    "dedup_status": ("HUMAN_REVIEWED_SAME_ROOT_CAUSE" if
                                     json.loads(gkey)[2][0] == "reviewed"
                                     else "STRICT_STRUCTURAL_MATCH_NOT_VERIFIED"),
                    "confirmed_vulnerabilities": 0})
    review = []
    for (path, anchor), rows in related.items():
        if len(rows) > 1 and len(set((x["invariant"], x["boundary"]) for x in rows)) > 1:
            review.append({"source_file": path, "code_anchor": anchor,
                           "candidate_ids": sorted(x["id"] for x in rows),
                           "reason": "SAME_ANCHOR_DIFFERENT_INVARIANT_MANUAL_REVIEW"})
    out.sort(key=lambda x: (-x["top_evidence_score_0_to_10"], x["group_id"]))
    return {"schema_version": 1, "mode": "web-root-cause-dedup",
            "project": project, "pinned_revision": rev, "candidates": len(entries),
            "groups": out, "review_related": review,
            "network_requests": 0, "confirmed_vulnerabilities": 0,
            "limitations": ("Evidence scores 0..10 are operator-supplied review ordering, "
                            "not exploit likelihood or payout prediction. Structural "
                            "matches may be coincidental; a shared code anchor and "
                            "different invariant is never auto-merged. True duplicate "
                            "status requires independent root-cause review.")}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--input", required=True)
    p.add_argument("--out", required=True)
    a = p.parse_args(argv)
    try:
        result = analyze(_load(a.input))
        _write(a.out, result)
    except (ValueError, OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
        p.error(str(exc))
    print(json.dumps({"out": a.out, "groups": len(result["groups"]),
                      "review_related": len(result["review_related"])}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
