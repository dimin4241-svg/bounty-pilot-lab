#!/usr/bin/env python3
"""Fail-closed, source-bound evidence packet for an owned Web test campaign.

Only joins one prepared campaign lead to an explicit independent operator
review of a repeatable owned-loopback effect with a negative control. Does
not authenticate local files, reviewer identities, program policies, source
deployments, or external production behavior. It never sends a report.
"""
import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path

SHA = re.compile(r"^[a-f0-9]{64}$")
IDENT = re.compile(r"^[A-Za-z0-9_.:-]{1,120}$")
MAX_BYTES = 3_000_000


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
        raise ValueError("bounded local JSON input required")
    return json.loads(p.read_text(encoding="utf-8"), object_pairs_hook=_unique)


def _write(path, obj):
    p = Path(path)
    if p.is_symlink() or p.exists():
        raise ValueError("output path already exists")
    p.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(p), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(obj, stream, indent=2, ensure_ascii=False, sort_keys=True)
        stream.write("\n")


def _checked_digest(value, key):
    if not isinstance(value, str) or not SHA.fullmatch(value):
        raise ValueError(key + " needs independent SHA-256 digest")
    return value


def review(campaign, statement):
    if (not isinstance(campaign, dict) or campaign.get("schema_version") != 1 or
            campaign.get("mode") != "web-hunt-loop" or
            campaign.get("state") != "CONTROLLED_LOCAL_EFFECT_REPLAY_UNVERIFIED" or
            campaign.get("confirmed_vulnerabilities") != 0 or
            campaign.get("ready_to_submit") is not False):
        raise ValueError("campaign must contain controlled owned-lab replay")
    if (not isinstance(statement, dict) or set(statement) != {
            "schema_version", "project", "source_revision", "candidate_id",
            "effect_case_id", "reviewer_id", "reviewer_independent_asserted",
            "authorization_policy_evidence_sha256",
            "source_reachability_evidence_sha256",
            "effect_observation_evidence_sha256",
            "negative_control_evidence_sha256",
            "novelty_review_evidence_sha256",
            "deployed_state_reviewed", "independent_replay_asserted"}):
        raise ValueError("strict independent review statement required")
    if type(statement["schema_version"]) is not int or statement["schema_version"] != 1:
        raise ValueError("review schema version 1 required")
    for key in ("reviewer_independent_asserted", "deployed_state_reviewed",
                "independent_replay_asserted"):
        if type(statement[key]) is not bool:
            raise ValueError("review flags must be explicit booleans")
    if (statement["project"] != campaign["project"] or
            statement["source_revision"] != campaign["source_revision"]):
        raise ValueError("review not bound to project/revision")
    for key in ("candidate_id", "effect_case_id", "reviewer_id"):
        value = statement[key]
        if not isinstance(value, str) or not IDENT.fullmatch(value):
            raise ValueError("invalid review identity")
    if statement["candidate_id"] not in {
            x["candidate_id"] for x in campaign.get("review_jobs", [])}:
        raise ValueError("candidate not in prepared, not-suppressed review queue")
    replay = campaign.get("owned_fixture_replay")
    if not isinstance(replay, dict) or replay.get("execution") != "RESEARCHER_OWNED_LOOPBACK_ONLY":
        raise ValueError("actual controlled fixture replay required")
    oracle = replay.get("oracle_review")
    if not isinstance(oracle, dict) or oracle.get("confirmed_vulnerabilities") != 0:
        raise ValueError("invalid owned-lab effect oracle artifact")
    matching = [x for x in oracle.get("results", [])
                if x.get("case_id") == statement["effect_case_id"]]
    if len(matching) != 1:
        raise ValueError("review effect ID does not match local replay")
    state = matching[0]["status"]
    if state != "CONTROLLED_EFFECT_IN_OPERATOR_SUPPLIED_LAB_DATA":
        raise ValueError("missing repeated candidate effect with stable negative controls")
    digest_fields = (
        "authorization_policy_evidence_sha256",
        "source_reachability_evidence_sha256",
        "effect_observation_evidence_sha256",
        "negative_control_evidence_sha256",
        "novelty_review_evidence_sha256")
    digests = [_checked_digest(statement[k], k) for k in digest_fields]
    if len(set(digests)) != len(digests):
        raise ValueError("independent review artifacts require distinct digests")
    # These digest fields are assertions supplied by the investigator; the
    # tool has not retrieved or authenticated independent source artifacts.
    flags = {
        "reviewer_independent_asserted": statement["reviewer_independent_asserted"],
        "independent_replay_asserted": statement["independent_replay_asserted"],
        "deployed_state_reviewed": statement["deployed_state_reviewed"]}
    complete = all(flags.values())
    return {
        "schema_version": 1, "mode": "web-evidence-packet",
        "status": ("OPERATOR_ATTESTED_LOCAL_REVIEW_NOT_INDEPENDENTLY_VERIFIED"
                   if complete else "INCOMPLETE_INDEPENDENT_REVIEW"),
        "project": campaign["project"], "source_revision": campaign["source_revision"],
        "candidate_id": statement["candidate_id"],
        "effect_case_id": statement["effect_case_id"],
        "reviewer_id": statement["reviewer_id"],
        "repeated_local_effect": True,
        "negative_control_unchanged": True,
        "review_flags": flags,
        "artifact_evidence_digests": dict(zip(digest_fields, digests)),
        "local_campaign_fingerprint": hashlib.sha256(json.dumps(
            campaign, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True).encode("ascii")).hexdigest(),
        "independently_attested_by_this_tool": False,
        "verified_production_vulnerability": False,
        "automatic_report_submission": False,
        "ready_to_submit": False,
        "note": ("Operator-provided hashes and flags are not independently verified. "
                 "Do not submit without manual confirmation of in-scope real target, "
                 "authorization, actual affected deployment, exploit impact and novelty.")
    }


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--campaign", required=True)
    p.add_argument("--review", required=True)
    p.add_argument("--out", required=True)
    a = p.parse_args(argv)
    try:
        report = review(_read(a.campaign), _read(a.review))
        _write(a.out, report)
    except (ValueError, OSError, TypeError, KeyError, json.JSONDecodeError) as exc:
        p.error(str(exc))
    print(json.dumps({"out": a.out, "status": report["status"],
                      "ready_to_submit": False}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
