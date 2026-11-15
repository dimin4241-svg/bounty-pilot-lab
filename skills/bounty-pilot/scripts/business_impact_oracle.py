#!/usr/bin/env python3
"""Offline, cross-domain protected-state candidate/control evidence preflight.

Checks integrity of local operator-supplied receipts. It never executes target
code and cannot independently attest to the honesty of the supplied receipts.
"""
import argparse
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path

SHA = re.compile(r"[0-9a-f]{64}\Z")
ID = re.compile(r"[A-Za-z0-9_.:-]{1,100}\Z")
DOMAINS = {"web", "api", "android", "ios", "electron", "web3"}
MAX_JSON = 1024 * 1024
MAX_RECEIPT = 2 * 1024 * 1024


def _pairs(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError("duplicate JSON field")
        obj[key] = value
    return obj


def _json(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_JSON:
        raise ValueError("input must be small regular JSON")
    return json.loads(path.read_text("utf-8"), object_pairs_hook=_pairs)


def _artifact(root, item):
    rel = item.get("receipt_file")
    digest = item.get("receipt_sha256")
    if (not isinstance(rel, str) or not rel or Path(rel).is_absolute()
            or any(part in ("", ".", "..") for part in Path(rel).parts)
            or not isinstance(digest, str) or not SHA.fullmatch(digest)):
        raise ValueError("witness requires a safe relative file and SHA-256")
    path = root / rel
    if path.is_symlink() or any(p.is_symlink() for p in path.parents if p != root):
        raise ValueError("witness symlinks are refused")
    real = path.resolve(strict=True)
    if root not in real.parents or not real.is_file() or real.stat().st_size > MAX_RECEIPT:
        raise ValueError("witness must be a bounded regular file within receipt root")
    h = hashlib.sha256()
    fd = os.open(str(real), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("witness is not regular")
        while True:
            chunk = stream.read(65536)
            if not chunk:
                break
            h.update(chunk)
    if h.hexdigest() != digest:
        raise ValueError("witness SHA-256 mismatch")
    return digest


def analyze(case, receipt_root):
    if not isinstance(case, dict) or case.get("schema_version") != 1:
        raise ValueError("unsupported evidence case")
    if case.get("domain") not in DOMAINS:
        raise ValueError("unknown domain")
    if not isinstance(case.get("scenario_id"), str) or not ID.fullmatch(case["scenario_id"]):
        raise ValueError("scenario_id must be opaque")
    scope = case.get("scope")
    if not isinstance(scope, dict) or type(scope.get("operator_confirmed")) is not bool:
        raise ValueError("explicit operator scope assertion required")
    if not isinstance(scope.get("policy_reference"), str) or not scope["policy_reference"]:
        raise ValueError("policy_reference required")
    policy = case.get("expected_policy")
    if (not isinstance(policy, dict)
            or type(policy.get("candidate_effect_permitted")) is not bool):
        raise ValueError("explicit expected action policy required")
    root = Path(receipt_root).expanduser().absolute()
    if not root.is_dir() or root.is_symlink():
        raise ValueError("receipt root must be a non-symlink directory")
    root = root.resolve(strict=True)
    observations = {}
    for label in ("candidate", "control"):
        row = case.get(label)
        if not isinstance(row, dict):
            raise ValueError("candidate and control required")
        for field in ("actor_id", "before_sha256", "after_sha256"):
            if field == "actor_id":
                valid = isinstance(row.get(field), str) and ID.fullmatch(row[field])
            else:
                valid = isinstance(row.get(field), str) and SHA.fullmatch(row[field])
            if not valid:
                raise ValueError(label + " missing " + field)
        observations[label] = {
            "actor_id": row["actor_id"],
            "before_sha256": row["before_sha256"],
            "after_sha256": row["after_sha256"],
            "receipt_sha256": _artifact(root, row),
            "changed": row["before_sha256"] != row["after_sha256"],
        }
    c, n = observations["candidate"], observations["control"]
    same_start = c["before_sha256"] == n["before_sha256"]
    differential = same_start and c["changed"] and not n["changed"]
    if not scope["operator_confirmed"]:
        state = "UNCONFIRMED_SCOPE_NO_TEST_AUTHORITY"
    elif not same_start:
        state = "INCOMPARABLE_INITIAL_STATE"
    elif not differential:
        state = "NO_UNIQUE_PROTECTED_STATE_CHANGE"
    elif policy["candidate_effect_permitted"]:
        state = "DIFFERENTIAL_BUT_ALLOWED_BY_STATED_POLICY"
    else:
        state = "DIFFERENTIAL_UNAUTHORIZED_BY_STATED_POLICY_REVIEW_REQUIRED"
    return {
        "schema_version": 1, "engine": "business-impact-oracle",
        "scenario_id": case["scenario_id"], "domain": case["domain"],
        "status": state, "scope_operator_asserted": scope["operator_confirmed"],
        "receipts_hash_checked": True,
        "initial_states_comparable": same_start,
        "candidate_changed": c["changed"],
        "control_changed": n["changed"],
        "candidate_control_differential": differential,
        "expected_policy_operator_supplied": True,
        "receipt_hashes": {k: v["receipt_sha256"] for k, v in observations.items()},
        "impact_verified": False, "runtime_executed_by_engine": False,
        "independent_attestation": False,
        "missing_evidence": [
            "real caller privilege and scope independently checked",
            "receipt content independently authenticated",
            "repeatability and causal attribution",
            "protected nature of state and actual harm",
        ],
    }


def _write_new(path, report):
    p = Path(path).expanduser().absolute()
    if p.is_symlink() or p.exists() or not p.parent.is_dir() or p.parent.is_symlink():
        raise ValueError("output must be a new file in existing directory")
    fd = os.open(str(p), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(report, stream, sort_keys=True, indent=2)
        stream.write("\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", required=True)
    parser.add_argument("--receipts", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    try:
        report = analyze(_json(args.case), args.receipts)
        _write_new(args.out, report)
        print(json.dumps({"status": report["status"], "impact_verified": False}))
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print("Error: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
