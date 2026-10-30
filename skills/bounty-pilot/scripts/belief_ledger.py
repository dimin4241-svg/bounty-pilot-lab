#!/usr/bin/env python3
"""Private, revision-bound memory of hypotheses and their evidence.

No raw vulnerability descriptions, secrets or target URLs are stored; each
lookup is advisory and NEVER automatically rejects or verifies a finding.
"""
import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    import fcntl
except ImportError:
    fcntl = None

HEX = re.compile(r"^[a-fA-F0-9]{64}$")
REV = re.compile(r"^[a-fA-F0-9]{40,64}$")
STATUSES = {"open", "blocked", "refuted", "reproduced"}
PROOFS = {"native-pair", "source-guard", "native-replay", "environment-blocker"}
MAX_LINES = 5000
MAX_BYTES = 3_000_000


def _value(v, field):
    if not isinstance(v, str) or not 1 <= len(v) <= 300:
        raise ValueError(field + " must be short text")
    if any(ord(ch) < 32 for ch in v):
        raise ValueError(field + " contains controls")
    v.encode("utf-8")
    return v


def _digest(value, field):
    return hashlib.sha256(_value(value, field).encode("utf-8")).hexdigest()


def _validate(row):
    if not isinstance(row, dict):
        raise ValueError("observation must be an object")
    target, mechanism = _digest(row.get("target"), "target"), _digest(
        row.get("mechanism"), "mechanism")
    rev = row.get("revision")
    if not isinstance(rev, str) or not REV.fullmatch(rev):
        raise ValueError("revision must be a pinned 40..64 hex commit")
    state = row.get("status")
    if state not in STATUSES:
        raise ValueError("invalid hypothesis status")
    proof = row.get("evidence_kind")
    artifact = row.get("artifact_sha256")
    if proof is not None and proof not in PROOFS:
        raise ValueError("invalid evidence kind")
    if artifact is not None and (not isinstance(artifact, str) or not HEX.fullmatch(artifact)):
        raise ValueError("artifact_sha256 must be a 64-character hex digest")
    if state in {"refuted", "reproduced"}:
        if proof not in {"native-pair", "source-guard", "native-replay"} or not artifact:
            raise ValueError("refuted/reproduced state requires a reviewable evidence kind and artifact hash")
    if state == "blocked" and (proof != "environment-blocker" or not artifact):
        raise ValueError("blocked requires an environment-blocker evidence artifact")
    return {"schema_version": 1, "target_sha256": target,
            "mechanism_sha256": mechanism, "revision": rev.lower(),
            "status": state, "evidence_kind": proof, "artifact_sha256": artifact,
            "recorded_at": datetime.now(timezone.utc).isoformat()}


def _open(path):
    p = Path(path).expanduser()
    if p.is_symlink() or (p.exists() and not p.is_file()):
        raise ValueError("ledger must be a regular, non-symlink file")
    if p.exists() and p.stat().st_size > MAX_BYTES:
        raise ValueError("ledger size cap exceeded")
    p.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(str(p), flags, 0o600)
    os.chmod(str(p), 0o600)
    return os.fdopen(fd, "r+", encoding="utf-8")


def _read_locked(fh):
    fh.seek(0)
    raw = fh.read(MAX_BYTES + 1)
    if len(raw.encode("utf-8")) > MAX_BYTES:
        raise ValueError("ledger exceeds byte cap")
    lines = raw.splitlines()
    if len(lines) > MAX_LINES:
        raise ValueError("ledger exceeds entry cap")
    records = []
    for line in lines:
        if not line.strip():
            raise ValueError("ledger contains an empty record")
        row = json.loads(line)
        if (not isinstance(row, dict) or row.get("schema_version") != 1
                or not HEX.fullmatch(str(row.get("target_sha256", "")))
                or not HEX.fullmatch(str(row.get("mechanism_sha256", "")))):
            raise ValueError("invalid ledger record")
        records.append(row)
    return records


def _lock(fh, exclusive):
    if fcntl is not None:
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)


def record(data, path):
    clean = _validate(data)
    with _open(path) as fh:
        _lock(fh, True)
        old = _read_locked(fh)
        if len(old) >= MAX_LINES:
            raise ValueError("ledger at entry cap")
        fh.seek(0, 2)
        fh.write(json.dumps(clean, sort_keys=True) + "\n")
        fh.flush()
        os.fsync(fh.fileno())
    return {"status": "recorded", "revision": clean["revision"],
            "evidence_kind": clean["evidence_kind"],
            "notice": "A recorded state is supplied by the reviewer, not verified by this ledger."}


def lookup(target, mechanism, revision, path):
    if not isinstance(revision, str) or not REV.fullmatch(revision):
        raise ValueError("revision must be a pinned commit")
    tgt, mech = _digest(target, "target"), _digest(mechanism, "mechanism")
    if not Path(path).exists():
        return {"match": None, "history_count": 0, "recommendation": "INVESTIGATE"}
    with _open(path) as fh:
        _lock(fh, False)
        entries = _read_locked(fh)
    history = [v for v in entries if v["target_sha256"] == tgt and
               v["mechanism_sha256"] == mech]
    same = [v for v in history if v["revision"] == revision.lower()]
    last = same[-1] if same else None
    return {"match": {"status": last["status"], "evidence_kind": last["evidence_kind"],
                      "artifact_sha256": last["artifact_sha256"]}
            if last else None,
            "history_count": len(history),
            "stale_other_revisions": len(history) - len(same),
            "recommendation": ("REVIEW_PRIOR_EVIDENCE" if last else "INVESTIGATE"),
            "notice": "Never suppress on a prior refutation automatically. Confirm original "
                      "evidence, actual code hash, attack path and changed dependencies."}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    subs = ap.add_subparsers(dest="command", required=True)
    r = subs.add_parser("record")
    r.add_argument("--input", required=True)
    r.add_argument("--ledger", required=True)
    q = subs.add_parser("lookup")
    q.add_argument("--ledger", required=True)
    q.add_argument("--target", required=True)
    q.add_argument("--mechanism", required=True)
    q.add_argument("--revision", required=True)
    args = ap.parse_args(argv)
    try:
        if args.command == "record":
            inp = Path(args.input)
            if inp.is_symlink() or not inp.is_file() or inp.stat().st_size > 4096:
                raise ValueError("record input must be regular and under 4kB")
            result = record(json.loads(inp.read_text(encoding="utf-8")), args.ledger)
        else:
            result = lookup(args.target, args.mechanism, args.revision, args.ledger)
        print(json.dumps(result, indent=2))
        return 0
    except (OSError, ValueError, UnicodeError) as exc:
        print("Error: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
