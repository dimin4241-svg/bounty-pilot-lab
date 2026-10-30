#!/usr/bin/env python3
"""Passive, evidence-bounded semantic identity and cross-phase research.

No target code is executed. Source scans are lexical leads. Observation comparisons
use investigator-supplied expected equivalence; they are never exploit proofs.
Python 3.9+ and stdlib only.
"""
import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

MAX_OBSERVATIONS = 1000
MAX_SOURCE_FILES = 4000
MAX_SOURCE_BYTES = 128 * 1024
MAX_FINDINGS = 200
SOURCE_EXTENSIONS = {".sol", ".vy", ".rs", ".go", ".py", ".ts", ".tsx",
                     ".js", ".jsx", ".cpp", ".cc", ".c", ".h", ".hpp", ".move"}
EXCLUDE_PARTS = {"vendor", "node_modules", "dist", "build", "target",
                 "__pycache__", "test", "tests", "fixtures", "examples"}
GIT_OPTS = ("--no-optional-locks", "-c", "core.fsmonitor=false", "-c",
            "core.hooksPath=/dev/null", "-c", "core.pager=cat")
PATTERNS = (
    ("packed_dynamic", re.compile(r"\babi\.encodePacked\s*\("),
     "Compare tuple identity with packed ABI encoding; multiple dynamic arguments may be ambiguous."),
    ("cache_context", re.compile(r"(?i)\b(?:cache_key|cachekey|proof_cache|cache_hash|cachehash)\b"),
     "Check that cache identity includes all verification context and unambiguous framing."),
    ("signature_quorum", re.compile(r"(?i)\b(?:signer_count|signatures\.length|quorum|threshold)\b"),
     "Review whether quorum counts unique authenticated signers rather than signatures."),
    ("phase_boundary", re.compile(r"(?i)\b(?:mempool|txpool|validate_block|sign_transaction|signTransaction|execute_job|withdrawal_worker)\b"),
     "Compare the admission policy, authorized payload, and execution decision."),
)


def _text(value, name, limit=500):
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise ValueError(name + " must be nonempty short text")
    if any(ord(c) < 32 for c in value):
        raise ValueError(name + " contains control characters")
    return value


def _json(path):
    p = Path(path)
    if p.is_symlink() or not p.is_file() or p.stat().st_size > 2_000_000:
        raise ValueError("input must be a regular non-symlink JSON file under 2 MB")
    return json.loads(p.read_text(encoding="utf-8"))


def _report(mode, items, notes=()):
    return {"schema_version": 1, "mode": mode, "classification": "RESEARCH_LEADS",
            "findings": items[:MAX_FINDINGS], "candidate_count": len(items),
            "truncated": len(items) > MAX_FINDINGS, "notes": list(notes),
            "confirmed_vulnerabilities": 0,
            "notice": "Source and supplied observations are clues, not native PoCs, "
                      "authorization proof, exploitable reachability, or severity."}


def identity(data):
    """Compare supplied *semantic identities* against actual representation identifiers.

    'same' and 'different' are user-supplied assumptions, not our conclusions.
    """
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise ValueError("identity input needs schema_version 1")
    pairs = data.get("pairs")
    if not isinstance(pairs, list) or len(pairs) > MAX_OBSERVATIONS:
        raise ValueError("pairs must be a bounded list")
    output = []
    for pos, p in enumerate(pairs):
        if not isinstance(p, dict):
            raise ValueError("pair must be an object")
        label = _text(p.get("id"), "id", 100)
        relation = p.get("expected_semantic_relation")
        if relation not in ("same", "different"):
            raise ValueError("expected_semantic_relation must be same or different")
        a, b = p.get("left"), p.get("right")
        if not isinstance(a, dict) or not isinstance(b, dict):
            raise ValueError("left and right must be objects")
        left = _text(a.get("identity_key"), "left.identity_key")
        right = _text(b.get("identity_key"), "right.identity_key")
        basis = p.get("equivalence_basis")
        if not isinstance(basis, str):
            raise ValueError("equivalence_basis must be a string, may be empty")
        if len(basis) > 500:
            raise ValueError("equivalence_basis too long")
        collision = relation == "different" and left == right
        split = relation == "same" and left != right
        if collision or split:
            output.append({
                "id": label, "index": pos,
                "signal": "DISTINCT_CONTEXT_SHARED_KEY" if collision else "SAME_ACTION_DISTINCT_KEY",
                "identity_keys": [left, right],
                "expected_semantic_relation": relation,
                "equivalence_basis": basis,
                "basis_status": "PROVIDED" if basis.strip() else "MISSING",
                "classification": "NEEDS_EVIDENCE",
                "next_experiment": "Verify the stated equivalence independently using native "
                                   "decoders/verifiers on an owned local fixture; compare "
                                   "candidate against a normal negative control.",
                "falsifier": "The two inputs are not semantically equivalent, the cache/replay "
                             "key is intentionally scoped, or authorization is independently checked.",
            })
    return _report("semantic-identity", output,
                   ["A shared key or distinct representation is not automatically unsafe. "
                    "Digest algorithms and binary encodings are not emulated."])


def phases(data):
    """Find contradictory stage decisions only within a declared comparable policy."""
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise ValueError("phase input needs schema_version 1")
    cases = data.get("cases")
    if not isinstance(cases, list) or len(cases) > MAX_OBSERVATIONS:
        raise ValueError("cases must be a bounded list")
    signals = []
    for idx, case in enumerate(cases):
        if not isinstance(case, dict):
            raise ValueError("case must be an object")
        ident = _text(case.get("id"), "case.id", 100)
        basis = case.get("equivalence_basis", "")
        if not isinstance(basis, str) or len(basis) > 500:
            raise ValueError("equivalence_basis must be short text or empty")
        comparable = case.get("same_policy_expected") is True and bool(basis.strip())
        stages = case.get("stages")
        if not isinstance(stages, list) or not 2 <= len(stages) <= 20:
            raise ValueError("stages must contain 2..20 objects")
        names, normalized = set(), []
        for step in stages:
            if not isinstance(step, dict):
                raise ValueError("stage must be an object")
            name = _text(step.get("name"), "stage.name", 100)
            if name in names:
                raise ValueError("stage name repeated")
            names.add(name)
            decision = step.get("decision")
            if decision not in ("allow", "deny", "unknown"):
                raise ValueError("decision must be allow, deny, or unknown")
            payload = step.get("payload_digest")
            if payload is not None:
                _text(payload, "payload_digest", 150)
            policy = step.get("policy_id")
            if policy is not None:
                _text(policy, "policy_id", 150)
            normalized.append({"name": name, "decision": decision,
                               "payload_digest": payload, "policy_id": policy})
        known = {s["decision"] for s in normalized if s["decision"] != "unknown"}
        digests = {s["payload_digest"] for s in normalized if s["payload_digest"] is not None}
        policies = {s["policy_id"] for s in normalized if s["policy_id"] is not None}
        types = []
        if len(known) > 1:
            types.append("DECISION_DIVERGENCE")
        if len(digests) > 1:
            types.append("PAYLOAD_DRIFT")
        if len(policies) > 1:
            types.append("POLICY_VERSION_DRIFT")
        if types:
            signals.append({
                "id": ident, "index": idx, "signals": types,
                "comparable": comparable, "stages": normalized,
                "equivalence_basis": basis, "classification": "NEEDS_EVIDENCE",
                "next_experiment": "Pin the same request, policy epoch and authorized input; "
                                   "run each native stage locally with a paired normal control.",
                "falsifier": "Distinct policy versions, mutable request context, or intentionally "
                             "different admission/execution requirements explain the difference.",
            })
    return _report("cross-phase", signals,
                   ["Comparability requires same_policy_expected=true plus a written basis. "
                    "Even comparable divergences are hypotheses until native reproduction."])


def source_scan(repo):
    """Tracked local source only, with symlink/size/extension bounds and safe git config."""
    root = Path(repo).resolve()
    if not (root / ".git").exists():
        raise ValueError("scan requires a local git checkout")
    p = subprocess.run(["git", *GIT_OPTS, "-C", str(root), "ls-files", "-z"],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       timeout=25, check=True, env=dict(os.environ, GIT_TERMINAL_PROMPT="0"))
    names = sorted(x for x in p.stdout.decode("utf-8", "replace").split("\0") if x)
    found = []
    skipped = {"non_source": 0, "oversized": 0, "unreadable": 0}
    scanned = 0
    for name in names[:MAX_SOURCE_FILES]:
        path = Path(name)
        if path.suffix.lower() not in SOURCE_EXTENSIONS or EXCLUDE_PARTS.intersection(path.parts):
            skipped["non_source"] += 1
            continue
        target = root / path
        try:
            if target.is_symlink() or not target.resolve().is_relative_to(root):
                skipped["unreadable"] += 1
                continue
            if not target.is_file() or target.stat().st_size > MAX_SOURCE_BYTES:
                skipped["oversized"] += 1
                continue
            lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            skipped["unreadable"] += 1
            continue
        scanned += 1
        for number, line in enumerate(lines, 1):
            for kind, pattern, question in PATTERNS:
                if pattern.search(line):
                    found.append({"signal": kind, "path": name, "line": number,
                                  "classification": "LEXICAL_LEAD",
                                  "review_question": question,
                                  "next_experiment": "Trace actual data dependencies and native "
                                                     "caller/validation behavior with a control."})
                    if len(found) >= MAX_FINDINGS:
                        return dict(_report("source-scan", found,
                                           ["Scan capped at 200 lexical signals."]),
                                    scanned_files=scanned, skipped=skipped,
                                    files_over_cap=max(0, len(names) - MAX_SOURCE_FILES))
    return dict(_report("source-scan", found),
                scanned_files=scanned, skipped=skipped,
                files_over_cap=max(0, len(names) - MAX_SOURCE_FILES))


def main(argv=None):
    cli = argparse.ArgumentParser(description=__doc__)
    subs = cli.add_subparsers(dest="command", required=True)
    for action in ("identity", "phases"):
        sub = subs.add_parser(action)
        sub.add_argument("--input", required=True)
    scan = subs.add_parser("scan")
    scan.add_argument("--repo", required=True)
    args = cli.parse_args(argv)
    try:
        if args.command == "identity":
            result = identity(_json(args.input))
        elif args.command == "phases":
            result = phases(_json(args.input))
        else:
            result = source_scan(args.repo)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0
    except (ValueError, OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        print("Error: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
