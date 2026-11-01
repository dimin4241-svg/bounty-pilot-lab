#!/usr/bin/env python3
"""Bounded, offline candidate/control differential checks for observed native traces.

This module does not execute target code, query a chain, verify provenance, or
assert exploit reachability. All observations are supplied by the researcher.
Requires Python 3.9+ and the standard library only.
"""
import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path

MAX_INPUT = 512_000
MAX_CASES = 100
MAX_ID = 96
MAX_REASON = 500
REVISION = re.compile(r"[a-fA-F0-9]{40}")
DIGEST = re.compile(r"[a-fA-F0-9]{64}")
ATOMIC = re.compile(r"0|[1-9][0-9]{0,77}")
ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,95}")
ENVIRONMENTS = {"mock-local", "anvil-local", "native-local"}
STATUS = {"success", "failed", "pending", "unknown"}
OUTCOME_POLICIES = {"all_required", "any_required"}
BOUND_FIELDS = {
    "operation_digest", "recipient", "amount_atomic", "asset", "chain_id",
    "domain", "nonce", "policy_epoch", "account", "delegate", "spender",
    "signer_set", "proof_context", "authorization_id",
}
NEXT_TEST = {
    "settlement": "Reproduce candidate and control on unchanged source. Trace actual asset holdings and obligations after final settlement; prove attacker reachability and who bears the deficit.",
    "outcome": "Execute the real nested/batched operation with an intentionally failing item and a successful control. Trace emitted errors, worker acknowledgements and finalized delivery before asserting an accounting impact.",
    "context": "Record native authorization, verifier input and executed-operation bytes on both paths. Check each policy/domain binding and cache key against a genuine negative control.",
}


def _unique_pairs(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise ValueError("duplicate JSON key")
        out[k] = v
    return out


def _text(value, label, *, max_length=MAX_REASON, pattern=None):
    if not isinstance(value, str) or not value or len(value) > max_length:
        raise ValueError(label + " must be nonempty bounded text")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError(label + " has invalid Unicode") from exc
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError(label + " has control characters")
    if pattern is not None and pattern.fullmatch(value) is None:
        raise ValueError(label + " has invalid format")
    return value


def _dictionary(obj, label):
    if not isinstance(obj, dict):
        raise ValueError(label + " must be an object")
    return obj


def _atomic(obj, label):
    # A JSON float or bool cannot silently become an accounting amount.
    value = _text(obj, label, max_length=78, pattern=ATOMIC)
    return int(value)


def _required(obj, keys, label):
    unknown = set(obj) - set(keys)
    if unknown:
        raise ValueError(label + " contains unsupported keys: " + ", ".join(sorted(unknown)))


def _sha(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, ensure_ascii=True,
                                     separators=(",", ":")).encode("ascii")).hexdigest()


def load_input(path):
    src = Path(path).expanduser()
    if src.is_symlink() or not src.is_file() or src.stat().st_size > MAX_INPUT:
        raise ValueError("input must be a regular non-symlink JSON under 512kB")
    try:
        return json.loads(src.read_text(encoding="utf-8"), object_pairs_hook=_unique_pairs,
                          parse_constant=lambda x: (_ for _ in ()).throw(ValueError("non-finite JSON: " + x)))
    except (UnicodeError, RecursionError) as exc:
        raise ValueError("invalid Unicode or excessive JSON nesting") from exc


def _settlement(side, label):
    _required(side, ("before", "after", "finality", "trace_sha256"), label)
    _text(side.get("trace_sha256"), label + ".trace_sha256", max_length=64, pattern=DIGEST)
    finality = side.get("finality")
    if finality not in ("finalized", "pending", "unknown"):
        raise ValueError(label + ".finality must be finalized, pending or unknown")
    levels = {}
    for stage in ("before", "after"):
        raw = _dictionary(side.get(stage), label + "." + stage)
        _required(raw, ("held_atomic", "owed_atomic"), label + "." + stage)
        levels[stage] = (_atomic(raw.get("held_atomic"), label + "." + stage + ".held_atomic"),
                         _atomic(raw.get("owed_atomic"), label + "." + stage + ".owed_atomic"))
    before, after = levels["before"], levels["after"]
    introduced = before[0] >= before[1] and after[0] < after[1]
    return introduced, {"before_deficit_atomic": str(max(0, before[1] - before[0])),
                        "after_deficit_atomic": str(max(0, after[1] - after[0]))}, finality == "finalized"


def _outcome(side, label):
    _required(side, ("outer_status", "recorded_status", "item_statuses",
                     "success_policy", "finality", "trace_sha256"), label)
    _text(side.get("trace_sha256"), label + ".trace_sha256", max_length=64, pattern=DIGEST)
    policy = side.get("success_policy")
    if policy not in OUTCOME_POLICIES:
        raise ValueError(label + ".success_policy unsupported")
    outer, recorded, finality = (side.get(k) for k in ("outer_status", "recorded_status", "finality"))
    if outer not in STATUS or recorded not in STATUS:
        raise ValueError(label + " statuses must be success/failed/pending/unknown")
    if finality not in ("finalized", "pending", "unknown"):
        raise ValueError(label + ".finality unsupported")
    items = side.get("item_statuses")
    if not isinstance(items, list) or not 1 <= len(items) <= 100 or any(x not in STATUS for x in items):
        raise ValueError(label + ".item_statuses must contain 1..100 known status strings")
    resolved = (finality == "finalized" and outer in ("success", "failed")
                and recorded in ("success", "failed")
                and all(x in ("success", "failed") for x in items))
    if not resolved:
        return False, {"items": len(items), "failed_items": items.count("failed")}, False
    should_fail = (outer == "failed" or
                   (policy == "all_required" and "failed" in items) or
                   (policy == "any_required" and "success" not in items))
    return should_fail and recorded == "success", {
        "items": len(items), "failed_items": items.count("failed"),
        "outer_status": outer, "recorded_status": recorded, "policy": policy,
    }, True


def _context(side, label, fields):
    _required(side, ("authorized", "verified", "executed", "cache_entries", "trace_sha256"), label)
    _text(side.get("trace_sha256"), label + ".trace_sha256", max_length=64, pattern=DIGEST)
    stages = {}
    complete = True
    for stage in ("authorized", "verified", "executed"):
        item = _dictionary(side.get(stage), label + "." + stage)
        _required(item, BOUND_FIELDS, label + "." + stage)
        # No implicit defaults: missing fields cannot be treated as equal.
        for k, v in item.items():
            _text(v, label + "." + stage + "." + k, max_length=200)
        stages[stage] = item
        complete = complete and all(f in item for f in fields)
    if not complete:
        return False, {"missing_bindings": True, "different_fields": []}, False
    differences = sorted({f for f in fields if
                          stages["authorized"][f] != stages["verified"][f] or
                          stages["verified"][f] != stages["executed"][f]})
    entries = side.get("cache_entries", [])
    if not isinstance(entries, list) or len(entries) > 100:
        raise ValueError(label + ".cache_entries must be a bounded list")
    keys = {}
    cache_collision = False
    for i, entry in enumerate(entries):
        ent = _dictionary(entry, label + ".cache_entries[" + str(i) + "]")
        _required(ent, ("key", "verified_context_digest"), label + ".cache_entries")
        key = _text(ent.get("key"), label + ".cache.key", max_length=200)
        context = _text(ent.get("verified_context_digest"), label + ".cache.context", max_length=200)
        if key in keys and keys[key] != context:
            cache_collision = True
        keys[key] = context
    return bool(differences or cache_collision), {
        "missing_bindings": False, "different_fields": differences,
        "cache_collision": cache_collision, "cache_entries": len(entries),
    }, True


def analyze(data, operation):
    if operation not in ("settlement", "outcome", "context"):
        raise ValueError("operation must be settlement, outcome or context")
    doc = _dictionary(data, "input")
    _required(doc, ("schema_version", "source_revision", "environment", "cases"), "input")
    if type(doc.get("schema_version")) is not int or doc["schema_version"] != 1:
        raise ValueError("schema_version must be integer 1")
    revision = _text(doc.get("source_revision"), "source_revision", max_length=40, pattern=REVISION).lower()
    if doc.get("environment") not in ENVIRONMENTS:
        raise ValueError("environment must name a local mock or native runner")
    cases = doc.get("cases")
    if not isinstance(cases, list) or not 1 <= len(cases) <= MAX_CASES:
        raise ValueError("cases must contain 1..100 pairs")
    seen, records = set(), []
    for case in cases:
        obj = _dictionary(case, "case")
        allowed = ("id", "invariant", "equivalence_basis", "candidate", "negative_control",
                   "asset", "bound_fields")
        _required(obj, allowed, "case")
        ident = _text(obj.get("id"), "case.id", max_length=MAX_ID, pattern=ID)
        if ident in seen:
            raise ValueError("duplicate case ID")
        seen.add(ident)
        _text(obj.get("invariant"), ident + ".invariant")
        _text(obj.get("equivalence_basis"), ident + ".equivalence_basis")
        a = _dictionary(obj.get("candidate"), ident + ".candidate")
        b = _dictionary(obj.get("negative_control"), ident + ".negative_control")
        if a == b:
            raise ValueError(ident + ": candidate and control observations are identical")
        fields = None
        if operation == "settlement":
            _text(obj.get("asset"), ident + ".asset", max_length=90)
            if "bound_fields" in obj:
                raise ValueError("bound_fields applies only to context")
            a_bad, a_metrics, a_ready = _settlement(a, ident + ".candidate")
            b_bad, b_metrics, b_ready = _settlement(b, ident + ".negative_control")
        elif operation == "outcome":
            if "asset" in obj or "bound_fields" in obj:
                raise ValueError("asset/bound_fields are not outcome fields")
            a_bad, a_metrics, a_ready = _outcome(a, ident + ".candidate")
            b_bad, b_metrics, b_ready = _outcome(b, ident + ".negative_control")
            if a.get("success_policy") != b.get("success_policy"):
                # Different completion rules are not a valid negative control.
                a_ready = b_ready = False
        else:
            if "asset" in obj:
                raise ValueError("asset applies only to settlement")
            fields = obj.get("bound_fields")
            if not isinstance(fields, list) or not 1 <= len(fields) <= len(BOUND_FIELDS):
                raise ValueError("bound_fields must be a nonempty bounded list")
            if any(not isinstance(f, str) or f not in BOUND_FIELDS for f in fields) or len(set(fields)) != len(fields):
                raise ValueError("bound_fields contain unsupported or repeated field names")
            a_bad, a_metrics, a_ready = _context(a, ident + ".candidate", fields)
            b_bad, b_metrics, b_ready = _context(b, ident + ".negative_control", fields)
        if not a_ready or not b_ready:
            decision = "INCONCLUSIVE"
        elif b_bad:
            decision = "CONTROL_ALSO_VIOLATES"
        elif a_bad:
            decision = "DIFFERENTIAL_LEAD"
        else:
            decision = "NO_DIFFERENTIAL"
        signals = []
        if decision == "DIFFERENTIAL_LEAD":
            signals = {
                "settlement": ["UNBACKED_FINALIZED_LIABILITY"],
                "outcome": ["RECORDED_SUCCESS_CONTRADICTS_INNER_OUTCOME"],
                "context": (["AUTHORIZED_VERIFIED_EXECUTED_MISMATCH"] if a_metrics["different_fields"] else [])
                           + (["VERIFICATION_CACHE_CONTEXT_COLLISION"] if a_metrics["cache_collision"] else []),
            }[operation]
        records.append({
            "id": ident, "decision": decision, "signals": signals,
            "candidate_observation": a_metrics, "control_observation": b_metrics,
            "evidence_digests_supplied_not_verified": {
                "candidate": a["trace_sha256"], "negative_control": b["trace_sha256"]
            }, "next_experiment": NEXT_TEST[operation] if decision == "DIFFERENTIAL_LEAD" else None,
        })
    return {
        "schema_version": 1, "engine": "reality-diff", "operation": operation,
        "source_revision_supplied_not_verified": revision,
        "environment_supplied_not_verified": doc["environment"],
        "input_sha256": _sha(doc),
        "classification": "INVESTIGATOR_SUPPLIED_OBSERVATIONS",
        "confirmed_vulnerabilities": 0,
        "leads": sum(r["decision"] == "DIFFERENTIAL_LEAD" for r in records),
        "cases": records,
        "notice": "This tool compares provided local observations, not source reachability, "
                  "real PoC execution, trace authenticity, severity, ownership or payout. "
                  "An independent reviewer must verify the native tests and negative controls.",
    }


def _write_private(path, result):
    dst = Path(path).expanduser()
    if dst.is_symlink():
        raise ValueError("output must not be a symlink")
    payload = (json.dumps(result, indent=2, ensure_ascii=True) + "\n").encode("utf-8")
    fd = os.open(str(dst), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(payload)
    except BaseException:
        try:
            dst.unlink()
        except OSError:
            pass
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("settlement", "outcome", "context"))
    parser.add_argument("--input", required=True, help="local paired observations JSON, no network")
    parser.add_argument("--out", help="new private JSON file (never overwrite)")
    args = parser.parse_args(argv)
    try:
        output = analyze(load_input(args.input), args.operation)
        if args.out:
            _write_private(args.out, output)
            print(json.dumps({"file": args.out, "leads": output["leads"],
                              "result": "RESEARCH_LEADS_ONLY"}))
        else:
            print(json.dumps(output, indent=2))
        return 0
    except (OSError, ValueError, TypeError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    sys.exit(main())
