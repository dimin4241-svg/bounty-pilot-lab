#!/usr/bin/env python3
"""Offline Web/API account and payment business-integrity research.

This tool never contacts targets or processes real credentials or payments.
Input observations are researcher-supplied and NOT authenticated native evidence.
The demo executes only its own disposable SQLite application, never a target.
"""
import argparse
import importlib.util
import json
import os
import re
import sys
from pathlib import Path

HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
SAFE_ID = re.compile(r"^[a-zA-Z0-9_.:-]{1,90}$")
MAX_CASES = 60
MAX_EVENTS = 120

RULES = {
    "account-owner": ("identity", "ACCOUNT_OWNER_VIOLATION",
                      "Unauthorized actor changed another account's credentials"),
    "mfa-gate": ("identity", "MFA_NOT_ENFORCED",
                 "Protected account change happened without required MFA"),
    "session-revocation": ("identity", "REVOKED_SESSION_ACCEPTED",
                            "A revoked session changed protected account state"),
    "reset-one-use": ("identity", "RESET_TOKEN_REPLAY",
                       "An already-consumed reset token changed credentials"),
    "oauth-binding": ("identity", "OAUTH_IDENTITY_MISMATCH",
                       "An unbound OAuth identity created a session"),
    "email-verification": ("identity", "UNVERIFIED_EMAIL_CHANGE",
                            "Account email changed without required verification"),
    "unpaid-credit": ("payment", "CREDIT_WITHOUT_SETTLEMENT",
                      "Balance increased although payment was explicitly unconfirmed"),
    "event-replay": ("payment", "DUPLICATE_PAYMENT_CREDIT",
                     "Repeated payment event credited an account twice"),
    "webhook-binding": ("payment", "PAYMENT_EVENT_UNBOUND",
                        "Balance credited despite invalid provider/order/amount/currency binding"),
    "refund-replay": ("payment", "DUPLICATE_REFUND_EFFECT",
                      "Repeated refund event produced another refund"),
    "subscription-entitlement": ("payment", "UNPAID_ENTITLEMENT",
                                 "Paid entitlement activated without payment or allowed grant"),
    "cancellation-stale": ("payment", "STALE_ENTITLEMENT_AFTER_CANCEL",
                            "Paid entitlement retained after cancellation without allowed grace"),
    "cross-tenant-credit": ("payment", "CROSS_TENANT_CREDIT",
                            "Unauthorized cross-tenant actor credited another balance"),
}
SENSITIVE = {"sensitive_account_update", "email_change", "password_reset"}


def _nonneg_int(obj, key):
    value = obj.get(key)
    return value if type(value) is int and value >= 0 else None


def _increase(event, field):
    before, after = event.get("before"), event.get("after")
    if not isinstance(before, dict) or not isinstance(after, dict):
        return None
    a, b = _nonneg_int(before, field), _nonneg_int(after, field)
    return b > a if a is not None and b is not None else None


def _flag(event, key):
    f = event.get("facts")
    value = f.get(key) if isinstance(f, dict) else None
    return value if type(value) is bool else None


def _event_kind(event):
    return event.get("kind") if isinstance(event, dict) else None


def _matching(event, rule, seen):
    kind = _event_kind(event)
    if kind not in {"sensitive_account_update", "email_change", "password_reset",
                    "oauth_login", "credit", "refund", "subscription_activated",
                    "subscription_cancelled"}:
        return False
    if rule == "account-owner":
        return (kind in SENSITIVE and _increase(event, "credential_version") is True
                and event.get("actor") != event.get("subject")
                and isinstance(event.get("actor"), str)
                and isinstance(event.get("subject"), str)
                and _flag(event, "actor_authorized") is False)
    if rule == "mfa-gate":
        return (kind in SENSITIVE and _increase(event, "credential_version") is True
                and _flag(event, "mfa_required") is True
                and _flag(event, "mfa_verified") is False)
    if rule == "session-revocation":
        return (kind in SENSITIVE and _increase(event, "credential_version") is True
                and _flag(event, "session_active") is False)
    if rule == "reset-one-use":
        return (kind == "password_reset" and
                _increase(event, "credential_version") is True and
                _flag(event, "reset_token_previously_used") is True)
    if rule == "oauth-binding":
        return (kind == "oauth_login" and _increase(event, "session_count") is True and
                any(_flag(event, f) is False for f in
                    ("issuer_valid", "audience_valid", "nonce_valid", "subject_matches")))
    if rule == "email-verification":
        return (kind == "email_change" and _increase(event, "email_version") is True and
                _flag(event, "verification_required") is True and
                _flag(event, "email_verified") is False)
    if rule in ("unpaid-credit", "webhook-binding", "cross-tenant-credit",
                "event-replay"):
        if kind != "credit":
            return False
        credited = _increase(event, "available_cents") is True
        if rule == "unpaid-credit":
            return (credited and _flag(event, "psp_confirmed") is False
                    and _flag(event, "non_payment_credit_allowed") is False)
        if rule == "webhook-binding":
            return (credited and any(_flag(event, x) is False for x in
                    ("signature_valid", "order_bound", "amount_bound",
                     "currency_bound", "merchant_bound")))
        if rule == "cross-tenant-credit":
            return (credited and _flag(event, "actor_authorized") is False and
                    _flag(event, "cross_tenant") is True)
        event_id = event.get("payment_event_ref")
        if isinstance(event_id, str) and SAFE_ID.fullmatch(event_id):
            duplicated = event_id in seen
            seen.add(event_id)
            return credited and duplicated
        return False
    if rule == "refund-replay":
        if kind != "refund":
            return False
        event_id = event.get("refund_event_ref")
        if isinstance(event_id, str) and SAFE_ID.fullmatch(event_id):
            duplicated = event_id in seen
            seen.add(event_id)
            return duplicated and _increase(event, "refunded_cents") is True
        return False
    if rule == "subscription-entitlement":
        before, after = event.get("before"), event.get("after")
        return (kind == "subscription_activated" and
                isinstance(before, dict) and isinstance(after, dict) and
                before.get("entitlement_active") is False and
                after.get("entitlement_active") is True and
                _flag(event, "psp_confirmed") is False and
                _flag(event, "non_payment_grant_allowed") is False)
    if rule == "cancellation-stale":
        after = event.get("after")
        return (kind == "subscription_cancelled" and isinstance(after, dict)
                and after.get("entitlement_active") is True
                and _flag(event, "cancelled_now") is True
                and _flag(event, "grace_period_allowed") is False)
    raise ValueError("unknown invariant")


def _validate_run(run):
    if not isinstance(run, dict) or not HEX64.fullmatch(str(run.get("evidence_sha256", ""))):
        raise ValueError("each run needs an evidence_sha256 digest")
    if not HEX64.fullmatch(str(run.get("initial_state_digest", ""))):
        raise ValueError("each run needs an initial_state_digest")
    events = run.get("events")
    if not isinstance(events, list) or not 1 <= len(events) <= MAX_EVENTS:
        raise ValueError("run must have 1..120 events")
    if any(not isinstance(event, dict) for event in events):
        raise ValueError("events must be JSON objects")
    return run


def _score_run(run, rule):
    seen = set()
    hit_steps = []
    for number, event in enumerate(run["events"], start=1):
        if _matching(event, rule, seen):
            hit_steps.append(number)
    return hit_steps


def analyze(doc):
    """Review candidate versus negative control; NEVER certify a deployed bug."""
    if not isinstance(doc, dict) or doc.get("schema_version") != 1:
        raise ValueError("schema_version=1 required")
    if doc.get("environment") != "researcher_owned_lab":
        raise ValueError("only researcher_owned_lab traces are accepted")
    if not HEX40.fullmatch(str(doc.get("source_revision", ""))):
        raise ValueError("exact pinned 40-character hex source_revision required")
    cases = doc.get("cases")
    if not isinstance(cases, list) or not 1 <= len(cases) <= MAX_CASES:
        raise ValueError("cases must contain 1..60 entries")
    result, ids = [], set()
    for case in cases:
        if not isinstance(case, dict):
            raise ValueError("case must be an object")
        cid, rule = case.get("id"), case.get("rule")
        if not isinstance(cid, str) or not SAFE_ID.fullmatch(cid) or cid in ids:
            raise ValueError("invalid or repeated case id")
        ids.add(cid)
        if rule not in RULES:
            raise ValueError("unknown rule")
        basis = case.get("invariant_basis")
        if basis not in ("documented", "reviewer-inferred"):
            raise ValueError("invariant_basis must identify documented or inferred policy")
        candidate, control = case.get("candidate_runs"), case.get("control_runs")
        if not isinstance(candidate, list) or not isinstance(control, list):
            raise ValueError("paired runs required")
        if not 2 <= len(candidate) == len(control) <= 5:
            raise ValueError("2..5 paired candidate/control repetitions required")
        all_runs = [_validate_run(x) for x in candidate + control]
        digests = [x["evidence_sha256"] for x in all_runs]
        if len(set(digests)) != len(digests):
            raise ValueError("repeated evidence digest; rounds must be independent")
        for a, b in zip(candidate, control):
            if a["initial_state_digest"] != b["initial_state_digest"]:
                raise ValueError("candidate/control must start at equivalent initial state")
        candidate_steps = [_score_run(run, rule) for run in candidate]
        control_steps = [_score_run(run, rule) for run in control]
        repeated = all(candidate_steps) and not any(control_steps)
        if any(control_steps):
            classification = "CONTROL_VIOLATION_INCONCLUSIVE"
        elif all(candidate_steps):
            classification = "REPEATED_LOCAL_TRACE_LEAD"
        elif any(candidate_steps):
            classification = "INCONSISTENT_LOCAL_TRACE_INCONCLUSIVE"
        else:
            classification = "NO_OBSERVED_VIOLATION"
        result.append({
            "id": cid, "family": RULES[rule][0], "rule": rule,
            "lead_kind": RULES[rule][1], "claimed_invariant": RULES[rule][2],
            "invariant_basis": basis,
            "classification": classification,
            "repetitions": len(candidate),
            "candidate_hit_steps": candidate_steps,
            "control_hit_steps": control_steps,
            "review_priority": "needs_policy_confirmation" if basis == "reviewer-inferred"
                               else "needs_native_evidence_review",
            "reproducible_trace_contradiction": bool(repeated)
        })
    return {
        "schema_version": 1, "mode": "web-business-lab", "source_revision": doc["source_revision"],
        "classification": "OFFLINE_RESEARCH_LEADS_NOT_VERIFIED",
        "cases": result, "candidate_count": sum(
            x["reproducible_trace_contradiction"] for x in result),
        "confirmed_production_vulnerabilities": 0,
        "real_model_calls": 0, "external_network_requests": 0,
        "ready_to_submit": False,
        "notice": ("Saved trace facts and evidence digests are supplied, not authenticated. "
                   "A local repeated candidate/control discrepancy is only a lead. "
                   "Verify current program authorization, exact code reachability, actual "
                   "native database/PSP receipts, stated product policy and independent "
                   "negative controls before any report.")
    }


def plan(doc):
    if not isinstance(doc, dict) or doc.get("schema_version") != 1 or (
            doc.get("environment") != "researcher_owned_lab"):
        raise ValueError("researcher_owned_lab plan required")
    if not HEX40.fullmatch(str(doc.get("source_revision", ""))):
        raise ValueError("pinned source_revision required")
    selected = doc.get("rules", list(RULES))
    if not isinstance(selected, list) or not selected or len(selected) > len(RULES):
        raise ValueError("nonempty bounded list of rules required")
    if len(set(selected)) != len(selected) or any(r not in RULES for r in selected):
        raise ValueError("invalid/duplicate rule")
    return {
        "schema_version": 1, "mode": "web-business-plan",
        "classification": "OFFLINE_TEST_DESCRIPTIONS_NOT_EXECUTED",
        "source_revision": doc["source_revision"], "jobs": [
            {"rule": r, "family": RULES[r][0], "invariant": RULES[r][2],
             "local_test": ("Use the same pinned code and starting state for two "
                            "candidate/control pairs; inspect real post-operation DB, "
                            "ledger or session state and exact authorization policy."),
             "source_of_truth": ("Identity database and session ledger" if
                                 RULES[r][0] == "identity" else
                                 "Payment provider confirmation and append-only ledger"),
             "required": ["source_anchor", "documented_or_inferred_invariant",
                          "two_candidate_replays", "two_negative_controls",
                          "native_effect", "independent_review", "novelty_gate"]}
            for r in selected],
        "external_network_requests": 0, "real_model_calls": 0,
        "ready_to_submit": False
    }


def _read(path):
    p = Path(path).expanduser()
    if p.is_symlink() or not p.is_file() or p.stat().st_size > 3_000_000:
        raise ValueError("input must be a regular file <=3MB")
    def reject_duplicates(pairs):
        result = {}
        for k, v in pairs:
            if k in result:
                raise ValueError("duplicate JSON object key")
            result[k] = v
        return result
    return json.loads(p.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates)


def _write(path, doc):
    p = Path(path).expanduser()
    if p.exists() or p.is_symlink():
        raise ValueError("output exists; refusing overwrite")
    p.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(p, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2, sort_keys=True)
        f.write("\n")


def _demo():
    path = Path(__file__).with_name("web_business_fixture.py")
    spec = importlib.util.spec_from_file_location("web_business_fixture_for_lab", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    fixture = module.generate()
    report = analyze(fixture)
    report["synthetic_fixture"] = True
    report["classification"] = "SYNTHETIC_SQLITE_BENCHMARK_NOT_TARGET_FINDING"
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("plan", "analyze", "demo"))
    parser.add_argument("--input", help="private local plan or observations; never credentials")
    parser.add_argument("--out", required=True, help="private, new JSON output path")
    args = parser.parse_args(argv)
    try:
        if args.action == "demo":
            if args.input is not None:
                raise ValueError("demo does not accept --input")
            report = _demo()
        else:
            if not args.input:
                raise ValueError("--input required for plan/analyze")
            data = _read(args.input)
            report = plan(data) if args.action == "plan" else analyze(data)
        _write(args.out, report)
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    print(json.dumps({"out": args.out, "mode": report["mode"],
                      "classification": report["classification"],
                      "cases": len(report.get("cases", report.get("jobs", []))),
                      "confirmed_production_vulnerabilities": 0}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
