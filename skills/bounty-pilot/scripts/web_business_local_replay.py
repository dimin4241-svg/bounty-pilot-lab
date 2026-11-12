#!/usr/bin/env python3
"""Explicitly opted-in multi-step business replay against a private loopback fixture.

No DNS, redirects, proxies, browser, production target, account discovery, real
payment or real credentials. Emits sanitized pre/post effects for offline review.
"""
import argparse
import hashlib
import importlib.util
import json
import os
import re
import sys
from pathlib import Path
from urllib import error, request

ORIGIN = re.compile(r"^http://127[.]0[.]0[.]1:([0-9]{4,5})$")
PATH = re.compile(r"^/[A-Za-z0-9_/-]{1,160}$")
IDENT = re.compile(r"^[A-Za-z0-9_.:-]{1,90}$")
HEX40 = re.compile(r"^[a-f0-9]{40}$")
ENV = re.compile(r"^BP_LOCAL_[A-Z0-9_]{3,70}$")
STATE = frozenset(("credential_version", "email_version", "session_count",
                   "session_active", "available_cents", "refunded_cents",
                   "ledger_credited_cents", "entitlement_active"))
FACTS = frozenset(("actor_authorized", "mfa_required", "mfa_verified",
                   "session_active", "reset_token_previously_used",
                   "issuer_valid", "audience_valid", "nonce_valid",
                   "subject_matches", "verification_required", "email_verified",
                   "psp_confirmed", "non_payment_credit_allowed",
                   "signature_valid", "order_bound", "amount_bound",
                   "currency_bound", "merchant_bound", "cross_tenant",
                   "non_payment_grant_allowed", "cancelled_now",
                   "grace_period_allowed"))
EVENTS = frozenset(("sensitive_account_update", "email_change", "password_reset",
                    "oauth_login", "credit", "refund", "subscription_activated",
                    "subscription_cancelled", "session_revoked"))
PAYLOAD_KEYS = frozenset(("operation", "actor", "subject", "payment_event_ref",
                          "refund_event_ref", "test_ref", "confirmed", "bound",
                          "authorized", "mfa_verified", "session_active",
                          "token_previously_used", "verified", "grace",
                          "amount_cents"))
MAX_BYTES = 8192


class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, hdrs, newurl):
        return None


def _digest(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True,
                 separators=(",", ":")).encode()).hexdigest()


def _path(value):
    if (not isinstance(value, str) or not PATH.fullmatch(value) or
            "//" in value or any(part in ("", ".", "..") for part in value.split("/")[1:])):
        raise ValueError("only bounded, unambiguous local ASCII paths are allowed")
    return value


def _id(value):
    if not isinstance(value, str) or not IDENT.fullmatch(value):
        raise ValueError("bounded pseudonymous actor/case ID required")
    return value


def _validate_step(step, actors):
    if not isinstance(step, dict) or set(step) != {
            "path", "actor", "subject", "kind", "payload", "payment_event_ref",
            "refund_event_ref"}:
        raise ValueError("exact step fields required")
    _path(step["path"])
    if _id(step["actor"]) not in actors:
        raise ValueError("unknown test actor")
    _id(step["subject"])
    if step["kind"] not in EVENTS:
        raise ValueError("unknown business event kind")
    payload = step["payload"]
    if not isinstance(payload, dict) or len(payload) > 14 or (
            any(key not in PAYLOAD_KEYS for key in payload)):
        raise ValueError("only non-secret scalar owned-fixture payloads allowed")
    for key, value in payload.items():
        if key == "amount_cents":
            if type(value) is not int or value < 0 or value > 10**10:
                raise ValueError("amount_cents must be a bounded integer")
        elif type(value) is bool:
            pass
        elif type(value) is str:
            _id(value)
        else:
            raise ValueError("payload fields must be scalar bool/int/string")
    if len(json.dumps(payload)) > 1000:
        raise ValueError("payload too large")
    for ref in ("payment_event_ref", "refund_event_ref"):
        if step[ref] is not None:
            _id(step[ref])
    if step["kind"] == "credit" and step["payment_event_ref"] is not None and (
            payload.get("payment_event_ref") != step["payment_event_ref"]):
        raise ValueError("observed payment ref must match submitted fake PSP ref")
    if step["kind"] == "refund" and step["refund_event_ref"] is not None and (
            payload.get("refund_event_ref") != step["refund_event_ref"]):
        raise ValueError("observed refund ref must match submitted fake refund ref")


def _business_rules():
    module_path = Path(__file__).with_name("web_business_lab.py")
    spec = importlib.util.spec_from_file_location("bp_local_business_rules", module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.RULES


def validate(doc):
    if not isinstance(doc, dict) or doc.get("schema_version") != 1 or (
            doc.get("attestation") != "I_CONTROL_THIS_LOCAL_FIXTURE"):
        raise ValueError("owned fixture attestation and schema required")
    origin = doc.get("origin")
    m = ORIGIN.fullmatch(origin) if isinstance(origin, str) else None
    if not m or not 1024 <= int(m.group(1)) <= 65535 or (
            str(int(m.group(1))) != m.group(1)):
        raise ValueError("literal canonical http://127.0.0.1:PORT required")
    if not HEX40.fullmatch(str(doc.get("source_revision", ""))):
        raise ValueError("exact pinned source_revision required")
    actors = doc.get("test_actors")
    if not isinstance(actors, dict) or not 2 <= len(actors) <= 4:
        raise ValueError("two to four researcher-owned test actors required")
    names = set()
    for actor, entry in actors.items():
        _id(actor)
        if not isinstance(entry, dict) or set(entry) != {"bearer_env"}:
            raise ValueError("each actor supplies a private bearer_env reference")
        env = entry["bearer_env"]
        if not isinstance(env, str) or not ENV.fullmatch(env) or env in names:
            raise ValueError("bounded distinct BP_LOCAL_ environment variables required")
        names.add(env)
    cases = doc.get("cases")
    if not isinstance(cases, list) or not 1 <= len(cases) <= 8:
        raise ValueError("1..8 cases required")
    ids, paths = set(), set()
    supported_rules = _business_rules()
    for case in cases:
        if not isinstance(case, dict) or set(case) != {
                "id", "rule", "invariant_basis", "rounds"}:
            raise ValueError("exact case fields required")
        ident = _id(case["id"])
        if ident in ids:
            raise ValueError("duplicate case ID")
        ids.add(ident)
        if case["invariant_basis"] not in ("documented", "reviewer-inferred"):
            raise ValueError("invariant policy provenance required")
        # Exact local rule catalog; no target module or external package loaded.
        if case["rule"] not in supported_rules:
            raise ValueError("unsupported invariant rule")
        rounds = case["rounds"]
        if not isinstance(rounds, list) or not 2 <= len(rounds) <= 5:
            raise ValueError("2..5 independent candidate/control rounds required")
        for pair in rounds:
            if not isinstance(pair, dict) or set(pair) != {"candidate", "control"}:
                raise ValueError("paired candidate and control required")
            for role in ("candidate", "control"):
                section = pair[role]
                if not isinstance(section, dict) or set(section) != {
                        "state_path", "state_actor", "steps"}:
                    raise ValueError("exact local section fields required")
                route = _path(section["state_path"])
                if route in paths:
                    raise ValueError("each role/round must use isolated state route")
                paths.add(route)
                if _id(section["state_actor"]) not in actors:
                    raise ValueError("unknown state reader")
                steps = section["steps"]
                if not isinstance(steps, list) or not 1 <= len(steps) <= 6:
                    raise ValueError("1..6 bounded actions per run required")
                for step in steps:
                    _validate_step(step, actors)
    return doc


def _read(path):
    p = Path(path).expanduser()
    if p.is_symlink() or not p.is_file() or p.stat().st_size > 2_000_000:
        raise ValueError("regular private JSON <=2MB required")
    def unique(pairs):
        d = {}
        for k, v in pairs:
            if k in d:
                raise ValueError("duplicate JSON object key")
            d[k] = v
        return d
    return json.loads(p.read_text(encoding="utf-8"), object_pairs_hook=unique)


def _write(path, data):
    p = Path(path).expanduser()
    if p.exists() or p.is_symlink():
        raise ValueError("output must be new")
    p.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(p, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f, sort_keys=True, indent=2)
        f.write("\n")


def _validated_body(blob, *, state):
    if len(blob) > MAX_BYTES:
        raise ValueError("local fixture response too large")
    try:
        data = json.loads(blob.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid local fixture JSON") from exc
    if not isinstance(data, dict):
        raise ValueError("JSON object response required")
    if state:
        observed = {}
        for field in STATE:
            value = data.get(field)
            if field == "entitlement_active":
                if type(value) is bool:
                    observed[field] = value
            elif type(value) is int and value >= 0:
                observed[field] = value
        if not observed:
            raise ValueError("no sanitized numeric state from owned fixture")
        return observed
    facts = data.get("facts")
    if not isinstance(facts, dict) or any(k not in FACTS or type(v) is not bool
                                           for k, v in facts.items()):
        raise ValueError("action must return only explicit boolean fixture facts")
    return facts


def _call(opener, url, method, token, payload=None):
    headers = {"Authorization": "Bearer " + token, "Accept": "application/json",
               "Cache-Control": "no-store", "User-Agent": "BP-Local-Business-Research/1"}
    if payload is not None:
        headers["Content-Type"] = "application/json"
    body = json.dumps(payload, sort_keys=True).encode() if payload is not None else None
    req = request.Request(url, data=body, method=method, headers=headers)
    try:
        response = opener.open(req, timeout=4)
    except error.HTTPError as exc:
        response = exc
    with response:
        status = response.status
        content = response.read(MAX_BYTES + 1)
    if status in (301, 302, 303, 307, 308):
        raise ValueError("redirect forbidden")
    return status, content


def execute(doc, *, run=False, environment=None):
    validate(doc)
    if not run:
        return {"schema_version": 1, "mode": "web-business-local-replay",
                "classification": "VALIDATED_LOCAL_PLAN_NOT_EXECUTED",
                "network_requests_local": 0, "external_network_requests": 0,
                "confirmed_production_vulnerabilities": 0}
    env = os.environ if environment is None else environment
    tokens = {}
    for actor, entry in doc["test_actors"].items():
        token = env.get(entry["bearer_env"], "")
        if not isinstance(token, str) or not 8 <= len(token) <= 200:
            raise ValueError("missing bounded local-only test bearer")
        tokens[actor] = token
    if len(set(tokens.values())) != len(tokens):
        raise ValueError("local test actor tokens must differ")
    opener = request.build_opener(NoRedirect(), request.ProxyHandler({}))
    origin = doc["origin"]
    result_cases, calls = [], 0
    for case in doc["cases"]:
        candidate_runs, control_runs = [], []
        for round_index, pair in enumerate(case["rounds"], 1):
            for role, destination in (("candidate", candidate_runs),
                                      ("control", control_runs)):
                section = pair[role]
                state_url = origin + section["state_path"]
                status, body = _call(opener, state_url, "GET",
                                     tokens[section["state_actor"]])
                calls += 1
                if status != 200:
                    raise ValueError("local state GET did not return 200")
                first = _validated_body(body, state=True)
                state = first
                events = []
                for step in section["steps"]:
                    status, body = _call(opener, origin + step["path"], "POST",
                                         tokens[step["actor"]], step["payload"])
                    calls += 1
                    if not 200 <= status <= 499:
                        raise ValueError("local action response status out of range")
                    facts = _validated_body(body, state=False)
                    next_status, state_body = _call(opener, state_url, "GET",
                        tokens[section["state_actor"]])
                    calls += 1
                    if next_status != 200:
                        raise ValueError("local state-after GET did not return 200")
                    after = _validated_body(state_body, state=True)
                    event = {"kind": step["kind"], "actor": step["actor"],
                             "subject": step["subject"], "facts": facts,
                             "before": state, "after": after}
                    for ref in ("payment_event_ref", "refund_event_ref"):
                        if step[ref] is not None:
                            event[ref] = step[ref]
                    events.append(event)
                    state = after
                observation = {"initial_state_digest": _digest(first),
                               "events": events}
                observation["evidence_sha256"] = _digest({
                    "case": case["id"], "round": round_index, "role": role,
                    "observed": observation})
                destination.append(observation)
            if candidate_runs[-1]["initial_state_digest"] != (
                    control_runs[-1]["initial_state_digest"]):
                raise ValueError("local fixture control starts at different state")
        result_cases.append({"id": case["id"], "rule": case["rule"],
                             "invariant_basis": case["invariant_basis"],
                             "candidate_runs": candidate_runs,
                             "control_runs": control_runs})
    return {"schema_version": 1, "mode": "web-business-local-replay",
            "environment": "researcher_owned_lab",
            "source_revision": doc["source_revision"], "cases": result_cases,
            "classification": "EXECUTED_OWNED_LOOPBACK_OBSERVATIONS_UNVERIFIED",
            "network_requests_local": calls, "external_network_requests": 0,
            "confirmed_production_vulnerabilities": 0, "ready_to_submit": False,
            "limitations": "Fixture identity and policy are operator supplied; this is not production proof."}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--plan", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--execute", action="store_true",
                   help="explicit opt-in to literal 127.0.0.1 owned fixture only")
    a = p.parse_args(argv)
    try:
        target = Path(a.out).expanduser()
        if target.exists() or target.is_symlink():
            raise ValueError("refusing to overwrite output before any request")
        result = execute(_read(a.plan), run=a.execute)
        _write(a.out, result)
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        p.error(str(exc))
    print(json.dumps({"out": a.out, "classification": result["classification"],
                      "network_requests_local": result["network_requests_local"],
                      "confirmed_production_vulnerabilities": 0}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
