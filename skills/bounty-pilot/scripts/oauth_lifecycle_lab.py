#!/usr/bin/env python3
"""Offline OAuth grant/token and role-transition traces under EXPLICIT policy.

No network, credentials, token strings, or production traffic. Event accept/deny
bits are operator-reported observations, not independently validated behavior.
"""
import argparse
import json
import os
import re
import sys
from pathlib import Path

ID = re.compile(r"[A-Za-z0-9_.:-]{1,100}\Z")
KINDS = {"grant", "issue_code", "exchange_code", "issue_refresh", "refresh",
         "revoke_grant", "set_role", "action"}
MAX_EVENTS = 1000


def _safe_id(value):
    if not isinstance(value, str) or not ID.fullmatch(value):
        raise ValueError("expected bounded opaque identifier")
    return value


def _policy(p):
    if not isinstance(p, dict):
        raise ValueError("explicit policy object required")
    for key in ("invalidate_unredeemed_codes", "invalidate_refresh_on_revoke"):
        if type(p.get(key)) is not bool:
            raise ValueError("missing explicit OAuth policy " + key)
    matrix = p.get("role_actions")
    if not isinstance(matrix, dict) or len(matrix) > 50:
        raise ValueError("role_actions matrix required")
    permissions = {}
    for role, actions in matrix.items():
        _safe_id(role)
        if not isinstance(actions, list) or len(actions) > 100:
            raise ValueError("role action list invalid")
        permissions[role] = {_safe_id(a) for a in actions}
    return permissions


def analyze(doc):
    if not isinstance(doc, dict) or doc.get("schema_version") != 1:
        raise ValueError("expected OAuth lifecycle schema 1")
    roles = _policy(doc.get("policy"))
    events = doc.get("events")
    if not isinstance(events, list) or not 1 <= len(events) <= MAX_EVENTS:
        raise ValueError("bounded nonempty event sequence required")
    active = {}
    codes = {}
    refreshes = {}
    actor_roles = {}
    traces = []
    seen_ids = set()
    last_seq = -1
    for e in events:
        if not isinstance(e, dict) or e.get("type") not in KINDS:
            raise ValueError("unrecognized lifecycle event")
        event_id = _safe_id(e.get("id"))
        seq = e.get("seq")
        if event_id in seen_ids or type(seq) is not int or seq <= last_seq:
            raise ValueError("events must have unique ids and increasing seq")
        last_seq = seq
        seen_ids.add(event_id)
        typ = e["type"]
        grant = e.get("grant")
        actor = e.get("actor")
        if grant is not None:
            _safe_id(grant)
        if actor is not None:
            _safe_id(actor)
        expected = None
        reason = None
        observed = e.get("accepted")
        if typ in {"exchange_code", "refresh", "action"}:
            if type(observed) is not bool:
                raise ValueError("observed accepted boolean required for attempted operation")
        elif observed is not None:
            raise ValueError("accepted only describes attempted operations")
        if typ == "grant":
            if grant is None or actor is None:
                raise ValueError("grant and actor required")
            active[grant] = True
        elif typ == "issue_code":
            code = _safe_id(e.get("code"))
            if grant not in active:
                raise ValueError("issued code requires declared grant")
            codes[code] = (grant, not active[grant], False)
        elif typ == "exchange_code":
            code = _safe_id(e.get("code"))
            if code not in codes or grant is None:
                raise ValueError("exchange requires prior issued code and grant")
            bound, issued_while_revoked, consumed = codes[code]
            expected = bool(bound == grant and not consumed
                            and (active.get(grant, False) or
                                 (not doc["policy"]["invalidate_unredeemed_codes"]
                                  and not issued_while_revoked)))
            reason = "CODE_EXCHANGE_ACCEPTANCE_MISMATCH"
            if observed and expected:
                codes[code] = (bound, issued_while_revoked, True)
        elif typ == "issue_refresh":
            token = _safe_id(e.get("refresh_id"))
            if grant not in active:
                raise ValueError("refresh token requires prior grant")
            refreshes[token] = grant
        elif typ == "refresh":
            token = _safe_id(e.get("refresh_id"))
            if token not in refreshes or grant is None:
                raise ValueError("refresh requires issued token and grant")
            bound = refreshes[token]
            expected = bool(bound == grant and (active.get(bound, False)
                            or not doc["policy"]["invalidate_refresh_on_revoke"]))
            reason = "REFRESH_ACCEPTANCE_MISMATCH"
        elif typ == "revoke_grant":
            if grant not in active:
                raise ValueError("revoke requires issued grant")
            active[grant] = False
        elif typ == "set_role":
            if actor is None:
                raise ValueError("role actor required")
            role = _safe_id(e.get("role"))
            if role not in roles:
                raise ValueError("unknown role")
            actor_roles[actor] = role
        elif typ == "action":
            action = _safe_id(e.get("action"))
            if actor not in actor_roles:
                raise ValueError("action requires explicit preceding role")
            expected = action in roles[actor_roles[actor]]
            reason = "ROLE_ACTION_ACCEPTANCE_MISMATCH"
        if expected is not None:
            mismatch = expected != observed
            traces.append({
                "event_id": event_id, "seq": seq, "action_type": typ,
                "expected_accepted": expected,
                "observed_accepted_operator_supplied": observed,
                "policy_divergence": mismatch,
                "rule": reason,
            })
    return {
        "schema_version": 1, "engine": "oauth-authorization-lifecycle",
        "status": "POLICY_DIVERGENCE_REVIEW" if any(x["policy_divergence"] for x in traces)
                  else "NO_DECLARED_POLICY_DIVERGENCE",
        "comparisons": traces,
        "divergence_count": sum(x["policy_divergence"] for x in traces),
        "events_seen": len(events),
        "model": "explicit policy state transitions",
        "observations": "operator supplied, not authenticated native receipts",
        "impact_verified": False,
        "warnings": ["revocation behavior varies by protocol, grant and service policy",
                     "HTTP acceptance alone is not a protected effect",
                     "trace cannot prove deployed state, session identity or consent"],
    }


def _load(path):
    p = Path(path)
    if p.is_symlink() or not p.is_file() or p.stat().st_size > 1024 * 1024:
        raise ValueError("case must be small regular JSON")
    return json.loads(p.read_text("utf-8"))


def _write(path, doc):
    p = Path(path)
    if p.is_symlink() or p.exists() or not p.parent.is_dir():
        raise ValueError("output must be new path under existing directory")
    fd = os.open(str(p), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(doc, stream, sort_keys=True, indent=2)
        stream.write("\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trace", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    try:
        report = analyze(_load(args.trace))
        _write(args.out, report)
        print(json.dumps({"status": report["status"],
                          "divergence_count": report["divergence_count"]}))
        return 0
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print("Error: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
