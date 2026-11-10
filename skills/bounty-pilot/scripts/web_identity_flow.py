#!/usr/bin/env python3
"""Offline Web identity, signed-intent and tenant-context consistency checks.

Consumes investigator-supplied observations only. It does not validate crypto,
authenticate logs, decode tokens, or execute the target. Every lead is unverified.
"""
import argparse
import hashlib
import json
import os
import sys
from pathlib import Path

FIELDS = frozenset(("account", "chain_id", "asset", "amount", "recipient", "spender",
                    "deadline", "nonce", "domain", "order_id", "destination", "fee"))
MAX_EVENTS = 5000


def _load(path):
    p = Path(path)
    if p.is_symlink() or not p.is_file() or p.stat().st_size > 2000000:
        raise ValueError("input must be a regular JSON file <=2MB")
    return json.loads(p.read_text(encoding="utf-8"))


def _write(path, obj):
    p = Path(path)
    if p.exists() or p.is_symlink():
        raise ValueError("output exists or is symlinked")
    p.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(p), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as out:
        json.dump(obj, out, sort_keys=True, ensure_ascii=False, indent=2)
        out.write("\n")


def _events(data):
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise ValueError("schema_version=1 required")
    events = data.get("events")
    if not isinstance(events, list) or len(events) > MAX_EVENTS:
        raise ValueError("events must be a bounded list")
    if any(not isinstance(ev, dict) for ev in events):
        raise ValueError("events must be objects")
    return events


def sessions(data):
    """Flag explicit denied/allowed contradiction across revocation and tenant boundaries."""
    events = _events(data)
    revoked = set()
    known = {}
    leads, unknown = [], []
    for i, ev in enumerate(events):
        action = ev.get("kind")
        sid = ev.get("session_ref")
        if action in ("issue", "revoke", "use", "rotate") and (
                not isinstance(sid, str) or len(sid) > 120):
            raise ValueError("session events require bounded session_ref alias, not token")
        if action == "issue":
            known[sid] = {"subject": ev.get("subject"), "tenant": ev.get("tenant")}
            revoked.discard(sid)
        elif action in ("revoke", "rotate"):
            revoked.add(sid)
        elif action == "use":
            accepted = ev.get("accepted")
            if accepted is True and sid in revoked:
                leads.append({"event_index": i, "kind": "REVOKED_SESSION_ACCEPTED",
                              "classification": "UNVERIFIED_OBSERVATION_CONTRADICTION"})
            info = known.get(sid)
            if accepted is True and info:
                actor, tenant = ev.get("subject"), ev.get("tenant")
                if info["subject"] is not None and actor != info["subject"]:
                    leads.append({"event_index": i, "kind": "SESSION_SUBJECT_MISMATCH",
                                  "classification": "UNVERIFIED_OBSERVATION_CONTRADICTION"})
                if info["tenant"] is not None and tenant != info["tenant"] and (
                        ev.get("cross_tenant_grant") is False):
                    leads.append({"event_index": i, "kind": "SESSION_TENANT_MISMATCH",
                                  "classification": "UNVERIFIED_OBSERVATION_CONTRADICTION"})
                elif tenant != info["tenant"] and ev.get("cross_tenant_grant") is None:
                    unknown.append(i)
        else:
            unknown.append(i)
    return {"schema_version": 1, "mode": "identity-session",
            "leads": leads, "unknown_event_indices": unknown[:100],
            "network_requests": 0, "confirmed_vulnerabilities": 0,
            "notice": "Session IDs are abstract aliases, not credentials; observations are unverified."}


def signed_intents(data):
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise ValueError("schema_version=1 required")
    cases = data.get("cases")
    if not isinstance(cases, list) or len(cases) > 300:
        raise ValueError("cases must be a list of <=300")
    leads, incomplete = [], []
    for index, case in enumerate(cases):
        if not isinstance(case, dict):
            raise ValueError("case must be object")
        fields = case.get("bound_fields")
        if not isinstance(fields, list) or not fields or len(fields) > 20 or (
                any(f not in FIELDS for f in fields)):
            raise ValueError("explicit bound_fields from supported values required")
        displayed, signed, executed = (case.get(stage) for stage in (
            "displayed", "signed", "executed"))
        if any(not isinstance(side, dict) for side in (displayed, signed, executed)):
            raise ValueError("displayed, signed and executed objects are required")
        if case.get("signature_verified_locally") is not True or case.get("executed_locally") is not True:
            incomplete.append(index)
            continue
        for field in fields:
            if any(field not in side for side in (displayed, signed, executed)):
                incomplete.append(index)
                continue
            if displayed[field] != signed[field] or signed[field] != executed[field]:
                leads.append({"case_index": index, "field": field,
                              "kind": "SIGNED_INTENT_LEG_MISMATCH",
                              "classification": "SUPPLIED_LOCAL_OBSERVATION_MISMATCH"})
    return {"schema_version": 1, "mode": "signed-intent",
            "leads": leads, "incomplete_cases": sorted(set(incomplete)),
            "network_requests": 0, "confirmed_vulnerabilities": 0,
            "notice": "Boolean local-verification declarations are NOT proof of valid signatures or execution."}


def tenant_isolation(data):
    """Explicit local authorization outcomes for owned tenant fixtures."""
    events = _events(data)
    leads, incomplete = [], []
    for index, ev in enumerate(events):
        if ev.get("kind") not in ("document_read", "tool_use", "cache_read", "rag_retrieval"):
            incomplete.append(index)
            continue
        required = ("caller_tenant", "resource_tenant", "authorized_cross_tenant", "allowed")
        if any(field not in ev for field in required):
            incomplete.append(index)
            continue
        if (ev["caller_tenant"] != ev["resource_tenant"] and
                ev["authorized_cross_tenant"] is False and ev["allowed"] is True):
            leads.append({"event_index": index, "kind": "CROSS_TENANT_ISOLATION_CONTRADICTION",
                          "surface": ev["kind"],
                          "classification": "SUPPLIED_LOCAL_OBSERVATION_MISMATCH"})
    return {"schema_version": 1, "mode": "tenant-isolation",
            "leads": leads, "incomplete_events": incomplete[:200],
            "network_requests": 0, "confirmed_vulnerabilities": 0,
            "notice": "Researcher-owned contexts only; do not fetch real other-user documents."}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("command", choices=("sessions", "intent", "tenant"))
    p.add_argument("--input", required=True)
    p.add_argument("--out", required=True)
    a = p.parse_args(argv)
    try:
        data = _load(a.input)
        fn = {"sessions": sessions, "intent": signed_intents, "tenant": tenant_isolation}[a.command]
        result = fn(data)
        _write(a.out, result)
    except (ValueError, TypeError, OSError, json.JSONDecodeError) as exc:
        p.error(str(exc))
    print(json.dumps({"mode": result["mode"], "leads": len(result["leads"]), "out": a.out}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
