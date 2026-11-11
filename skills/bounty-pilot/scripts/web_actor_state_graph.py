#!/usr/bin/env python3
"""Reconstruct an offline actor/resource state graph from private lab observations.

Expected grants and owner/tenant restrictions are explicit facts supplied by
an operator, never guessed from HTTP status. Results are review hypotheses,
NOT proof of a live IDOR, vulnerable site, or verified authorization policy.
"""
import argparse
import json
import os
import re
import sys
from pathlib import Path

ID = re.compile(r"^[A-Za-z0-9_.:-]{1,100}$")
ACTION = frozenset(("read", "use", "export", "update", "delete", "invoke-job", "refund"))
MAX_EVENTS = 3000


def _ident(value, label):
    if not isinstance(value, str) or not ID.fullmatch(value):
        raise ValueError(label + " requires bounded opaque id")
    return value


def _unique(pairs):
    obj = {}
    for k, v in pairs:
        if k in obj:
            raise ValueError("duplicate JSON key")
        obj[k] = v
    return obj


def _load(path):
    p = Path(path)
    if p.is_symlink() or not p.is_file() or p.stat().st_size > 2_000_000:
        raise ValueError("regular JSON <=2MB required")
    return json.loads(p.read_text(encoding="utf-8"), object_pairs_hook=_unique)


def _write(path, data):
    p = Path(path)
    if p.is_symlink() or p.exists():
        raise ValueError("output already exists")
    p.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, sort_keys=True)
        f.write("\n")


def _validate(doc):
    if (not isinstance(doc, dict) or set(doc) != {
            "schema_version", "environment", "actors", "resources", "initial_grants",
            "events"} or type(doc["schema_version"]) is not int or
            doc["schema_version"] != 1 or
            doc["environment"] != "researcher_owned_lab"):
        raise ValueError("requires version 1 researcher-owned lab graph")
    actors, resources = {}, {}
    for arr, target, fields in (
        (doc["actors"], actors, {"id", "tenant"}),
        (doc["resources"], resources, {"id", "owner", "tenant", "visibility"}),
    ):
        if not isinstance(arr, list) or len(arr) > 500:
            raise ValueError("actor/resource array too large")
        for row in arr:
            if not isinstance(row, dict) or set(row) != fields:
                raise ValueError("actor/resource fields invalid")
            ident = _ident(row["id"], "node id")
            if ident in target:
                raise ValueError("duplicate node id")
            _ident(row["tenant"], "tenant")
            target[ident] = row.copy()
    for res in resources.values():
        if res["visibility"] not in ("private", "public"):
            raise ValueError("unknown visibility")
        if res["owner"] not in actors:
            raise ValueError("resource owner must be a declared actor")
    grants = set()
    if not isinstance(doc["initial_grants"], list) or len(doc["initial_grants"]) > 1500:
        raise ValueError("too many initial grants")
    for g in doc["initial_grants"]:
        if not isinstance(g, dict) or set(g) != {"actor", "resource", "action"}:
            raise ValueError("invalid grant")
        if g["actor"] not in actors or g["resource"] not in resources or g["action"] not in ACTION:
            raise ValueError("initial grant references undeclared actor/resource/action")
        item = (g["actor"], g["resource"], g["action"])
        if item in grants:
            raise ValueError("duplicate initial grant")
        grants.add(item)
    events = doc["events"]
    if not isinstance(events, list) or not 1 <= len(events) <= MAX_EVENTS:
        raise ValueError("events must be bounded nonempty array")
    seen, last = set(), -1
    for e in events:
        if not isinstance(e, dict) or set(e) != {
                "id", "seq", "type", "actor", "resource", "action",
                "subject", "new_owner", "observed_effect", "evidence_sha256"}:
            raise ValueError("event fields invalid")
        ident = _ident(e["id"], "event id")
        if ident in seen or type(e["seq"]) is not int or e["seq"] <= last:
            raise ValueError("events need unique ids and monotonic sequence")
        seen.add(ident)
        last = e["seq"]
        if e["type"] not in ("grant", "revoke", "transfer", "action"):
            raise ValueError("event type unsupported")
        if e["actor"] not in actors or e["resource"] not in resources:
            raise ValueError("event references unknown nodes")
        if e["action"] is not None and e["action"] not in ACTION:
            raise ValueError("unknown action")
        if e["subject"] is not None and e["subject"] not in actors:
            raise ValueError("unknown subject")
        if e["new_owner"] is not None and e["new_owner"] not in actors:
            raise ValueError("unknown new owner")
        if type(e["observed_effect"]) not in (bool, type(None)):
            raise ValueError("observed_effect must be true, false or null")
        if e["evidence_sha256"] is not None and (
                not isinstance(e["evidence_sha256"], str) or
                not re.fullmatch(r"[a-f0-9]{64}", e["evidence_sha256"])):
            raise ValueError("evidence_sha256 invalid")
        if e["type"] == "action":
            if e["action"] is None or e["subject"] is not None or e["new_owner"] is not None:
                raise ValueError("action event shape invalid")
        elif e["type"] in ("grant", "revoke"):
            if (e["actor"] != resources[e["resource"]]["owner"] and
                    (e["actor"], e["resource"], "update") not in grants):
                # Actual ability to issue a grant may be dynamic. Never assume
                # this saved event is itself valid; treat separately below.
                pass
            if e["action"] is None or e["subject"] is None or (
                    e["new_owner"] is not None or e["observed_effect"] is not None):
                raise ValueError("grant/revoke event shape invalid")
        elif (e["type"] == "transfer" and
              (e["new_owner"] is None or e["action"] is not None or
               e["subject"] is not None or e["observed_effect"] is not None)):
            raise ValueError("transfer event shape invalid")
    return actors, resources, grants, events


def analyze(doc):
    actors, resources, grants, events = _validate(doc)
    leads, transitions, uncertain = [], [], []
    revoked = set()
    for e in events:
        rid, actor, kind = e["resource"], e["actor"], e["type"]
        r = resources[rid]
        if kind == "action":
            action = e["action"]
            is_owner = r["owner"] == actor
            same_tenant = actors[actor]["tenant"] == r["tenant"]
            granted = (actor, rid, action) in grants
            # Public read alone is permissible; write/job/export never
            # inherit permission merely because a read route is public.
            allowed = ((r["visibility"] == "public" and action == "read") or
                       (same_tenant and (is_owner or granted)))
            fact = {"event_id": e["id"], "seq": e["seq"], "actor": actor,
                    "resource": rid, "action": action, "expected_allow": bool(allowed),
                    "observed_effect": e["observed_effect"],
                    "owner_at_event": r["owner"], "tenant_match": same_tenant,
                    "was_revoked": (actor, rid, action) in revoked}
            transitions.append(fact)
            if e["observed_effect"] is None:
                uncertain.append({"event_id": e["id"], "reason": "NO_EFFECT_OBSERVATION"})
            elif not allowed and e["observed_effect"] is True:
                leads.append({"event_id": e["id"],
                              "kind": ("REVOKED_GRANT_STILL_EFFECTIVE"
                                       if (actor, rid, action) in revoked
                                       else "DECLARED_ACTOR_POLICY_CONTRADICTION"),
                              "evidence_sha256": e["evidence_sha256"],
                              "action": action, "subject": actor, "object": rid,
                              "status": "UNVERIFIED_OPERATOR_SUPPLIED_EFFECT",
                              "basis": ("Lab-declared ownership, tenant and grants "
                                        "would deny this operation, but a supplied "
                                        "observation says its intended effect occurred.")})
        elif kind in ("grant", "revoke"):
            item = (e["subject"], rid, e["action"])
            if kind == "grant":
                grants.add(item)
                revoked.discard(item)
            else:
                grants.discard(item)
                revoked.add(item)
        else:
            r["owner"] = e["new_owner"]
            # Grants are explicit and cannot be silently inherited by new owners.
    return {"schema_version": 1, "mode": "web-actor-state-graph",
            "events_reviewed": len(events), "transition_facts": transitions,
            "leads": leads, "unknowns": uncertain,
            "confirmed_vulnerabilities": 0, "network_requests": 0,
            "limitations": ("Supplied local facts are not authenticated and do not model "
                            "all deployment-specific IAM rules, organization membership, "
                            "grant creation rights or eventual consistency. Only observed "
                            "effects, not HTTP status, can lead to a policy contradiction. "
                            "No production authorization is inferred.")}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--input", required=True)
    p.add_argument("--out", required=True)
    a = p.parse_args(argv)
    try:
        result = analyze(_load(a.input))
        _write(a.out, result)
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        p.error(str(exc))
    print(json.dumps({"out": a.out, "leads": len(result["leads"]),
                      "confirmed_vulnerabilities": 0}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
