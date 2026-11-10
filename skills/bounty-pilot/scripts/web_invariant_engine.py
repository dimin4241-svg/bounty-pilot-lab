#!/usr/bin/env python3
"""Offline Web/API invariant research: operation graph, state observations, plans and parser leads.

All inputs are untrusted, supplied local files. No network traffic, target execution,
authentication, or exploit verification occurs in this module. Output is a research
queue, NOT a finding, exploit claim, or authorization to test a target.
Python 3.9+; standard library only.
"""
import argparse
import hashlib
import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlsplit, unquote

METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")
ID = re.compile(r"^[A-Za-z0-9_.:-]{1,100}$")
SAFE_KEY = re.compile(r"^[A-Za-z][A-Za-z0-9_.:/-]{0,150}$")
VERSION = re.compile(r"^v[0-9]+$", re.I)
PARAM = re.compile(r"^\{[A-Za-z_][A-Za-z0-9_]*\}$")
MAX_PATHS = 5000
MAX_EVENTS = 5000


def digest(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":"),
                                    ensure_ascii=True).encode("utf-8")).hexdigest()


def load_file(path, max_bytes=4_000_000):
    p = Path(path).expanduser()
    if p.is_symlink() or not p.is_file() or p.stat().st_size > max_bytes:
        raise ValueError("input must be a regular non-symlink JSON file within size limits")
    return json.loads(p.read_text(encoding="utf-8"), object_pairs_hook=_unique)


def _unique(pairs):
    obj = {}
    for key, val in pairs:
        if key in obj:
            raise ValueError("duplicate JSON object member: " + str(key)[:60])
        obj[key] = val
    return obj


def save_new(path, data):
    dest = Path(path).expanduser()
    if dest.is_symlink() or dest.exists():
        raise ValueError("output path must be new, not symlinked or existing")
    dest.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(dest), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(data, stream, ensure_ascii=False, indent=2, sort_keys=True)
        stream.write("\n")


def _path(path):
    if (not isinstance(path, str) or not path.startswith("/") or
            path.startswith("//") or len(path) > 500 or
            "?" in path or "#" in path or "\\" in path or
            any(ord(char) < 32 for char in path)):
        raise ValueError("invalid OpenAPI path template")
    # Never write opaque 30+ character path identifiers to output.
    parts = path.split("/")
    return "/".join("{opaque}" if len(s) >= 30 and not PARAM.fullmatch(s)
                    else s for s in parts)


def _resource_key(path):
    parts = [x for x in path.split("/") if x]
    parts = [x for x in parts if not VERSION.fullmatch(x) and x != "api"]
    # Explicitly ignore only Next.js transport decoration; not proof of equivalence.
    if len(parts) >= 3 and parts[0] == "_next" and parts[1] == "data":
        parts = parts[3:]
    parts = ["{}" if PARAM.fullmatch(x) or x == "{opaque}" else x.lower()
             for x in parts]
    return "/".join(parts)


def _roles(op):
    raw = op.get("x-bp-roles", [])
    if not isinstance(raw, list) or len(raw) > 20:
        return []
    return sorted({x for x in raw if isinstance(x, str) and SAFE_KEY.fullmatch(x)})


def _security(op, spec):
    sec = op.get("security", spec.get("security", None))
    if sec is None:
        return "UNDECLARED"
    if sec == []:
        return "DOCUMENTED_PUBLIC"
    if isinstance(sec, list):
        return "DOCUMENTED_SECURITY"
    return "INVALID_SCHEMA"


def build_operation_graph(spec):
    """Map OpenAPI 3 operations and emit discrepancies as review leads.

    x-bp-handler and x-bp-operation are investigator-supplied, untrusted hints.
    Structural grouping alone is never called proof of a shared backend handler.
    """
    if not isinstance(spec, dict) or not str(spec.get("openapi", "")).startswith("3."):
        raise ValueError("OpenAPI 3.x object required")
    paths = spec.get("paths")
    if not isinstance(paths, dict) or len(paths) > MAX_PATHS:
        raise ValueError("OpenAPI paths must be an object of <=5000 paths")
    operations = []
    for path, entry in sorted(paths.items()):
        safe_path = _path(path)
        if not isinstance(entry, dict):
            continue
        for method in METHODS:
            op = entry.get(method.lower())
            if not isinstance(op, dict):
                continue
            hints = {}
            for field, label in (("x-bp-handler", "handler"), ("x-bp-operation", "operation")):
                value = op.get(field)
                if isinstance(value, str) and SAFE_KEY.fullmatch(value):
                    hints[label] = value
            operation = {
                "id": digest([method, safe_path])[:16],
                "method": method, "path": safe_path,
                "operation_id": str(op.get("operationId") or "")[:120],
                "structural_resource": _resource_key(safe_path),
                "advertised_security": _security(op, spec),
                "declared_roles": _roles(op),
                "hints": hints,
                "schema_provenance": "operator_supplied_openapi",
            }
            operations.append(operation)
    grouped = defaultdict(list)
    for op in operations:
        hint = op["hints"]
        if "handler" in hint:
            key = "handler:" + hint["handler"]
            basis = "operator_handler_hint"
        elif "operation" in hint:
            key = "operation:" + hint["operation"]
            basis = "operator_operation_hint"
        else:
            key = "structure:" + op["structural_resource"]
            basis = "structural_heuristic"
        grouped[(key, basis)].append(op)
    groups, leads = [], []
    for (key, basis), members in sorted(grouped.items()):
        if len(members) < 2:
            continue
        gs = sorted({m["advertised_security"] for m in members})
        roles = sorted({tuple(m["declared_roles"]) for m in members})
        methods = sorted({m["method"] for m in members})
        path_ids = [m["id"] for m in members]
        groups.append({"key": key, "basis": basis, "operation_ids": path_ids,
                       "security_variants": gs, "methods": methods})
        if len(gs) > 1 and "DOCUMENTED_PUBLIC" in gs and "DOCUMENTED_SECURITY" in gs:
            kind, priority = "ADVERTISED_AUTH_MISMATCH", 85
        elif len(roles) > 1 and any(roles):
            kind, priority = "DECLARED_ROLE_MISMATCH", 72
        elif len(methods) > 1:
            kind, priority = "CROSS_METHOD_BOUNDARY_REVIEW", 48
        else:
            continue
        leads.append({"id": digest([key, kind])[:16], "kind": kind,
                      "priority": priority if basis != "structural_heuristic" else priority - 20,
                      "basis": basis, "operation_ids": path_ids,
                      "review": "Trace runtime guards and persisted objects; a spec mismatch is not a vulnerability",
                      "classification": "UNVERIFIED_LEAD"})
    leads.sort(key=lambda x: (-x["priority"], x["id"]))
    return {"schema_version": 1, "mode": "operation-graph",
            "operations": operations, "groups": groups, "leads": leads,
            "input_sha256": digest(spec), "network_requests": 0,
            "confirmed_vulnerabilities": 0,
            "limitations": ("OpenAPI and x-bp hints are untrusted; no call graph, framework AST, "
                            "runtime guard, or handler equivalence is independently verified.")}


def build_auth_matrix(graph, fixtures):
    """Generate explicit owned-account test CASES, not runnable requests."""
    if graph.get("mode") != "operation-graph" or not isinstance(graph.get("operations"), list):
        raise ValueError("operation graph required")
    if not isinstance(fixtures, dict) or fixtures.get("schema_version") != 1:
        raise ValueError("fixture manifest schema_version=1 required")
    resources = fixtures.get("resources", [])
    if not isinstance(resources, list) or len(resources) > 100:
        raise ValueError("resources must be a bounded list")
    index = {o["id"]: o for o in graph["operations"]}
    cases = []
    for obj in resources:
        if not isinstance(obj, dict) or not obj.get("private_resource_confirmed"):
            continue
        oid = obj.get("operation_id")
        if oid not in index:
            raise ValueError("resource references an unknown operation")
        if not all(isinstance(obj.get(f), str) and ID.fullmatch(obj[f])
                   for f in ("id", "owner", "outsider", "owner_fixture", "outsider_fixture")):
            raise ValueError("actor and fixture references must be bounded IDs")
        if obj["owner"] == obj["outsider"] or obj["owner_fixture"] == obj["outsider_fixture"]:
            raise ValueError("need distinct controlled identities and their objects")
        op = index[oid]
        cases.append({
            "case_id": obj["id"], "operation_id": oid,
            "method": op["method"], "path_template": op["path"],
            "owner_actor": obj["owner"], "outsider_actor": obj["outsider"],
            "owner_fixture": obj["owner_fixture"],
            "outsider_fixture": obj["outsider_fixture"],
            "checks": [
                {"kind": "owner_positive", "expected": "own private marker readable"},
                {"kind": "cross_owner_negative", "expected": "other private marker inaccessible"},
                {"kind": "outsider_positive", "expected": "own private marker readable"},
                {"kind": "revoked_actor", "expected": "remains denied after subsequent activity",
                 "optional": True}
            ], "classification": "TEST_PLAN_NOT_EXECUTED",
        })
    return {"schema_version": 1, "mode": "authorization-matrix",
            "cases": cases, "count": len(cases), "network_requests": 0,
            "notice": "Plans require actual owned fixtures and explicit program permission; not proof."}


def analyze_state_trace(trace):
    """Observe declared authorization/payment invariant violations in saved LOCAL traces.

    Only positive assertions on explicit, observed fields are used; missing data
    becomes unknown. Trace JSON can be fabricated and needs an independent review.
    """
    if not isinstance(trace, dict) or trace.get("schema_version") != 1:
        raise ValueError("trace schema_version=1 required")
    events = trace.get("events")
    if not isinstance(events, list) or len(events) > MAX_EVENTS:
        raise ValueError("events must be a bounded list")
    revoked = set()
    seen_payments = set()
    findings, unknown = [], []
    def add(event, kind, why):
        findings.append({"event_index": event, "kind": kind, "reason": why,
                         "classification": "SUPPLIED_TRACE_INVARIANT_MISMATCH"})
    for i, ev in enumerate(events):
        if not isinstance(ev, dict):
            raise ValueError("events must be objects")
        kind = ev.get("kind")
        actor = ev.get("actor")
        resource = ev.get("resource")
        if kind in ("revoke", "grant"):
            if not isinstance(actor, str) or not isinstance(resource, str):
                raise ValueError("grant/revoke requires actor and resource")
            key = (actor, resource)
            if kind == "revoke":
                revoked.add(key)
            else:
                revoked.discard(key)
        elif kind == "access":
            if not isinstance(actor, str) or not isinstance(resource, str):
                raise ValueError("access requires actor and resource")
            if ev.get("allowed") is True and (actor, resource) in revoked:
                add(i, "REVOKED_ACCESS_RESTORED", "Access allowed after revocation without regrant")
            if ev.get("allowed") is True and ev.get("confirmed_private") is True:
                if ev.get("owner") and actor != ev["owner"] and ev.get("authorized_delegate") is False:
                    add(i, "CROSS_OWNER_ACCESS", "Explicitly nondelegated foreign object allowed")
                elif ev.get("authorized_delegate") is None and actor != ev.get("owner"):
                    unknown.append(i)
        elif kind == "payment_settled":
            fields = ("signature_valid", "order_bound", "amount_bound", "currency_bound")
            values = [ev.get(x) for x in fields]
            if any(v is False for v in values) and ev.get("settled") is True:
                add(i, "PAYMENT_BINDING_BROKEN", "Settlement despite an explicitly failed binding")
            elif not all(type(v) is bool for v in values):
                unknown.append(i)
            key = ev.get("idempotency_key")
            if isinstance(key, str) and key:
                if key in seen_payments and ev.get("additional_credit") is True:
                    add(i, "NON_IDEMPOTENT_SETTLEMENT", "Duplicate key credited again")
                seen_payments.add(key)
        else:
            unknown.append(i)
    return {"schema_version": 1, "mode": "state-trace",
            "events_checked": len(events), "leads": findings,
            "unknown_event_indices": unknown[:200], "input_sha256": digest(trace),
            "confirmed_vulnerabilities": 0, "network_requests": 0,
            "notice": "Supplied trace contradictions only, not authenticated execution evidence."}


def parser_differential(cases):
    """Deterministic offline parser ambiguity leads; no HTTP requests or payload delivery."""
    if not isinstance(cases, dict) or cases.get("schema_version") != 1:
        raise ValueError("schema_version=1 required")
    items = cases.get("cases")
    if not isinstance(items, list) or len(items) > 200:
        raise ValueError("cases must be a bounded list")
    leads = []
    for i, item in enumerate(items):
        if not isinstance(item, dict):
            raise ValueError("parser cases must be objects")
        raw = item.get("url")
        if not isinstance(raw, str) or len(raw) > 700 or any(ord(c) < 32 for c in raw):
            raise ValueError("parser URL must be a short printable string")
        p = urlsplit(raw)
        once = unquote(p.path)
        twice = unquote(once)
        if once != twice:
            leads.append({"case_index": i, "kind": "MULTI_STAGE_URL_DECODING",
                          "classification": "OFFLINE_DIFFERENTIAL_LEAD"})
        if "\\" in raw:
            leads.append({"case_index": i, "kind": "BACKSLASH_URL_NORMALIZATION",
                          "classification": "OFFLINE_DIFFERENTIAL_LEAD"})
        if p.fragment and p.query:
            leads.append({"case_index": i, "kind": "QUERY_FRAGMENT_INTERPRETATION",
                          "classification": "LOW_PRIORITY_REVIEW"})
    return {"schema_version": 1, "mode": "parser-diff", "leads": leads,
            "count": len(leads), "network_requests": 0,
            "notice": "Parser ambiguity is not smuggling, bypass, reachability or impact."}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("command", choices=("graph", "matrix", "state", "parser"))
    p.add_argument("--input", required=True, help="local OpenAPI/trace/cases JSON")
    p.add_argument("--fixtures", help="local owned fixture manifest; required for matrix")
    p.add_argument("--out", required=True, help="new private JSON artifact path")
    a = p.parse_args(argv)
    try:
        source = load_file(a.input)
        if a.command == "graph":
            result = build_operation_graph(source)
        elif a.command == "matrix":
            if not a.fixtures:
                raise ValueError("--fixtures is required for matrix")
            result = build_auth_matrix(source, load_file(a.fixtures))
        elif a.command == "state":
            result = analyze_state_trace(source)
        else:
            result = parser_differential(source)
        save_new(a.out, result)
    except (ValueError, OSError, TypeError, json.JSONDecodeError) as exc:
        p.error(str(exc))
    print(json.dumps({"mode": result["mode"], "out": a.out,
                      "leads": len(result.get("leads", []))}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
