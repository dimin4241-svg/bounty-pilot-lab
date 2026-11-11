#!/usr/bin/env python3
"""Bounded actual HTTP effect replay against a researcher-owned 127.0.0.1 fixture.

This is NOT a remotely usable scanner. It only issues literal loopback GETs
for before/after state and empty-body POSTs on distinct owned lab endpoints.
No redirects, DNS, proxies, cookies, arbitrary headers, external URLs,
credentials, or target source execution. Outputs only one declared scalar
business-state field per observation plus evidence hashes.
"""
import argparse
import hashlib
import importlib.util
import json
import math
import os
import re
import sys
from pathlib import Path
from urllib import error, request
from urllib.parse import urlsplit

MAX_BODY = 8192
MAX_ROUNDS = 5
PATH = re.compile(r"^/[A-Za-z0-9_./:-]{1,239}$")
ID = re.compile(r"^[A-Za-z0-9_.:-]{1,100}$")


class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("local fixture redirects are forbidden")


def _load(path):
    p = Path(path)
    if p.is_symlink() or not p.is_file() or p.stat().st_size > 300000:
        raise ValueError("regular owned-fixture plan <=300KB required")
    return json.loads(p.read_text(encoding="utf-8"), object_pairs_hook=_unique)


def _unique(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise ValueError("duplicate JSON field")
        d[k] = v
    return d


def _save(path, obj):
    p = Path(path)
    if p.is_symlink() or p.exists():
        raise ValueError("private output must not already exist")
    p.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(obj, f, sort_keys=True, ensure_ascii=False, indent=2)
        f.write("\n")


def _path(value):
    if (not isinstance(value, str) or not PATH.fullmatch(value) or
            "//" in value or any(part in (".", "..") for part in value.split("/"))):
        raise ValueError("fixture path must be unambiguous local ASCII path")
    return value


def _port_origin(value):
    if not isinstance(value, str):
        raise ValueError("literal loopback origin required")
    try:
        u = urlsplit(value)
        port = u.port
    except ValueError as exc:
        raise ValueError("invalid loopback port") from exc
    if (u.scheme != "http" or u.hostname != "127.0.0.1" or
            port is None or not 1024 <= port <= 65535 or
            value != "http://127.0.0.1:" + str(port) or
            u.username is not None or u.password is not None or
            u.query or u.fragment or u.path):
        raise ValueError("only canonical http://127.0.0.1:PORT is accepted")
    return value


def validate(plan):
    if (not isinstance(plan, dict) or set(plan) != {
            "schema_version", "ownership_attestation", "origin", "case_id",
            "resource_kind", "business_effect", "predicate", "rounds"} or
            type(plan["schema_version"]) is not int or plan["schema_version"] != 1 or
            plan["ownership_attestation"] != "I_CONTROL_THIS_LOCAL_FIXTURE"):
        raise ValueError("exact owned loopback fixture plan required")
    origin = _port_origin(plan["origin"])
    for key in ("case_id", "business_effect"):
        if not isinstance(plan[key], str) or not ID.fullmatch(plan[key]):
            raise ValueError(key + " must be bounded opaque label")
    if plan["resource_kind"] not in (
            "payment-sandbox", "subscription", "export", "approval",
            "job", "object", "refund-sandbox", "other"):
        raise ValueError("unknown resource type")
    rule = plan["predicate"]
    if (not isinstance(rule, dict) or set(rule) != {"field", "relation", "value"}
            or not isinstance(rule["field"], str) or not ID.fullmatch(rule["field"])
            or rule["relation"] not in (
                "increased", "decreased", "changed", "unchanged", "equals")
            or type(rule["value"]) not in (int, float, bool, str, type(None))):
        raise ValueError("invalid effect predicate")
    rounds = plan["rounds"]
    if not isinstance(rounds, list) or not 2 <= len(rounds) <= MAX_ROUNDS:
        raise ValueError("two to five independent owned fixture rounds required")
    seen_state, seen_action = set(), set()
    for item in rounds:
        if not isinstance(item, dict) or set(item) != {"candidate", "negative_control"}:
            raise ValueError("each round needs candidate and control routes")
        for role in ("candidate", "negative_control"):
            paths = item[role]
            if not isinstance(paths, dict) or set(paths) != {
                    "state_path", "action_path"}:
                raise ValueError("mode requires state_path and action_path")
            st, act = _path(paths["state_path"]), _path(paths["action_path"])
            if st == act or st in seen_state or act in seen_action or (
                    st in seen_action or act in seen_state):
                raise ValueError("rounds/controls require disjoint fixture endpoints")
            seen_state.add(st)
            seen_action.add(act)
    return origin


def _call(opener, origin, path, method):
    body = b"{}" if method == "POST" else None
    req = request.Request(origin + path, method=method, data=body,
                          headers={"Content-Type": "application/json",
                                   "X-Bp-Fixture": "owned-loopback-only"})
    try:
        with opener.open(req, timeout=3) as response:
            if not 200 <= response.status < 300:
                raise ValueError("fixture returned non-2xx response")
            content = response.read(MAX_BODY + 1)
            if len(content) > MAX_BODY:
                raise ValueError("fixture body exceeds 8KB limit")
            return response.status, content
    except (error.URLError, error.HTTPError, TimeoutError) as exc:
        raise ValueError("local fixture request failed; see local server logs") from exc


def _read_state(opener, origin, path, field):
    status, body = _call(opener, origin, path, "GET")
    try:
        state = json.loads(body)
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError("owned local fixture did not return JSON state") from exc
    if not isinstance(state, dict) or field not in state:
        raise ValueError("owned fixture missing required observed state field")
    value = state[field]
    if (type(value) not in (int, float, str, bool, type(None)) or
            isinstance(value, str) and len(value) > 120 or
            isinstance(value, float) and not math.isfinite(value)):
        raise ValueError("fixture state field must be a safe bounded scalar")
    return status, {field: value}


def _evidence(round_number, role, before, after, action_status, state_path):
    record = {"round": round_number, "role": role, "before": before,
              "after": after, "action_http_status": action_status,
              "state_path": state_path}
    return hashlib.sha256(json.dumps(record, sort_keys=True,
                                     ensure_ascii=True).encode("ascii")).hexdigest()


def replay(plan):
    origin = validate(plan)
    # ProxyHandler({}) explicitly disables proxies. The bare literal IPv4
    # host prohibits DNS rebinding, and redirects never change the peer.
    opener = request.build_opener(request.ProxyHandler({}), NoRedirect())
    candidate, controls = [], []
    field = plan["predicate"]["field"]
    for index, paths in enumerate(plan["rounds"]):
        c = paths["candidate"]
        n = paths["negative_control"]
        _, c_before = _read_state(opener, origin, c["state_path"], field)
        _, n_before = _read_state(opener, origin, n["state_path"], field)
        if c_before != n_before:
            raise ValueError("candidate/control fixture baseline differs")
        cs, _ = _call(opener, origin, c["action_path"], "POST")
        ns, _ = _call(opener, origin, n["action_path"], "POST")
        _, c_after = _read_state(opener, origin, c["state_path"], field)
        _, n_after = _read_state(opener, origin, n["state_path"], field)
        for mode, before, after, status, route, output in (
            ("candidate", c_before, c_after, cs, c["state_path"], candidate),
            ("control", n_before, n_after, ns, n["state_path"], controls)):
            output.append({"before": before, "after": after,
                           "evidence_sha256": _evidence(
                               index, mode, before, after, status, route),
                           "effect_observed_at_step": 2})
    oracle_input = {
        "schema_version": 1, "environment": "researcher_owned_lab",
        "cases": [{
            "id": plan["case_id"], "resource_kind": plan["resource_kind"],
            "business_effect": plan["business_effect"],
            "predicate": plan["predicate"],
            "candidate_repetitions": candidate, "negative_control": controls
        }]}
    # Invoke the *same* offline oracle that checks investigator-supplied
    # traces, so the native replay and manual workflow share one gate.
    spec = importlib.util.spec_from_file_location(
        "bp_effect_oracle_local",
        Path(__file__).with_name("web_effect_oracle.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    reviewed = module.analyze(oracle_input)
    return {
        "schema_version": 1, "mode": "web-effect-fixture-replay",
        "effect_oracle_input": oracle_input,
        "oracle_review": reviewed,
        "execution": "RESEARCHER_OWNED_LOOPBACK_ONLY",
        "network_request_count_local": len(plan["rounds"]) * 6,
        "network_requests_external": 0, "confirmed_production_vulnerabilities": 0,
        "limitations": ("A locally observed effect is not authorization bypass "
                        "or evidence of a deployed site's configuration. "
                        "Fixtures are declared owned and not externally attested. "
                        "Before/after JSON values come from a local fixture and "
                        "must be independently reviewed for real semantics.")}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--plan", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--execute", action="store_true",
                   help="mandatory confirmation before any loopback POST")
    a = p.parse_args(argv)
    try:
        plan = _load(a.plan)
        validate(plan)
        if a.execute and (Path(a.out).exists() or Path(a.out).is_symlink()):
            raise ValueError("output path must be unused before executing local actions")
        if not a.execute:
            result = {"status": "PLAN_VALIDATED_NOT_EXECUTED", "network_requests": 0,
                      "out": None, "production_targets_supported": False}
        else:
            result = replay(plan)
            _save(a.out, result)
    except (ValueError, OSError, TypeError, KeyError, json.JSONDecodeError) as exc:
        p.error(str(exc))
    print(json.dumps({"out": a.out if a.execute else None,
                      "status": (result["oracle_review"]["results"][0]["status"]
                                 if a.execute else result["status"]),
                      "external_network_requests": 0}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
