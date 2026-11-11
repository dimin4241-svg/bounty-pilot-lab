#!/usr/bin/env python3
"""One bounded, evidence-first Web/API research loop on owned observations.

Stages:
  1) fail-closed current operator-provided program policy preflight;
  2) compare sanitized owner/outsider owned-fixture HAR sequences;
  3) accept bounded precomputed local TS flow candidates;
  4) conservatively group candidates by code/operation invariant;
  5) suppress ONLY explicitly reviewed prior mechanisms at same revision;
  6) budget candidate work orders for independent model/manual review;
  7) optionally replay a distinct owned 127.0.0.1 fixture, with explicit opt-in
     and independent candidate/negative-control effect measurement.

No live target scanning, no report submission, no LLM calls, and no claim of
exploitable deployed behavior. This prepares a reproducible evidence trail
that the operator can use to coordinate existing agent_dispatch and
evidence_verifier, which retain their own security/evidence gates.
"""
import argparse
import hashlib
import json
import math
import os
import re
import sys
from pathlib import Path

MAX_DOC = 3_000_000
SHA40 = re.compile(r"^[a-f0-9]{40}$")
SHA64 = re.compile(r"^[a-f0-9]{64}$")
IDENT = re.compile(r"^[A-Za-z0-9_.:/-]{1,160}$")
ROUTE = re.compile(r"^[a-f0-9]{20}$")
MAX_STATIC = 100
MAX_CAPTURE = 200


def _load_module(name):
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "bp_campaign_" + name, Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _unique(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError("duplicate JSON field")
        obj[key] = value
    return obj


def _read(path):
    p = Path(path).expanduser()
    if p.is_symlink() or not p.is_file() or p.stat().st_size > MAX_DOC:
        raise ValueError("bounded, non-symlink local JSON input required")
    return json.loads(p.read_text(encoding="utf-8"), object_pairs_hook=_unique)


def _write(path, data):
    p = Path(path).expanduser()
    if p.is_symlink() or p.exists():
        raise ValueError("report output must be unused")
    p.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as file:
        json.dump(data, file, ensure_ascii=False, indent=2, sort_keys=True)
        file.write("\n")


def _digest(value):
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")).hexdigest()


def _id(value, label):
    if not isinstance(value, str) or not IDENT.fullmatch(value):
        raise ValueError(label + " requires opaque bounded identifier")
    return value


def _validate_capture(doc, expected_role):
    if (not isinstance(doc, dict) or doc.get("schema_version") != 1 or
            doc.get("mode") != "owned-loopback-har-capture" or
            doc.get("actor") != expected_role or
            doc.get("origin_kind") != "literal_127_0_0_1" or
            doc.get("network_requests") != 0):
        raise ValueError("only local, sanitized, expected-role HAR summaries")
    if (doc.get("raw_headers_preserved") is not False or
            doc.get("raw_query_preserved") is not False or
            doc.get("raw_body_preserved") is not False):
        raise ValueError("unsanitized HAR summaries are prohibited")
    rows = doc.get("events")
    if (not isinstance(rows, list) or not 1 <= len(rows) <= MAX_CAPTURE or
            doc.get("event_count") != len(rows)):
        raise ValueError("capture event list malformed")
    ids, last = set(), 0
    normalized = []
    for row in rows:
        if not isinstance(row, dict) or set(row) != {
                "event", "seq", "actor", "method", "route_key",
                "route_shape", "object_key", "http_status", "status_class",
                "privileged_business_effect_proven"}:
            raise ValueError("unexpected capture event fields")
        if row["actor"] != expected_role or row["event"] in ids:
            raise ValueError("capture actor/id mismatch")
        ids.add(row["event"])
        if type(row["seq"]) is not int or row["seq"] <= last:
            raise ValueError("capture sequence invalid")
        last = row["seq"]
        if not isinstance(row["route_key"], str) or not ROUTE.fullmatch(row["route_key"]):
            raise ValueError("route fingerprint invalid")
        if (not isinstance(row["route_shape"], str) or
                not re.fullmatch(r"/[A-Za-z0-9_./:-]{0,800}", row["route_shape"])):
            raise ValueError("unsafe route shape")
        if (row["object_key"] is not None and
                (not isinstance(row["object_key"], str) or not
                 re.fullmatch(r"[a-f0-9]{24}", row["object_key"]))):
            raise ValueError("object fingerprint invalid")
        if (row["method"] not in ("GET", "POST", "PUT", "PATCH", "DELETE") or
                type(row["http_status"]) is not int or not
                100 <= row["http_status"] <= 599 or
                row["status_class"] != str(row["http_status"] // 100) + "xx"):
            raise ValueError("HTTP observation malformed")
        if row["privileged_business_effect_proven"] is not False:
            raise ValueError("HTTP response cannot be marked proven effect")
        normalized.append(row)
    return normalized


def _static_flows(doc):
    if doc is None:
        return []
    if (not isinstance(doc, dict) or doc.get("schema_version") != 1 or
            doc.get("mode") != "web-ts-cross-file-flow" or
            doc.get("network_requests") != 0 or
            doc.get("confirmed_vulnerabilities") != 0):
        raise ValueError("only offline unverified JS/TS analysis supported")
    rows = doc.get("flows")
    if not isinstance(rows, list) or len(rows) > MAX_STATIC:
        raise ValueError("bounded JS/TS flow list required")
    out = []
    for row in rows:
        if (not isinstance(row, dict) or
                row.get("classification") != "UNVERIFIED_STATIC_ARGUMENT_FLOW"):
            raise ValueError("unsupported static finding classification")
        entry, sink = row.get("entry"), row.get("sink")
        if not isinstance(entry, dict) or not isinstance(sink, dict):
            raise ValueError("static entry/sink missing")
        src = _id(entry.get("file"), "relative source file")
        dst = _id(sink.get("file"), "relative sink file")
        if src.startswith("/") or ".." in src.split("/") or dst.startswith("/") or ".." in dst.split("/"):
            raise ValueError("static path outside checkout")
        call = _id(sink.get("call"), "sensitive call")
        if len(call) > 160:
            raise ValueError("sensitive call too long")
        if type(sink.get("line")) is not int or sink["line"] < 1:
            raise ValueError("static finding requires source line")
        out.append({"source_file": dst, "code_anchor": call + ":" + str(sink["line"]),
                    "route_shape": entry.get("path", ""),
                    "invariant": "request-argument-to-sensitive-call",
                    "boundary": "request-to-storage",
                    "source_kind": "STATIC_SYNTAX_ONLY",
                    "source_ref": str(row.get("id", ""))[:60]})
    return out


def _candidate(name, source, anchor, invariant, boundary, effect, scores,
               origin, digest):
    key = _digest([name, source, anchor, invariant, boundary, effect, origin])[:20]
    return {
        "id": "lead-" + key,
        "source_file": source, "code_anchor": anchor,
        "invariant_id": invariant, "trust_boundary_id": boundary,
        "reviewed_root_cause_id": None, "claimed_effect_id": effect,
        "evidence": dict(zip((
            "reachability", "trust_boundary", "business_effect",
            "novelty", "testability"), scores)),
        "evidence_digest": digest, "disposition": "unreviewed"
    }


def _source_candidate(row):
    digest = _digest(row)
    return _candidate("static", row["source_file"], row["code_anchor"],
                      "unverified-static-flow", "request-to-sink",
                      "unverified-impact", (1, 1, 0, 1, 1),
                      row["source_ref"], digest)


def _cap_candidates(owner, outsider, declared_owner_only):
    own = {}
    other = {}
    for rows, target in ((owner, own), (outsider, other)):
        for r in rows:
            if r["object_key"] and r["method"] == "GET":
                target.setdefault((r["route_key"], r["object_key"]), []).append(r)
    shared = sorted(set(own) & set(other))
    leads, observations = [], []
    for route, obj in shared[:120]:
        a, b = own[(route, obj)][0], other[(route, obj)][0]
        is_owner_only = route in declared_owner_only
        both_success = a["status_class"] == "2xx" and b["status_class"] == "2xx"
        difference = (a["status_class"] != b["status_class"])
        state = ("OWNER_ONLY_DECLARED_AND_BOTH_HTTP_2XX_REVIEW_ONLY"
                 if is_owner_only and both_success else
                 "CROSS_ACTOR_STATUS_DIFFERENCE_REVIEW_ONLY" if difference else
                 "SHARED_OBJECT_ROUTE_NO_AUTHORIZATION_CONCLUSION")
        observations.append({
            "route_key": route, "object_key": obj,
            "owner_http_status": a["http_status"],
            "outsider_http_status": b["http_status"],
            "operator_declared_owner_only": is_owner_only,
            "classification": state, "protected_effect_proven": False})
        if is_owner_only and both_success:
            leads.append(_candidate(
                "observed-cross-actor", "captured-http", route,
                "declared-owner-only", "owner-outsider",
                "unverified-private-read", (2, 1, 0, 1, 2),
                obj, _digest([a["event"], b["event"], route, obj, state])))
    return leads, observations


def _known_records(rows, project, revision):
    if not isinstance(rows, list) or len(rows) > 300:
        raise ValueError("known root-cause ledger must be bounded list")
    keys = set()
    for row in rows:
        if not isinstance(row, dict) or set(row) != {
                "project", "revision", "source_file", "code_anchor",
                "invariant_id", "trust_boundary_id", "reviewed_by",
                "evidence_sha256", "disposition"}:
            raise ValueError("invalid known mechanism entry")
        if row["project"] != project or row["revision"] != revision:
            continue
        for key in ("source_file", "code_anchor", "invariant_id",
                    "trust_boundary_id", "reviewed_by"):
            _id(row[key], key)
        if (row["disposition"] not in ("known-duplicate", "refuted") or
                not isinstance(row["evidence_sha256"], str) or
                not SHA64.fullmatch(row["evidence_sha256"])):
            raise ValueError("reviewed previous cause needs evidence and disposition")
        keys.add((row["source_file"], row["code_anchor"], row["invariant_id"],
                  row["trust_boundary_id"]))
    return keys


def _budget(spec):
    if not isinstance(spec, dict) or set(spec) != {
            "max_review_jobs", "max_usd_per_job", "max_usd_total"}:
        raise ValueError("strict per-campaign planning budget required")
    count, per, total = (spec["max_review_jobs"], spec["max_usd_per_job"],
                         spec["max_usd_total"])
    if type(count) is not int or not 0 <= count <= 30:
        raise ValueError("review job count must be 0..30")
    if (type(per) not in (int, float) or not math.isfinite(per)
            or not 0 < per <= 10):
        raise ValueError("planned per-job USD must be 0..10 and finite")
    if (type(total) not in (int, float) or not math.isfinite(total)
            or not 0 <= total <= 100):
        raise ValueError("planned total USD must be 0..100")
    return {"max_review_jobs": count, "max_usd_per_job": round(per, 6),
            "max_usd_total": round(total, 6)}


def _manifest(doc):
    if not isinstance(doc, dict) or set(doc) != {
            "schema_version", "environment", "project", "source_revision",
            "program_policy", "request_plan", "owner_capture",
            "outsider_capture", "owner_only_route_keys", "static_analysis",
            "known_mechanisms", "budget", "local_effect_fixture"}:
        raise ValueError("exact self-contained Web hunt plan fields required")
    if type(doc["schema_version"]) is not int or doc["schema_version"] != 1:
        raise ValueError("schema 1 required")
    if doc["environment"] != "researcher_owned_lab":
        raise ValueError("only owned research environment")
    _id(doc["project"], "project")
    if not isinstance(doc["source_revision"], str) or not SHA40.fullmatch(doc["source_revision"]):
        raise ValueError("pinned source revision required")
    keys = doc["owner_only_route_keys"]
    if (not isinstance(keys, list) or len(keys) > 100 or
            len(set(keys)) != len(keys) or
            any(not isinstance(k, str) or not ROUTE.fullmatch(k) for k in keys)):
        raise ValueError("operator-declared route fingerprints invalid")
    _budget(doc["budget"])
    if not isinstance(doc["request_plan"], list):
        raise ValueError("policy request plan must be JSON array")
    if not isinstance(doc["known_mechanisms"], list):
        raise ValueError("known mechanisms must be list")
    if doc["local_effect_fixture"] is not None:
        _load_module("web_effect_fixture_replay").validate(doc["local_effect_fixture"])
    return doc


def execute(doc, run_owned_fixture=False, now=None):
    _manifest(doc)
    policy = _load_module("web_program_policy")
    prelim = policy.evaluate(doc["program_policy"], doc["request_plan"], now)
    permitted = all(x["allowed_by_saved_preflight"] for x in prelim["checks"])
    if not permitted:
        if run_owned_fixture:
            raise ValueError("blocked program preflight: no local execution")
        return {"schema_version": 1, "mode": "web-hunt-loop",
                "state": "BLOCKED_POLICY_PLAN", "program_policy": prelim,
                "candidates": [], "review_jobs": [],
                "confirmed_vulnerabilities": 0, "real_model_calls": 0,
                "actual_model_cost_usd": 0, "network_requests": 0}
    owner = _validate_capture(doc["owner_capture"], "owner")
    outsider = _validate_capture(doc["outsider_capture"], "outsider")
    static = _static_flows(doc["static_analysis"])
    cap, cross = _cap_candidates(owner, outsider, set(doc["owner_only_route_keys"]))
    candidates = cap + [_source_candidate(x) for x in static]
    if len(candidates) > 300:
        raise ValueError("too many candidate leads")
    unique = {x["id"]: x for x in candidates}
    if len(unique) != len(candidates):
        # Duplicate leads from the exact same source anchor provide no
        # independent evidence: group before ranking, never count twice.
        candidates = list(unique.values())
    known = _known_records(doc["known_mechanisms"], doc["project"],
                           doc["source_revision"])
    unreviewed, suppressed = [], []
    for c in candidates:
        key = (c["source_file"], c["code_anchor"], c["invariant_id"],
               c["trust_boundary_id"])
        if key in known:
            suppressed.append({"candidate_id": c["id"],
                               "reason": "OPERATOR_ASSERTED_REVIEWED_SAME_REVISION"})
        else:
            unreviewed.append(c)
    dedup = _load_module("web_root_cause_dedup")
    grouped = (dedup.analyze({
        "schema_version": 1, "project": doc["project"],
        "pinned_revision": doc["source_revision"],
        "candidates": unreviewed}) if unreviewed else {
            "groups": [], "review_related": [], "confirmed_vulnerabilities": 0})
    budget = _budget(doc["budget"])
    capacity = min(budget["max_review_jobs"], int(
        (budget["max_usd_total"] + 1e-9) / budget["max_usd_per_job"]))
    jobs = []
    by_id = {c["id"]: c for c in unreviewed}
    for group in grouped["groups"][:capacity]:
        chosen = by_id[group["preferred_review_id"]]
        jobs.append({
            "job_id": "review-" + group["group_id"],
            "candidate_id": group["preferred_review_id"],
            "source_file": chosen["source_file"],
            "code_anchor": chosen["code_anchor"],
            "invariant_id": chosen["invariant_id"],
            "trust_boundary_id": chosen["trust_boundary_id"],
            "claimed_effect_id": chosen["claimed_effect_id"],
            "planned_max_usd": budget["max_usd_per_job"],
            "reason": "INDEPENDENT_HUMAN_OR_MODEL_REVIEW_NEEDED",
            "required_checks": [
                "Verify actual identity and authorization policy",
                "Prove reachable execution and inspect existing guards",
                "Run candidate and independent negative control",
                "Measure real post-state, not HTTP status alone",
                "Check prior published and internal duplicates",
                "Independently review all claimed effect artifacts"],
            "automatically_invoked": False
        })
    local = None
    if run_owned_fixture:
        if doc["local_effect_fixture"] is None:
            raise ValueError("owned fixture plan absent")
        replay = _load_module("web_effect_fixture_replay")
        local = replay.replay(doc["local_effect_fixture"])
    return {
        "schema_version": 1, "mode": "web-hunt-loop",
        "state": ("CONTROLLED_LOCAL_EFFECT_REPLAY_UNVERIFIED" if local else
                  "OFFLINE_REVIEW_QUEUE_NOT_EXECUTED"),
        "project": doc["project"], "source_revision": doc["source_revision"],
        "program_policy": prelim,
        "capture_summaries": {
            "owner_events": len(owner), "outsider_events": len(outsider),
            "cross_actor_same_object": cross},
        "static_flow_leads": len(static),
        "candidate_count": len(candidates),
        "reviewed_suppressions": suppressed,
        "root_cause_groups": grouped["groups"],
        "manual_similarity_review": grouped["review_related"],
        "review_jobs": jobs, "unassigned_group_count": max(
            0, len(grouped["groups"]) - len(jobs)),
        "budget": dict(budget, max_planned_spend_usd=round(
            len(jobs) * budget["max_usd_per_job"], 6)),
        "owned_fixture_replay": local,
        "real_model_calls": 0, "actual_model_cost_usd": 0,
        "network_requests_external": 0,
        "confirmed_vulnerabilities": 0, "ready_to_submit": False,
        "limitations": ("Program rules, capture identity, policy assertions, source "
                        "revision and prior-review evidence are operator supplied "
                        "and not independently verified. Only limited owned-loopback "
                        "fixture actions run with explicit opt-in. No model CLI, "
                        "black-box exploration or external target is launched. "
                        "Status-code leads, local scalar effects and source syntax "
                        "are never treated as deployable exploit proof.")}
    

def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--input", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--execute-owned-fixture", action="store_true",
                   help="only literal 127.0.0.1 owned fixture GET/empty POST, opt-in")
    a = p.parse_args(argv)
    try:
        data = _read(a.input)
        output = Path(a.out).expanduser()
        if output.exists() or output.is_symlink():
            raise ValueError("output must not exist before any local execution")
        result = execute(data, a.execute_owned_fixture)
        _write(a.out, result)
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
        p.error(str(exc))
    print(json.dumps({"out": a.out, "state": result["state"],
                      "jobs_planned": len(result["review_jobs"]),
                      "model_calls": 0, "confirmed_vulnerabilities": 0}))
    return 0 if result["state"] != "BLOCKED_POLICY_PLAN" else 2


if __name__ == "__main__":
    sys.exit(main())
