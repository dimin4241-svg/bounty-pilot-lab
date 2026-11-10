#!/usr/bin/env python3
"""Offline HTTP frontend/backend parser observation differential with paired controls.

No raw HTTP payloads, requests, network sockets, target URLs or generated
smuggling probes. Input consists solely of bounded, saved observations from
two owned, isolated parser fixtures on identical input bytes. Input claims
are not independently authenticated; output never labels exploitation proven.
"""
import argparse
import json
import os
import re
import sys
from pathlib import Path

SHA = re.compile(r"^[0-9a-f]{64}$")
IDENT = re.compile(r"^[A-Za-z0-9_.:-]{1,100}$")
MAX_PAIRS = 100
CATEGORIES = (
    "HTTP_MESSAGE_BOUNDARY_DIFFERENCE",
    "HTTP_REQUEST_ROUTE_DIFFERENCE",
    "HTTP_AUTHORIZATION_CONTEXT_DIFFERENCE",
    "HTTP_CACHE_KEY_DIFFERENCE",
    "HTTP_BODY_INTERPRETATION_DIFFERENCE",
)
SEMANTIC_KEYS = ("method", "canonical_route", "authority", "auth_context",
                 "cache_key", "body_sha256")


def _load(path):
    p = Path(path).expanduser()
    if p.is_symlink() or not p.is_file() or p.stat().st_size > 2_000_000:
        raise ValueError("input must be regular, non-symlink JSON <=2MB")
    return json.loads(p.read_text(encoding="utf-8"), object_pairs_hook=_unique)


def _unique(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate JSON field")
        out[key] = value
    return out


def _save(path, data):
    p = Path(path)
    if p.exists() or p.is_symlink():
        raise ValueError("output must be new")
    p.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(p), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2, sort_keys=True)
        f.write("\n")


def _capture(c):
    if not isinstance(c, dict) or set(c) != {"parser_id", "parser_build", "input_sha256",
                                             "request_count", "consumed_bytes", "requests"}:
        raise ValueError("capture fields invalid")
    for key in ("parser_id", "parser_build"):
        if not isinstance(c[key], str) or not IDENT.fullmatch(c[key]):
            raise ValueError("parser identifiers must be bounded labels")
    if not isinstance(c["input_sha256"], str) or not SHA.fullmatch(c["input_sha256"]):
        raise ValueError("capture requires exact input sha256")
    count = c["request_count"]
    length = c["consumed_bytes"]
    if type(count) is not int or not 0 <= count <= 4 or (
            type(length) is not int or not 0 <= length <= 1_000_000):
        raise ValueError("invalid bounded consumed bytes/request count")
    rows = c["requests"]
    if not isinstance(rows, list) or len(rows) != count:
        raise ValueError("captured request list must match count")
    last = -1
    for row in rows:
        if not isinstance(row, dict) or set(row) != set(SEMANTIC_KEYS) | {
                "start_offset", "end_offset"}:
            raise ValueError("each request requires exact semantic and boundary fields")
        a, b = row["start_offset"], row["end_offset"]
        if (type(a) is not int or type(b) is not int or
                not 0 <= a < b <= 1_000_000 or a < last):
            raise ValueError("invalid or overlapping request byte offsets")
        last = b
        if b > length:
            raise ValueError("request end boundary exceeds parser consumed bytes")
        if row["body_sha256"] is not None and (
                not isinstance(row["body_sha256"], str) or
                not SHA.fullmatch(row["body_sha256"])):
            raise ValueError("body_sha256 invalid")
        for key in SEMANTIC_KEYS[:-1]:
            value = row[key]
            if value is not None and (not isinstance(value, str) or len(value) > 250 or
                                      any(ord(x) < 32 for x in value)):
                raise ValueError("request field is invalid")
    return c


def _trial(trial):
    if not isinstance(trial, dict) or set(trial) != {"front", "back"}:
        raise ValueError("trial must have separate front/back captures")
    a, b = _capture(trial["front"]), _capture(trial["back"])
    if a["parser_id"] == b["parser_id"]:
        raise ValueError("need two distinct declared parser identifiers")
    if a["input_sha256"] != b["input_sha256"]:
        raise ValueError("front/back must use the same input digest")
    return a, b


def _differences(a, b):
    # Unknown semantic fields must not masquerade as a parser disagreement.
    def known_difference(left, right, field):
        return (left[field] is not None and right[field] is not None and
                left[field] != right[field])

    differences = []
    if (a["request_count"] != b["request_count"] or
            a["consumed_bytes"] != b["consumed_bytes"] or
            [(r["start_offset"], r["end_offset"]) for r in a["requests"]] !=
            [(r["start_offset"], r["end_offset"]) for r in b["requests"]]):
        differences.append(CATEGORIES[0])
    for ar, br in zip(a["requests"], b["requests"]):
        if any(known_difference(ar, br, field) for field in ("method", "canonical_route", "authority")):
            differences.append(CATEGORIES[1])
        if known_difference(ar, br, "auth_context"):
            differences.append(CATEGORIES[2])
        if known_difference(ar, br, "cache_key"):
            differences.append(CATEGORIES[3])
        if known_difference(ar, br, "body_sha256"):
            differences.append(CATEGORIES[4])
    return sorted(set(differences))


def compare(doc):
    if not isinstance(doc, dict) or set(doc) != {"schema_version", "environment", "pairs"} or (
            type(doc.get("schema_version")) is not int or doc["schema_version"] != 1):
        raise ValueError("document requires exact schema_version, environment, pairs")
    if doc["environment"] != "researcher_owned_isolated_lab":
        raise ValueError("only researcher_owned_isolated_lab observation documents supported")
    pairs = doc["pairs"]
    if not isinstance(pairs, list) or not 1 <= len(pairs) <= MAX_PAIRS:
        raise ValueError("pairs must be 1..100 bounded lab pairs")
    results, seen = [], set()
    for row in pairs:
        if not isinstance(row, dict) or set(row) != {"pair_id", "candidate", "negative_control"}:
            raise ValueError("pair requires candidate and independent negative control")
        pid = row["pair_id"]
        if not isinstance(pid, str) or not IDENT.fullmatch(pid) or pid in seen:
            raise ValueError("invalid or duplicate pair ID")
        seen.add(pid)
        candidate_a, candidate_b = _trial(row["candidate"])
        control_a, control_b = _trial(row["negative_control"])
        if candidate_a["input_sha256"] == control_a["input_sha256"]:
            raise ValueError("negative control must use a distinct input digest")
        if candidate_a["parser_id"] != control_a["parser_id"] or (
                candidate_b["parser_id"] != control_b["parser_id"] or
                candidate_a["parser_build"] != control_a["parser_build"] or
                candidate_b["parser_build"] != control_b["parser_build"]):
            raise ValueError("candidate/control must use the same declared two parser builds")
        kinds = _differences(candidate_a, candidate_b)
        control_kinds = _differences(control_a, control_b)
        if kinds and not control_kinds:
            status = "CONTROLLED_PARSER_DIFFERENCE_IN_SUPPLIED_TRACES"
        elif kinds:
            status = "INCONCLUSIVE_CONTROL_ALSO_DIFFERS"
        else:
            status = "NO_DIFFERENCE_IN_SUPPLIED_TRACES"
        results.append({"pair_id": pid, "candidate_differences": kinds,
                        "negative_control_differences": control_kinds,
                        "status": status,
                        "input_digest_candidate": candidate_a["input_sha256"],
                        "input_digest_control": control_a["input_sha256"]})
    lead_count = sum(r["status"] == "CONTROLLED_PARSER_DIFFERENCE_IN_SUPPLIED_TRACES"
                     for r in results)
    result = {"schema_version": 1, "mode": "web-http-parser-boundary",
              "pairs_reviewed": len(results), "controlled_difference_leads": lead_count,
              "results": results,
              "network_requests": 0, "confirmed_vulnerabilities": 0,
              "limitations": ("All parser observations and build identifiers are operator-supplied "
                              "and unauthenticated; no raw requests or parser executables "
                              "are run. A parser difference does not prove request smuggling, "
                              "access control bypass or impact. Validate against the real "
                              "deployment with explicit scope permission and safe controls.") }
    return result


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--input", required=True, help="local paired parser observation JSON")
    p.add_argument("--out", required=True, help="new private output; no overwrite")
    a = p.parse_args(argv)
    try:
        result = compare(_load(a.input))
        _save(a.out, result)
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
        p.error(str(exc))
    print(json.dumps({"out": a.out, "controlled_difference_leads":
                      result["controlled_difference_leads"]}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
