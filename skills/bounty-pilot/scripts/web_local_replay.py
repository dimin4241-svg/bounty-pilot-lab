#!/usr/bin/env python3
"""Bounded HTTP replay of researcher-owned loopback fixtures.

Never accepts public hosts, DNS names, redirects, proxies, cookie jars, browser
state, arbitrary headers, or production targets. Credentials and marker values
are environment-only and never written. Results establish only LOCAL fixture
behavior, not production exploitability or bounty eligibility.
"""
import argparse
import hashlib
import json
import os
import re
import sys
import time
from pathlib import Path
from urllib import request, error
from urllib.parse import urlsplit

MAX_CASES = 12
MAX_BODY = 32768
ALLOWED = frozenset(("GET", "POST", "PUT", "PATCH", "DELETE"))
IDENT = re.compile(r"^[A-Za-z0-9_.:-]{1,100}$")
ENVNAME = re.compile(r"^BP_[A-Z0-9_]{3,75}$")


class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _read(path):
    p = Path(path)
    if p.is_symlink() or not p.is_file() or p.stat().st_size > 150000:
        raise ValueError("local input must be a regular JSON file <=150kB")
    return json.loads(p.read_text(encoding="utf-8"))


def _save_new(path, data):
    p = Path(path)
    if p.is_symlink() or p.exists():
        raise ValueError("output must be a new file")
    p.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(p), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(data, stream, ensure_ascii=False, sort_keys=True, indent=2)
        stream.write("\n")


def _env(name):
    if not isinstance(name, str) or not ENVNAME.fullmatch(name):
        raise ValueError("secret reference must be a BP_* environment variable")
    return name


def _path(value):
    if (not isinstance(value, str) or not value.startswith("/") or value.startswith("//") or
            len(value) > 450 or "#" in value or "\\" in value or
            any(ord(c) < 32 for c in value)):
        raise ValueError("only bounded loopback-relative paths are allowed")
    return value


def _config(plan):
    if not isinstance(plan, dict) or plan.get("schema_version") != 1:
        raise ValueError("plan schema_version=1 required")
    url = plan.get("base_url")
    if not isinstance(url, str):
        raise ValueError("base_url required")
    p = urlsplit(url)
    if p.scheme != "http" or p.hostname != "127.0.0.1" or not p.port or (
            p.username or p.password or p.path not in ("", "/") or p.query or p.fragment):
        raise ValueError("only literal http://127.0.0.1:PORT is permitted; no DNS")
    actors = plan.get("test_actors")
    if not isinstance(actors, dict) or not 2 <= len(actors) <= 6:
        raise ValueError("2..6 owned test actors required")
    refs = []
    for name, actor in actors.items():
        if not isinstance(name, str) or not IDENT.fullmatch(name) or not isinstance(actor, dict):
            raise ValueError("invalid test actor")
        refs.append(_env(actor.get("bearer_env")))
    if len(set(refs)) != len(refs):
        raise ValueError("actors must use distinct credential environment references")
    cases = plan.get("cases")
    if not isinstance(cases, list) or not 1 <= len(cases) <= MAX_CASES:
        raise ValueError("1..12 local owned cases required")
    identifiers = set()
    for case in cases:
        if not isinstance(case, dict) or not IDENT.fullmatch(str(case.get("id", ""))):
            raise ValueError("case requires bounded ID")
        if case["id"] in identifiers:
            raise ValueError("duplicate case ID")
        identifiers.add(case["id"])
        if case.get("private_resource_confirmed") is not True:
            raise ValueError("each case requires an investigator-owned PRIVATE resource")
        for field in ("owner", "cross", "outsider_control"):
            op = case.get(field)
            if not isinstance(op, dict) or op.get("actor") not in actors:
                raise ValueError(field + " requires a known owned test actor")
            if op.get("method") not in ALLOWED:
                raise ValueError("only explicitly supported HTTP methods are allowed")
            _path(op.get("path"))
            if "json_body" in op and (not isinstance(op["json_body"], dict) or
                                      len(json.dumps(op["json_body"])) > 4000):
                raise ValueError("json_body must be a small JSON object")
        if case["owner"]["actor"] == case["cross"]["actor"]:
            raise ValueError("owner and cross owner must be different actors")
        if case["cross"]["actor"] != case["outsider_control"]["actor"]:
            raise ValueError("cross and outsider control must use same outsider actor")
        _env(case.get("owner_marker_env"))
        _env(case.get("outsider_marker_env"))
        if case["owner_marker_env"] == case["outsider_marker_env"]:
            raise ValueError("private marker references must differ")
    return p, actors, cases


def _get_secret(name, env):
    value = env.get(name)
    if not isinstance(value, str) or not (8 <= len(value) <= 512) or "\n" in value or "\r" in value:
        raise ValueError("required fixture credential/marker is missing or invalid: " + name)
    return value


def _run_request(opener, url, step, actors, env, marker):
    token_name = actors[step["actor"]]["bearer_env"]
    bearer = _get_secret(token_name, env)
    method = step["method"]
    payload = None
    headers = {"Authorization": "Bearer " + bearer, "Accept": "application/json"}
    if "json_body" in step:
        payload = json.dumps(step["json_body"], separators=(",", ":")).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = request.Request(url + _path(step["path"]), data=payload,
                          headers=headers, method=method)
    try:
        with opener.open(req, timeout=2.5) as response:
            status = response.status
            body = response.read(MAX_BODY + 1)
    except error.HTTPError as exc:
        status = exc.code
        body = exc.read(MAX_BODY + 1)
    if len(body) > MAX_BODY:
        return {"status": status, "truncated": True, "marker_present": None}
    # Never persist body, private markers, bearer strings or their hashes.
    return {"status": status, "truncated": False,
            "marker_present": marker.encode("utf-8") in body}


def run(plan, env, execute=False):
    """Dry by default; execution is loopback ONLY with an explicit local flag."""
    parsed, actors, cases = _config(plan)
    if not execute:
        return {"schema_version": 1, "mode": "local-web-replay",
                "classification": "VALIDATED_PLAN_NOT_EXECUTED",
                "cases": len(cases), "network_requests": 0,
                "notice": "Only literal loopback can be executed and only with --execute."}
    if plan.get("local_fixture_confirmed") is not True:
        raise ValueError("must affirm local_fixture_confirmed=true")
    for actor in actors.values():
        _get_secret(actor["bearer_env"], env)
    opener = request.build_opener(request.ProxyHandler({}), NoRedirect())
    url = "http://127.0.0.1:" + str(parsed.port)
    results, total_requests = [], 0
    for case in cases:
        owner_marker = _get_secret(case["owner_marker_env"], env)
        outsider_marker = _get_secret(case["outsider_marker_env"], env)
        if owner_marker == outsider_marker:
            raise ValueError("fixture markers must be distinct")
        rounds = 2 if all(step["method"] == "GET" for step in
                          (case["owner"], case["cross"], case["outsider_control"])) else 1
        rounds_data = []
        for _ in range(rounds):
            samples = []
            for kind, marker in (("owner", owner_marker),
                                 ("cross", owner_marker),
                                 ("outsider_control", outsider_marker)):
                samples.append(_run_request(opener, url, case[kind], actors, env, marker))
                total_requests += 1
                time.sleep(0.02)
            rounds_data.append(samples)
        good_controls = all(r[0]["status"] in range(200, 300) and
                            r[0]["marker_present"] is True and
                            r[2]["status"] in range(200, 300) and
                            r[2]["marker_present"] is True for r in rounds_data)
        unauthorized = all(r[1]["status"] in range(200, 300) and
                           r[1]["marker_present"] is True for r in rounds_data)
        safe_negative = all(r[1]["status"] in (401, 403, 404) and
                            r[1]["marker_present"] is False for r in rounds_data)
        if good_controls and unauthorized:
            status = "LOCAL_REPRODUCED" if rounds == 2 else "LOCAL_CANDIDATE_SINGLE_ROUND"
        elif good_controls and safe_negative:
            status = "NO_BYPASS_OBSERVED_IN_LOCAL_FIXTURE"
        else:
            status = "INCONCLUSIVE"
        results.append({"id": case["id"], "status": status, "rounds": rounds,
                        "control_valid": good_controls, "observations": rounds_data,
                        "http_method": case["owner"]["method"]})
    evidence = {"schema_version": 1, "mode": "local-web-replay",
                "classification": "LOOPBACK_FIXTURE_OBSERVATION_ONLY",
                "results": results, "network_requests": total_requests,
                "environment": "literal_127.0.0.1_only",
                "confirmed_production_vulnerabilities": 0,
                "notice": ("Output does not establish a real-target defect, real-user impact or "
                           "eligibility. Review local fixture implementation and negative controls. "
                           "No live web requests were made.")}
    evidence["evidence_sha256"] = hashlib.sha256(json.dumps(
        results, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return evidence


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--plan", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--execute", action="store_true", help="loopback fixture only; never production")
    a = p.parse_args(argv)
    try:
        result = run(_read(a.plan), os.environ, execute=a.execute)
        _save_new(a.out, result)
    except (ValueError, OSError, TypeError, json.JSONDecodeError,
            error.URLError, TimeoutError) as exc:
        p.error(str(exc).replace(os.environ.get("BP_OWNER_TOKEN", "\0"), "[redacted]"))
    print(json.dumps({"classification": result["classification"],
                      "out": a.out, "requests": result["network_requests"]}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
