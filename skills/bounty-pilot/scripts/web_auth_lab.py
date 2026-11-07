#!/usr/bin/env python3
"""Safe-by-default, controlled two-account GET authorization replay.

Dry-run validates a privately curated plan. Execution requires an explicitly
confirmed, currently allowed scope, two investigator-owned test identities and
a pinned HTTPS hostname. Only bounded GETs, no redirects, no cookies, no
mutations, no guessed identifiers, no broad scans, no response-body logging.
The tester must confirm the resource is genuinely PRIVATE and markers unique.
"""
import argparse
import hashlib
import json
import os
import platform
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib import error, request
from urllib.parse import urlsplit

ID = re.compile(r"^[A-Za-z0-9_.:-]{1,100}$")
TOKEN_ENV = re.compile(r"^[A-Z][A-Z0-9_]{2,79}$")
MAX_BODY = 65536
MAX_CASES = 12


class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, request_, fp, code, msg, hdrs, newurl):
        return None


def _date(value):
    if not isinstance(value, str):
        raise ValueError("scope_confirmed_at must be a timezone-aware ISO8601 string")
    try:
        d = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("invalid scope timestamp") from exc
    if d.tzinfo is None:
        raise ValueError("scope timestamp missing timezone")
    return d.astimezone(timezone.utc)


def _path(value):
    if not isinstance(value, str) or len(value) > 600 or not value.startswith("/") or value.startswith("//"):
        raise ValueError("resource paths must be bounded same-origin absolute paths")
    if any(c in value for c in ("\r", "\n", "\\", "#")):
        raise ValueError("resource paths contain disallowed characters")
    u = urlsplit(value)
    if u.scheme or u.netloc or u.fragment or "/../" in u.path or u.path.endswith("/.."):
        raise ValueError("no absolute or traversing resource URLs")
    return value


def validate(data, host, require_permission=False):
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise ValueError("plan schema_version=1 required")
    url = data.get("base_url")
    if not isinstance(url, str) or len(url) > 500:
        raise ValueError("base_url required")
    p = urlsplit(url)
    if p.scheme != "https" or not p.hostname or p.username or p.password or p.path not in ("", "/") or p.query or p.fragment:
        raise ValueError("base_url must be HTTPS origin without credentials/path/query")
    if host is not None and host.casefold() != p.hostname.casefold():
        raise ValueError("--allowed-host differs from base_url")
    cases = data.get("cases")
    if not isinstance(cases, list) or not 1 <= len(cases) <= MAX_CASES:
        raise ValueError("1..12 cases required")
    seen = set()
    for c in cases:
        if not isinstance(c, dict) or not isinstance(c.get("id"), str) or not ID.fullmatch(c["id"]):
            raise ValueError("each case must have safe id")
        if c["id"] in seen:
            raise ValueError("duplicate case id")
        seen.add(c["id"])
        if c.get("private_resource_confirmed") is not True:
            raise ValueError("private_resource_confirmed=true required for each case")
        for key in ("owner_resource", "outsider_control_resource"):
            _path(c.get(key))
        if c["owner_resource"] == c["outsider_control_resource"]:
            raise ValueError("owner and outsider control resources must differ")
        for key in ("owner_marker", "outsider_control_marker"):
            val = c.get(key)
            if not isinstance(val, str) or len(val) < 8 or len(val) > 200:
                raise ValueError("each account must have a unique >=8-character synthetic marker")
        if c["owner_marker"] == c["outsider_control_marker"]:
            raise ValueError("control marker must differ from victim marker")
    names = data.get("test_actors")
    if not isinstance(names, dict) or set(names) != {"owner", "outsider"}:
        raise ValueError("test_actors requires owner and outsider")
    env_names = []
    for actor in ("owner", "outsider"):
        entry = names[actor]
        val = entry.get("bearer_env") if isinstance(entry, dict) else None
        if not isinstance(val, str) or not TOKEN_ENV.fullmatch(val):
            raise ValueError("bearer_env must name an environment variable")
        env_names.append(val)
    if len(set(env_names)) != 2:
        raise ValueError("test identities must use different credentials")
    if require_permission:
        if data.get("authorization_confirmed") is not True or data.get("automation_permitted") is not True:
            raise ValueError("explicit authorization_confirmed and automation_permitted required")
        official = data.get("program_url")
        if not isinstance(official, str) or not official.startswith("https://"):
            raise ValueError("official program_url required")
        confirmed = _date(data.get("scope_confirmed_at"))
        age = datetime.now(timezone.utc) - confirmed
        if age.total_seconds() < -300 or age.total_seconds() > 30 * 86400:
            raise ValueError("scope confirmation must be within the past 30 days")
    return url.rstrip("/")


def fetch(opener, url, token, marker):
    req = request.Request(url, method="GET", headers={
        "Authorization": "Bearer " + token,
        "Accept": "application/json, text/plain, */*",
        "Cache-Control": "no-store",
        "User-Agent": "BountyPilot-ControlledAuthLab/1.0"
    })
    try:
        resp = opener.open(req, timeout=8)
    except error.HTTPError as response:
        resp = response
    with resp:
        body = resp.read(MAX_BODY + 1)
        status = resp.status
    complete = len(body) <= MAX_BODY
    # Never persist raw response, marker or bearer token.
    return {"status": int(status), "complete": complete,
            "marker_present": bool(complete and marker.encode("utf-8") in body),
            "body_sha256": hashlib.sha256(body).hexdigest() if complete else None}


def evaluate_case(item, owner, crossed, outsider_control):
    owner_ok = owner["complete"] and owner["status"] == 200 and owner["marker_present"]
    outsider_works = (outsider_control["complete"] and
                      outsider_control["status"] == 200 and outsider_control["marker_present"])
    crossed_seen = crossed["complete"] and crossed["status"] == 200 and crossed["marker_present"]
    status = ("cross-account-exposure-candidate-needs-review"
              if owner_ok and outsider_works and crossed_seen
              else "inconclusive")
    return {
        "id": item["id"], "status": status,
        "owner": owner, "outsider_to_owner": crossed, "outsider_self_control": outsider_control,
        "review": ("Only synthetic markers on investigator-owned test accounts; "
                   "confirm the endpoint is private, roles and scope, no shared data, "
                   "cache artifacts or expected cross-account authorization.")
    }


def run(data, host):
    origin = validate(data, host, True)
    tokens = {}
    for role in ("owner", "outsider"):
        env = data["test_actors"][role]["bearer_env"]
        value = os.environ.get(env, "")
        if len(value) < 8 or len(value) > 8192:
            raise ValueError("missing or invalid bearer token environment for " + role)
        tokens[role] = value
    opener = request.build_opener(NoRedirect(), request.ProxyHandler({}))
    results = []
    for item in data["cases"]:
        own_url = origin + item["owner_resource"]
        outsider_url = origin + item["outsider_control_resource"]
        a = fetch(opener, own_url, tokens["owner"], item["owner_marker"])
        time.sleep(0.5)
        b = fetch(opener, own_url, tokens["outsider"], item["owner_marker"])
        time.sleep(0.5)
        c = fetch(opener, outsider_url, tokens["outsider"], item["outsider_control_marker"])
        results.append(evaluate_case(item, a, b, c))
        time.sleep(0.5)
    return {"schema_version": 1, "execution": "reviewed-controlled-GET-only",
            "base_origin": origin, "results": results, "candidates": sum(
                r["status"] == "cross-account-exposure-candidate-needs-review"
                for r in results),
            "notice": ("No vulnerability is proven by these observations alone. "
                       "Check confidentiality/authorization policy, response equivalence, "
                       "cache behavior, replay determinism and program terms. "
                       "A marker can be public or shared by design.")}


def read(path):
    p = Path(path).expanduser()
    if not p.is_file() or p.is_symlink() or p.stat().st_size > 1_000_000:
        raise ValueError("plan must be a regular non-symlink JSON <=1MB")
    return json.loads(p.read_text(encoding="utf-8"))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--plan", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--execute", action="store_true")
    ap.add_argument("--allowed-host", help="hostname must exactly match approved plan origin")
    ap.add_argument("--confirm-authorized", action="store_true")
    args = ap.parse_args(argv)
    dest = Path(args.out).expanduser()
    if dest.exists() or dest.is_symlink():
        ap.error("output must not exist")
    try:
        plan = read(args.plan)
        if args.execute:
            if platform.system() != "Darwin":
                raise ValueError("active replay is restricted to a vetted Mac environment")
            if not args.allowed_host or not args.confirm_authorized:
                raise ValueError("active mode requires --allowed-host and --confirm-authorized")
            report = run(plan, args.allowed_host)
        else:
            origin = validate(plan, args.allowed_host, False)
            report = {"schema_version": 1, "execution": "dry-run",
                      "origin": origin, "cases": len(plan["cases"]),
                      "notice": "Only manifest validation; no network requests."}
        dest.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(dest), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            json.dump(report, out, ensure_ascii=False, indent=2)
            out.write("\n")
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        ap.error(str(exc))
    print(json.dumps({"out": str(dest), "execution": report["execution"]}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
