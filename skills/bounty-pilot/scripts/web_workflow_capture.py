#!/usr/bin/env python3
"""Extract privacy-preserving API state transitions from an owned loopback HAR.

Never executes requests. Only accepts captures explicitly marked as owned
literal 127.0.0.1 fixtures; refuses any other request host, even if a browser
followed a redirect. Does not persist body, cookies, credentials, query, user
names, token values or original paths. All non-template route segments are
HMACed with an operator-held comparison key, absent from output. HTTP 200
is never an authorization or business-effect oracle.
"""
import argparse
import hashlib
import hmac
import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlsplit, unquote

MAX_INPUT = 3_000_000
MAX_EVENTS = 200
METHODS = frozenset(("GET", "POST", "PUT", "PATCH", "DELETE"))
ACTORS = frozenset(("owner", "outsider", "control"))
SHA64 = re.compile(r"^[a-f0-9]{64}$")
LOOP = re.compile(r"^http://127\.0\.0\.1:([0-9]{4,5})$")
SEG = re.compile(r"^[A-Za-z0-9_.-]{1,120}$")
STATIC = frozenset((
    "api", "v1", "v2", "v3", "users", "user", "orders", "order", "items",
    "item", "invoices", "invoice", "projects", "project", "organizations",
    "organization", "orgs", "teams", "members", "roles", "access",
    "permissions", "subscriptions", "subscription", "plans", "plan",
    "billing", "payments", "payment", "refunds", "refund", "sessions",
    "session", "tokens", "token", "files", "documents", "document",
    "jobs", "job", "exports", "export", "webhooks", "webhook",
    "approvals", "approval", "approve", "state", "actions", "action",
    "status", "accounts", "account", "profile", "profiles", "auth",
    "login", "logout", "artifacts", "artifact", "repositories",
    "repository", "builds", "build", "runs", "run", "admin", "public",
    "private", "download", "upload", "search", "checkout", "cart",
    "carts", "me", "settings", "activate", "deactivate", "groups",
    "group", "list", "detail", "details", "history", "revoke", "grant"
))


def _unique(pairs):
    d = {}
    for key, val in pairs:
        if key in d:
            raise ValueError("duplicate JSON field")
        d[key] = val
    return d


def _read(path):
    p = Path(path).expanduser()
    if p.is_symlink() or not p.is_file() or p.stat().st_size > MAX_INPUT:
        raise ValueError("bounded regular HAR JSON <=3MB required")
    return json.loads(p.read_text(encoding="utf-8"), object_pairs_hook=_unique)


def _write(path, report):
    p = Path(path).expanduser()
    if p.exists() or p.is_symlink():
        raise ValueError("private report already exists")
    p.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(p), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as file:
        json.dump(report, file, sort_keys=True, ensure_ascii=False, indent=2)
        file.write("\n")


def _origin(value):
    if not isinstance(value, str):
        raise ValueError("literal owned loopback origin required")
    match = LOOP.fullmatch(value)
    if not match or not 1024 <= int(match.group(1)) <= 65535:
        raise ValueError("only http://127.0.0.1:PORT local owned fixtures")
    if value != "http://127.0.0.1:" + str(int(match.group(1))):
        raise ValueError("non-canonical port")
    return value


def _comparison_key(path):
    p = Path(path).expanduser()
    if (p.is_symlink() or not p.is_file() or p.stat().st_size > 66 or
            p.stat().st_mode & 0o077):
        raise ValueError("private comparison key must be regular 0600 file <=66B")
    value = p.read_text(encoding="ascii").strip()
    if not SHA64.fullmatch(value):
        raise ValueError("32-byte hex comparison key file required")
    return value


def _fingerprint(key, label, data):
    return hmac.new(key, (label + "\x00" + data).encode("utf-8"),
                    hashlib.sha256).hexdigest()


def _route(path, key):
    if (not isinstance(path, str) or not path.startswith("/") or
            path.startswith("//") or len(path) > 1500 or
            "\\" in path or "%" in path or "//" in path or
            any(x in (".", "..") for x in path.split("/"))):
        raise ValueError("ambiguous path")
    if path == "/":
        return "/", None
    parts = path.split("/")[1:]
    if len(parts) > 25:
        raise ValueError("path depth too large")
    template, variables = [], []
    for part in parts:
        if not SEG.fullmatch(part):
            raise ValueError("path component unsupported")
        if part.lower() in STATIC:
            template.append(part.lower())
        else:
            template.append(":opaque")
            variables.append(_fingerprint(key, "path-segment", part))
    return "/" + "/".join(template), variables[-1] if variables else None


def capture(har, origin, actor, comparison_key):
    _origin(origin)
    if actor not in ACTORS:
        raise ValueError("only owner / outsider / control fixture actors")
    if not isinstance(comparison_key, str) or not SHA64.fullmatch(comparison_key):
        raise ValueError("32-byte operator-held hex comparison key required")
    key = bytes.fromhex(comparison_key)
    if (not isinstance(har, dict) or not isinstance(har.get("log"), dict) or
            not isinstance(har["log"].get("entries"), list)):
        raise ValueError("HAR log.entries array required")
    rows = har["log"]["entries"]
    if not 1 <= len(rows) <= MAX_EVENTS:
        raise ValueError("1..200 owned loopback requests required")
    events, stats, edges, prior_by_object = [], defaultdict(int), [], defaultdict(list)
    for idx, row in enumerate(rows):
        if not isinstance(row, dict) or not isinstance(row.get("request"), dict):
            raise ValueError("HAR request malformed")
        rq = row["request"]
        if not isinstance(rq.get("url"), str) or not isinstance(rq.get("method"), str):
            raise ValueError("HAR URL and method required")
        method = rq["method"].upper()
        if method not in METHODS or method != rq["method"]:
            raise ValueError("unsupported or non-canonical method")
        url = urlsplit(rq["url"])
        if (url.scheme + "://" + url.netloc != origin or
                url.username is not None or url.password is not None or
                url.fragment):
            raise ValueError("HAR includes an out-of-origin or redirected request")
        template, object_id = _route(url.path or "/", key)
        response = row.get("response")
        status = response.get("status") if isinstance(response, dict) else None
        if type(status) is not int or not 100 <= status <= 599:
            raise ValueError("real HTTP numeric status required")
        op = _fingerprint(key, "route", method + " " + template)[:20]
        item = {"event": "h" + str(idx + 1).zfill(4),
                "seq": idx + 1, "actor": actor, "method": method,
                "route_key": op, "route_shape": template,
                "object_key": object_id[:24] if object_id else None,
                "http_status": status,
                "status_class": str(status // 100) + "xx",
                "privileged_business_effect_proven": False}
        events.append(item)
        stats[op] += 1
        if object_id:
            for prev in prior_by_object[object_id][-8:]:
                if prev["route_key"] != op:
                    edges.append({"from_event": prev["event"],
                                  "to_event": item["event"],
                                  "basis": "SAME_OPAQUE_PATH_SEGMENT_ONLY"})
            prior_by_object[object_id].append(item)
    return {"schema_version": 1, "mode": "owned-loopback-har-capture",
            "actor": actor, "origin_kind": "literal_127_0_0_1",
            "event_count": len(events), "events": events, "possible_object_links": edges[:300],
            "distinct_routes": len(stats),
            "raw_headers_preserved": False, "raw_query_preserved": False,
            "raw_body_preserved": False, "network_requests": 0,
            "confirmed_vulnerabilities": 0,
            "limitations": ("HAR is operator supplied and not independently authenticated. "
                            "Route shapes are heuristic, object tokens are HMACed, and "
                            "successful HTTP status does not establish authorization, "
                            "access to private data or protected business effect.")}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--har", required=True)
    p.add_argument("--origin", required=True)
    p.add_argument("--actor", choices=sorted(ACTORS), required=True)
    p.add_argument("--comparison-key-file", required=True,
                   help="local 0600 secret 32-byte hex file; never commit, log or share")
    p.add_argument("--out", required=True)
    a = p.parse_args(argv)
    try:
        report = capture(_read(a.har), a.origin, a.actor, _comparison_key(a.comparison_key_file))
        _write(a.out, report)
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
        p.error(str(exc))
    print(json.dumps({"out": a.out, "events": report["event_count"],
                      "routes": report["distinct_routes"],
                      "confirmed_vulnerabilities": 0}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
