#!/usr/bin/env python3
"""Fail-closed offline bug-bounty program policy preflight.

A passed preflight NEVER grants permission or automatically starts network
activity. The operator must independently verify the program's latest rules.
Unverified/stale snapshots, wildcards, ambiguous URL encodings and excluded
actions are denied. No network requests are made.
"""
import argparse
import datetime as dt
import json
import os
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit, unquote

ACTIONS = frozenset(("source-review", "read-only", "account-test", "state-change",
                     "browser-test", "automation", "upload", "payment-sandbox"))
STATUSES = frozenset(("active", "paused", "closed"))
MAX_BYTES = 512000
SHA = re.compile(r"^[a-f0-9]{64}$")
ORIGIN = re.compile(r"^https://(?:[a-z0-9-]+\.)+[a-z0-9-]+(?::[0-9]{2,5})?$")
LABEL = re.compile(r"^[a-zA-Z0-9_.:-]{1,100}$")
# no wildcard matching: a broad program name is not permission for subdomains


def load(path):
    p = Path(path).expanduser()
    if p.is_symlink() or not p.is_file() or p.stat().st_size > MAX_BYTES:
        raise ValueError("regular non-symlink JSON <=512KB required")
    return json.loads(p.read_text(encoding="utf-8"), object_pairs_hook=_unique)


def _unique(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise ValueError("duplicate JSON key")
        out[k] = v
    return out


def save_new(path, value):
    p = Path(path).expanduser()
    if p.is_symlink() or p.exists():
        raise ValueError("output must not exist")
    p.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(value, f, indent=2, sort_keys=True, ensure_ascii=False)
        f.write("\n")


def _at(value):
    if not isinstance(value, str) or len(value) > 40:
        raise ValueError("timestamp required")
    try:
        stamp = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("timestamp must be ISO8601") from exc
    if stamp.tzinfo is None:
        raise ValueError("timestamp requires timezone")
    return stamp.astimezone(dt.timezone.utc)


def _origin(value):
    if not isinstance(value, str) or not ORIGIN.fullmatch(value):
        raise ValueError("exact lowercase https origin required (no wildcard, paths or userinfo)")
    parts = urlsplit(value)
    if not parts.hostname or parts.hostname.startswith("xn--") and ".." in value:
        raise ValueError("invalid hostname")
    if parts.port and parts.port == 443:
        raise ValueError("canonical origin must omit default port")
    return value


def _path(value):
    if (not isinstance(value, str) or not value.startswith("/") or
            value.startswith("//") or len(value) > 1200 or
            any(ord(c) < 33 or ord(c) > 126 for c in value) or
            any(c in value for c in ("\\", "#", "?"))):
        raise ValueError("absolute unambiguous ASCII path required")
    # An encoded slash, percent, backslash or traversal must not change
    # whether a URL falls within an allowlisted prefix.
    decoded = unquote(value)
    if decoded != value and any(x in decoded for x in ("\\", "%")):
        raise ValueError("ambiguous encoded path")
    if unquote(decoded) != decoded or any("%2f" in value.lower() or
                                          "%5c" in value.lower() for _ in (0,)):
        raise ValueError("encoded slash/backslash or nested decoding")
    if any(seg in (".", "..") for seg in decoded.split("/")) or "//" in decoded:
        raise ValueError("traversal or repeated path separators")
    return value


def _rule(row):
    if not isinstance(row, dict) or set(row) != {"origin", "path_prefix", "actions"}:
        raise ValueError("scope rule requires origin/path_prefix/actions only")
    origin, prefix = _origin(row["origin"]), _path(row["path_prefix"])
    acts = row["actions"]
    if (not isinstance(acts, list) or not acts or len(acts) > len(ACTIONS) or
            any(not isinstance(x, str) or x not in ACTIONS for x in acts) or
            len(set(acts)) != len(acts)):
        raise ValueError("scope actions must be unique supported labels")
    return {"origin": origin, "path_prefix": prefix, "actions": acts}


def validate(policy, now=None):
    if not isinstance(policy, dict) or set(policy) != {
            "schema_version", "platform", "program_id", "status",
            "source_url", "rules_sha256", "reviewed_at",
            "expires_at", "include", "exclude", "required_headers",
            "operator_reviewed"}:
        raise ValueError("policy schema incomplete/extra fields")
    if type(policy["schema_version"]) is not int or policy["schema_version"] != 1:
        raise ValueError("schema version must be 1")
    if policy["platform"] not in ("standoff365", "bizone", "other"):
        raise ValueError("platform is unsupported")
    if not isinstance(policy["program_id"], str) or not LABEL.fullmatch(policy["program_id"]):
        raise ValueError("invalid program ID")
    if policy["status"] not in STATUSES:
        raise ValueError("invalid program status")
    page = urlsplit(policy["source_url"]) if isinstance(policy["source_url"], str) else None
    if not page or page.scheme != "https" or not page.hostname or page.username or page.password:
        raise ValueError("official source URL must be https without userinfo")
    if not isinstance(policy["rules_sha256"], str) or not SHA.fullmatch(policy["rules_sha256"]):
        raise ValueError("rules SHA256 is required")
    if type(policy["operator_reviewed"]) is not bool:
        raise ValueError("operator_reviewed must be explicit boolean")
    start, end = _at(policy["reviewed_at"]), _at(policy["expires_at"])
    now = now or dt.datetime.now(dt.timezone.utc)
    if not isinstance(now, dt.datetime) or now.tzinfo is None:
        raise ValueError("evaluation clock requires timezone")
    if end <= start or (end - start).total_seconds() > 30 * 86400:
        raise ValueError("policy validity must be <=30 days")
    include, exclude = policy["include"], policy["exclude"]
    if (not isinstance(include, list) or not 1 <= len(include) <= 100 or
            not isinstance(exclude, list) or len(exclude) > 100):
        raise ValueError("bounded include/exclude scope arrays required")
    inc, exc = [_rule(x) for x in include], [_rule(x) for x in exclude]
    headers = policy["required_headers"]
    if (not isinstance(headers, list) or len(headers) > 20 or
            any(not isinstance(h, str) or not re.fullmatch(r"[A-Za-z0-9-]{1,64}", h)
                for h in headers) or len(set(h.lower() for h in headers)) != len(headers)):
        raise ValueError("required_headers must be unique header names (never values)")
    return {"include": inc, "exclude": exc, "window_valid": start <= now <= end,
            "operator_reviewed": policy["operator_reviewed"],
            "status": policy["status"], "headers": headers,
            "rule_digest": policy["rules_sha256"],
            "program_id": policy["program_id"]}


def _matches(rule, origin, path, action):
    prefix = rule["path_prefix"]
    return (rule["origin"] == origin and action in rule["actions"] and
            (prefix == "/" or path == prefix or
             path.startswith(prefix.rstrip("/") + "/")))


def evaluate(policy, requests, now=None):
    valid = validate(policy, now)
    if not isinstance(requests, list) or not 1 <= len(requests) <= 100:
        raise ValueError("requests must be 1..100 entries")
    rows = []
    for item in requests:
        if (not isinstance(item, dict) or set(item) != {"id", "url", "action",
                                                        "provided_header_names"}):
            raise ValueError("request must specify id/url/action/provided_header_names")
        if not isinstance(item["id"], str) or not LABEL.fullmatch(item["id"]):
            raise ValueError("invalid request id")
        action = item["action"]
        if action not in ACTIONS:
            raise ValueError("unknown requested action")
        headers = item["provided_header_names"]
        if (not isinstance(headers, list) or len(headers) > 50 or
                any(not isinstance(h, str) or
                    not re.fullmatch(r"[A-Za-z0-9-]{1,64}", h) for h in headers)):
            raise ValueError("header names only, never header values")
        reasons = []
        try:
            url = urlsplit(item["url"])
            if url.query or url.fragment or url.username or url.password:
                raise ValueError("query, fragment, credentials not allowed for preflight")
            origin = _origin(url.scheme + "://" + url.netloc)
            path = _path(url.path or "/")
        except (ValueError, TypeError, AttributeError):
            reasons.append("NONCANONICAL_URL")
            origin, path = None, None
        if valid["status"] != "active":
            reasons.append("PROGRAM_NOT_ACTIVE")
        if not valid["window_valid"]:
            reasons.append("RULES_EXPIRED_OR_NOT_YET_VALID")
        if not valid["operator_reviewed"]:
            reasons.append("NO_OPERATOR_RULES_REVIEW")
        if origin is not None:
            if not any(_matches(r, origin, path, action) for r in valid["include"]):
                reasons.append("ACTION_OR_ASSET_NOT_EXPLICITLY_INCLUDED")
            if any(_matches(r, origin, path, action) for r in valid["exclude"]):
                reasons.append("EXPLICIT_EXCLUSION")
        provided = {x.lower() for x in headers}
        if any(x.lower() not in provided for x in valid["headers"]):
            reasons.append("MISSING_REQUIRED_HEADER_NAMES")
        rows.append({"id": item["id"], "action": action,
                     "allowed_by_saved_preflight": not reasons,
                     "reasons": sorted(set(reasons))})
    return {"schema_version": 1, "status": "OFFLINE_PREFLIGHT_NOT_PERMISSION",
            "program_id": valid["program_id"],
            "rules_sha256": valid["rule_digest"],
            "checks": rows, "network_requests": 0,
            "warning": ("These are operator-supplied policy snapshots. A green check "
                        "never authorizes or launches testing; verify the current "
                        "original rules and obtain any required permission first.")}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--policy", required=True)
    p.add_argument("--requests", required=True)
    p.add_argument("--out", required=True)
    a = p.parse_args(argv)
    try:
        result = evaluate(load(a.policy), load(a.requests))
        save_new(a.out, result)
    except (ValueError, OSError, TypeError, KeyError, json.JSONDecodeError) as exc:
        p.error(str(exc))
    print(json.dumps({"out": a.out, "preflight_passed": sum(
        x["allowed_by_saved_preflight"] for x in result["checks"]),
        "total": len(result["checks"]), "testing_authorized": False}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
