#!/usr/bin/env python3
"""Offline JS diff for previously saved, authorized website snapshots.

Optional jsluice integration parses local files using fixed arguments. This
never downloads scripts, visits target URLs or outputs raw token values.
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

MAX_JS = 4_000_000
ROUTES = re.compile(
    r'https?://[A-Za-z0-9_.:-]+/[A-Za-z0-9_./?%=&{}:$-]{1,180}'
    r'|/(?:api|graphql|v[0-9]+|auth|oauth|rpc|rest|users|accounts|payments|orders)'
    r'(?:/[A-Za-z0-9_{}.$:%-]+){0,12}(?:\?[A-Za-z0-9_=&%{}.$:-]{0,160})?', re.I)
TOPICS = {
    "authorization": ("authorization", "authorize", "permission", "role", "ownership",
                      "accesscontrol", "x-user-id", "bearer", "admin", "isowner"),
    "payment-flow": ("withdraw", "payment", "checkout", "refund", "amount",
                     "minout", "destination", "creditnote", "receiver", "transfer"),
    "session-and-origin": ("redirect_uri", "postmessage", "window.origin",
                           "jwt", "callbackurl", "localstorage", "sessionstorage"),
}
ID = re.compile(r"^[A-Za-z0-9._:-]{1,100}$")


def date(value):
    if not isinstance(value, str):
        raise ValueError("captured_at must be a timezone-aware ISO8601 string")
    try:
        d = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as e:
        raise ValueError("invalid captured_at") from e
    if d.tzinfo is None:
        raise ValueError("captured_at lacks timezone")
    return d


def route(raw):
    if not isinstance(raw, str) or not raw or len(raw) > 2048:
        return None
    try:
        u = urlsplit(raw.strip().replace("\\/", "/"))
        if u.scheme:
            if u.scheme not in ("https", "http") or not u.hostname or u.username:
                return None
            prefix = u.scheme + "://" + u.hostname.lower()
            if u.port:
                prefix += ":" + str(u.port)
        else:
            if not raw.startswith("/") or raw.startswith("//"):
                return None
            prefix = ""
        if len(u.path) > 240 or any(ord(c) < 32 for c in u.path):
            return None
        # URL path segments may be signed bearer values or opaque account
        # references. Never store long, potentially secret identifiers.
        safe_path = "/".join("{opaque}" if len(segment) >= 30 else segment
                             for segment in (u.path or "/").split("/"))
        names = sorted({k for k, _ in parse_qsl(u.query, keep_blank_values=True)
                        if 0 < len(k) < 81})
        return (prefix + safe_path, tuple(names))
    except ValueError:
        return None


def jsluice_local(path):
    proc = subprocess.run(["jsluice", "urls", "-u", str(path)],
                          text=True, capture_output=True, timeout=30, check=False)
    if proc.returncode or len(proc.stdout) > 10_000_000:
        raise ValueError("jsluice local parse failed; check installation and logs privately")
    found = set()
    for line in proc.stdout.splitlines():
        obj = json.loads(line)
        if isinstance(obj, dict):
            item = route(obj.get("url"))
            if item is not None:
                found.add(item)
    return found


def snapshot(data, home, with_jsluice=False):
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise ValueError("snapshot schema_version=1 required")
    at = date(data.get("captured_at"))
    items = data.get("assets")
    if not isinstance(items, list) or not 1 <= len(items) <= 80:
        raise ValueError("1..80 local JS assets required")
    home = Path(home).resolve()
    scripts = {}
    for entry in items:
        if not isinstance(entry, dict) or not isinstance(entry.get("id"), str) or not ID.fullmatch(entry["id"]):
            raise ValueError("asset id invalid")
        ident = entry["id"]
        if ident in scripts:
            raise ValueError("duplicate script id")
        url = entry.get("script_url")
        if not isinstance(url, str) or len(url) > 900:
            raise ValueError("invalid script URL")
        u = urlsplit(url)
        if u.scheme != "https" or not u.hostname or u.username:
            raise ValueError("script URL must be HTTPS without userinfo")
        # Keep only origin + path; signed CDN query parameters and fragments
        # must not leak into output JSON.
        url = "https://" + u.hostname.lower() + ((":" + str(u.port)) if u.port else "") + (u.path or "/")
        name = entry.get("file")
        if not isinstance(name, str) or not name or len(name) > 400:
            raise ValueError("file is required")
        path = home / name
        if path.is_symlink():
            raise ValueError("symlinked scripts are forbidden")
        path = path.resolve()
        if home not in path.parents or not path.is_file() or path.stat().st_size > MAX_JS:
            raise ValueError("JS file must be in snapshot directory and <=4MB")
        raw = path.read_bytes()
        js = raw.decode("utf-8", errors="replace")
        urls = {v for found in ROUTES.findall(js) if (v := route(found)) is not None}
        if with_jsluice:
            urls |= jsluice_local(path)
        if len(urls) > 5000:
            raise ValueError("too many extracted routes")
        scripts[ident] = {"url": url, "sha256": hashlib.sha256(raw).hexdigest(),
                          "size": len(raw), "routes": urls,
                          "topics": {name for name, keys in TOPICS.items()
                                     if any(key in js.casefold() for key in keys)}}
    return at, scripts


def compare(before, after, before_dir, after_dir, with_jsluice=False):
    old_at, old = snapshot(before, before_dir, with_jsluice)
    new_at, new = snapshot(after, after_dir, with_jsluice)
    if new_at <= old_at:
        raise ValueError("snapshot captures must ascend")
    leads = []
    for ident in sorted(set(old) | set(new)):
        a, b = old.get(ident), new.get(ident)
        if a is None or b is None:
            item = a or b
            leads.append({"script_id": ident, "kind": "script-added" if b else "script-removed",
                          "script_url": item["url"], "sha256": item["sha256"]})
            continue
        if a["sha256"] == b["sha256"]:
            continue
        for kind, entries in (("endpoint-added", b["routes"] - a["routes"]),
                              ("endpoint-removed", a["routes"] - b["routes"])):
            for endpoint, params in sorted(entries):
                leads.append({"script_id": ident, "kind": kind, "endpoint": endpoint,
                              "parameter_names": list(params), "script_url": b["url"],
                              "old_sha256": a["sha256"], "new_sha256": b["sha256"]})
        leads.append({"script_id": ident, "kind": "js-source-changed",
                      "script_url": b["url"], "old_sha256": a["sha256"],
                      "new_sha256": b["sha256"], "size_delta": b["size"] - a["size"],
                      "present_topics": sorted(b["topics"]),
                      "new_topics": sorted(b["topics"] - a["topics"])})
    return {"schema_version": 1, "leads": leads, "count": len(leads),
            "before_at": old_at.isoformat(), "after_at": new_at.isoformat(),
            "method": "local-jsluice+lexical" if with_jsluice else "local-lexical",
            "notice": ("No site was probed. Static analysis is incomplete and does not "
                       "establish vulnerable authorization. URLs omit query VALUES, "
                       "raw JavaScript and potential token contents. Use an authorized scope.")}


def read(path):
    p = Path(path).expanduser()
    if p.is_symlink() or not p.is_file() or p.stat().st_size > 1_000_000:
        raise ValueError("manifest must be regular non-symlink JSON <=1MB")
    return json.loads(p.read_text(encoding="utf-8")), p.parent.resolve()


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--before", required=True)
    p.add_argument("--after", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--use-jsluice", action="store_true")
    args = p.parse_args(argv)
    output = Path(args.out).expanduser()
    if output.exists() or output.is_symlink():
        p.error("output must not exist")
    try:
        b, bd = read(args.before)
        a, ad = read(args.after)
        report = compare(b, a, bd, ad, args.use_jsluice)
        output.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(output), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(report, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
    except (ValueError, OSError, TypeError, KeyError, json.JSONDecodeError,
            subprocess.TimeoutExpired) as exc:
        p.error(str(exc))
    print(json.dumps({"out": str(output), "leads": report["count"]}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
