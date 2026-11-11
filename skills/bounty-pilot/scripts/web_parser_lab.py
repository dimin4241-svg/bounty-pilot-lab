#!/usr/bin/env python3
"""Real offline URL normalization comparison: Python urllib vs Node WHATWG URL.

Two actual local implementations are invoked on bounded synthetic fixture URLs.
No HTTP requests, DNS, socket connections, target JS, raw payload generators
or remote hostnames. No request-smuggling capability is implemented.
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit

MAX_CASES = 80
SAFE = re.compile(r"^[\x21-\x7e]{1,240}$")
NODE = r"""
'use strict';
const fs = require('fs');
const list = JSON.parse(fs.readFileSync(0,'utf8'));
if (!Array.isArray(list) || list.length > 160) throw Error('bounded fixtures only');
process.stdout.write(JSON.stringify(list.map(raw => {
  try {
    const u = new URL(raw);
    return {valid:true, host:u.hostname.toLowerCase(),
            port:u.port ? Number(u.port) : null,
            path:u.pathname, query:u.search.startsWith('?') ? u.search.slice(1) : u.search};
  } catch (_) {
    return {valid:false,host:null,port:null,path:null,query:null};
  }
})));
"""


def _load(path):
    p = Path(path).expanduser()
    if p.is_symlink() or not p.is_file() or p.stat().st_size > 150000:
        raise ValueError("regular local fixture JSON <=150KB required")
    return json.loads(p.read_text(encoding="utf-8"), object_pairs_hook=_unique)


def _unique(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise ValueError("duplicate JSON key")
        d[k] = v
    return d


def _write(path, data):
    p = Path(path).expanduser()
    if p.exists() or p.is_symlink():
        raise ValueError("output must not exist")
    p.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(p), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True, ensure_ascii=False)
        f.write("\n")


def _safe_url(value):
    if not isinstance(value, str) or not SAFE.fullmatch(value):
        raise ValueError("synthetic URL requires bounded printable ASCII")
    try:
        u = urlsplit(value)
    except ValueError as exc:
        raise ValueError("malformed local fixture URL") from exc
    if (u.scheme != "https" or u.username is not None or
            u.password is not None or u.fragment or not u.hostname or
            not (u.hostname.endswith(".invalid") or u.hostname.endswith(".test") or
                 u.hostname.endswith(".example"))):
        raise ValueError("only https *.invalid, *.test, *.example fixture hosts")
    return value


def _python_url(value):
    try:
        u = urlsplit(value)
        return {"valid": True, "host": u.hostname.lower(),
                "port": u.port, "path": u.path or "/",
                "query": u.query}
    except ValueError:
        return {"valid": False, "host": None, "port": None,
                "path": None, "query": None}


def _diff(a, b):
    if a["valid"] != b["valid"]:
        return ["PARSER_ACCEPTANCE_DIFFERENCE"]
    if not a["valid"]:
        return []
    return [field.upper() + "_NORMALIZATION_DIFFERENCE"
            for field in ("host", "port", "path", "query")
            if a[field] != b[field]]


def analyze(doc, node_binary=None):
    if not isinstance(doc, dict) or set(doc) != {
            "schema_version", "environment", "pairs"} or
            type(doc["schema_version"]) is not int or doc["schema_version"] != 1 or
            doc["environment"] != "synthetic_offline_fixtures"):
        raise ValueError("synthetic offline URL parser lab schema required")
    pairs = doc["pairs"]
    if not isinstance(pairs, list) or not 1 <= len(pairs) <= MAX_CASES:
        raise ValueError("1..80 paired URL fixtures required")
    seen, urls = set(), []
    for p in pairs:
        if not isinstance(p, dict) or set(p) != {
                "id", "candidate_url", "negative_control_url"}:
            raise ValueError("pair must include candidate and negative-control URLs")
        ident = p["id"]
        if (not isinstance(ident, str) or not
                re.fullmatch(r"[A-Za-z0-9_.:-]{1,100}", ident) or ident in seen):
            raise ValueError("duplicate/invalid pair ID")
        seen.add(ident)
        candidate = _safe_url(p["candidate_url"])
        control = _safe_url(p["negative_control_url"])
        if candidate == control:
            raise ValueError("independent control must use different input")
        urls.extend([candidate, control])
    if node_binary is None:
        node_binary = shutil.which("node")
    if not node_binary:
        raise ValueError("Node.js URL implementation is not installed")
    # Executable Node program is a fixed, reviewed constant and runs no user code.
    try:
        run = subprocess.run([node_binary, "--max-old-space-size=128", "-e", NODE],
                             input=json.dumps(urls), text=True, capture_output=True,
                             check=False, timeout=15, env={
                                 "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                                 "NODE_OPTIONS": ""})
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError("local Node URL parser failed") from exc
    if run.returncode or len(run.stdout) > 100000:
        raise ValueError("local Node URL parser returned an error")
    try:
        node_rows = json.loads(run.stdout)
    except json.JSONDecodeError as exc:
        raise ValueError("Node URL parser returned invalid JSON") from exc
    if not isinstance(node_rows, list) or len(node_rows) != len(urls):
        raise ValueError("Node parser did not return the expected number of observations")
    rows = []
    for i, p in enumerate(pairs):
        c = _diff(_python_url(urls[i * 2]), node_rows[i * 2])
        n = _diff(_python_url(urls[i * 2 + 1]), node_rows[i * 2 + 1])
        if c and not n:
            status = "CONTROLLED_LOCAL_URL_PARSER_DIFFERENCE"
        elif c:
            status = "INCONCLUSIVE_CONTROL_DIFFERS"
        else:
            status = "NO_DIFFERENCE"
        rows.append({"id": p["id"], "candidate_differences": c,
                     "control_differences": n, "status": status})
    return {"schema_version": 1, "mode": "web-local-url-parser-lab",
            "python_parser": "urllib.parse.urlsplit", "node_parser": "WHATWG URL",
            "pairs": rows, "controlled_leads": sum(
                x["status"] == "CONTROLLED_LOCAL_URL_PARSER_DIFFERENCE" for x in rows),
            "network_requests": 0, "confirmed_vulnerabilities": 0,
            "limitations": ("Actual URL parser comparison on synthetic .invalid/.test/.example "
                            "hosts only, NOT HTTP framing, request smuggling, cookie semantics, "
                            "cache exploitation or deployed reverse proxy behavior. "
                            "No URL or query values are saved in reports.")}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--input", required=True)
    p.add_argument("--out", required=True)
    a = p.parse_args(argv)
    try:
        result = analyze(_load(a.input))
        _write(a.out, result)
    except (ValueError, OSError, TypeError, KeyError, json.JSONDecodeError) as exc:
        p.error(str(exc))
    print(json.dumps({"out": a.out, "controlled_leads": result["controlled_leads"],
                      "confirmed_vulnerabilities": 0}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
