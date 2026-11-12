#!/usr/bin/env python3
"""Real offline protocol/hostname parse of researcher-supplied candidate URLs.

A hostname-only guard is the classic dApp/link bypass: `javascript://host/%0a...`
parses with protocol `javascript:` and hostname `host`, so a check that reads only
the hostname still "passes" it. This parses each candidate with both Python's
urllib and Node's real WHATWG URL (the model browsers actually use) and flags
anything whose protocol is dangerous but still carries a non-empty hostname -
exactly the shape that slips past a naive comparison. It never fetches a URL,
makes a network request, or tests the target's own guard code; the researcher
still has to read that code and compare its verdict against this parse by hand.
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

MAX_URLS = 60
MAX_URL_LEN = 2000
SAFE = re.compile(r"^[\x09\x0a\x0d\x20-\x7e]{1,2000}$")
DANGEROUS_PROTOCOLS = frozenset(("javascript:", "data:", "vbscript:", "file:"))
NODE = r"""
'use strict';
const fs = require('fs');
const list = JSON.parse(fs.readFileSync(0,'utf8'));
if (!Array.isArray(list) || list.length > 60) throw Error('bounded candidate list only');
process.stdout.write(JSON.stringify(list.map(raw => {
  try {
    const u = new URL(raw);
    return {valid:true, protocol:u.protocol, hostname:u.hostname};
  } catch (_) {
    try {
      // WHATWG URL requires an absolute/base-relative form; relative candidates
      // (protocol-relative `//host/...`, bare `/path`) are parsed against an
      // inert local base so their own hostname (if any) is still observable.
      const u = new URL(raw, 'https://bp-local-base.invalid/');
      return {valid:true, protocol:u.protocol, hostname:u.hostname,
              resolved_against_relative_base:true};
    } catch (__) {
      return {valid:false, protocol:null, hostname:null};
    }
  }
})));
"""


def _python_parse(value):
    try:
        u = urlsplit(value)
    except ValueError:
        return {"valid": False, "scheme": None, "hostname": None}
    return {"valid": True, "scheme": (u.scheme + ":") if u.scheme else None,
            "hostname": u.hostname}


def _candidates(value):
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_URLS:
        raise ValueError("1..60 candidate URLs required")
    seen = set()
    out = []
    for item in value:
        if (not isinstance(item, str) or not item or len(item) > MAX_URL_LEN or
                not SAFE.fullmatch(item)):
            raise ValueError("each candidate must be bounded printable text")
        if item in seen:
            raise ValueError("duplicate candidate URL")
        seen.add(item)
        out.append(item)
    return out


def check(candidates, node_binary=None):
    candidates = _candidates(candidates)
    if node_binary is None:
        node_binary = shutil.which("node")
    if not node_binary:
        raise ValueError("Node.js WHATWG URL implementation is not installed")
    try:
        run = subprocess.run([node_binary, "--max-old-space-size=128", "-e", NODE],
                             input=json.dumps(candidates), text=True, capture_output=True,
                             check=False, timeout=15, env={
                                 "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                                 "NODE_OPTIONS": ""})
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError("local Node URL parser failed") from exc
    if run.returncode or len(run.stdout) > 200_000:
        raise ValueError("local Node URL parser returned an error")
    try:
        node_rows = json.loads(run.stdout)
    except json.JSONDecodeError as exc:
        raise ValueError("Node URL parser returned invalid JSON") from exc
    if not isinstance(node_rows, list) or len(node_rows) != len(candidates):
        raise ValueError("Node parser did not return the expected number of observations")
    rows = []
    bypass_shaped = 0
    for candidate, node in zip(candidates, node_rows):
        python_row = _python_parse(candidate)
        whatwg_protocol = node.get("protocol") if isinstance(node, dict) else None
        whatwg_hostname = node.get("hostname") if isinstance(node, dict) else None
        dangerous = isinstance(whatwg_protocol, str) and whatwg_protocol in DANGEROUS_PROTOCOLS
        slips_hostname_check = bool(dangerous and whatwg_hostname)
        scheme_disagreement = (python_row["scheme"] != whatwg_protocol and
                               node.get("valid") and python_row["valid"])
        if slips_hostname_check:
            bypass_shaped += 1
        rows.append({
            "candidate": candidate,
            "python_urllib": python_row,
            "whatwg_url": {"valid": bool(node.get("valid")) if isinstance(node, dict) else False,
                          "protocol": whatwg_protocol, "hostname": whatwg_hostname,
                          "resolved_against_relative_base": bool(
                              isinstance(node, dict) and
                              node.get("resolved_against_relative_base"))},
            "dangerous_protocol": dangerous,
            "hostname_check_bypass_shape": slips_hostname_check,
            "python_whatwg_scheme_disagreement": bool(scheme_disagreement),
        })
    return {
        "schema_version": 1, "mode": "web-url-scheme-guard-check",
        "python_parser": "urllib.parse.urlsplit", "node_parser": "WHATWG URL",
        "candidates_checked": len(rows), "rows": rows,
        "hostname_check_bypass_shapes": bypass_shaped,
        "network_requests": 0, "confirmed_vulnerabilities": 0,
        "notice": ("hostname_check_bypass_shape describes the candidate URL's own parse, "
                  "never the target's guard: a guard that reads the WHATWG protocol (not just "
                  "the hostname) before deciding is unaffected by this shape. The researcher "
                  "must still read the actual comparison code and confirm it only inspects "
                  "hostname, origin or a regex over the raw string before concluding a bypass.")
    }


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--input", required=True, help="JSON file: a bounded list of candidate URLs")
    p.add_argument("--out")
    a = p.parse_args(argv)
    try:
        src = Path(a.input)
        if src.is_symlink() or not src.is_file() or src.stat().st_size > 50_000:
            raise ValueError("regular local candidate-list JSON <=50KB required")
        result = check(json.loads(src.read_text(encoding="utf-8")))
        text = json.dumps(result, indent=2, ensure_ascii=False)
        if a.out:
            out = Path(a.out)
            if out.exists() or out.is_symlink():
                raise ValueError("refusing to overwrite an existing output file")
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            fd = os.open(str(out), flags, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(text)
        else:
            print(text)
        return 0
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print("Error: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
