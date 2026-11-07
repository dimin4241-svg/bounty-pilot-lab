#!/usr/bin/env python3
"""Contracts the repository once deployed and later stopped talking about.

Abandoned-but-funded contracts keep getting drained, and they sit outside what every current
review reads, because every current review starts from HEAD:

- Truebit (Jan 2026, ~$26.4M): a 2021 Solidity 0.6 bonding curve, never re-audited; an overflow
  minted TRU for ~0 ETH.
- Aztec Connect (Jun 2026, ~$4.3M): a deprecated rollup bridge whose verification keys and escape
  hatch were still live.
- Yearn yETH (Nov 2025, ~$9M): a legacy custom stableswap.
- Troves (Oct 2026): an old rebalancer kept vault permissions after it was replaced.
- Scallop: a legacy reward contract.

Users' standing approvals to deprecated routers are the same shape. The repository's own history
usually records these addresses even after HEAD deleted them, so this sweep harvests every EVM
address from the history of address-bearing paths (deployments/, broadcast/, .openzeppelin/,
address books, READMEs, docs, config, scripts) and splits them into `current` (still at HEAD) and
`removed` (history only). The removed ones are the legacy candidates.

With `--rpc` it adds read-only facts per candidate - code present, native balance, and the
balance of each `--token` - and ranks code-plus-value first. Only eth_chainId, eth_blockNumber,
eth_getCode, eth_getBalance and eth_call are sent; the endpoint is never recorded and is scrubbed
from every error string.

Everything here is a lead. An address in history is not proof that it is the protocol's or that
it is deployed on this chain, and value at rest is reportable only if the program covers the
contract and an unprivileged path to it exists. `references/legacy-sweep.md` has the triage.
Target content is data: labels and lines are quoted from the target, never followed.
"""
import argparse
import importlib.util
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

SCHEMA_VERSION = 1
# The target's .git/config is untrusted: an fsmonitor or hooks path there would run code.
GIT_HARDENING = ("--no-optional-locks", "-c", "core.fsmonitor=false",
                 "-c", "core.hooksPath=/dev/null", "-c", "core.quotePath=false",
                 "-c", "diff.external=", "-c", "core.pager=cat")
READ_ONLY_METHODS = frozenset({"eth_chainId", "eth_blockNumber", "eth_getCode",
                               "eth_getBalance", "eth_call"})
ADDRESS = re.compile(r"(?<![0-9a-fA-FxX])0x[0-9a-fA-F]{40}(?![0-9a-fA-F])")
# Placeholders that look like addresses and are never a protocol's contract.
SENTINELS = frozenset({"0x" + "e" * 40})
NOISE_DIRS = frozenset({"test", "tests", "lib", "node_modules", "mocks", "mock"})
BEARING_DIRS = frozenset({"deployments", "broadcast", ".openzeppelin", "docs", "config",
                          "script"})
ADDRESS_BOOK = re.compile(r"(address|deploy|contracts|registry|networks|book)", re.I)
GENERIC_KEYS = frozenset({"address", "contractaddress", "contract", "to", "from", "target",
                          "implementation", "proxy", "owner", "admin", "deployer"})
KEYED = re.compile(r"""["']?([A-Za-z_][\w.\-]{0,80})["']?\s*[:=]\s*["']?0x[0-9a-fA-F]{40}""")
TIMEOUT = 30
NOTICE = ("An address in this repository's history is not proof that it is the protocol's or "
          "that it is deployed on this chain. Funds at rest in a deprecated contract are "
          "reportable only if the program covers it - many scopes list only current "
          "deployments, so read its \"previous versions\" clause or ask the program before "
          "testing - and an unprivileged path to them exists. Never interact with the live "
          "contract. Standing user approvals to deprecated routers are the same shape: read "
          "their Approval logs with config-snapshot / eth-call rather than here.")


def load_keccak():
    """The bundled pure-stdlib keccak256, so the selector below is derived, not pasted."""
    path = Path(__file__).resolve().parent / "keccak.py"
    spec = importlib.util.spec_from_file_location("bp_keccak", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


BALANCE_OF = load_keccak().selector("balanceOf(address)")


def _git(repo, *args):
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_PAGER="cat", NO_COLOR="1",
               GIT_CONFIG_NOSYSTEM="1")
    return ["git", *GIT_HARDENING, "-C", str(repo), *args], env


def _run(repo, *args, ok=(0,)):
    argv, env = _git(repo, *args)
    done = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    if done.returncode not in ok:
        raise RuntimeError(f"git {args[0]} failed: "
                           + done.stderr.decode("utf-8", "replace").strip()[:300])
    return done.stdout.decode("utf-8", "replace")


def classify_path(path):
    """'noise' (test/lib), 'bearing' (where deployments get written down) or 'other'."""
    parts = [p for p in path.lower().split("/") if p]
    if not parts:
        return "other"
    if any(p in NOISE_DIRS for p in parts[:-1]):
        return "noise"
    name = parts[-1]
    dirs = parts[:-1]
    if any(p in BEARING_DIRS or p.startswith("deploy") for p in dirs):
        return "bearing"
    if name.startswith("readme") or name.endswith(".env.example"):
        return "bearing"
    stem, _, ext = name.rpartition(".")
    if stem.startswith("addresses") and ext in ("json", "ts", "md"):
        return "bearing"
    if ext == "json" and ADDRESS_BOOK.search(stem):
        return "bearing"
    return "other"


def _excluded(address):
    return int(address, 16) <= 9 or address in SENTINELS


def _label(path, line):
    match = KEYED.search(line)
    if match and match.group(1).lower() not in GENERIC_KEYS:
        return match.group(1)
    p = Path(path)
    if p.suffix.lower() == ".json" and classify_path(path) == "bearing" and any(
            part.lower().startswith("deploy") or part.lower() == "broadcast"
            for part in p.parts[:-1]):
        return p.stem
    return None


def _record(book, address, path, line, commit=None):
    rec = book.setdefault(address, {"history": {}, "head_paths": set(), "categories": set(),
                                    "label": None, "line": None})
    category = classify_path(path)
    rec["categories"].add(category)
    if category == "noise":
        return
    if commit is None:
        rec["head_paths"].add(path)
    else:
        rec["history"].setdefault(path, [])
        seen = rec.setdefault("seen", [])
        if not seen or seen[-1] is not commit:
            seen.append(commit)
    # The first sighting in an address-bearing path names the address; a named key beats a line.
    if rec.get("label_from") == "bearing" and rec["label"]:
        return
    label = _label(path, line)
    if rec["line"] is None or (category == "bearing" and (
            rec.get("label_from") != "bearing" or label)):
        rec.update(label=label, line=line.strip()[:120], label_from=category)


def _scan_history(repo, max_commits, book):
    """Stream `git log -p` over every ref, newest `max_commits` commits, oldest first."""
    argv, env = _git(repo, "log", "--all", "--reverse", "--no-renames", "--no-color",
                     "--no-ext-diff", "--no-textconv", "-U0", "-p",
                     f"--max-count={max_commits}", "--format=%x01%H %ct %cI")
    proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env)
    commits, commit, path, in_header = 0, None, None, False
    for raw in proc.stdout:
        line = raw.decode("utf-8", "replace").rstrip("\n")
        if line.startswith("\x01"):
            sha, ct, iso = (line[1:].split(" ") + ["", ""])[:3]
            commit = {"commit": sha, "date": iso, "ts": int(ct or 0), "order": commits}
            commits += 1
            path, in_header = None, False
            continue
        if line.startswith("diff --git "):
            in_header = True
            tail = line[len("diff --git "):]
            path = tail.split(" b/", 1)[1] if " b/" in tail else None
            continue
        if in_header:
            if line.startswith("--- a/"):
                path = line[6:]
            elif line.startswith("+++ b/"):
                path = line[6:]
            elif line.startswith("@@"):
                in_header = False
            continue
        if commit is None or path is None or not line[:1] in ("+", "-"):
            continue
        for match in ADDRESS.finditer(line):
            address = match.group(0).lower()
            if not _excluded(address):
                _record(book, address, path, line[1:], commit)
    proc.stdout.close()
    if proc.wait() != 0:
        raise RuntimeError("git log failed on this checkout")
    return commits


def _scan_head(repo, book):
    out = _run(repo, "grep", "-I", "-i", "-z", "-E", "0x[0-9a-f]{40}", "HEAD", ok=(0, 1))
    for row in out.split("\n"):
        if "\0" not in row:
            continue
        name, line = row.split("\0", 1)
        path = name[len("HEAD:"):] if name.startswith("HEAD:") else name
        for match in ADDRESS.finditer(line):
            address = match.group(0).lower()
            if not _excluded(address):
                _record(book, address, path, line)


def _program(program):
    if not program:
        return None, None
    data = json.loads(Path(program).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("program.json must be an object")
    listed = set()
    for item in data.get("in_scope_addresses") or []:
        address = item.get("address") if isinstance(item, dict) else item
        if isinstance(address, str) and ADDRESS.fullmatch(address.strip()):
            listed.add(address.strip().lower())
    chains = data.get("chain_ids")
    chains = [c for c in chains if type(c) is int] if isinstance(chains, list) else []
    for item in data.get("in_scope_addresses") or []:
        if isinstance(item, dict) and type(item.get("chain_id")) is int:
            chains.append(item["chain_id"])
    return listed, sorted(set(chains)) or None


def scrub(text, url):
    """Drop the endpoint the caller passed - whole URL, bare host, userinfo and query."""
    text = str(text)
    if isinstance(url, str) and url.strip():
        url = url.strip()
        text = text.replace(url, "<endpoint>")
        parts = urllib.parse.urlsplit(url)
        for piece in (parts.hostname, parts.netloc, parts.query, parts.path.strip("/")):
            if piece and len(piece) > 3:
                text = re.sub(re.escape(piece), "<endpoint>", text, flags=re.I)
    return re.sub(r"https?://\S+", "<url>", text)


def rpc_call(url, method, params, opener=None, timeout=TIMEOUT):
    if method not in READ_ONLY_METHODS:
        raise ValueError(f"{method} is not a read-only method this sweep may send")
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
                          "params": params}).encode("utf-8")
    request = urllib.request.Request(url, data=payload, headers={
        "Content-Type": "application/json", "Accept": "application/json",
        "User-Agent": "bounty-pilot-legacy-sweep"})
    open_fn = opener or (lambda req, timeout: urllib.request.urlopen(req, timeout=timeout))
    with open_fn(request, timeout=timeout) as response:
        body = json.loads(response.read().decode("utf-8"))
    if "error" in body:
        raise ValueError(f"{method} returned an error: {json.dumps(body['error'])[:200]}")
    return body.get("result")


def _hex_int(value):
    if not isinstance(value, str) or not value.startswith("0x"):
        raise ValueError(f"not a hex quantity: {str(value)[:80]}")
    return int(value, 16) if len(value) > 2 else 0


def _onchain(address, rpc, tokens, opener):
    facts = {"has_code": None, "balances": {}, "errors": []}
    try:
        code = rpc_call(rpc, "eth_getCode", [address, "latest"], opener)
        facts["has_code"] = isinstance(code, str) and len(code) > 2 and int(code, 16) != 0
        facts["code_bytes"] = (len(code) - 2) // 2 if isinstance(code, str) else 0
    except Exception as exc:  # one address failing must not end the sweep
        facts["errors"].append({"method": "eth_getCode",
                                "reason": scrub(f"{type(exc).__name__}: {exc}", rpc)[:200]})
    try:
        facts["balances"]["native"] = str(_hex_int(
            rpc_call(rpc, "eth_getBalance", [address, "latest"], opener)))
    except Exception as exc:
        facts["errors"].append({"method": "eth_getBalance",
                                "reason": scrub(f"{type(exc).__name__}: {exc}", rpc)[:200]})
    for token in tokens:
        data = BALANCE_OF + address[2:].rjust(64, "0")
        try:
            facts["balances"][token] = str(_hex_int(
                rpc_call(rpc, "eth_call", [{"to": token, "data": data}, "latest"], opener)))
        except Exception as exc:
            facts["errors"].append({"method": "eth_call", "token": token,
                                    "reason": scrub(f"{type(exc).__name__}: {exc}", rpc)[:200]})
    facts["has_value"] = any(int(v) > 0 for v in facts["balances"].values())
    facts["value_raw_total"] = str(sum(int(v) for v in facts["balances"].values()))
    return facts


def _rank(row):
    chain = row.get("onchain") or {}
    code, value = bool(chain.get("has_code")), bool(chain.get("has_value"))
    tier = 0 if code and value else 1 if code else 2 if value else 3
    held = sum(1 for v in (chain.get("balances") or {}).values() if int(v) > 0)
    native = int((chain.get("balances") or {}).get("native") or 0)
    return (tier, -held, -native, row["first_seen"]["date"] if row["first_seen"] else "",
            row["address"])


def _stamp(commit):
    return {"commit": commit["commit"], "date": commit["date"]} if commit else None


def sweep(repo, program=None, rpc=None, tokens=None, opener=None, max_commits=5000):
    repo = Path(repo)
    if max_commits < 1:
        raise ValueError("max_commits must be at least 1")
    head = _run(repo, "rev-parse", "--verify", "HEAD").strip()
    total = int(_run(repo, "rev-list", "--all", "--count").strip() or 0)
    listed, chains = _program(program)
    tokens = [t.lower() for t in (tokens or [])]
    for token in tokens:
        if not ADDRESS.fullmatch(token):
            raise ValueError(f"--token {token!r} is not an EVM address")
    book = {}
    scanned = _scan_history(repo, max_commits, book)
    _scan_head(repo, book)

    counts = {"excluded_test_or_lib_only": 0, "excluded_outside_address_paths": 0}
    rows = []
    for address, rec in sorted(book.items()):
        if "bearing" not in rec["categories"]:
            key = ("excluded_test_or_lib_only" if rec["categories"] == {"noise"}
                   else "excluded_outside_address_paths")
            counts[key] += 1
            continue
        seen = sorted(rec.get("seen", []), key=lambda c: (c["ts"], c["order"]))
        present = bool(rec["head_paths"])
        row = {"address": address,
               "status": "current" if present else "removed",
               "present_at_head": present,
               "first_seen": _stamp(seen[0] if seen else None),
               "last_seen": _stamp(seen[-1] if seen else None),
               "paths": sorted(set(rec["history"]) | rec["head_paths"]),
               "head_paths": sorted(rec["head_paths"]),
               "label": rec["label"], "line": rec["line"]}
        if listed is not None:
            row["scope"] = "in_scope" if address in listed else "not_listed"
        rows.append(row)

    result = {"schema_version": SCHEMA_VERSION, "repo_commit": head,
              "commits_scanned": scanned, "commits_total": total,
              "truncated": total > scanned, "chain_id": None, "notes": []}
    if result["truncated"]:
        result["notes"].append(
            f"history truncated: {scanned} of {total} commits scanned (the newest ones); "
            "first_seen is a lower bound and older removed addresses may be missing - raise "
            "--max-commits")
    if listed is not None and chains:
        result["program_chain_ids"] = chains
    candidates = [row for row in rows if row["status"] == "removed"]
    if rpc:
        result["endpoint"] = "not recorded"
        try:
            result["chain_id"] = _hex_int(rpc_call(rpc, "eth_chainId", [], opener))
            result["head_block"] = _hex_int(rpc_call(rpc, "eth_blockNumber", [], opener))
        except Exception as exc:
            result["rpc_error"] = scrub(f"{type(exc).__name__}: {exc}", rpc)[:200]
        if chains and result["chain_id"] is not None and result["chain_id"] not in chains:
            result["chain_id_mismatch"] = True
            result["notes"].append(
                f"chain mismatch: the endpoint answers chain {result['chain_id']} but "
                f"program.json lists {chains}; these on-chain facts describe another chain")
        if "rpc_error" not in result:
            for row in candidates:
                row["onchain"] = _onchain(row["address"], rpc, tokens, opener)
            result["tokens"] = tokens
    candidates.sort(key=_rank)
    counts.update({"addresses": len(rows),
                   "current": sum(1 for r in rows if r["status"] == "current"),
                   "removed": len(candidates),
                   "legacy_with_code_and_value": sum(
                       1 for r in candidates if (r.get("onchain") or {}).get("has_code")
                       and r["onchain"].get("has_value"))})
    if listed is not None:
        counts["in_scope"] = sum(1 for r in rows if r["scope"] == "in_scope")
        counts["legacy_in_scope"] = sum(1 for r in candidates if r["scope"] == "in_scope")
    result.update({"addresses": rows, "legacy_candidates": candidates, "counts": counts,
                   "notice": NOTICE})
    return result


def main(argv=None):
    p = argparse.ArgumentParser(prog="bounty.py legacy-sweep", description=__doc__.split("\n")[0])
    p.add_argument("--repo", default=".", help="target checkout (its history is read)")
    p.add_argument("--program", help="<run>/program.json; in_scope_addresses and chain_ids")
    p.add_argument("--rpc", help="read-only JSON-RPC URL; never recorded")
    p.add_argument("--token", action="append", default=[],
                   help="ERC-20 whose balanceOf each candidate to read (repeatable)")
    p.add_argument("--max-commits", type=int, default=5000)
    p.add_argument("--out", help="write the JSON report here")
    a = p.parse_args(argv)
    try:
        report = sweep(a.repo, program=a.program, rpc=a.rpc, tokens=a.token,
                       max_commits=a.max_commits)
    except (OSError, ValueError, RuntimeError) as exc:
        p.error(scrub(str(exc), a.rpc))
    payload = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if a.out:
        Path(a.out).write_text(payload, encoding="utf-8")
        print(json.dumps({"out": a.out, "counts": report["counts"]}))
    else:
        sys.stdout.write(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
