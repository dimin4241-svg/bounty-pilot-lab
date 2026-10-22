#!/usr/bin/env python3
"""Opt-in, evidence-labelled blind-spot data collection for Bounty Pilot Lab.

This module turns existing heuristic inventories and user-collected native artifacts into
bounded review queues. It never executes target code, probes RPC endpoints, applies mutations,
or changes finding status. Every output keeps observed data separate from inferred leads.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from collections import Counter
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import state_graph  # noqa: E402

GIT_HARDENING = ("--no-optional-locks", "-c", "core.fsmonitor=false", "-c",
                 "core.hooksPath=/dev/null", "--no-pager")
MAX_JSON_BYTES = 8_000_000
MAX_FILES = 30_000
MAX_LIVE_CALLS = 500


def _read_json(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_JSON_BYTES:
        raise ValueError("input must be a regular non-symlink file under the size limit")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("input JSON must be an object")
    return value


def _write(value, out=None):
    payload = json.dumps(value, ensure_ascii=False, indent=2) + "\n"
    if out:
        path = Path(out)
        if path.exists():
            raise ValueError("refusing to overwrite output: " + str(path))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(payload, encoding="utf-8")
        print(json.dumps({"out": str(path), "status": value.get("status", "created")}))
    else:
        print(payload, end="")


def _git(root, *args, timeout=30):
    return subprocess.run(["git", *GIT_HARDENING, "-C", str(root), *args],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout,
                          env={**os.environ, "GIT_TERMINAL_PROMPT": "0"}, check=False)


def _git_history(root):
    proc = _git(root, "log", "--format=commit %ct", "--name-only", "--no-renames", "-n", "3000")
    if proc.returncode:
        raise ValueError("git history unavailable: " + proc.stderr.decode("utf-8", "replace")[:240])
    last, current = {}, None
    for line in proc.stdout.decode("utf-8", "replace").splitlines():
        if line.startswith("commit "):
            try:
                current = int(line[7:].strip())
            except ValueError:
                current = None
        elif current is not None and line.strip():
            last.setdefault(line.strip(), current)
    return last


def legacy_inventory(repo, limit=600):
    """Rank old functions using age only as context, alongside dependency, privilege, assets,
    and test-reference signals. State graph edges remain explicitly lexical and low confidence."""
    root = Path(repo).resolve()
    graph = state_graph.scan(root, limit=limit)
    history = _git_history(root)
    now = int(dt.datetime.now(dt.timezone.utc).timestamp())
    symbols = graph["symbols"]
    inbound = Counter(edge["to"] for edge in graph["edges"])
    outbound = Counter(edge["from"] for edge in graph["edges"])
    tracked, mode = state_graph._tracked(root)
    test_text = []
    for relative in tracked[:MAX_FILES]:
        path = Path(relative)
        if not any(part.lower() in {"test", "tests", "spec", "specs"} for part in path.parts) \
                and not path.name.lower().startswith(("test_", "spec_")) \
                and not path.name.lower().endswith(("_test.go", ".t.sol", ".spec.ts", ".test.ts")):
            continue
        absolute = root / relative
        if absolute.is_symlink() or not absolute.is_file() or absolute.stat().st_size > 500_000:
            continue
        test_text.append(absolute.read_text(encoding="utf-8", errors="replace").lower())
    tests = "\n".join(test_text)
    rows = []
    for item in symbols:
        source = root / item["path"]
        try:
            body = source.read_text(encoding="utf-8", errors="replace").lower()
        except OSError:
            body = ""
        stamp = history.get(item["path"])
        age_days = max(0, (now - stamp) // 86400) if stamp else None
        auth_tokens = ("onlyowner", "onlyrole", "onlyadmin", "authorize", "msg.sender",
                       "hasrole", "accesscontrol", "signer", "delegate", "upgrade")
        asset_tokens = ("transfer", "withdraw", "deposit", "mint", "burn", "claim",
                        "reward", "borrow", "repay", "settle", "fee", "reserve")
        authority = [word for word in auth_tokens if word in body]
        assets = [word for word in asset_tokens if word in body]
        has_test_reference = item["symbol"].lower() in tests or \
            (Path(item["path"]).stem.lower() in tests and len(Path(item["path"]).stem) > 4)
        dependencies = inbound[item["id"]] + outbound[item["id"]]
        # Score dimensions are inspectable and age is deliberately not a proxy for risk.
        dependency_score = min(30, dependencies * 5)
        authority_score = min(25, len(authority) * 7)
        asset_score = min(25, len(assets) * 5)
        test_gap_score = 0 if has_test_reference else 20
        total = dependency_score + authority_score + asset_score + test_gap_score
        if age_days is not None and age_days < 180:
            continue
        rows.append({"symbol_id": item["id"], "path": item["path"], "symbol": item["symbol"],
                     "line": item["line"], "last_change_epoch": stamp,
                     "age_days_context_only": age_days,
                     "history_status": "file-last-change-known" if stamp else "outside-recent-history-window",
                     "dependency_edges_heuristic": dependencies,
                     "authority_signals": authority, "asset_operation_signals": assets,
                     "test_symbol_reference_found": has_test_reference,
                     "risk_score": total,
                     "score_components": {"dependency": dependency_score, "authority": authority_score,
                                          "asset_operations": asset_score, "test_gap": test_gap_score},
                     "evidence_level": "source-and-git-observations-with-lexical-dependency-hints",
                     "next_step": "confirm call/reachability and inspect native test coverage"})
    rows.sort(key=lambda row: (-row["risk_score"], -(row["age_days_context_only"] or 0),
                               row["path"], row["line"]))
    return {"schema": 1, "status": "review-queue", "method": "legacy-dependency-authority-assets-test-gap",
            "repo": str(root), "file_listing": mode, "candidates": rows,
            "counts": {"symbols_ranked": len(rows),
                       "old_file_symbols": sum(row["history_status"] == "file-last-change-known" for row in rows),
                       "history_window_unknown": sum(row["history_status"] != "file-last-change-known" for row in rows),
                       "without_test_symbol_reference": sum(not x["test_symbol_reference_found"] for x in rows)},
            "notice": "Age is context only. Dependency edges are regex-lexical, not a call graph; a test-name match is not coverage."}


INVALIDATION_PATTERNS = (
    ("transfer-then-old-authority", ("transfer", "changeowner", "setowner"),
     ("authorize", "onlyowner", "role", "admin", "execute")),
    ("revoke-then-old-permission", ("revoke", "disable", "remove", "unapprove"),
     ("permit", "allowance", "delegate", "execute", "transfer")),
    ("upgrade-then-old-state-reinterpretation", ("upgrade", "migrate", "initialize"),
     ("read", "load", "withdraw", "settle", "version")),
    ("oracle-disable-then-cached-read", ("disableoracle", "setoracle", "unregisterfeed"),
     ("price", "cached", "quote", "borrow", "liquidate")),
    ("withdraw-or-unvote-then-old-reward-weight", ("withdraw", "unvote", "unstake", "exit"),
     ("reward", "claim", "weight", "checkpoint", "distribute")),
    ("cancel-then-execute", ("cancel", "revokeorder", "cancelrequest"),
     ("execute", "settle", "consume", "finalize")),
    ("delete-recreate-then-old-state", ("delete", "remove", "unregister"),
     ("create", "register", "recreate", "initialize")),
    ("failure-retry-then-duplicate-or-lost-state", ("retry", "resume", "recover"),
     ("claim", "pay", "settle", "ack", "finalize")),
)


def state_invalidation(repo, limit=600, edge_limit=250):
    """Prioritize heuristic writer/reader links around invalidation-shaped transitions."""
    graph = state_graph.scan(repo, limit=limit)
    symbols = {item["id"]: item for item in graph["symbols"]}
    leads = []
    for edge in graph["edges"]:
        if edge.get("reason") != "qualified-or-indexed-write / lexical-read overlap":
            continue
        source, reader = symbols.get(edge.get("from")), symbols.get(edge.get("to"))
        if not source or not reader:
            continue
        source_words = source["symbol"].lower() + " " + " ".join(source.get("reads_approx", [])).lower()
        reader_words = reader["symbol"].lower() + " " + " ".join(reader.get("reads_approx", [])).lower()
        for label, transitions, uses in INVALIDATION_PATTERNS:
            if any(term in source_words for term in transitions) and \
                    any(term in reader_words for term in uses):
                leads.append({"scenario": label, "sequence": [source["id"], reader["id"]],
                              "shared_state_token": edge.get("token"),
                              "transition": {"path": source["path"], "line": source["line"],
                                             "symbol": source["symbol"]},
                              "later_reader": {"path": reader["path"], "line": reader["line"],
                                               "symbol": reader["symbol"]},
                              "confidence": "low-lexical-link",
                              "required_next_evidence": ["confirm actual state identity and call graph",
                                                         "establish caller permissions and ordered reachability",
                                                         "write native candidate and negative-control tests"]})
    # Keep the strongest evidence first and deduplicate identical source/reader/token leads.
    unique = {}
    for row in leads:
        key = (row["scenario"], tuple(row["sequence"]), row["shared_state_token"])
        unique.setdefault(key, row)
    rows = sorted(unique.values(), key=lambda row: (row["scenario"], row["transition"]["path"],
                                                    row["transition"]["line"], row["later_reader"]["path"]))
    return {"schema": 1, "status": "state-invalidation-review-queue", "method": graph["method"],
            "target": graph["source"], "candidates": rows[:edge_limit],
            "scenarios_present": sorted({row["scenario"] for row in rows}),
            "source_graph_edges": len(graph["edges"]), "candidate_count": len(rows),
            "notice": "These are symbol-name and lexical state-token overlaps, not reachable transitions. The engine does not treat a model trace as a native test."}


def parse_lcov(path, repo=None):
    """Read LCOV BRDA observations; zero or '-' hits are unexecuted branch outcomes."""
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_JSON_BYTES * 4:
        raise ValueError("LCOV input must be a regular non-symlink file under the size limit")
    current, rows, total, hit = None, [], 0, 0
    files = set()
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("SF:"):
            current = line[3:].strip()
            files.add(current)
        elif line.startswith("BRDA:") and current:
            parts = line[5:].split(",")
            if len(parts) != 4:
                continue
            source_line, block, branch, count = parts
            total += 1
            observed = count != "-" and count.isdigit() and int(count) > 0
            hit += observed
            if not observed:
                rows.append({"path": current, "line": int(source_line) if source_line.isdigit() else None,
                             "block": block, "branch": branch, "observed_count": count,
                             "state": "uncovered-branch-outcome"})
        elif line == "end_of_record":
            current = None
    source_checks, source_revision = [], None
    if repo:
        root = Path(repo).resolve()
        head = _git(root, "rev-parse", "HEAD")
        if head.returncode == 0:
            source_revision = head.stdout.decode("utf-8", "replace").strip()
        for name in sorted(files):
            candidate = Path(name)
            candidate = candidate if candidate.is_absolute() else root / candidate
            try:
                resolved = candidate.resolve()
                if candidate.is_symlink() or root not in resolved.parents or not resolved.is_file():
                    raise OSError("missing or outside repository")
                source_checks.append({"path": str(resolved.relative_to(root)),
                                      "sha256": hashlib.sha256(resolved.read_bytes()).hexdigest(),
                                      "status": "current-source-hash-recorded"})
            except OSError as exc:
                source_checks.append({"path": name, "status": "unverified", "reason": str(exc)})
    return {"schema": 1, "status": "instrumented-branch-gaps", "source": str(path),
            "source_revision": source_revision, "source_files": source_checks,
            "branch_outcomes_observed": hit, "branch_outcomes_total": total,
            "uncovered": rows,
            "notice": "LCOV is an observation artifact, not proof that the branch is unsafe. Check build/revision identity and inspect fallback, exception, and boundary semantics."}


def summarize_mutations(data):
    """Summarize common JSON mutation result shapes without claiming the tool ran correctly."""
    source = data.get("mutants", data.get("results"))
    if not isinstance(source, list):
        raise ValueError("mutation JSON requires a mutants or results array")
    rows, counts = [], Counter()
    for entry in source:
        if not isinstance(entry, dict):
            continue
        status = str(entry.get("status", entry.get("outcome", "unknown"))).lower()
        counts[status] += 1
        if status in {"survived", "missed", "timeout", "no_tests", "not_killed"}:
            rows.append({"id": entry.get("id", entry.get("mutant", "unknown")),
                         "path": entry.get("path", entry.get("file")),
                         "line": entry.get("line"), "status": status,
                         "mutation": entry.get("mutation", entry.get("diff")),
                         "review_action": "inspect whether the existing test suite detects this semantic change"})
    return {"schema": 1, "status": "mutation-review-queue", "counts": dict(counts),
            "survivors_and_unresolved": rows,
            "notice": "Mutation outcomes are test-strength signals. Verify target commit, tool exit and mutation scope; survivors do not establish a vulnerability."}


def _function_words(text):
    return re.findall(r"\b(?:function|fn|def|fun)\s+([A-Za-z_]\w*)", text)


def patch_propagation(repo, commit, limit=100):
    root = Path(repo).resolve()
    if not re.fullmatch(r"[0-9a-fA-F]{7,64}", commit):
        raise ValueError("--commit must be a hexadecimal git revision")
    check = _git(root, "rev-parse", "--verify", "--quiet", commit + "^{commit}")
    if check.returncode:
        raise ValueError("commit is not present in this checkout")
    revision = check.stdout.decode().strip()
    parent = _git(root, "rev-parse", "--verify", "--quiet", revision + "^")
    if parent.returncode:
        raise ValueError("patch propagation needs a non-root commit with one parent")
    base = parent.stdout.decode().strip()
    diff = _git(root, "diff", "--no-ext-diff", "--no-textconv", "--unified=0", base, revision, "--")
    if diff.returncode:
        raise ValueError("could not read commit diff")
    changed, tokens, names = set(), set(), set()
    for line in diff.stdout.decode("utf-8", "replace").splitlines():
        if line.startswith("+++ b/"):
            changed.add(line[6:])
        if line.startswith("+") and not line.startswith("+++"):
            names.update(_function_words(line[1:]))
            tokens.update(x.lower() for x in re.findall(r"[A-Za-z_][A-Za-z_0-9]{3,}", line[1:]))
    graph = state_graph.scan(root, limit=5000)
    symbols_by_name = {}
    for item in graph["symbols"]:
        symbols_by_name.setdefault(item["symbol"], []).append(item)
    candidates = []
    for name in sorted(names):
        for item in symbols_by_name.get(name, []):
            if item["path"] in changed:
                continue
            candidates.append({"symbol_id": item["id"], "path": item["path"],
                               "symbol": name, "line": item["line"],
                               "reason": "same function name as a function declaration added by the security-fix diff",
                               "review": "compare guard, authorization, state transition and call reachability manually"})
    # If no function declaration changed, use shared security-relevant identifiers only within
    # likely sibling files, and clearly mark the much lower confidence.
    if not candidates and tokens:
        for item in graph["symbols"]:
            if item["path"] in changed:
                continue
            body_terms = set(item.get("reads_approx", []))
            overlap = sorted(tokens & body_terms)
            if overlap:
                candidates.append({"symbol_id": item["id"], "path": item["path"],
                                   "symbol": item["symbol"], "line": item["line"],
                                   "reason": "changed-line identifier overlap: " + ", ".join(overlap[:8]),
                                   "review": "low-confidence candidate; establish semantic equivalence before comparing protections"})
    return {"schema": 1, "status": "patch-propagation-review-queue", "fix_commit": revision,
            "changed_paths": sorted(changed), "changed_function_names": sorted(names),
            "candidate_paths": candidates[:limit],
            "notice": "This search proposes similar paths only. It does not infer the fix's security meaning or prove equivalence, reachability, or missing protection."}


def live_config_diff(snapshot):
    """Compare collected read-only observations against explicit expectations and siblings."""
    expected = snapshot.get("expected")
    instances = snapshot.get("instances")
    if not isinstance(expected, dict) or not isinstance(instances, list) or not instances:
        raise ValueError("snapshot requires expected object and non-empty instances array")
    observed, missing, drift = [], [], []
    for instance in instances:
        if not isinstance(instance, dict) or not isinstance(instance.get("id"), str):
            raise ValueError("each instance needs a stable id")
        config = instance.get("values")
        if not isinstance(config, dict):
            config = {}
        missing_keys = sorted(set(expected) - set(config))
        if missing_keys:
            missing.append({"instance": instance["id"], "keys": missing_keys,
                            "state": "LIVE_STATE_UNVERIFIED"})
        for key in sorted(set(expected) & set(config)):
            left, right = expected[key], config[key]
            equal = (left.lower() == right.lower() if isinstance(left, str) and
                     isinstance(right, str) and re.fullmatch(r"0x[0-9a-fA-F]*", left) and
                     re.fullmatch(r"0x[0-9a-fA-F]*", right) else left == right)
            if not equal:
                sensitive = bool(re.search(r"(?i)(secret|private|mnemonic|seed|password|passwd|token|api[_-]?key|credential)", key))
                drift.append({"instance": instance["id"], "key": key,
                              "expected": "<REDACTED>" if sensitive else expected[key],
                              "observed": "<REDACTED>" if sensitive else config[key],
                              "state": "configuration-difference-needs-triage"})
        observed.append({"instance": instance["id"], "chain": instance.get("chain"),
                         "block": instance.get("block"), "values_present": len(config),
                         "read_status": instance.get("read_status", "unverified"),
                         "source": instance.get("source", "not-recorded")})
    return {"schema": 1, "status": "configuration-review-queue", "observed": observed,
            "differences": drift, "unverified": missing,
            "open_tasks": [{"instance": item["instance"], "key": key,
                            "state": "LIVE_STATE_UNVERIFIED"}
                           for item in missing for key in item["keys"]],
            "notice": "Values are compared only as supplied. A difference is not a vulnerability; confirm chain, block, proxy path, and authorization semantics. Missing RPC evidence stays open."}


def _rpc_read(url, method, params, timeout=15, opener=None):
    """The only RPC methods in this module are chain/head reads and eth_call."""
    if method not in ("eth_chainId", "eth_blockNumber", "eth_call"):
        raise ValueError("read-only method refused")
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
                          "params": params}).encode("utf-8")
    request = urllib.request.Request(url, data=payload, headers={
        "Content-Type": "application/json", "Accept": "application/json"})
    open_fn = opener or (lambda req, timeout: urllib.request.urlopen(req, timeout=timeout))
    with open_fn(request, timeout=timeout) as response:
        body = json.loads(response.read().decode("utf-8"))
    if not isinstance(body, dict) or "error" in body or "result" not in body:
        raise ValueError("RPC returned no result")
    return body["result"]


def _decode_static_result(raw, decoder):
    if not isinstance(raw, str) or not re.fullmatch(r"0x(?:[0-9a-fA-F]{2})*", raw):
        raise ValueError("eth_call returned malformed hex data")
    payload = raw[2:]
    if decoder == "hex":
        return "0x" + payload.lower()
    if len(payload) != 64:
        raise ValueError("static eth_call return must be exactly 32 bytes")
    if decoder == "uint":
        return int(payload, 16)
    if decoder == "bool":
        value = int(payload, 16)
        if value not in (0, 1):
            raise ValueError("boolean return must be exactly zero or one")
        return bool(value)
    if decoder == "address":
        return "0x" + payload[-40:].lower()
    if decoder == "bytes32":
        return "0x" + payload.lower()
    raise ValueError("decoder must be uint, bool, address, bytes32, or hex")


def query_live_config(snapshot, timeout=15, env=None, opener=None):
    """Fill instance.values with explicitly described eth_call reads, never writes.

    An endpoint is referenced only by an environment-variable name. Endpoint URLs are never
    copied into the snapshot, report, exception, or command output.
    """
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 1 <= timeout <= 60:
        raise ValueError("RPC timeout must be 1..60 seconds")
    instances = snapshot.get("instances")
    if not isinstance(instances, list):
        raise ValueError("snapshot.instances must be an array")
    call_count = sum(len(row.get("calls", [])) for row in instances
                     if isinstance(row, dict) and isinstance(row.get("calls"), list))
    if call_count > MAX_LIVE_CALLS:
        raise ValueError(f"live query is capped at {MAX_LIVE_CALLS} eth_call operations per run")
    out = json.loads(json.dumps(snapshot))
    env = env if env is not None else os.environ
    for instance in out["instances"]:
        instance["values"] = {}
        instance["read_status"] = "LIVE_STATE_UNVERIFIED"
        env_name = instance.get("rpc_env")
        calls = instance.get("calls")
        if not isinstance(env_name, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", env_name):
            instance["read_errors"] = ["missing a valid rpc_env variable name"]
            continue
        endpoint = env.get(env_name)
        if not isinstance(endpoint, str) or not endpoint.strip():
            instance["read_errors"] = ["RPC environment variable is unavailable"]
            continue
        if not isinstance(calls, list) or not calls:
            instance["read_errors"] = ["no explicit eth_call reads were supplied"]
            continue
        errors, keys = [], set()
        try:
            chain_hex = _rpc_read(endpoint, "eth_chainId", [], timeout, opener)
            head_hex = _rpc_read(endpoint, "eth_blockNumber", [], timeout, opener)
            if not isinstance(chain_hex, str) or not re.fullmatch(r"0x[0-9a-fA-F]+", chain_hex):
                raise ValueError("invalid chain id response")
            if not isinstance(head_hex, str) or not re.fullmatch(r"0x[0-9a-fA-F]+", head_hex):
                raise ValueError("invalid block response")
            actual_chain = int(chain_hex, 16)
            expected_chain = instance.get("expected_chain_id", instance.get("chain_id"))
            instance["chain"] = actual_chain
            instance["chain_id"] = actual_chain
            if expected_chain is not None and actual_chain != expected_chain:
                raise ValueError("RPC chain id differs from expected chain id")
            requested = instance.get("block", "latest")
            if requested == "latest":
                block_tag = head_hex
                instance["block"] = int(head_hex, 16)
            elif isinstance(requested, int) and not isinstance(requested, bool) and requested >= 0:
                block_tag = hex(requested)
            elif isinstance(requested, str) and re.fullmatch(r"0x[0-9a-fA-F]+", requested):
                block_tag = requested
            else:
                raise ValueError("block must be latest or a non-negative block number")
            instance["head_block_at_read"] = int(head_hex, 16)
            for call in calls:
                if not isinstance(call, dict):
                    errors.append("malformed call row")
                    continue
                key, address, data, decoder = (call.get("key"), call.get("to"),
                                               call.get("data"), call.get("decoder"))
                if not isinstance(key, str) or not key or key in keys:
                    errors.append("call keys must be non-empty and unique")
                    continue
                keys.add(key)
                if (not isinstance(address, str) or not re.fullmatch(r"0x[0-9a-fA-F]{40}", address)
                        or not isinstance(data, str) or len(data) > 8194 or
                        not re.fullmatch(r"0x(?:[0-9a-fA-F]{2})*", data)):
                    errors.append(key + ": invalid call target or calldata")
                    continue
                try:
                    raw = _rpc_read(endpoint, "eth_call", [{"to": address, "data": data}, block_tag],
                                    timeout, opener)
                    instance["values"][key] = _decode_static_result(raw, decoder)
                except (OSError, ValueError, TypeError, json.JSONDecodeError,
                        urllib.error.URLError, TimeoutError):
                    errors.append(key + ": read failed or returned data could not be decoded")
            instance["read_status"] = "read-complete" if not errors and len(instance["values"]) == len(calls) else "partial-read"
        except (OSError, ValueError, TypeError, json.JSONDecodeError,
                urllib.error.URLError, TimeoutError):
            errors.append("chain, head, or call read failed; endpoint omitted")
        instance["read_errors"] = errors
        instance["source"] = "read-only eth_call; endpoint environment variable " + env_name
    return out


def capacity_review(data, budget):
    if isinstance(budget, bool) or not isinstance(budget, (int, float)) or budget <= 0:
        raise ValueError("budget must be positive")
    samples = data.get("samples")
    if not isinstance(samples, list) or not samples:
        raise ValueError("measurements require a non-empty samples array")
    valid, failures = [], []
    for row in samples:
        if not isinstance(row, dict) or not isinstance(row.get("load"), (int, float, str)):
            continue
        measured = row.get("gas", row.get("compute", row.get("bytes")))
        if not isinstance(measured, int) or isinstance(measured, bool) or measured < 0:
            continue
        source_ref = row.get("source")
        if isinstance(source_ref, str) and (re.search(r"(?i)https?://|(?:token|secret|key|password)=", source_ref)
                                             or "@" in source_ref):
            source_ref = "<REDACTED>"
        item = {"load": row["load"], "measured": measured, "outcome": row.get("outcome", "unknown"),
                "recovery": row.get("recovery", "unknown"), "source": source_ref}
        valid.append(item)
        if measured > budget or row.get("outcome") in ("failed", "blocked", "reverted"):
            failures.append(item)
    def load_key(row):
        try:
            return float(row["load"])
        except (TypeError, ValueError):
            return float("inf")
    valid.sort(key=lambda row: (load_key(row), row["measured"]))
    failures.sort(key=lambda row: (load_key(row), row["measured"]))
    cliff = failures[0] if failures else None
    recovery = ("demonstrated" if any(row["recovery"] == "succeeded" for row in failures) else
                "failed" if any(row["recovery"] == "failed" for row in failures) else "unverified")
    return {"schema": 1, "status": "capacity-measurement-review", "metric": data.get("metric", "unspecified"),
            "budget": budget, "samples": valid, "first_observed_cliff": cliff,
            "self_recovery": recovery,
            "notice": "Threshold is derived only from supplied measurements. A single failure is not a permanent denial of service; verify native reproduction, maximum reachable load, and recovery after load reduction."}


def reopen_review(repo, findings):
    root = Path(repo).resolve()
    if not isinstance(findings, list):
        raise ValueError("findings must be an array")
    head = _git(root, "rev-parse", "HEAD")
    if head.returncode:
        raise ValueError("target checkout has no readable HEAD")
    current = head.stdout.decode().strip()
    rows = []
    for row in findings:
        if not isinstance(row, dict) or row.get("status") not in ("refuted", "parked"):
            continue
        prior = row.get("revision")
        paths = row.get("affected_paths", [])
        changed, unavailable = [], False
        if not isinstance(prior, str) or not re.fullmatch(r"[0-9a-fA-F]{7,64}", prior):
            unavailable = True
        else:
            result = _git(root, "diff", "--name-only", "--no-ext-diff", "--no-textconv", prior, current, "--")
            if result.returncode:
                unavailable = True
            else:
                changed = [line for line in result.stdout.decode("utf-8", "replace").splitlines() if line]
        overlap = sorted(set(paths if isinstance(paths, list) else []) & set(changed))
        new_artifact = row.get("new_evidence")
        if unavailable:
            state = "reopen-review-required-unverifiable-source-delta"
        elif overlap or (isinstance(new_artifact, str) and new_artifact.strip()):
            state = "reopen-review-required-new-evidence"
        else:
            state = "remains-closed-no-new-evidence"
        rows.append({"finding_id": row.get("id"), "prior_status": row.get("status"),
                     "state": state, "prior_revision": prior, "current_revision": current,
                     "changed_affected_paths": overlap,
                     "new_evidence_reference": new_artifact or None,
                     "notice": "Review only; finding status is never changed automatically."})
    return {"schema": 1, "status": "rejected-lead-review", "current_revision": current,
            "findings": rows,
            "notice": "A lead is reopened only for anchored new source or evidence. Path overlap is a trigger for independent review, not proof the earlier rejection was wrong."}


def trust_boundary_review(model):
    components = model.get("components")
    flows = model.get("flows")
    if not isinstance(components, list) or not components or not isinstance(flows, list):
        raise ValueError("trust model requires components and flows arrays")
    by_id = {}
    for component in components:
        if not isinstance(component, dict) or not isinstance(component.get("id"), str):
            raise ValueError("each trust component needs id")
        if component["id"] in by_id:
            raise ValueError("duplicate component id")
        by_id[component["id"]] = component
    gaps = []
    normalized = []
    for index, flow in enumerate(flows):
        if not isinstance(flow, dict):
            raise ValueError("each trust flow must be an object")
        source, destination = flow.get("source"), flow.get("destination")
        if source not in by_id or destination not in by_id:
            raise ValueError("flow references an unknown component")
        checks = flow.get("checks", {})
        if not isinstance(checks, dict):
            checks = {}
        required = ("parameter_origin", "signer_or_authenticator", "validation", "executed_value")
        missing = [key for key in required if not isinstance(checks.get(key), str) or not checks[key].strip()]
        if missing:
            gaps.append({"flow_index": index, "source": source, "destination": destination,
                         "missing": missing, "state": "trust-boundary-unverified"})
        normalized.append({"source": source, "destination": destination,
                           "data": flow.get("data"), "checks_recorded": sorted(set(required) - set(missing)),
                           "dependency_source_status": flow.get("dependency_source_status", "not-checked")})
    missing_sources = [item["id"] for item in components
                       if item.get("kind") == "external-dependency" and
                       item.get("source_status", "unavailable") not in ("available", "reviewed")]
    return {"schema": 1, "status": "trust-boundary-review", "flows": normalized,
            "unverified_flows": gaps, "unavailable_dependency_sources": missing_sources,
            "notice": "This validates inventory completeness only. It does not prove cryptographic correctness or runtime data flow; absent dependency source remains an explicit gap."}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    legacy = sub.add_parser("legacy", help="rank untouched legacy functions by concrete risk signals")
    legacy.add_argument("--repo", required=True)
    legacy.add_argument("--limit", type=int, default=600)
    legacy.add_argument("--out")
    invalidation = sub.add_parser("state-invalidation", help="rank invalidation-shaped writer/reader sequences")
    invalidation.add_argument("--repo", required=True)
    invalidation.add_argument("--limit", type=int, default=600)
    invalidation.add_argument("--edge-limit", type=int, default=250)
    invalidation.add_argument("--out")
    branch = sub.add_parser("branches", help="extract uncovered instrumented branch outcomes from LCOV")
    branch.add_argument("--lcov", required=True)
    branch.add_argument("--repo", help="checkout used to record current HEAD and source hashes")
    branch.add_argument("--out")
    mutations = sub.add_parser("mutations", help="turn mutation-tool JSON into a review queue")
    mutations.add_argument("--results", required=True)
    mutations.add_argument("--out")
    patch = sub.add_parser("patch-propagation", help="find sibling paths for a local security-fix commit")
    patch.add_argument("--repo", required=True)
    patch.add_argument("--commit", required=True)
    patch.add_argument("--limit", type=int, default=100)
    patch.add_argument("--out")
    live = sub.add_parser("live-config", help="compare collected read-only deployment values")
    live.add_argument("--snapshot", required=True)
    live.add_argument("--query-live", action="store_true",
                      help="explicitly issue only eth_chainId, eth_blockNumber and configured eth_call reads")
    live.add_argument("--timeout", type=float, default=15)
    live.add_argument("--out")
    capacity = sub.add_parser("capacity", help="locate measured capacity cliffs and recovery state")
    capacity.add_argument("--measurements", required=True)
    capacity.add_argument("--budget", required=True, type=float)
    capacity.add_argument("--out")
    reopen = sub.add_parser("reopen", help="review rejected leads only when new evidence exists")
    reopen.add_argument("--repo", required=True)
    reopen.add_argument("--findings", required=True)
    reopen.add_argument("--out")
    trust = sub.add_parser("trust", help="check a human-built cross-component trust-flow inventory")
    trust.add_argument("--model", required=True)
    trust.add_argument("--out")
    args = parser.parse_args(argv)
    try:
        if args.action == "legacy":
            if not 1 <= args.limit <= 5000:
                raise ValueError("--limit must be 1..5000")
            report = legacy_inventory(args.repo, args.limit)
        elif args.action == "state-invalidation":
            if not 1 <= args.limit <= 5000 or not 1 <= args.edge_limit <= 3000:
                raise ValueError("--limit must be 1..5000 and --edge-limit 1..3000")
            report = state_invalidation(args.repo, args.limit, args.edge_limit)
        elif args.action == "branches":
            report = parse_lcov(args.lcov, args.repo)
        elif args.action == "mutations":
            report = summarize_mutations(_read_json(args.results))
        elif args.action == "patch-propagation":
            if not 1 <= args.limit <= 500:
                raise ValueError("--limit must be 1..500")
            report = patch_propagation(args.repo, args.commit, args.limit)
        elif args.action == "live-config":
            snapshot = _read_json(args.snapshot)
            if args.query_live:
                snapshot = query_live_config(snapshot, args.timeout)
            report = live_config_diff(snapshot)
        elif args.action == "capacity":
            report = capacity_review(_read_json(args.measurements), args.budget)
        elif args.action == "reopen":
            raw = _read_json(args.findings)
            findings = raw.get("findings")
            if not isinstance(findings, list):
                raise ValueError("findings JSON requires a findings array")
            report = reopen_review(args.repo, findings)
        else:
            report = trust_boundary_review(_read_json(args.model))
        _write(report, args.out)
    except (OSError, ValueError, KeyError, json.JSONDecodeError, subprocess.SubprocessError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
