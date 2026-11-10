#!/usr/bin/env python3
"""Offline N-day regression and incomplete-fix review of two pinned route AST reports.

A newly added apparent auth guard is an investigation lead, NOT evidence that
any prior version was vulnerable. This does not query running deployments.
"""
import argparse
import hashlib
import json
import os
import sys
from pathlib import Path


def load(path):
    p = Path(path)
    if p.is_symlink() or not p.is_file() or p.stat().st_size > 3_000_000:
        raise ValueError("input must be a regular JSON file <=3MB")
    return json.loads(p.read_text(encoding="utf-8"))


def _index(snapshot):
    if not isinstance(snapshot, dict) or snapshot.get("mode") != "web-route-ast":
        raise ValueError("both inputs must be web-route-ast reports")
    routes = snapshot.get("routes")
    if not isinstance(routes, list) or len(routes) > 10000:
        raise ValueError("routes must be a bounded list")
    out = {}
    for item in routes:
        if not isinstance(item, dict):
            raise ValueError("invalid route")
        key = (item.get("handler"), item.get("method"), item.get("path"))
        if any(not isinstance(v, str) for v in key):
            raise ValueError("invalid route key")
        if key in out:
            raise ValueError("duplicate route in snapshot")
        guards = item.get("guard_name_cues")
        calls = item.get("call_names")
        if not isinstance(guards, list) or not isinstance(calls, list):
            raise ValueError("route lacks bounded source cues")
        out[key] = {"guards": set(guards), "calls": set(calls)}
    return out


def compare(before, after):
    old, new = _index(before), _index(after)
    leads = []
    for key, row in sorted(new.items()):
        prior = old.get(key)
        if prior is None:
            continue
        added = sorted(row["guards"] - prior["guards"])
        if not added:
            continue
        siblings = []
        for other_key, other_row in new.items():
            if other_key == key:
                continue
            # Shared business call sites only; common builtins don't count.
            shared = (row["calls"] & other_row["calls"]) - {
                "str", "int", "dict", "list", "len", "print", "json.dumps"}
            if shared and not set(added).intersection(other_row["guards"]):
                siblings.append({"handler": other_key[0], "method": other_key[1],
                                 "path": other_key[2], "common_calls": sorted(shared)[:8]})
        leads.append({
            "id": hashlib.sha256(repr(key).encode()).hexdigest()[:16],
            "kind": "AUTH_GUARD_CUE_ADDED", "handler": key[0],
            "method": key[1], "path": key[2], "added_guard_names": added,
            "unreviewed_sibling_candidates": sorted(siblings, key=lambda x: (
                x["handler"], x["method"], x["path"]))[:30],
            "classification": "UNVERIFIED_NDAY_REVIEW",
            "next_step": ("Read the fixing commit and the exact dependent router policies, "
                          "then test owned local fixtures on both pinned versions.")
        })
    return {
        "schema_version": 1, "mode": "web-nday-review",
        "leads": leads, "before_routes": len(old), "after_routes": len(new),
        "network_requests": 0, "confirmed_vulnerabilities": 0,
        "limitations": ("Only AST-extracted guard-name deltas; no patch impact, "
                        "runtime revision, vulnerability, or duplicate status is proven.")}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--before", required=True, help="old pinned source route AST JSON")
    p.add_argument("--after", required=True, help="new pinned source route AST JSON")
    p.add_argument("--out", required=True, help="create-only local output")
    a = p.parse_args(argv)
    try:
        result = compare(load(a.before), load(a.after))
        path = Path(a.out)
        if path.exists() or path.is_symlink():
            raise ValueError("output must be new")
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False, sort_keys=True)
            f.write("\n")
    except (ValueError, TypeError, OSError, json.JSONDecodeError) as exc:
        p.error(str(exc))
    print(json.dumps({"out": a.out, "leads": len(result["leads"])}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
