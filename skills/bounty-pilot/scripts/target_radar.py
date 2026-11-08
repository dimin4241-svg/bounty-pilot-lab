#!/usr/bin/env python3
"""Offline Target Radar: compare two pinned, read-only deployment/config snapshots.

Accepts config_snapshot.py output and/or a declared inventory with targets
containing address, implementation, code_hash, scope and reads. No network,
RPC writes or live probing. Changed values are research leads, not exploitable bugs.
"""
import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path

ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}$")


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest(value):
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _targets(data):
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise ValueError("snapshot requires schema_version=1")
    chain = data.get("chain_id")
    block = data.get("block")
    if type(chain) is not int or chain < 1 or type(block) is not int or block < 0:
        raise ValueError("snapshot requires pinned chain_id and block")
    targets = data.get("targets")
    if not isinstance(targets, list) or len(targets) > 5000:
        raise ValueError("targets must be a list <=5000")
    mapped = {}
    for item in targets:
        if not isinstance(item, dict):
            raise ValueError("invalid target entry")
        addr = item.get("address")
        if not isinstance(addr, str) or not ADDRESS.fullmatch(addr):
            raise ValueError("target must have 20-byte address")
        addr = addr.lower()
        if addr in mapped:
            raise ValueError("duplicate target address: " + addr)
        # Read-only snapshots may have failed halfway. Never report a change
        # if either snapshot has an error for that target.
        mapped[addr] = item
    return chain, block, mapped


def compare(before, after):
    chain, old_block, old = _targets(before)
    chain_new, new_block, new = _targets(after)
    if chain != chain_new or new_block <= old_block:
        raise ValueError("must compare ascending pinned blocks on the same chain")
    leads = []
    for address in sorted(set(old) | set(new)):
        if address not in old:
            leads.append({"address": address, "kind": "new-deployment-in-inventory",
                          "confidence": "declared-inventory-only",
                          "detail": "target newly present in supplied snapshot"})
            continue
        if address not in new:
            leads.append({"address": address, "kind": "inventory-removed",
                          "confidence": "declared-inventory-only",
                          "detail": "does not prove contract self-destructed or lost scope"})
            continue
        a, b = old[address], new[address]
        if a.get("errors") or b.get("errors"):
            leads.append({"address": address, "kind": "comparison-blocked",
                          "confidence": "unknown",
                          "detail": "one or both read-only snapshots have errors"})
            continue
        for field, kind in (("implementation", "proxy-implementation-changed"),
                            ("code_hash", "runtime-bytecode-changed"),
                            ("scope", "declared-scope-changed")):
            if field in a and field in b and a[field] != b[field]:
                leads.append({"address": address, "kind": kind,
                              "before": str(a[field])[:160], "after": str(b[field])[:160],
                              "confidence": "snapshot-difference"})
        if isinstance(a.get("reads"), dict) and isinstance(b.get("reads"), dict):
            for key in sorted(set(a["reads"]) & set(b["reads"])):
                if a["reads"][key] != b["reads"][key]:
                    leads.append({"address": address, "kind": "deployed-config-changed",
                                  "field": key[:100], "before_digest": _digest(a["reads"][key]),
                                  "after_digest": _digest(b["reads"][key]),
                                  "confidence": "snapshot-difference"})
    return {"schema_version": 1, "chain_id": chain,
            "before_block": old_block, "after_block": new_block,
            "new_inventory_addresses": sum(x["kind"] == "new-deployment-in-inventory" for x in leads),
            "implementation_changes": sum(x["kind"] == "proxy-implementation-changed" for x in leads),
            "leads": leads, "provenance": "two-operator-supplied-read-only-snapshots",
            "notice": ("Snapshot comparison is not continuous monitoring or proof that "
                       "an implementation is vulnerable. Verify both values and scope "
                       "independently, inspect the diff, and check previous audits before "
                       "claiming novelty. No transactions were sent.")}


def _read(path):
    path = Path(path).expanduser()
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 4_000_000:
        raise ValueError("snapshot must be a regular non-symlink file <=4MB")
    return json.loads(path.read_text(encoding="utf-8"))


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--before", required=True)
    p.add_argument("--after", required=True)
    p.add_argument("--out", required=True)
    a = p.parse_args(argv)
    out = Path(a.out).expanduser()
    if out.exists() or out.is_symlink():
        p.error("output must be create-only")
    try:
        result = compare(_read(a.before), _read(a.after))
    except (ValueError, TypeError, OSError, json.JSONDecodeError) as exc:
        p.error(str(exc))
    out.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(out), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(result, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
    print(json.dumps({"out": str(out), "leads": len(result["leads"])}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
