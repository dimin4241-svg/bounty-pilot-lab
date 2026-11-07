#!/usr/bin/env python3
"""Offline, scope-first intelligence for bounty programs.

Inputs: normalized snapshots, gkdataio/security-research-library programs.json,
or program-change-history.json. The external snapshot is *untrusted*; nothing
here authorizes testing and the tool makes no network requests.
"""
import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

MAX_INPUT = 9_000_000
MAX_ITEMS = 50000
SAFE_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
SOURCE = "offline-program-snapshot"


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False,
                                     separators=(",", ":")).encode("utf-8")).hexdigest()


def timestamp(value):
    if not isinstance(value, str):
        raise ValueError("snapshot_at must be an ISO8601 time with timezone")
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("invalid ISO8601 snapshot time") from exc
    if dt.tzinfo is None:
        raise ValueError("snapshot_at must have timezone")
    return dt.astimezone(timezone.utc)


def asset_value(asset):
    if isinstance(asset, str):
        text = asset
        kind = "unknown"
        eligible = None
    elif isinstance(asset, dict):
        text = asset.get("location") or asset.get("name") or asset.get("asset")
        kind = asset.get("asset_type") or "unknown"
        eligible = asset.get("bounty_eligible")
    else:
        raise ValueError("asset entry must be string or object")
    if not isinstance(text, str) or not text.strip() or len(text) > 1200:
        raise ValueError("asset must have a bounded, nonempty name/location")
    if eligible not in (None, True, False):
        raise ValueError("bounty_eligible must be true, false or null")
    if not isinstance(kind, str) or len(kind) > 64:
        raise ValueError("invalid asset_type")
    # Preserve path and wildcard exactly; any attempt to infer authorization
    # from a broad wildcard would be unsafe.
    return {"value": text.strip(), "type": kind.strip().lower(),
            "bounty_eligible": eligible}


def _asset_map(items):
    if not isinstance(items, list) or len(items) > MAX_ITEMS:
        raise ValueError("scope entries must be a bounded array")
    out = {}
    for item in items:
        row = asset_value(item)
        key = (row["value"].casefold(), row["type"])
        if key in out and out[key] != row:
            raise ValueError("conflicting duplicate scope entries")
        out[key] = row
    return out


def normalize(snapshot, format_hint="auto"):
    """A canonical program list, preserving in/out and eligibility separately."""
    if not isinstance(snapshot, dict):
        raise ValueError("snapshot must be a JSON object")
    library = isinstance(snapshot.get("schema_version"), str) and "programs" in snapshot
    if format_hint == "library" and not library:
        raise ValueError("expected gkdataio programs.json")
    if not library and snapshot.get("schema_version") != 1:
        raise ValueError("expected schema_version=1 or a library programs snapshot")
    at = snapshot.get("snapshot_at")
    if library:
        records = snapshot.get("programs")
        # Do not substitute a download time for when policies were verified.
        stamps = [p.get("last_verified_at") for p in records or []]
        if not at:
            # Per-program last verified timestamps are recorded on each entry.
            at = "1970-01-01T00:00:00Z"
    else:
        records = snapshot.get("programs")
    if not isinstance(records, list) or len(records) > 5000:
        raise ValueError("programs must be a bounded array")
    pinned_time = timestamp(at).isoformat()
    mapped = {}
    for row in records:
        if not isinstance(row, dict):
            raise ValueError("invalid program")
        platform = row.get("platform")
        ident = row.get("id")
        if not isinstance(platform, str) or not platform.strip() or len(platform) > 80:
            raise ValueError("program.platform required")
        if not isinstance(ident, str) or not SAFE_ID.fullmatch(ident):
            raise ValueError("program.id required (safe ID)")
        key = (platform.casefold(), ident.casefold())
        if key in mapped:
            raise ValueError("duplicate program " + ident)
        url = row.get("program_url")
        if not isinstance(url, str) or not url.startswith("https://") or not urlsplit(url).hostname:
            raise ValueError("program requires official HTTPS program_url")
        if library:
            scoped = row.get("asset_scope") or {}
            reward = (row.get("program_type") or {}).get("value", "unknown")
            in_scope = scoped.get("in_scope", [])
            out_scope = scoped.get("out_of_scope", [])
            verified = row.get("last_verified_at")
        else:
            in_scope = row.get("in_scope", [])
            out_scope = row.get("out_of_scope", [])
            reward = row.get("program_type", "unknown")
            verified = row.get("verified_at", pinned_time)
        if not isinstance(reward, str) or len(reward) > 80:
            raise ValueError("program_type invalid")
        if verified is not None:
            timestamp(verified)
        ins, outs = _asset_map(in_scope), _asset_map(out_scope)
        if set(ins) & set(outs):
            raise ValueError("asset simultaneously in/out of scope")
        mapped[key] = {
            "id": ident, "platform": platform, "program_url": url,
            "program_type": reward, "verified_at": verified,
            "in_scope": ins, "out_of_scope": outs,
        }
    return {"snapshot_at": pinned_time, "programs": mapped, "provenance": SOURCE,
            "count": len(mapped)}


def compare(before, after):
    a, b = normalize(before), normalize(after)
    if timestamp(b["snapshot_at"]) <= timestamp(a["snapshot_at"]):
        raise ValueError("after.snapshot_at must be strictly later than before.snapshot_at")
    old, new = a["programs"], b["programs"]
    leads = []
    for key in sorted(set(old) | set(new)):
        o, n = old.get(key), new.get(key)
        if o is None:
            leads.append({"kind": "new-program-in-snapshot", "program": key[1],
                          "platform": key[0], "program_url": n["program_url"],
                          "review": "verify live program and bounty terms"})
            continue
        if n is None:
            leads.append({"kind": "program-missing-in-snapshot", "program": key[1],
                          "platform": key[0], "program_url": o["program_url"],
                          "review": "could be collection failure; not necessarily closed"})
            continue
        base = {"program": key[1], "platform": key[0],
                "program_url": n["program_url"]}
        if o["program_type"] != n["program_type"]:
            leads.append(dict(base, kind="program-type-changed",
                              before=o["program_type"], after=n["program_type"],
                              review="check official reward policy before testing"))
        for scope in ("in_scope", "out_of_scope"):
            aa, bb = o[scope], n[scope]
            for asset_key in sorted(set(bb) - set(aa)):
                leads.append(dict(base, kind=scope + "-added",
                                  asset=bb[asset_key], review="verify current official scope"))
            for asset_key in sorted(set(aa) - set(bb)):
                leads.append(dict(base, kind=scope + "-removed",
                                  asset=aa[asset_key], review="verify current official scope"))
            for asset_key in sorted(set(aa) & set(bb)):
                if aa[asset_key]["bounty_eligible"] != bb[asset_key]["bounty_eligible"]:
                    leads.append(dict(base, kind=scope + "-eligibility-changed",
                                      asset=bb[asset_key],
                                      before=aa[asset_key]["bounty_eligible"],
                                      after=bb[asset_key]["bounty_eligible"],
                                      review="verify official eligibility and reward rules"))
    return {"schema_version": 1,
            "before_at": a["snapshot_at"], "after_at": b["snapshot_at"],
            "before_digest": fingerprint(before), "after_digest": fingerprint(after),
            "leads": leads, "count": len(leads),
            "confidence": "untrusted-public-snapshot-difference",
            "notice": ("A changed public listing or missing item is NOT permission to probe. "
                       "Manually check live policy, account/automation rules, exact scope, "
                       "effective date, exclusions and duplicate history.")}


def from_library_history(data):
    """Consume gkdataio program-change-history schema 1.0.0 as leads."""
    if not isinstance(data, dict) or data.get("schema_version") != "1.0.0":
        raise ValueError("expected library history schema_version 1.0.0")
    records = data.get("entries")
    if not isinstance(records, list) or len(records) > 500:
        raise ValueError("history entries must be a bounded array")
    leads = []
    for entry in records:
        if not isinstance(entry, dict):
            raise ValueError("invalid history entry")
        recorded = timestamp(entry.get("recorded_at")).isoformat()
        for change in entry.get("changes", []):
            base = {"recorded_at": recorded,
                    "program": str(change.get("name") or change.get("key") or "")[:150],
                    "platform": str(change.get("platform") or "")[:80],
                    "program_url": str(change.get("program_url") or "")[:600]}
            for field in change.get("fields", []):
                path = field.get("field", "")
                if not (path.endswith("in_scope") or path.endswith("out_of_scope")
                        or path.endswith("asset_scope.in_scope")
                        or path.endswith("asset_scope.out_of_scope")):
                    continue
                for verb in ("added", "removed"):
                    for entry_asset in field.get(verb, []):
                        value = asset_value(entry_asset)
                        if len(leads) >= MAX_ITEMS:
                            raise ValueError("too many history leads")
                        leads.append(dict(base, kind="history-" + path + "-" + verb,
                                          asset=value, source_field=path,
                                          confidence="recorded-listing-change-only",
                                          review="check current official rules and when change took effect"))
    return {"schema_version": 1, "leads": leads, "count": len(leads),
            "source_digest": fingerprint(data),
            "notice": ("Library's recorded_at is NOT scope effective time. A published "
                       "difference is neither program authorization nor a bounty guarantee.")}


def read(path):
    p = Path(path).expanduser()
    if not p.is_file() or p.is_symlink() or p.stat().st_size > MAX_INPUT:
        raise ValueError("input must be a regular non-symlink JSON <=9MB")
    return json.loads(p.read_text(encoding="utf-8"))


def write(path, data):
    p = Path(path).expanduser()
    if p.exists() or p.is_symlink():
        raise ValueError("out must be create-only")
    p.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(p), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as out:
        json.dump(data, out, indent=2, ensure_ascii=False)
        out.write("\n")


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    source = p.add_mutually_exclusive_group(required=True)
    source.add_argument("--history", help="gkdataio program-change-history.json")
    source.add_argument("--before", help="previous normalized/library programs snapshot")
    p.add_argument("--after", help="next snapshot; required with --before")
    p.add_argument("--out", required=True)
    args = p.parse_args(argv)
    if bool(args.after) != bool(args.before):
        p.error("--before and --after must be used together")
    try:
        result = (from_library_history(read(args.history)) if args.history
                  else compare(read(args.before), read(args.after)))
        write(args.out, result)
    except (ValueError, OSError, TypeError, KeyError, json.JSONDecodeError) as exc:
        p.error(str(exc))
    print(json.dumps({"out": args.out, "leads": result["count"]}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
