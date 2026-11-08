#!/usr/bin/env python3
"""Merge program, JS and OpenAPI leads into a prioritized *review* queue.

This module NEVER authorizes or executes testing. Priority is a heuristic for
review order, not severity, exploitability, novelty or payout likelihood.
"""
import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit

DOMAIN = re.compile(r"^(?:\*\.)?[a-zA-Z0-9.-]{3,253}$")
MAX_LEADS = 100000


def _host(value):
    if not isinstance(value, str) or not value or len(value) > 1200:
        return None
    try:
        if value.startswith("http://") or value.startswith("https://"):
            return urlsplit(value).hostname
        if value.startswith("*.") and DOMAIN.fullmatch(value):
            return value.lower()
        if DOMAIN.fullmatch(value) and "." in value:
            return value.lower()
    except ValueError:
        return None
    return None


def _in_host(host, candidate):
    if not host or not candidate:
        return False
    if candidate.startswith("*."):
        suffix = candidate[2:]
        return host.endswith("." + suffix)
    return host == candidate


def _digest(data):
    return hashlib.sha256(json.dumps(data, ensure_ascii=False, sort_keys=True,
                                     separators=(",", ":")).encode("utf-8")).hexdigest()


def _lead_id(source, item):
    return hashlib.sha256((source + ":" + _digest(item)).encode("ascii")).hexdigest()[:20]


def merge(program=None, javascript=None, openapi=None, api_host=None,
          max_queue=2500):
    if type(max_queue) is not int or not 1 <= max_queue <= 10000:
        raise ValueError("max_queue must be 1..10000")
    sources = {"scope": program, "javascript": javascript, "openapi": openapi}
    if not any(value is not None for value in sources.values()):
        raise ValueError("at least one source report required")
    for name, obj in sources.items():
        if obj is None:
            continue
        if not isinstance(obj, dict) or obj.get("schema_version") != 1:
            raise ValueError(name + " schema_version=1 required")
        if not isinstance(obj.get("leads"), list) or len(obj["leads"]) > MAX_LEADS:
            raise ValueError(name + " leads must be bounded array")
    if api_host is not None:
        api_host = _host(api_host)
        if not api_host or api_host.startswith("*."):
            raise ValueError("--api-host must be an exact hostname")
    new_scope_hosts = {}
    if program:
        for r in program["leads"]:
            if not isinstance(r, dict):
                continue
            typ = r.get("kind", "")
            # Only positively listed IN-scope additions are eligible for
            # correlation. 'out_of_scope-added' must NEVER raise priority.
            # This also recognizes upstream history field prefixes such as
            # 'history-policy.asset_scope.in_scope-added'.
            if not isinstance(typ, str) or not (
                typ == "in_scope-added" or typ.endswith(".in_scope-added")
            ):
                continue
            a = r.get("asset", {})
            if isinstance(a, dict) and a.get("bounty_eligible") is False:
                continue
            host = _host(a.get("value") if isinstance(a, dict) else a)
            if host:
                new_scope_hosts.setdefault(host, []).append(r.get("program_url"))
    queue = []
    seen = set()

    def add(source, record, score, method, host=None, reason=""):
        if not isinstance(record, dict):
            return
        ident = _lead_id(source, record)
        if ident in seen:
            return
        seen.add(ident)
        related = sorted({link for needle, links in new_scope_hosts.items()
                          if _in_host(host, needle) for link in links
                          if isinstance(link, str)})
        boosted = min(100, score + (12 if source != "scope" and related else 0))
        row = {"id": ident, "source": source, "kind": str(record.get("kind") or record.get("review_category") or "unspecified")[:90],
               "priority_score": boosted,
               "proposed_next_step": method,
               "reasons": [reason] if reason else [],
               "matching_scope_change_urls": related,
               "requires_official_scope_recheck": True,
               "evidence_source_digest": _digest(record)}
        if host:
            row["host"] = host
        # Include bounded references, not unsanitized raw report contents.
        if source == "javascript":
            row["script_id"] = str(record.get("script_id") or "")[:100]
            if record.get("endpoint"):
                row["endpoint"] = str(record["endpoint"])[:250]
        elif source == "openapi":
            row["path_template"] = str(record.get("path_template") or "")[:600]
        else:
            row["program"] = str(record.get("program") or "")[:150]
            row["program_url"] = str(record.get("program_url") or "")[:600]
        queue.append(row)

    if program:
        for r in program["leads"]:
            if not isinstance(r, dict):
                continue
            typ = str(r.get("kind") or "")
            a = r.get("asset")
            host = _host(a.get("value") if isinstance(a, dict) else a)
            positively_scoped = typ == "in_scope-added" or typ.endswith(".in_scope-added")
            reward_excluded = isinstance(a, dict) and a.get("bounty_eligible") is False
            reward_revoked = typ.endswith("eligibility-changed") and (
                r.get("after") is False or reward_excluded)
            score = (35 if reward_revoked or reward_excluded else
                     85 if "eligibility-changed" in typ else
                     80 if positively_scoped else 30)
            add("scope", r, score, "read live official program policy and date; check bounty eligibility",
                host=host, reason="changed public program snapshot")

    if javascript:
        for r in javascript["leads"]:
            if not isinstance(r, dict):
                continue
            typ = str(r.get("kind") or "")
            host = _host(r.get("endpoint")) or _host(r.get("script_url"))
            tags = r.get("present_topics") or []
            score = (75 if typ == "endpoint-added" else
                     68 if typ == "js-source-changed" and
                     ("authorization" in tags or "payment-flow" in tags) else
                     35)
            add("javascript", r, score,
                "review pinned JS diff and owner/actor trust boundaries before building test plan",
                host=host, reason="changed local script or extracted endpoint")

    if openapi:
        for r in openapi["leads"]:
            if not isinstance(r, dict):
                continue
            score = 63 if r.get("review_category") == "object-identifier-review" else 25
            add("openapi", r, score,
                "materialize owned test IDs, then prepare controlled two-account GET plan",
                host=api_host, reason="unverified OpenAPI GET path candidate")

    queue.sort(key=lambda r: (-r["priority_score"], r["source"], r["id"]))
    return {"schema_version": 1, "leads": queue[:max_queue],
            "total_generated": len(queue), "written": min(max_queue, len(queue)),
            "truncated": max(0, len(queue) - max_queue),
            "source_digests": {key: _digest(value) for key, value in sources.items()
                               if value is not None},
            "execution": "offline-review-prioritization-only",
            "notice": ("A priority score is NOT severity, proof, scope permission or originality. "
                       "Before any testing, independently check live program policy, authorized "
                       "identities, safe-harbor limits and duplicate disclosures. "
                       "Never feed these leads into an automatic production scanner.")}


def _read(path):
    p = Path(path).expanduser()
    if p.is_symlink() or not p.is_file() or p.stat().st_size > 8_000_000:
        raise ValueError("input must be regular non-symlink JSON <=8MB")
    return json.loads(p.read_text(encoding="utf-8"))


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--program-leads")
    p.add_argument("--js-leads")
    p.add_argument("--openapi-leads")
    p.add_argument("--api-host")
    p.add_argument("--max-queue", type=int, default=2500)
    p.add_argument("--out", required=True)
    a = p.parse_args(argv)
    out = Path(a.out).expanduser()
    if out.is_symlink() or out.exists():
        p.error("output must not exist")
    try:
        result = merge(_read(a.program_leads) if a.program_leads else None,
                       _read(a.js_leads) if a.js_leads else None,
                       _read(a.openapi_leads) if a.openapi_leads else None,
                       a.api_host, a.max_queue)
        out.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(out), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(result, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
    except (ValueError, OSError, TypeError, json.JSONDecodeError) as exc:
        p.error(str(exc))
    print(json.dumps({"out": str(out), "written": result["written"],
                      "truncated": result["truncated"]}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
