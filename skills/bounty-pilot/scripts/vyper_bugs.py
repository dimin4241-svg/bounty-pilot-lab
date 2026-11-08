#!/usr/bin/env python3
"""Offline Vyper compiler-advisory version matching (known issues only).

The bundled seed is one VERIFIED public GitHub advisory. Add other official
advisories as a reviewed local JSON export; NEVER infer missing affected ranges.
A version match is not proof a source pattern is present or that a deployed
contract is exploitable. Known disclosed advisories are generally not eligible
for a new compiler bounty. No remote lookups or target execution.
"""
import argparse
import json
import os
import re
import sys
from pathlib import Path

MAX_SIZE = 2_000_000
VERSION = re.compile(r"^(?:vyper:)?([0-9]+)\.([0-9]+)\.([0-9]+)(?:\+[A-Za-z0-9_.-]+)?$")
OFFICIAL = "https://github.com/vyperlang/vyper/security/advisories/"
KNOWN = [{
    "id": "GHSA-5824-cm3x-3c38",
    "title": "Incorrectly allocated named re-entrancy locks",
    "url": OFFICIAL + "GHSA-5824-cm3x-3c38",
    "exact_versions": ["0.2.15", "0.2.16", "0.3.0"],
    "required_conditions": [
        "contract compiled with a matching Vyper version",
        "two functions use the same named @nonreentrant key",
        "one function externally calls before effects are committed",
        "secondary function can misuse inconsistent storage during reentrancy",
    ],
    "source": "bundled-reviewed-2023-advisory",
}]


def parsed(version):
    if not isinstance(version, str):
        raise ValueError("Vyper version must be a string")
    m = VERSION.fullmatch(version.strip())
    if m is None:
        raise ValueError("unsupported version format (only stable MAJOR.MINOR.PATCH)")
    return tuple(int(x) for x in m.groups())


def _read(path):
    p = Path(path).expanduser()
    if p.is_symlink() or not p.is_file() or p.stat().st_size > MAX_SIZE:
        raise ValueError("input must be regular non-symlink JSON <=2 MB")
    return json.loads(p.read_text(encoding="utf-8"), object_pairs_hook=_pairs)


def _pairs(pairs):
    result = {}
    for k, v in pairs:
        if k in result:
            raise ValueError("duplicate JSON field: " + k)
        result[k] = v
    return result


def advisories(extra):
    rows = list(KNOWN)
    if extra is not None:
        if not isinstance(extra, dict) or extra.get("schema_version") != 1:
            raise ValueError("advisory export needs schema_version=1")
        more = extra.get("advisories")
        if not isinstance(more, list) or len(more) > 250:
            raise ValueError("advisory export must be bounded list")
        rows += more
    seen = set()
    for item in rows:
        if not isinstance(item, dict):
            raise ValueError("invalid advisory row")
        ident = item.get("id")
        if not isinstance(ident, str) or not re.fullmatch(r"GHSA-[a-z0-9-]{9,50}", ident):
            raise ValueError("invalid GitHub advisory id")
        if ident in seen:
            raise ValueError("duplicate advisory")
        seen.add(ident)
        if item.get("url") != OFFICIAL + ident:
            raise ValueError("advisory URL must match its official Vyper GHSA path")
        versions = item.get("exact_versions", [])
        ranges = item.get("ranges", [])
        if not isinstance(versions, list) or len(versions) > 50 or not isinstance(ranges, list) or len(ranges) > 20:
            raise ValueError("invalid affected version bounds")
        if not versions and not ranges:
            raise ValueError("advisory without an explicit affected range is unsafe")
        for version in versions:
            parsed(version)
        for region in ranges:
            if not isinstance(region, dict) or set(region) != {"introduced", "fixed"}:
                raise ValueError("range needs introduced (inclusive) and fixed (exclusive)")
            if parsed(region["introduced"]) >= parsed(region["fixed"]):
                raise ValueError("empty/reversed affected range")
        conditions = item.get("required_conditions", [])
        if not isinstance(conditions, list) or len(conditions) > 12 or not all(
                isinstance(x, str) and 0 < len(x) <= 250 for x in conditions):
            raise ValueError("invalid required conditions")
    return rows


def _affected(version, advisory):
    t = parsed(version)
    if any(t == parsed(v) for v in advisory.get("exact_versions", [])):
        return True
    return any(parsed(r["introduced"]) <= t < parsed(r["fixed"])
               for r in advisory.get("ranges", []))


def evaluate(doc, extra=None):
    if not isinstance(doc, dict) or doc.get("schema_version") != 1:
        raise ValueError("inventory requires schema_version=1")
    builds = doc.get("builds")
    if not isinstance(builds, list) or not 1 <= len(builds) <= 1000:
        raise ValueError("builds must be nonempty and <=1000")
    catalog = advisories(extra)
    out = []
    seen = set()
    for row in builds:
        if not isinstance(row, dict):
            raise ValueError("invalid build")
        name = row.get("id")
        if not isinstance(name, str) or not 1 <= len(name) <= 128 or name in seen:
            raise ValueError("build id invalid or duplicated")
        seen.add(name)
        compiler = row.get("compiler")
        if compiler not in ("vyper", "solc"):
            raise ValueError("compiler must be 'vyper' or 'solc'")
        verified = row.get("verified_actual_compiler")
        if type(verified) is not bool:
            raise ValueError("verified_actual_compiler must be boolean")
        version = row.get("version")
        if compiler == "solc":
            out.append({"id": name, "status": "unsupported-compiler",
                        "matches": [], "notice": "Use existing solc-bugs, not this tool"})
            continue
        parsed(version)
        matches = [{"id": a["id"], "url": a["url"], "title": a.get("title", "")[:150],
                    "required_conditions": a.get("required_conditions", []),
                    "status": "version-match-only",
                    "catalog_source": a.get("source", "operator-import-unverified")}
                   for a in catalog if _affected(version, a)]
        out.append({"id": name, "version": version,
                    "status": ("matched-known-advisory-review-conditions" if verified
                               else "unverified-build-compiler-version") if matches
                              else "no-match-in-incomplete-catalog",
                    "matches": matches,
                    "verified_actual_compiler": verified})
    return {"schema_version": 1, "execution": "offline-version-comparison-only",
            "advisory_count": len(catalog),
            "builds": out,
            "notice": ("The catalog is incomplete, and optional imported advisories are "
                       "operator-supplied. Compiler versions alone prove no affected "
                       "source path, reachability, deployed build, vulnerability, or payout. "
                       "Known public compiler advisories are not a new vulnerability.")}


def _write(path, data):
    p = Path(path).expanduser()
    if p.is_symlink() or p.exists():
        raise ValueError("output already exists")
    p.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(p), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, sort_keys=True, indent=2)
        f.write("\n")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--inventory", required=True, help="private compiler build inventory JSON")
    ap.add_argument("--advisories", help="optional manually reviewed official GHSA JSON export")
    ap.add_argument("--out", required=True, help="new private results JSON")
    args = ap.parse_args(argv)
    try:
        result = evaluate(_read(args.inventory),
                          _read(args.advisories) if args.advisories else None)
        _write(args.out, result)
    except (OSError, ValueError, TypeError, KeyError) as exc:
        ap.error(str(exc))
    print(json.dumps({"builds": len(result["builds"]), "catalog": result["advisory_count"],
                      "out": args.out, "execution": result["execution"]}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
