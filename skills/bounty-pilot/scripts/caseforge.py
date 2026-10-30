#!/usr/bin/env python3
"""CaseForge: provenance-checked research corpus, never a benchmark oracle.

Only published cases are stored. A blind worklist is allowed ONLY for cases
with a concrete pre-fix pinned commit; it excludes all mechanism/answer fields.
Use Bounty Pilot's existing backtest init -> seal -> score for actual evaluation.
"""
import argparse
import json
import os
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit

CATALOG = Path(__file__).resolve().parent.parent / "references" / "caseforge-catalog.json"
TYPES = {"incident-postmortem", "paid-disclosure", "audited-finding"}
STATUSES = {"documented", "revision-pinned"}
FAMILIES = {"semantic-identity", "cross-phase", "authorization",
            "stateful-economics", "lifecycle", "signing", "other"}
SHA = re.compile(r"^[0-9a-f]{40}$")
MAX_CASES = 5000


def _string(value, label, maxlen=1000):
    if not isinstance(value, str) or not value.strip() or len(value) > maxlen:
        raise ValueError(label + ": expected nonempty short text")
    if any(ord(c) < 32 for c in value):
        raise ValueError(label + ": control character")
    return value


def _url(value, label):
    url = _string(value, label)
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
        raise ValueError(label + ": expected public HTTPS URL without credentials")
    return url


def _read(path):
    p = Path(path)
    if p.is_symlink() or not p.is_file() or p.stat().st_size > 3_000_000:
        raise ValueError("catalog must be a regular non-symlink JSON file under 3 MB")
    return json.loads(p.read_text(encoding="utf-8"))


def validate(data):
    """Fail closed: unknown revisions cannot be used for historical rediscovery."""
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise ValueError("catalog schema_version must be 1")
    cases = data.get("cases")
    if not isinstance(cases, list) or len(cases) > MAX_CASES:
        raise ValueError("cases must be a bounded list")
    seen = set()
    summary = {"documented": 0, "revision-pinned": 0}
    for index, case in enumerate(cases):
        tag = "cases[%s]" % index
        if not isinstance(case, dict):
            raise ValueError(tag + " must be an object")
        ident = _string(case.get("id"), tag + ".id", 100)
        if ident in seen:
            raise ValueError(tag + ": duplicate id")
        seen.add(ident)
        _string(case.get("project"), tag + ".project", 150)
        _string(case.get("mechanism"), tag + ".mechanism")
        _string(case.get("invariant"), tag + ".invariant")
        _url(case.get("source_url"), tag + ".source_url")
        source_type = case.get("source_type")
        if source_type not in TYPES:
            raise ValueError(tag + ": invalid source_type")
        family = case.get("family")
        if family not in FAMILIES:
            raise ValueError(tag + ": invalid family")
        state = case.get("status")
        if state not in STATUSES:
            raise ValueError(tag + ": invalid status")
        sha = case.get("vulnerable_commit")
        repo = case.get("repository_url")
        if state == "revision-pinned":
            _url(repo, tag + ".repository_url")
            if not isinstance(sha, str) or not SHA.fullmatch(sha):
                raise ValueError(tag + ": revision-pinned case requires 40-hex commit")
        elif sha is not None:
            raise ValueError(tag + ": documented case cannot assert a pinned commit")
        summary[state] += 1
    return {"schema_version": 1, "total_cases": len(cases), "by_status": summary,
            "measurement_ready": summary["revision-pinned"],
            "notice": "Documented incidents are retrospective leads, not measured rediscoveries."}


def index(data, family=None):
    validate(data)
    if family is not None and family not in FAMILIES:
        raise ValueError("invalid family filter")
    entries = []
    for case in data["cases"]:
        if family is not None and case["family"] != family:
            continue
        entries.append({key: case[key] for key in (
            "id", "project", "family", "source_type", "source_url",
            "mechanism", "invariant", "status")})
    return {"schema_version": 1, "cases": entries, "count": len(entries),
            "notice": "This is an unblinded research index; do not feed it to benchmark hunters."}


def blind_queue(data):
    validate(data)
    cases = [row for row in data["cases"] if row["status"] == "revision-pinned"]
    # NEVER leak ids, titles, root-cause descriptions or source URLs to hunters.
    # All pinned cases should be imported into an isolated backtest. This queue is
    # a preparation aid only and has no scoring/coverage permissions.
    return {"schema_version": 1, "tasks": [
        {"case": "CASE-%04d" % (index + 1), "repository_url": row["repository_url"],
         "pinned_commit": row["vulnerable_commit"],
         "protocol": "Use separate checkout; run existing backtest init, hunt, seal, then score."}
        for index, row in enumerate(cases)],
        "unavailable_without_pin": len(data["cases"]) - len(cases),
        "leak_warning": "Never expose the source catalog, its filenames, or the truth to "
                        "the hunting agent. A task list alone does not prove blinded isolation.",
        "measured_rediscoveries": 0}


def main(argv=None):
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("command", choices=["validate", "index", "blind-queue"])
    cli.add_argument("--catalog", default=str(CATALOG))
    cli.add_argument("--family", choices=sorted(FAMILIES))
    cli.add_argument("--out", default=None, help="optional output path for index or blind queue")
    args = cli.parse_args(argv)
    try:
        data = _read(args.catalog)
        if args.command == "validate":
            result = validate(data)
        elif args.command == "index":
            result = index(data, args.family)
        else:
            if args.family is not None:
                raise ValueError("--family only applies to index")
            result = blind_queue(data)
        serialized = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
        if args.out:
            target = Path(args.out).absolute()
            if target.exists():
                raise ValueError("output exists; refusing to overwrite")
            if target.parent.resolve() == Path(args.catalog).resolve().parent:
                raise ValueError("output must not share the source catalog directory")
            fd = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as out:
                out.write(serialized)
        else:
            print(serialized, end="")
        return 0
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print("Error: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
