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
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError(label + ": invalid Unicode text") from exc
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
    try:
        return json.loads(p.read_text(encoding="utf-8"), object_pairs_hook=_unique_object)
    except RecursionError as exc:
        raise ValueError("catalog JSON nesting exceeds the parser limit") from exc


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("catalog JSON contains a duplicate object key")
        result[key] = value
    return result


def validate(data):
    """Fail closed: unknown revisions cannot be used for historical rediscovery."""
    if (not isinstance(data, dict) or type(data.get("schema_version")) is not int
            or data["schema_version"] != 1):
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
        if not isinstance(source_type, str) or source_type not in TYPES:
            raise ValueError(tag + ": invalid source_type")
        family = case.get("family")
        if not isinstance(family, str) or family not in FAMILIES:
            raise ValueError(tag + ": invalid family")
        state = case.get("status")
        if not isinstance(state, str) or state not in STATUSES:
            raise ValueError(tag + ": invalid status")
        sha = case.get("vulnerable_commit")
        repo = case.get("repository_url")
        scope_paths = case.get("scope_paths")
        if scope_paths is not None:
            if (not isinstance(scope_paths, list) or not scope_paths
                    or len(scope_paths) > 30):
                raise ValueError(tag + ": scope_paths must be 1..30 relative paths")
            for scope in scope_paths:
                if (not isinstance(scope, str) or not scope
                        or scope.startswith("/") or chr(0) in scope
                        or ".." in Path(scope).parts or "\\" in scope):
                    raise ValueError(tag + ": invalid scope path")
        revision_source_url = case.get("revision_source_url")
        if revision_source_url is not None:
            _url(revision_source_url, tag + ".revision_source_url")
        snapshot_note = case.get("snapshot_note")
        if snapshot_note is not None:
            _string(snapshot_note, tag + ".snapshot_note", 500)
        if state == "revision-pinned":
            _url(repo, tag + ".repository_url")
            if not isinstance(sha, str) or not SHA.fullmatch(sha):
                raise ValueError(tag + ": revision-pinned case requires 40-hex commit")
            if not revision_source_url or not scope_paths:
                raise ValueError(tag + ": pinned case needs source revision citation and paths")
        elif sha is not None or repo is not None or revision_source_url is not None:
            raise ValueError(tag + ": documented case cannot assert pinned revision metadata")
        summary[state] += 1
    snapshots = {(c["repository_url"], c["vulnerable_commit"]) for c in cases
                 if c["status"] == "revision-pinned"}
    return {"schema_version": 1, "total_cases": len(cases), "by_status": summary,
            "pinned_finding_truths": summary["revision-pinned"],
            "measurement_ready": len(snapshots),
            "notice": "A pinned snapshot is only ready for benchmark preparation. "
                      "No historical case is counted as rediscovered until a sealed blind run."}


def index(data, family=None):
    validate(data)
    if family is not None and (not isinstance(family, str) or family not in FAMILIES):
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
    # Group by source snapshot so multiple findings in one audit cannot leak
    # the answer count or cause repeated non-blind hunts against the same revision.
    snapshots = sorted({(row["repository_url"], row["vulnerable_commit"])
                        for row in cases})
    # NEVER leak ids, titles, affected paths, root causes or source report URLs.
    # This opaque preparation queue cannot measure rediscovery.
    return {"schema_version": 1, "tasks": [
        {"case": "CASE-%04d" % (index + 1), "repository_url": repository,
         "pinned_commit": commit,
         "protocol": "Use separate checkout; run existing backtest init, hunt, seal, then score."}
        for index, (repository, commit) in enumerate(snapshots)],
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
