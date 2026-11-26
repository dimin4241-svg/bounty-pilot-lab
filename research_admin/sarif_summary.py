"""Read-only administrative inventory of a local SARIF 2.1.0 report."""
import argparse
import hashlib
import json
import os
import stat
from pathlib import Path

MAX_BYTES = 16 * 1024 * 1024
LEVELS = ("error", "warning", "note", "none", "unspecified")

def summarize(raw):
    if len(raw) > MAX_BYTES:
        raise ValueError("Report exceeds size limit")
    report = json.loads(raw)
    if not isinstance(report, dict) or report.get("version") != "2.1.0":
        raise ValueError("Expected a SARIF 2.1.0 object")
    runs = report.get("runs")
    if not isinstance(runs, list):
        raise ValueError("Expected runs array")
    counts = dict.fromkeys(LEVELS, 0)
    for run in runs:
        if not isinstance(run, dict):
            raise ValueError("Invalid run")
        results = run.get("results", [])
        if not isinstance(results, list):
            raise ValueError("Invalid results array")
        for result in results:
            if not isinstance(result, dict):
                raise ValueError("Invalid result")
            level = result.get("level", "unspecified")
            if not isinstance(level, str) or level not in LEVELS:
                raise ValueError("Unsupported result level")
            counts[level] += 1
    return {
        "format": "SARIF 2.1.0",
        "sha256": hashlib.sha256(raw).hexdigest(),
        "bytes": len(raw),
        "runs": len(runs),
        "result_count": sum(counts.values()),
        "reported_levels": counts,
        "review_status": "pending_manual_review",
        "technical_validity": "not_assessed",
        "notice": "Counts are unverified report metadata, not confirmed findings.",
    }

def read_local(path):
    # Refuse final-component symlinks, pipes and devices. Never follow SARIF URIs.
    flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW
    fd = os.open(Path(path).expanduser(), flags)
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("Report must be a regular file")
        return stream.read(MAX_BYTES + 1)

def save_summary(summary, destination):
    """Save a private summary without overwriting existing files."""
    path = Path(destination).expanduser()
    payload = (json.dumps(summary, indent=2, sort_keys=True) + "\n").encode("utf-8")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise

def verify_summary(report, stored):
    """Compare a stored inventory with a newly computed inventory."""
    expected = summarize(read_local(report))
    raw = read_local(stored)
    if len(raw) > MAX_BYTES:
        raise ValueError("Stored summary exceeds size limit")
    supplied = json.loads(raw)
    if not isinstance(supplied, dict):
        raise ValueError("Stored summary must be an object")
    # Canonical JSON comparison also distinguishes booleans from numbers.
    return json.dumps(expected, sort_keys=True) == json.dumps(supplied, sort_keys=True)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report")
    output = parser.add_mutually_exclusive_group()
    output.add_argument("--save", metavar="SUMMARY")
    output.add_argument("--verify", metavar="SUMMARY")
    args = parser.parse_args()
    try:
        if args.verify:
            matched = verify_summary(args.report, args.verify)
            print(json.dumps({"matches": matched, "technical_validity": "not_assessed"}))
            return 0 if matched else 1
        result = summarize(read_local(args.report))
        if args.save:
            save_summary(result, args.save)
    except (OSError, ValueError, RecursionError):
        parser.exit(2, "Invalid, unreadable or oversized local SARIF report\n")
    print(json.dumps(result, indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
