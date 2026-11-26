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

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report")
    args = parser.parse_args()
    try:
        result = summarize(read_local(args.report))
    except (OSError, ValueError, RecursionError):
        parser.exit(2, "Invalid, unreadable or oversized local SARIF report\n")
    print(json.dumps(result, indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
