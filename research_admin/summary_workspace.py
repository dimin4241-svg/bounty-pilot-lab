"""Private, manually operated storage of SARIF inventory summaries only."""
import argparse
import json
import os
import re
import stat
from pathlib import Path

from sarif_summary import LEVELS, MAX_BYTES, summarize, read_local, save_summary

NAME = re.compile(r"^[0-9a-f]{64}\.json$")

def workspace(path, create=False):
    root = Path(path).expanduser()
    if create:
        root.mkdir(mode=0o700, exist_ok=True)
    info = root.lstat()
    if not stat.S_ISDIR(info.st_mode):
        raise ValueError("Workspace must be a real directory")
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise ValueError("Workspace must be owner-controlled and private (0700)")
    return root

def store(root, report):
    root = workspace(root)
    summary = summarize(read_local(report))
    destination = root / (summary["sha256"] + ".json")
    try:
        save_summary(summary, destination)
        status = "stored"
    except FileExistsError:
        info = destination.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) & 0o077):
            raise ValueError("Existing summary is not private and regular")
        existing = load_summary(destination)
        if json.dumps(existing, sort_keys=True) != json.dumps(summary, sort_keys=True):
            raise ValueError("Existing summary does not match; refusing overwrite")
        status = "already_stored"
    return {"status": status, "sha256": summary["sha256"],
            "technical_validity": "not_assessed"}

def load_summary(path):
    """Check local inventory structure; not authenticity or finding validity."""
    raw = read_local(path)
    if len(raw) > MAX_BYTES:
        raise ValueError("Oversized summary")
    record = json.loads(raw)
    fields = {"format", "sha256", "bytes", "runs", "result_count",
              "reported_levels", "review_status", "technical_validity", "notice"}
    if (not isinstance(record, dict) or set(record) != fields
            or record["sha256"] != path.stem
            or record["format"] != "SARIF 2.1.0"
            or record["technical_validity"] != "not_assessed"
            or record["review_status"] != "pending_manual_review"
            or record["notice"] != "Counts are unverified report metadata, not confirmed findings."):
        raise ValueError("Invalid inventory metadata")
    for key in ("bytes", "runs", "result_count"):
        if type(record[key]) is not int or not 0 <= record[key] <= MAX_BYTES:
            raise ValueError("Invalid inventory count")
    levels = record["reported_levels"]
    if (not isinstance(levels, dict) or set(levels) != set(LEVELS)
            or any(type(v) is not int or not 0 <= v <= MAX_BYTES for v in levels.values())
            or sum(levels.values()) != record["result_count"]
            or (record["runs"] == 0 and record["result_count"] != 0)
            or record["bytes"] == 0):
        raise ValueError("Inconsistent inventory counts")
    return record

def inventory(root):
    root = workspace(root)
    summaries = invalid = 0
    for path in root.iterdir():
        if not NAME.fullmatch(path.name):
            continue
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) & 0o077):
            invalid += 1
            continue
        try:
            load_summary(path)
        except (OSError, ValueError, RecursionError):
            invalid += 1
            continue
        summaries += 1
    return {"summary_files": summaries, "invalid_files": invalid,
            "technical_validity": "not_assessed",
            "notice": "Inventory metadata only; original reports are not verified by this command."}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True)
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("init")
    sub.add_parser("store").add_argument("report")
    sub.add_parser("inventory")
    args = parser.parse_args()
    try:
        if args.action == "init":
            workspace(args.workspace, create=True)
            result = {"status": "initialized"}
        elif args.action == "store":
            result = store(args.workspace, args.report)
        else:
            result = inventory(args.workspace)
        print(json.dumps(result, indent=2))
        return 1 if result.get("invalid_files", 0) else 0
    except (OSError, ValueError, RecursionError):
        parser.exit(2, "Invalid workspace, report or existing summary\n")

if __name__ == "__main__":
    raise SystemExit(main())
