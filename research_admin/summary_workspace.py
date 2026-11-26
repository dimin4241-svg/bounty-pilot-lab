"""Private, manually operated storage of SARIF inventory summaries only."""
import argparse
import json
import os
import re
import stat
from pathlib import Path

from sarif_summary import summarize, read_local, save_summary, verify_summary

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
        if not verify_summary(report, destination):
            raise ValueError("Existing summary does not match; refusing overwrite")
        status = "already_stored"
    return {"status": status, "sha256": summary["sha256"],
            "technical_validity": "not_assessed"}

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
            record = json.loads(read_local(path))
            if (not isinstance(record, dict)
                    or record.get("sha256") != path.stem
                    or record.get("format") != "SARIF 2.1.0"
                    or record.get("technical_validity") != "not_assessed"):
                raise ValueError("Invalid inventory metadata")
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
