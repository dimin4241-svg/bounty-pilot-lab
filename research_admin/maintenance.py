"""Offline SQLite maintenance for the administrative database only."""
import argparse
import json
import os
import sqlite3
from contextlib import closing
from pathlib import Path

def open_readonly(path):
    path = Path(path).expanduser().resolve(strict=True)
    if not path.is_file():
        raise ValueError("Database must be an existing regular file")
    return sqlite3.connect(path.as_uri()+"?mode=ro", uri=True, timeout=10)

def check(conn):
    integrity = [r[0] for r in conn.execute("PRAGMA integrity_check")]
    foreign_keys = list(conn.execute("PRAGMA foreign_key_check"))
    return {"ok": integrity == ["ok"] and not foreign_keys,
            "integrity": integrity, "foreign_key_violations": foreign_keys}

def doctor(path):
    with closing(open_readonly(path)) as conn:
        result = check(conn)
        tables = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        required = {"projects","charges","artifacts","reviews","evaluations"}
        result["missing_tables"] = sorted(required-tables)
        result["ok"] = result["ok"] and not result["missing_tables"]
    return result

def backup(source, destination):
    source = Path(source).expanduser().resolve(strict=True)
    dest = Path(destination).expanduser()
    if not doctor(source)["ok"]:
        raise ValueError("Source database failed integrity checks")
    fd = os.open(dest, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(fd)
    try:
        with closing(open_readonly(source)) as src:
            target = sqlite3.connect(dest,timeout=10)
            try:
                src.backup(target)
                if not check(target)["ok"]:
                    raise ValueError("Backup failed integrity checks")
            finally:
                target.close()
        if not doctor(dest)["ok"]:
            raise ValueError("Backup is not a valid ledger")
        return {"ok":True,"path":str(dest),"bytes":dest.stat().st_size}
    except BaseException:
        dest.unlink(missing_ok=True)
        raise

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db",required=True)
    sub = parser.add_subparsers(dest="action",required=True)
    sub.add_parser("doctor")
    sub.add_parser("backup").add_argument("destination")
    args = parser.parse_args()
    try:
        data = doctor(args.db) if args.action=="doctor" else backup(args.db,args.destination)
        print(json.dumps(data,ensure_ascii=False,indent=2))
        return 0 if data["ok"] else 1
    except (OSError,sqlite3.Error,ValueError) as exc:
        parser.exit(1,f"Error: {exc}\n")

if __name__ == "__main__":
    raise SystemExit(main())
