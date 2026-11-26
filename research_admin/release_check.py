"""Offline release metadata and tracked-path privacy checks, no deployment."""
import argparse
import fnmatch
import json
from pathlib import Path, PurePosixPath
import subprocess

PRIVATE_PATTERNS = (
    ".env", ".env.*", "*.pem", "*.key", "*.p12", "*.pfx",
    "*.sqlite", "*.sqlite3", "*.db", "*.sqlite-*", "*.sqlite3-*", "*.db-*",
    "*.sqlite.backup", "*.sqlite3.backup", "*.db.backup",
    "private-review*.json", "research-status*.html",
)
PRIVATE_ROOTS = {"private", "runs", "backtests"}

def private_paths(paths):
    flagged = set()
    for name in paths:
        p = PurePosixPath(name)
        if not p.parts:
            continue
        if (p.parts[0].lower() in PRIVATE_ROOTS
                or any(fnmatch.fnmatchcase(p.name.lower(), pattern)
                       for pattern in PRIVATE_PATTERNS)):
            flagged.add(name)
    return sorted(flagged)

def evaluate(root, paths):
    root = Path(root)
    errors = []
    version = (root / "VERSION").read_text(encoding="utf-8").strip()
    plugin = json.loads((root / ".claude-plugin/plugin.json").read_text(encoding="utf-8"))
    if not version or version != plugin.get("version"):
        errors.append("VERSION and plugin version differ or are empty")
    if plugin.get("name") != "bounty-pilot-lab":
        errors.append("Unexpected plugin name")
    marketplace = json.loads((root / ".claude-plugin/marketplace.json").read_text(encoding="utf-8"))
    entries = [p for p in marketplace.get("plugins", [])
               if p.get("name") == plugin.get("name")]
    if len(entries) != 1 or entries[0].get("source") != "./":
        errors.append("Expected one matching local marketplace entry")
    flagged = private_paths(paths)
    if flagged:
        errors.append("Potential private files are tracked")
    return {"ok": not errors, "version": version, "errors": errors,
            "flagged_count": len(flagged),
            "notice": "Metadata and filename screening only; not a secret scanner or release approval."}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".")
    args = parser.parse_args()
    root = Path(args.root).resolve()
    try:
        actual = Path(subprocess.check_output(
            ["git", "-C", str(root), "rev-parse", "--show-toplevel"],
            text=True, timeout=10).strip()).resolve()
        if actual != root:
            raise ValueError("Use the repository root")
        raw = subprocess.check_output(
            ["git", "-C", str(root), "ls-files", "-z"], timeout=10)
        paths = [p.decode("utf-8", errors="surrogateescape") for p in raw.split(b"\0") if p]
        result = evaluate(root, paths)
        print(json.dumps(result, indent=2))
        return 0 if result["ok"] else 1
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        parser.exit(2, f"Release metadata check failed: {exc}\n")

if __name__ == "__main__":
    raise SystemExit(main())
