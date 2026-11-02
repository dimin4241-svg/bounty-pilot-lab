#!/usr/bin/env python3
"""Plan bounded, separate source-scope runs for oversized Bounty Pilot bundles.

Read-only, tracked local source only. A shard is a set of file-specific
--scope arguments; one private Bounty Pilot run per shard is required.
This is a *coverage plan*, not a security analysis or dependency call graph.
"""
import argparse
import importlib.util
import json
import os
import sys
from pathlib import Path

spec = importlib.util.spec_from_file_location("source_shards_bounty", Path(__file__).resolve().parent / "bounty.py")
bounty = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bounty)


def plan(repo, scope=None, max_source_bytes=160000):
    if type(max_source_bytes) is not int or not 1024 <= max_source_bytes <= 1_000_000:
        raise ValueError("max_source_bytes must be 1024..1000000")
    repo = Path(repo).expanduser().resolve()
    root = Path(bounty.git(repo, "rev-parse", "--show-toplevel").strip()).resolve()
    if repo != root:
        raise ValueError("--repo must be the Git checkout root")
    head = bounty.git(root, "rev-parse", "HEAD").strip()
    if len(head) != 40:
        raise ValueError("expected pinned Git commit")
    tracked = [x for x in bounty.git(root, "ls-files", "-z").split("\0") if x]
    eligible = [p for p in tracked if Path(p).suffix.lower() in bounty.SOURCE_SUFFIXES
                and not bounty._is_test_path(p)
                and bounty.path_in_scope(p, scope)]
    # Group nearby files first to keep one module's definitions together;
    # no relationship is inferred from filename or extension alone.
    eligible.sort(key=lambda p: (str(Path(p).parent), p))
    shards = []
    files = []
    total = 0
    excluded = []
    large_files = []

    def flush():
        nonlocal files, total
        if files:
            shards.append({"index": len(shards) + 1, "paths": files,
                           "source_bytes": total,
                           "scope_args": [item for p in files for item in ("--scope", p)],
                           "requires_manual_file_split": any(p in large_files for p in files)})
            files, total = [], 0

    for path in eligible:
        size = bounty.target_file_size(root, path)
        if size is None:
            excluded.append({"path": path, "reason": "unreadable/symlink/special"})
            continue
        if size > max_source_bytes:
            flush()
            large_files.append(path)
            files, total = [path], size
            flush()
            continue
        if files and total + size > max_source_bytes:
            flush()
        files.append(path)
        total += size
    flush()
    represented = [path for shard in shards for path in shard["paths"]]
    if len(represented) != len(set(represented)):
        raise ValueError("internal error: source file appeared in more than one shard")
    return {"schema_version": 1, "target_commit": head, "max_source_bytes": max_source_bytes,
            "scoped_source_files": len(eligible), "sharded_source_files": len(represented),
            "excluded": excluded, "oversized_single_files": large_files, "shards": shards,
            "notice": ("Each shard is an independent --scope file list, not a complete "
                       "cross-file semantic audit. Use a DIFFERENT private run directory for "
                       "each shard; bundle outputs overwrite within one run. "
                       "Inspect imports, dependency boundaries and excluded paths separately. "
                       "Config, docs and tests add further bytes to final bundles.")}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--repo", required=True)
    p.add_argument("--scope", action="append", default=None)
    p.add_argument("--max-source-bytes", type=int, default=160000)
    p.add_argument("--out", help="new private JSON plan (create-only)")
    a = p.parse_args(argv)
    try:
        report = plan(a.repo, a.scope, a.max_source_bytes)
        text = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
        if a.out:
            path = Path(a.out).expanduser()
            if path.is_symlink():
                raise ValueError("refusing symlink output")
            fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(text)
            print(json.dumps({"plan": str(path), "shards": len(report["shards"]),
                              "oversized_single_files": len(report["oversized_single_files"])}))
        else:
            print(text, end="")
        return 0
    except (ValueError, OSError) as exc:
        p.error(str(exc))


if __name__ == "__main__":
    sys.exit(main())
