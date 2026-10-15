#!/usr/bin/env python3
"""Audit mixed-stack hunt coverage against files actually included in a source bundle.

Coverage here means 'included for review', not 'audited' or 'secure'.
"""
import argparse
import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

EXT_STACK = {
    ".sol": "evm", ".vy": "evm", ".yul": "evm", ".huff": "evm",
    ".rs": "rust", ".move": "move", ".cairo": "cairo",
    ".go": "go", ".py": "python", ".ts": "js-ts", ".tsx": "js-ts",
    ".js": "js-ts", ".jsx": "js-ts", ".java": "java", ".cs": "csharp",
}
IGNORE_PARTS = {"node_modules", "vendor", "target", "build", "dist", "out", ".git"}
TEST_PARTS = {"test", "tests", "__tests__", "fixtures", "mocks"}
BUNDLE_PATH = re.compile(r"^### ([^\r\n]+)$", re.M)


def _sources(paths):
    result = {}
    for name in paths:
        p = Path(name)
        if (p.suffix not in EXT_STACK or
                any(x.lower() in IGNORE_PARTS for x in p.parts) or
                any(x.lower() in TEST_PARTS for x in p.parts) or
                p.name.endswith((".t.sol", ".test.ts", ".spec.ts", "_test.go"))):
            continue
        result[name] = EXT_STACK[p.suffix]
    return result


def audit(repo, run, scope=None):
    repo, run = Path(repo).resolve(), Path(run).resolve()
    out = subprocess.check_output(["git", "-C", str(repo), "ls-files", "-z"])
    all_sources = _sources(x for x in out.decode("utf-8").split("\0") if x)
    bundle = run / "bundles" / "source.md"
    included = set(BUNDLE_PATH.findall(bundle.read_text(encoding="utf-8"))) if bundle.is_file() else set()
    selected = {name: stack for name, stack in all_sources.items()
                if not scope or any(name == prefix.rstrip("/") or
                                    name.startswith(prefix.rstrip("/") + "/") for prefix in scope)}
    missed_in_bundle = sorted(set(selected) - included)
    excluded = sorted(set(all_sources) - set(selected))
    stacks = sorted(set(all_sources.values()))
    included_by_stack = Counter(all_sources[name] for name in included if name in all_sources)
    missing_stacks = [stack for stack in stacks if included_by_stack[stack] == 0]
    return {"state": "missing-stack" if missing_stacks else (
                "not-bundled" if not included else "partial" if missed_in_bundle or excluded else "all-included"),
            "tracked_source_files": len(all_sources), "selected_source_files": len(selected),
            "bundled_source_files": len(set(included) & set(all_sources)),
            "stacks_detected": stacks,
            "included_by_stack": dict(included_by_stack),
            "missing_stacks": missing_stacks,
            "missed_in_bundle": missed_in_bundle[:100],
            "excluded_by_scope": excluded[:100],
            "truncated_lists": len(missed_in_bundle) > 100 or len(excluded) > 100,
            "notice": "Lexical inventory only. Verify eligibility for every component; third-party "
                      "code exclusions may be legitimate, but cross-stack boundaries still matter."}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--run", required=True)
    parser.add_argument("--scope", action="append", default=[])
    parser.add_argument("--gate", action="store_true", help="fail if a tracked language stack was missed")
    args = parser.parse_args(argv)
    try:
        result = audit(args.repo, args.run, args.scope)
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print("Error: " + str(exc), file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2))
    return 1 if args.gate and (result["missing_stacks"] or result["state"] == "not-bundled") else 0


if __name__ == "__main__":
    sys.exit(main())
