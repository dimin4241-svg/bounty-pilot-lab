#!/usr/bin/env python3
"""Operator-opted local JADX/Apktool decompiler adapter for authorized APKs.

The tool executable is taken only from PATH (jadx or apktool), never from APK
contents. Untrusted decompilers and input APKs should run in a no-network VM.
This adapter cannot itself establish a sandbox or grant scope authorization.
"""
import argparse
import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import mobile_lab

TOOLS = {"jadx", "apktool"}
MAX_TIMEOUT = 1800
MAX_OUTPUT_FILES = 40000


def _file_inventory(path):
    scanned = 0
    kinds = {".java": 0, ".kt": 0, ".smali": 0, ".xml": 0}
    truncated = False
    for item in sorted(path.rglob("*")):
        if item.is_symlink() or any(p.is_symlink() for p in item.parents if p != path):
            raise ValueError("decompiler produced unsafe symlink path")
        if item.is_file():
            scanned += 1
            if scanned > MAX_OUTPUT_FILES:
                truncated = True
                break
            if item.suffix.lower() in kinds:
                kinds[item.suffix.lower()] += 1
    return {"files_seen": min(scanned, MAX_OUTPUT_FILES),
            "source_kinds": kinds, "truncated": truncated}


def _execute(cmd, timeout):
    result = subprocess.run(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout,
        check=False, stdin=subprocess.DEVNULL,
        env={k: v for k, v in os.environ.items()
             if k in {"PATH", "HOME", "JAVA_HOME", "TMPDIR", "LANG", "LC_ALL"}},
    )
    if result.returncode:
        raise ValueError("local tool exited with code " + str(result.returncode))


def analyze(artifact, out_sources, tool="jadx", confirm=False, timeout=900,
            finder=None, executor=None):
    if tool not in TOOLS:
        raise ValueError("unsupported decompiler")
    if not confirm:
        raise ValueError("explicit --confirm-isolated-local-analysis required")
    if type(timeout) is not int or not 1 <= timeout <= MAX_TIMEOUT:
        raise ValueError("timeout must be 1..1800 seconds")
    source = Path(artifact).expanduser().absolute()
    if source.suffix.lower() != ".apk":
        raise ValueError("decompile adapter currently accepts only APK")
    digest, length = mobile_lab._regular_digest_stream(source, mobile_lab.MAX_ARCHIVE)
    destination = Path(out_sources).expanduser().absolute()
    if (destination.is_symlink() or destination.exists()
            or not destination.parent.is_dir()
            or destination.parent.is_symlink()
            or source == destination or source in destination.parents):
        raise ValueError("output source directory must be NEW under existing private parent")
    finder = finder or shutil.which
    binary = finder(tool)
    if not binary or not Path(binary).is_file():
        raise ValueError(tool + " is not installed in local PATH")
    executor = executor or _execute
    destination.mkdir(mode=0o700)
    if tool == "jadx":
        command = [str(binary), "-d", str(destination), str(source)]
    else:
        command = [str(binary), "d", "-o", str(destination), str(source)]
    executor(command, timeout)
    after_sha, after_len = mobile_lab._regular_digest_stream(
        source, mobile_lab.MAX_ARCHIVE)
    if digest != after_sha or length != after_len:
        raise ValueError("APK changed during local decompile")
    inventory = _file_inventory(destination)
    return {
        "schema_version": 1, "engine": "mobile-local-decompile",
        "status": "DECOMPILER_RETURNED_ZERO_REVIEW_SOURCES",
        "artifact_sha256": digest, "artifact_bytes": length,
        "tool": tool, "binary_source": "LOCAL_OPERATOR_PATH",
        "out_sources": str(destination),
        "inventory": inventory,
        "code_flow_verified": False, "native_app_executed": False,
        "scope_independently_verified": False,
        "warnings": ["no OS-level network sandbox imposed by this adapter",
                     "decompiler output may be incomplete, renamed or incorrect",
                     "native runtime and authorization are not proved"],
    }


def _write_new(path, report):
    target = Path(path)
    if target.exists() or target.is_symlink() or not target.parent.is_dir():
        raise ValueError("report output must be new file")
    fd = os.open(str(target), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(report, stream, sort_keys=True, indent=2)
        stream.write("\n")


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--artifact", required=True)
    p.add_argument("--sources-out", required=True)
    p.add_argument("--tool", choices=sorted(TOOLS), default="jadx")
    p.add_argument("--confirm-isolated-local-analysis", action="store_true")
    p.add_argument("--timeout", type=int, default=900)
    p.add_argument("--out", required=True)
    args = p.parse_args(argv)
    try:
        result = analyze(args.artifact, args.sources_out, args.tool,
                         args.confirm_isolated_local_analysis, args.timeout)
        _write_new(args.out, result)
        print(json.dumps({"status": result["status"],
                          "source_files": result["inventory"]["files_seen"]}))
        return 0
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        print("Error: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
