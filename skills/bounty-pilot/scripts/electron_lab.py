#!/usr/bin/env python3
"""Offline Electron source inventory for trust-boundary review, not execution.

No ASAR extraction or JS execution. Operator must provide trusted extracted
sources. API co-location is NOT evidence that a remote origin can call IPC.
"""
import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path

import mobile_flow

SUFFIXES = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
LIMIT_FILES = 800
LIMIT_BYTES = 10 * 1024 * 1024
MAX_FILE = 320000
MAX_ANCHORS = 250

CUES = {
    "browser-window": r"\b(?:new\s+BrowserWindow|BrowserWindow\s*\()",
    "preload": r"\bpreload\s*:",
    "context-isolation-disabled": r"\bcontextIsolation\s*:\s*false\b",
    "node-integration-enabled": r"\bnodeIntegration\s*:\s*true\b",
    "sandbox-disabled": r"\bsandbox\s*:\s*false\b",
    "web-security-disabled": r"\bwebSecurity\s*:\s*false\b",
    "ipc-main": r"\bipcMain\s*\.\s*(?:handle|on|handleOnce)\s*\(",
    "ipc-renderer": r"\bipcRenderer\s*\.\s*(?:invoke|send|on)\s*\(",
    "context-bridge": r"\bcontextBridge\s*\.\s*exposeInMainWorld\s*\(",
    "permission-handler": r"\bsetPermission(?:Request|Check)Handler\s*\(",
    "desktop-capture": r"\b(?:desktopCapturer|getDisplayMedia)\s*(?:\.|\()",
    "external-navigation": r"\b(?:loadURL|setWindowOpenHandler|will-navigate)\s*\(",
    "shell-external": r"\bshell\s*\.\s*openExternal\s*\(",
    "exec-process": r"\b(?:execFile|spawn|exec)\s*\(",
}
PATTERNS = {key: re.compile(pat) for key, pat in CUES.items()}


def analyze(sources):
    root = Path(sources).expanduser().absolute()
    if root.is_symlink() or not root.is_dir():
        raise ValueError("sources must be a non-symlink directory")
    root = root.resolve(strict=True)
    records, total, skipped, anchors, truncated = [], 0, 0, 0, False
    for path in sorted(root.rglob("*")):
        if path.suffix.lower() not in SUFFIXES or not path.is_file():
            continue
        if path.is_symlink() or any(p.is_symlink() for p in path.parents if p != root):
            skipped += 1
            continue
        size = path.stat().st_size
        if len(records) >= LIMIT_FILES or total + size > LIMIT_BYTES:
            truncated = True
            break
        if size > MAX_FILE:
            skipped += 1
            truncated = True
            continue
        data = path.read_bytes()
        total += len(data)
        try:
            source = data.decode("utf-8")
        except UnicodeDecodeError:
            skipped += 1
            continue
        masked = mobile_flow._mask(source)
        hits = []
        for kind, pattern in PATTERNS.items():
            for match in pattern.finditer(masked):
                if anchors >= MAX_ANCHORS:
                    truncated = True
                    break
                anchors += 1
                hits.append({"kind": kind, "line": masked.count("\n", 0, match.start()) + 1})
        if hits:
            records.append({"file": path.relative_to(root).as_posix(),
                            "sha256": hashlib.sha256(data).hexdigest(),
                            "anchors": sorted(hits, key=lambda r: (r["line"], r["kind"]))})
        if anchors >= MAX_ANCHORS:
            break
    kinds = sorted({a["kind"] for record in records for a in record["anchors"]})
    return {
        "schema_version": 1, "engine": "electron-static-boundary-review",
        "assurance": "LEXICAL_CUES_NOT_TRUSTED_ORIGIN_REACHABILITY",
        "coverage": {"files_with_anchors": len(records), "source_bytes": total,
                     "skipped_files": skipped, "truncated": truncated},
        "anchors": records, "cue_types": kinds,
        "review_candidates": [
            {"type": "REMOTE_ORIGIN_TO_PRIVILEGED_PRELOAD_REVIEW",
             "evidence_kind": "PROJECT_WIDE_COLOCATION_ONLY",
             "origin_authorized": "NOT_EVALUATED",
             "ipc_invocation_proven": False}
        ] if ("preload" in kinds
              and ("context-bridge" in kinds or "ipc-renderer" in kinds)
              and ("ipc-main" in kinds or "desktop-capture" in kinds)) else [],
        "unproven": ["effective BrowserWindow preferences",
                     "exact origin and navigation runtime",
                     "IPC handler sender validation",
                     "permission approval and consent",
                     "protected state/screen content exposure"],
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--sources", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    try:
        report = analyze(args.sources)
        dest = Path(args.out)
        if dest.exists() or dest.is_symlink() or not dest.parent.is_dir():
            raise ValueError("output must be a new private file")
        fd = os.open(str(dest), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2, sort_keys=True)
            stream.write("\n")
        print(json.dumps({"anchor_files": len(report["anchors"]),
                          "assurance": report["assurance"]}))
        return 0
    except (ValueError, OSError) as exc:
        print("Error: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
