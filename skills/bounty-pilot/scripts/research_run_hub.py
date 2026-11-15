#!/usr/bin/env python3
"""One-command, offline multi-engine Bounty Pilot evidence review orchestrator.

Requires an operator-confirmed scope document; never downloads files, executes
target binaries, launches emulators, runs decompilers or contacts a remote host.
All input paths are confined to a private operator-provided work tree.
"""
import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path

ID = re.compile(r"[A-Za-z0-9_.:-]{1,80}\Z")
SHA = re.compile(r"[0-9a-f]{64}\Z")
ENGINES = {"android-entry", "mobile-crossfile", "electron", "ios-trust",
           "impact", "oauth", "graph-variant", "feedback", "paired-eval"}
MAX_JOBS = 12
MAX_INPUT = 2 * 1024 * 1024
MAX_REPORT = 5 * 1024 * 1024


def _pairs(items):
    out = {}
    for k, value in items:
        if k in out:
            raise ValueError("duplicate JSON field")
        out[k] = value
    return out


def _file(root, name, folder=False):
    if (not isinstance(name, str) or not name
            or Path(name).is_absolute()
            or any(x in ("", ".", "..") for x in name.replace("\\", "/").split("/"))):
        raise ValueError("unsafe private relative path")
    candidate = root / name
    if (candidate.is_symlink() or
            any(parent.is_symlink() for parent in candidate.parents if parent != root)):
        raise ValueError("symlink paths are prohibited")
    resolved = candidate.resolve(strict=True)
    if root not in resolved.parents:
        raise ValueError("path outside work tree")
    if folder:
        if not resolved.is_dir():
            raise ValueError("work tree folder required")
    elif not resolved.is_file() or resolved.stat().st_size > MAX_INPUT:
        raise ValueError("bounded regular input required")
    return resolved


def _load(root, name):
    return json.loads(_file(root, name).read_text("utf-8"), object_pairs_hook=_pairs)


def _analyzer(engine, job, root):
    if engine == "android-entry":
        import mobile_reachability
        return mobile_reachability.analyze(str(_file(root, job.get("path"), True)))
    if engine == "mobile-crossfile":
        import mobile_crossfile
        platform = job.get("platform")
        return mobile_crossfile.analyze(str(_file(root, job.get("path"), True)),
                                        platform)
    if engine == "electron":
        import electron_lab
        return electron_lab.analyze(str(_file(root, job.get("path"), True)))
    if engine == "ios-trust":
        import ios_trust_lab
        optional = job.get("entitlements")
        return ios_trust_lab.analyze(
            _file(root, job.get("path")),
            _file(root, optional) if optional is not None else None)
    if engine == "impact":
        import business_impact_oracle
        case = _load(root, job.get("path"))
        return business_impact_oracle.analyze(
            case, _file(root, job.get("receipts"), True))
    if engine == "oauth":
        import oauth_lifecycle_lab
        return oauth_lifecycle_lab.analyze(_load(root, job.get("path")))
    if engine == "graph-variant":
        import graph_variant_lab
        return graph_variant_lab.analyze(_load(root, job.get("path")))
    if engine == "feedback":
        import bounty_outcome_feedback
        return bounty_outcome_feedback.analyze(_load(root, job.get("path")))
    if engine == "paired-eval":
        import historical_paired_eval
        return historical_paired_eval.evaluate(
            _load(root, job.get("answers")), _load(root, job.get("predictions")))
    raise ValueError("unknown offline analysis engine")


def _write(path, obj):
    data = json.dumps(obj, sort_keys=True, indent=2, ensure_ascii=False).encode("utf-8")
    if len(data) > MAX_REPORT:
        raise ValueError("bounded review output exceeded 5MiB")
    fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data + b"\n")


def analyze(manifest, work_root, output_dir):
    root = Path(work_root).expanduser().absolute()
    if not root.is_dir() or root.is_symlink():
        raise ValueError("root must be a non-symlink directory")
    root = root.resolve(strict=True)
    if not isinstance(manifest, dict) or manifest.get("schema_version") != 1:
        raise ValueError("orchestrator requires schema_version=1")
    scope = manifest.get("scope")
    if not isinstance(scope, dict) or scope.get("operator_confirmed") is not True:
        raise ValueError("explicit operator scope confirmation required")
    sha = scope.get("policy_sha256")
    if not isinstance(sha, str) or not SHA.fullmatch(sha):
        raise ValueError("scope policy SHA-256 required")
    policy = _file(root, scope.get("policy_file"))
    if hashlib.sha256(policy.read_bytes()).hexdigest() != sha:
        raise ValueError("scope policy file SHA-256 differs from manifest")
    jobs = manifest.get("jobs")
    if not isinstance(jobs, list) or not 1 <= len(jobs) <= MAX_JOBS:
        raise ValueError("bounded jobs array required")
    seen = set()
    for job in jobs:
        if not isinstance(job, dict) or job.get("engine") not in ENGINES:
            raise ValueError("unsupported engine")
        name = job.get("id")
        if not isinstance(name, str) or not ID.fullmatch(name) or name in seen:
            raise ValueError("jobs require unique bounded ids")
        seen.add(name)
    dest = Path(output_dir).expanduser().absolute()
    if (dest.is_symlink() or dest.exists() or not dest.parent.is_dir()
            or dest.parent.is_symlink() or dest == root or root in dest.parents):
        raise ValueError("output must be a new directory outside private work tree")
    dest.mkdir(mode=0o700)
    index = {
        "schema_version": 1, "engine": "offline-research-orchestrator",
        "scope_policy_sha256": sha,
        "scope_independently_verified": False,
        "native_execution": False, "network_requests": 0,
        "findings_independently_verified": 0,
        "jobs": [],
    }
    for job in jobs:
        report = _analyzer(job["engine"], job, root)
        _write(dest / (job["id"] + ".json"), report)
        index["jobs"].append({
            "id": job["id"], "engine": job["engine"],
            "result_file": job["id"] + ".json",
            "status": report.get("status", report.get("assurance", "OFFLINE_REVIEW")),
            "lead_count": report.get("lead_count", len(report.get("review_candidates", []))),
            "impact_verified_by_orchestrator": False,
        })
    _write(dest / "index.json", index)
    return index


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--work-root", required=True)
    ap.add_argument("--out-dir", required=True)
    a = ap.parse_args(argv)
    try:
        root = Path(a.work_root).expanduser().absolute()
        if root.is_symlink() or not root.is_dir():
            raise ValueError("work root is invalid")
        source = _file(root.resolve(), a.manifest)
        manifest = json.loads(source.read_text("utf-8"), object_pairs_hook=_pairs)
        report = analyze(manifest, a.work_root, a.out_dir)
        print(json.dumps({"jobs": len(report["jobs"]),
                          "output": str(Path(a.out_dir).absolute()),
                          "independently_verified": False}))
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print("Error: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
