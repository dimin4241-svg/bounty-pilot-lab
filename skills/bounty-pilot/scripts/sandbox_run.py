#!/usr/bin/env python3
"""Run an explicitly approved paired local PoC in a restricted Docker container.

The Docker image must already be installed, pinned by digest, and trusted by
the operator. This isolates the host home directory and network from the
target's test code; it is not a substitute for a disposable checkout/host.
"""
import argparse
import hashlib
import json
import sys
import os
import re
import subprocess
from pathlib import Path

IMAGE_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._/-]*@sha256:[0-9a-fA-F]{64}$")
CONTAINER_REPO = "/target"
CONTAINER_PLAN = "/input/plan.json"
CONTAINER_OUT = "/evidence"
CONTAINER_HELPERS = "/pilot"


def _path(value, name, directory):
    original = Path(value).expanduser()
    if original.is_symlink():
        raise ValueError(name + " must not be a symlink")
    path = original.resolve(strict=True)
    if directory != path.is_dir():
        raise ValueError(name + (" must be a directory" if directory else " must be a file"))
    if any(char in str(path) for char in (",", "\n", "\r")):
        raise ValueError(name + " contains characters unsupported by Docker mount syntax")
    return path


def build_command(repo, plan, out, image, *, docker="docker", uid=None, gid=None):
    """Construct a no-shell, isolated Docker command; never executes the target on host."""
    if not IMAGE_RE.fullmatch(image):
        raise ValueError("--image must be a trusted, immutable IMAGE@sha256:<64 hex> reference")
    if not isinstance(docker, str) or not docker or "/" in docker or "\\" in docker:
        raise ValueError("--docker must be an executable name, not a path")
    if os.name != "posix":
        raise ValueError("the sandbox wrapper currently supports POSIX Docker hosts only")
    uid = os.getuid() if uid is None else uid
    gid = os.getgid() if gid is None else gid
    if uid <= 0 or gid < 0:
        raise ValueError("refusing to run target tests as root in the container")
    root = _path(repo, "--repo", True)
    source = _path(plan, "--plan", False)
    destination = Path(out).expanduser()
    if destination.is_symlink() or destination.exists():
        raise ValueError("--out must name a new JSON file, not an existing file or symlink")
    parent = _path(destination.parent, "--out parent", True)
    helpers = Path(__file__).resolve().parent
    if root == parent or root in parent.parents or parent in root.parents:
        raise ValueError("--out must be outside the target repository")
    if root == helpers or root in helpers.parents or helpers in root.parents:
        raise ValueError("--repo must not contain the Bounty Pilot helper scripts")
    if not destination.name.endswith(".json") or destination.name in (".json", "..json"):
        raise ValueError("--out must name a fresh .json evidence file")
    return [
        docker, "run", "--rm", "--pull=never",
        "--network=none", "--cap-drop=ALL",
        "--security-opt=no-new-privileges", "--read-only",
        "--pids-limit=256", "--memory=4g", "--cpus=2",
        "--user=" + str(uid) + ":" + str(gid),
        "--tmpfs=/tmp:rw,nosuid,nodev,size=1g",
        "--workdir=" + CONTAINER_REPO,
        "--mount=type=bind,src=" + str(root) + ",dst=" + CONTAINER_REPO,
        "--mount=type=bind,src=" + str(source) + ",dst=" + CONTAINER_PLAN + ",readonly",
        "--mount=type=bind,src=" + str(parent) + ",dst=" + CONTAINER_OUT,
        "--mount=type=bind,src=" + str(helpers) + ",dst=" + CONTAINER_HELPERS + ",readonly",
        "--env=HOME=/tmp", "--env=XDG_CONFIG_HOME=/tmp",
        "--entrypoint=python3", image,
        CONTAINER_HELPERS + "/scenario_runner.py",
        "--repo", CONTAINER_REPO, "--plan", CONTAINER_PLAN,
        "--out", CONTAINER_OUT + "/" + destination.name, "--allow-exec",
    ]


def build_mutation_command(repo, bank, property_spec, out, image, *,
                           docker="docker", uid=None, gid=None):
    """Run ONLY the fixed data-only mutation scorer inside the no-network Docker.

    The target checkout is checked for output separation, but not mounted
    inside the mutation container: the scorer needs only bank and rule JSON.
    In particular, an AI property author must be a different OS process
    without the bank mount.
    """
    old = build_command(repo, bank, out, image, docker=docker, uid=uid, gid=gid)
    prop = _path(property_spec, "--property-spec", False)
    root = _path(repo, "--repo", True)
    if root == prop or root in prop.parents:
        raise ValueError("--property-spec must stay outside the target source checkout")
    new_mount = "--mount=type=bind,src=" + str(prop) + ",dst=/input/rules.json,readonly"
    args = []
    for flag in old:
        if flag.startswith("--mount=type=bind,") and ",dst=/target" in flag:
            continue
        if flag.startswith("--mount=type=bind,") and ",dst=/input/plan.json" in flag:
            flag = flag + ",readonly"
        args.append(flag)
    args.insert(args.index("--env=HOME=/tmp"), new_mount)
    args[args.index("--workdir=" + CONTAINER_REPO)] = "--workdir=/tmp"
    entry = args.index(CONTAINER_HELPERS + "/scenario_runner.py")
    args[entry:] = [
        CONTAINER_HELPERS + "/mutation_lab.py", "score",
        "--bank", CONTAINER_PLAN, "--property-spec", "/input/rules.json",
        "--out", CONTAINER_OUT + "/" + Path(out).name]
    return args


def build_foundry_command(repo, harness_plan, out, image, contract, *,
                          docker="docker", uid=None, gid=None):
    """Opt-in source harness validation in pinned, offline, non-root Docker."""
    if (not isinstance(contract, str) or not
            re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,65}Invariants", contract)):
        raise ValueError("exact safe *Invariants harness contract required")
    old = build_command(repo, harness_plan, out, image,
                        docker=docker, uid=uid, gid=gid)
    args = []
    for flag in old:
        if (flag.startswith("--mount=type=bind,") and
                ",dst=/target" in flag and not flag.endswith(",readonly")):
            flag += ",readonly"
        args.append(flag)
    args.insert(args.index("--env=HOME=/tmp"), "--env=FOUNDRY_OUT=/tmp/out")
    args.insert(args.index("--env=HOME=/tmp"), "--env=FOUNDRY_CACHE_PATH=/tmp/cache")
    entry = args.index(CONTAINER_HELPERS + "/scenario_runner.py")
    args[entry:] = [
        CONTAINER_HELPERS + "/sandbox_run.py", "--inside-forge",
        "--repo", CONTAINER_REPO, "--plan", CONTAINER_PLAN,
        "--out", CONTAINER_OUT + "/" + Path(out).name,
        "--match-contract", contract]
    return args


def handler_coverage_from_log(raw, expected_signatures):
    """Strict, bounded parse of selector counter summaries; otherwise UNKNOWN."""
    if not isinstance(raw, str) or len(raw) > 2_000_000:
        raise ValueError("bounded Foundry log required")
    if not isinstance(expected_signatures, list) or len(expected_signatures) > 120:
        raise ValueError("bounded handler signatures required")
    allowed = set(expected_signatures)
    rows = {}
    pattern = re.compile(r"(?m)^\s*([A-Za-z_][A-Za-z0-9_]*\([^()\r\n]{0,160}\))"
                         r"\s+(\d{1,12})\s+(\d{1,12})\s*$")
    for match in pattern.finditer(raw):
        sign, calls, reverts = match.groups()
        if sign not in allowed:
            continue
        n, bad = int(calls), int(reverts)
        if n > 1_000_000_000 or bad > n:
            raise ValueError("invalid handler call/revert counters")
        if sign in rows:
            # Duplicate logs from repeated tests are ambiguous; refuse
            # to silently merge counters with different semantics.
            raise ValueError("duplicate handler summary")
        rows[sign] = {"calls": n, "reverts": bad,
                      "accepted": n - bad,
                      "revert_fraction": round(bad / n, 4) if n else None}
    unknown = sorted(allowed - set(rows))
    poor = [name for name, v in rows.items() if v["calls"] == 0 or
            v["revert_fraction"] is not None and
            v["revert_fraction"] >= 0.8]
    return {"per_handler": rows,
            "missing_handlers": unknown,
            "zero_or_high_revert_handlers": sorted(poor),
            "all_handler_counts_available": not unknown,
            "total_calls": sum(x["calls"] for x in rows.values()),
            "total_reverts": sum(x["reverts"] for x in rows.values()),
            "coverage_verified": not unknown and not poor and bool(rows)}


def _inside_forge(argv):
    """Only invoked inside the operator-approved offline Docker sandbox."""
    p = argparse.ArgumentParser(description="bounded offline Foundry harness receipt")
    p.add_argument("--repo", required=True)
    p.add_argument("--plan", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--match-contract", required=True)
    a = p.parse_args(argv)
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,65}Invariants", a.match_contract):
        p.error("invalid fixed harness name")
    try:
        root = _path(a.repo, "--repo", True)
        plan_file = _path(a.plan, "--plan", False)
        cfg = json.loads(plan_file.read_text(encoding="utf-8"))
        expected = a.match_contract[:-len("Invariants")]
        if not isinstance(cfg, dict) or cfg.get("schema_version") != 1:
            raise ValueError("harness plan schema must match")
        contracts = cfg.get("contracts", [])
        if not isinstance(contracts, list) or not any(
                isinstance(c, dict) and c.get("name") == expected
                for c in contracts):
            raise ValueError("harness plan has no matching contract")
        funcs = cfg.get("functions_included", [])
        if not isinstance(funcs, list):
            raise ValueError("invalid handler set")
        signatures = [f["signature"] for f in funcs
                      if isinstance(f, dict) and f.get("contract") == expected]
        if not signatures or len(signatures) > 120:
            raise ValueError("no bounded function signatures for harness")
        for sig in signatures:
            if not isinstance(sig, str) or not re.fullmatch(
                    r"[A-Za-z_][A-Za-z0-9_]*\([^()\r\n]{0,160}\)", sig):
                raise ValueError("invalid handler signature")
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
               "HOME": "/tmp", "FOUNDRY_OUT": "/tmp/out",
               "FOUNDRY_CACHE_PATH": "/tmp/cache", "FOUNDRY_OFFLINE": "true",
               "CI": "true", "LANG": "C"}
        result = subprocess.run([
            "forge", "test", "--root", str(root),
            "--match-contract", a.match_contract,
            "--no-match-test", "testNeverRunThisName",
            "-vvv", "--json"], cwd=str(root), env=env,
            capture_output=True, text=True, timeout=120,
            check=False, stdin=subprocess.DEVNULL)
        if len(result.stdout.encode("utf-8")) > 2_000_000:
            raise ValueError("Foundry output too large")
        counts = handler_coverage_from_log(result.stdout, signatures)
        status = ("NATIVE_HARNESS_FAILED" if result.returncode != 0 else
                  "HANDLER_COVERAGE_NOT_OBSERVED" if not counts["all_handler_counts_available"] else
                  "MOST_CALLS_REVERT_OR_ZERO" if not counts["coverage_verified"] else
                  "NATIVE_HARNESS_COMPLETED_WITH_COUNTERS_NOT_SECURITY_PROOF")
        digest = hashlib.sha256(result.stdout.encode("utf-8")).hexdigest()
        report = {"schema_version": 1, "mode": "sandbox-native-foundry-harness",
                  "status": status, "exit_code": result.returncode,
                  "stdout_sha256": digest, "coverage": counts,
                  "confirmed_vulnerabilities": 0,
                  "native_target_executed": True,
                  "limitations": ("Only pinned offline Docker, untrusted target test code "
                                  "with no network. A passing test does not prove any "
                                  "invariant, and missing handler console counters "
                                  "cannot establish coverage. Raw logs withheld.")}
        output = Path(a.out)
        if output.exists() or output.is_symlink():
            raise ValueError("native receipt already exists")
        fd = os.open(str(output), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(report, stream, sort_keys=True, indent=2)
            stream.write("\n")
        return 0 if result.returncode == 0 else 1
    except (OSError, ValueError, KeyError, TypeError,
            subprocess.TimeoutExpired) as exc:
        p.error("native harness aborted: " + str(exc))


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "--inside-forge":
        return _inside_forge(argv[1:])
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, help="disposable target checkout; writable INSIDE Docker")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--plan", help="approved candidate/control JSON plan")
    source.add_argument("--mutation-bank", help="previously sealed property-blind model bank")
    parser.add_argument("--property-spec", help="separately authored data-only invariant spec")
    parser.add_argument("--forge-harness", help="explicit opt-in native *Invariants Foundry harness in offline Docker")
    parser.add_argument("--out", required=True, help="new private output JSON outside --repo")
    parser.add_argument("--image", required=True, help="trusted locally installed Docker image by sha256 digest")
    parser.add_argument("--docker", default="docker", help="Docker CLI executable name")
    args = parser.parse_args(argv)
    try:
        if args.forge_harness:
            if args.mutation_bank or args.property_spec or not args.plan:
                raise ValueError("--forge-harness requires --plan only")
            command = build_foundry_command(
                args.repo, args.plan, args.out, args.image,
                args.forge_harness, docker=args.docker)
        elif args.mutation_bank:
            if not args.property_spec:
                raise ValueError("--mutation-bank requires --property-spec")
            command = build_mutation_command(
                args.repo, args.mutation_bank, args.property_spec,
                args.out, args.image, docker=args.docker)
        else:
            if args.property_spec:
                raise ValueError("--property-spec requires --mutation-bank")
            command = build_command(
                args.repo, args.plan, args.out, args.image, docker=args.docker)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    try:
        return subprocess.run(command, stdin=subprocess.DEVNULL, check=False).returncode
    except OSError as exc:
        parser.error("could not start Docker: " + str(exc))


if __name__ == "__main__":
    raise SystemExit(main())
