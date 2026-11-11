#!/usr/bin/env python3
"""Run an explicitly approved paired local PoC in a restricted Docker container.

The Docker image must already be installed, pinned by digest, and trusted by
the operator. This isolates the host home directory and network from the
target's test code; it is not a substitute for a disposable checkout/host.
"""
import argparse
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


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, help="disposable target checkout; writable INSIDE Docker")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--plan", help="approved candidate/control JSON plan")
    source.add_argument("--mutation-bank", help="previously sealed property-blind model bank")
    parser.add_argument("--property-spec", help="separately authored data-only invariant spec")
    parser.add_argument("--out", required=True, help="new private output JSON outside --repo")
    parser.add_argument("--image", required=True, help="trusted locally installed Docker image by sha256 digest")
    parser.add_argument("--docker", default="docker", help="Docker CLI executable name")
    args = parser.parse_args(argv)
    try:
        if args.mutation_bank:
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
