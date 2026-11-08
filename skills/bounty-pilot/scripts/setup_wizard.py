#!/usr/bin/env python3
"""Offline interactive/JSON research onboarding and local toolchain preflight.

No RPC queries, keys, private environment values, package installs, model
calls, target execution or network traffic. Plans are NOT authorization.
"""
import argparse
import json
import os
import re
import shutil
import sys
from pathlib import Path

STACKS = {
    "solidity-evm": ("python3", "forge", "cast", "docker"),
    "rust-solana": ("python3", "cargo", "rustc", "solana", "anchor"),
    "rust-native": ("python3", "cargo", "rustc"),
    "move": ("python3", "aptos", "sui"),
    "web-backend": ("python3", "node", "docker"),
    "cosmos-sdk": ("python3", "go", "docker"),
}
SCOPE_RE = re.compile(r"^[A-Za-z0-9_.\-/]{1,180}$")
ENV_RE = re.compile(r"^[A-Z][A-Z0-9_]{2,95}$")


def validate(data):
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise ValueError("wizard answers need schema_version=1")
    repo = data.get("repo")
    if not isinstance(repo, str) or not repo or len(repo) > 1000:
        raise ValueError("repo path required")
    path = Path(repo).expanduser()
    if path.is_symlink() or not path.is_dir():
        raise ValueError("repo must be existing local directory, not symlink")
    path = path.resolve()
    stack = data.get("stack")
    if stack not in STACKS:
        raise ValueError("stack must be an explicitly selected supported runtime")
    scopes = data.get("scope_paths")
    if not isinstance(scopes, list) or not 1 <= len(scopes) <= 12:
        raise ValueError("1..12 reviewed scope paths required")
    for scope in scopes:
        if not isinstance(scope, str) or not SCOPE_RE.fullmatch(scope):
            raise ValueError("invalid scope path")
        item = Path(scope)
        if item.is_absolute() or ".." in item.parts or scope.startswith("."):
            raise ValueError("scope must be relative and non-traversing")
        current = path
        for part in item.parts:
            current = current / part
            if current.is_symlink():
                raise ValueError("scope contains a symlink")
        if not current.exists():
            raise ValueError("scope path not present: " + scope)
    scope_url = data.get("program_url", "")
    if not isinstance(scope_url, str) or len(scope_url) > 400:
        raise ValueError("invalid program_url")
    if scope_url and not scope_url.startswith("https://"):
        raise ValueError("only official HTTPS program URLs accepted")
    # This is an optional *name*, never a secret or the value of the RPC.
    rpc_env = data.get("rpc_env_var")
    if rpc_env is not None and (not isinstance(rpc_env, str) or not ENV_RE.fullmatch(rpc_env)):
        raise ValueError("rpc_env_var must be variable name only, not a URL or secret")
    return path, stack, scopes


def build(data, which=shutil.which):
    repo, stack, scopes = validate(data)
    need = STACKS[stack]
    tools = {name: {"installed": bool(which(name)),
                    "executable_name": name} for name in need}
    required = ("python3",)
    status = "preflight-needs-attention" if any(not tools[t]["installed"] for t in required) else "preflight-ready-for-offline-planning"
    return {
        "schema_version": 1, "execution": "offline-configuration-only",
        "status": status, "repo": str(repo), "stack": stack,
        "scope_paths": scopes,
        "program_url": data.get("program_url") or None,
        "scope_eligibility": "NOT_VERIFIED",
        "rpc_env_var_name_only": data.get("rpc_env_var"),
        "available_tools": tools,
        "native_harness_ready": all(x["installed"] for x in tools.values()),
        "suggested_next_steps": [
            ["python3", "skills/bounty-pilot/scripts/bounty.py", "route",
             "--repo", "<LOCAL_REPO>"],
            ["python3", "skills/bounty-pilot/scripts/surface_route.py", "--list"],
            ["python3", "skills/bounty-pilot/scripts/discovery_doctor.py",
             "--run", "<PRIVATE_RUN_DIR>"],
        ],
        "required_manual_checks": [
            "Check current official bounty scope and permission; a URL is not authorization.",
            "Pin source revision, deployment and compiled toolchain before running PoCs.",
            "Install missing native tools explicitly outside this wizard.",
            "Use GitHub-hosted only for synthetic CI, authorized Mac for private AI/fork.",
        ],
    }


def interactive():
    print("Bounty Pilot — offline setup. Never enter keys, secrets or RPC URLs.", file=sys.stderr)
    repo = input("Local checkout directory: ").strip()
    options = ", ".join(STACKS)
    stack = input("Stack (%s): " % options).strip()
    scopes = input("In-scope relative path(s), comma separated: ").strip()
    program = input("Official program HTTPS URL (optional): ").strip()
    var = input("RPC environment VARIABLE NAME (optional, no values): ").strip()
    return {"schema_version": 1, "repo": repo, "stack": stack,
            "scope_paths": [x.strip() for x in scopes.split(",") if x.strip()],
            "program_url": program, "rpc_env_var": var or None}


def read(path):
    p = Path(path).expanduser()
    if p.is_symlink() or not p.is_file() or p.stat().st_size > 100_000:
        raise ValueError("answers file must be local regular JSON <=100KB")
    return json.loads(p.read_text(encoding="utf-8"))


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--answers", help="offline JSON input for CI/noninteractive usage")
    group.add_argument("--interactive", action="store_true")
    p.add_argument("--out", required=True, help="new private JSON path, never overwrite")
    args = p.parse_args(argv)
    try:
        result = build(read(args.answers) if args.answers else interactive())
        out = Path(args.out).expanduser().absolute()
        if out.exists() or out.is_symlink():
            raise ValueError("output exists")
        out.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(out), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, sort_keys=True)
            f.write("\n")
        print(json.dumps({"status": result["status"],
                          "native_harness_ready": result["native_harness_ready"],
                          "out": str(out)}))
    except (OSError, ValueError, TypeError, UnicodeError) as exc:
        p.error(str(exc))
    return 0


if __name__ == "__main__":
    sys.exit(main())
