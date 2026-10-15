#!/usr/bin/env python3
"""Run an explicitly approved paired local test plan without a shell.

This runner does not generate an exploit, attest protocol safety or submit reports.
Default is dry-run. Execute only in disposable, network-isolated and secret-free workspaces.
"""
import argparse
import json
import os
import re
import signal
import subprocess
import sys
from pathlib import Path

MAX_OUTPUT_BYTES = 40000
MAX_TIMEOUT_SEC = 1800
# Toolchains need a working home/cache or go/cargo refuse to run; keep this list
# tight and never copy process secrets that are not explicitly in pass_env.
ENV_ALLOWLIST = {"PATH", "LANG", "LC_ALL", "LC_CTYPE", "TMPDIR", "TEMP", "TMP",
                 "SYSTEMROOT", "WINDIR", "HOME", "USER", "LOGNAME", "SHELL", "TERM",
                 "GOPATH", "GOCACHE", "GOMODCACHE", "GOFLAGS", "GOROOT",
                 "CARGO_HOME", "RUSTUP_HOME", "RUSTC_WRAPPER",
                 "XDG_CACHE_HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME"}

# argv[0] basenames that run inline code when given the matching flag. A plan must
# name a real test binary, never a shell or interpreter smuggling a command.
SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "fish",
          "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "pwsh.exe"}
SHELL_CODE_FLAGS = {"-c", "/c", "/k", "-command", "-encodedcommand"}
INTERPRETERS = {"python", "python2", "python3", "node", "nodejs", "deno", "bun",
                "perl", "ruby", "php", "lua"}
INTERPRETER_CODE_FLAGS = {"-c", "-e", "--eval", "--eval-file"}

_REDACT = "<REDACTED>"
# Key=value / key: value where the key NAME carries a sensitive token, even with
# surrounding word characters (ETH_PRIVATE_KEY, "private_key", APIKEY, ...).
KEY_VALUE = re.compile(
    r'(?i)(["\']?[\w.\-]*'
    r'(?:authorization|private[_-]?key|secret[_-]?key|secret|passphrase|password|passwd'
    r'|mnemonic|seed[_-]?phrase|api[_-]?key|access[_-]?token|auth[_-]?token|token|apikey)'
    r'[\w.\-]*["\']?\s*[:=]\s*)(["\']?)([^\s,"\';]+)(["\']?)')
# "Authorization: Bearer <token>" / bare "Bearer <token>".
BEARER = re.compile(r'(?i)(bearer\s+)([A-Za-z0-9._~+/\-]{6,}=*)')
# Managed-RPC provider URLs that put the project key in the path.
PROVIDER_URL = re.compile(
    r'(?i)\b((?:[a-z0-9-]+\.)*'
    r'(?:alchemy\.com|alchemyapi\.io|infura\.io|quiknode\.pro|quicknode\.com'
    r'|ankr\.com|getblock\.io|blastapi\.io|nodereal\.io|chainstack\.com'
    r'|pokt\.network|blockpi\.network|tenderly\.co|drpc\.org|llamarpc\.com)'
    r'/[A-Za-z0-9._/\-]*?/)([A-Za-z0-9_\-]{12,})')
# Secrets smuggled through a query string.
QUERY_SECRET = re.compile(
    r'(?i)([?&](?:api[_-]?key|apikey|key|token|secret|access[_-]?token|auth)=)([^&\s"\']+)')


def _working_directory(root, relative):
    if not isinstance(relative, str) or Path(relative).is_absolute():
        raise ValueError("cwd must be repository-relative")
    resolved = (root / relative).resolve()
    if resolved != root and root not in resolved.parents:
        raise ValueError("cwd escapes repository")
    if not resolved.is_dir():
        raise ValueError("cwd is not a directory: " + relative)
    return resolved


def _env_names(value, where):
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
        raise ValueError(where + " must be an array of environment variable names")
    names = []
    for name in value:
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            raise ValueError("invalid environment variable name in " + where + ": " + name)
        names.append(name)
    return names


def _reject_shell(argv):
    base = Path(argv[0]).name.lower()
    rest = [a.lower() for a in argv[1:]]
    if base == "env":
        # `env NAME=v bash -c ...` — look past leading assignments for a wrapped shell.
        idx = 1
        while idx < len(argv) and "=" in argv[idx] and not argv[idx].startswith("-"):
            idx += 1
        if idx < len(argv):
            _reject_shell(argv[idx:])
        return
    if base in SHELLS and any(f in rest for f in SHELL_CODE_FLAGS):
        raise ValueError("argv runs an inline shell command; name a real test binary instead")
    stem = base[:-3] if base.endswith(".exe") else base
    if stem in INTERPRETERS and any(f in rest for f in INTERPRETER_CODE_FLAGS):
        raise ValueError("argv runs inline interpreter code (-c/-e); run a test module or file instead")


def _validate(plan, root):
    if not isinstance(plan, dict):
        raise ValueError("plan must be a JSON object")
    _env_names(plan.get("pass_env"), "plan.pass_env")
    cases = plan.get("cases")
    if not isinstance(cases, list) or not cases or len(cases) > 40:
        raise ValueError("plan.cases must contain between 1 and 40 cases")
    pairs, names = {}, set()
    for case in cases:
        if not isinstance(case, dict):
            raise ValueError("each case must be a JSON object")
        ident = case.get("id")
        pair = case.get("pair_id")
        role = case.get("role")
        argv = case.get("argv")
        if not isinstance(ident, str) or not ident or ident in names:
            raise ValueError("missing or duplicate case id")
        names.add(ident)
        if not isinstance(pair, str) or not pair:
            raise ValueError("missing pair_id")
        if role not in ("candidate", "negative-control"):
            raise ValueError("role must be candidate or negative-control")
        if not isinstance(argv, list) or not argv or not all(isinstance(x, str) and x for x in argv):
            raise ValueError("argv must be an array of nonempty strings; shell syntax is not accepted")
        if any("\x00" in x for x in argv):
            raise ValueError("NUL byte in argv")
        _reject_shell(argv)
        timeout = case.get("timeout_sec", 30)
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0 < timeout <= MAX_TIMEOUT_SEC:
            raise ValueError("timeout_sec must be 1..%d" % MAX_TIMEOUT_SEC)
        expected = case.get("expected_exit", 0)
        if isinstance(expected, bool) or not isinstance(expected, int) or expected < 0:
            raise ValueError("expected_exit must be an integer >= 0")
        _env_names(case.get("pass_env"), "case.pass_env")
        _working_directory(root, case.get("cwd", "."))
        pairs.setdefault(pair, set()).add(role)
    if any(roles != {"candidate", "negative-control"} for roles in pairs.values()):
        raise ValueError("each pair_id needs candidate and negative-control experiments")


def _scrub(text, extra_secrets=()):
    # Bearer first, so the whole token is removed before the key=value rule would
    # otherwise stop at the space and keep it.
    text = BEARER.sub(lambda m: m.group(1) + _REDACT, text)
    text = KEY_VALUE.sub(lambda m: m.group(1) + m.group(2) + _REDACT + m.group(4), text)
    text = PROVIDER_URL.sub(lambda m: m.group(1) + _REDACT, text)
    text = QUERY_SECRET.sub(lambda m: m.group(1) + _REDACT, text)
    for secret in extra_secrets:
        if secret and len(secret) >= 4:
            text = text.replace(secret, _REDACT)
    return text


def _decode(blob):
    truncated = len(blob) > MAX_OUTPUT_BYTES
    return blob[:MAX_OUTPUT_BYTES].decode("utf-8", "replace"), truncated


def _dotenv_offenders(directory):
    allowed = {".env.example", ".env.sample", ".env.template", ".env.dist"}
    offenders = []
    try:
        for entry in sorted(directory.iterdir()):
            name = entry.name
            if not entry.is_file():
                continue
            if name == ".env" or (name.startswith(".env.") and name.lower() not in allowed):
                offenders.append(name)
    except OSError:
        pass
    return offenders


def _zero_tests(argv, returncode, text):
    """True when the tool reported that the selector matched no test at all."""
    base = Path(argv[0]).name.lower()
    low = text.lower()
    if "forge" in base and "test" in argv:
        if "no tests match the provided pattern" in low:
            return True
        if "ran " not in low and "test suite" not in low:
            return True
        return False
    if "cargo" in base and "test" in argv:
        counts = re.findall(r"running (\d+) tests?", low)
        if counts and all(c == "0" for c in counts):
            return True
        return False
    if base.startswith("go") and "test" in argv:
        return "no tests to run" in low
    if base.startswith("pytest") or "pytest" in argv:
        if returncode == 5:
            return True
        return "no tests ran" in low
    return False


def _run_case(command, cwd, timeout, env):
    """Run in its own session and kill the whole group on timeout so child
    processes (anvil, rustc, cargo build jobs) do not survive."""
    kwargs = {"cwd": cwd, "env": env, "stdout": subprocess.PIPE,
              "stderr": subprocess.PIPE, "stdin": subprocess.DEVNULL}
    if hasattr(os, "setsid"):
        kwargs["start_new_session"] = True
    proc = subprocess.Popen(command, shell=False, **kwargs)
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
        return proc.returncode, stdout, stderr, False
    except subprocess.TimeoutExpired:
        if hasattr(os, "killpg"):
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                proc.kill()
        else:
            proc.kill()
        stdout, stderr = proc.communicate()
        return None, stdout, stderr, True


def _checkout_identity(root):
    """Observed local checkout SHA and status; untracked PoC files make it dirty."""
    try:
        rev = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"],
                             capture_output=True, text=True, timeout=5, check=True).stdout.strip()
        status = subprocess.run(["git", "-C", str(root), "status", "--porcelain"],
                                capture_output=True, text=True, timeout=5, check=True).stdout
        return rev, "dirty" if status.strip() else "clean"
    except (OSError, subprocess.SubprocessError):
        return None, "unavailable"


def execute(plan, root, allow_exec=False, allow_dotenv=False):
    root = Path(root).resolve()
    if not root.is_dir():
        raise ValueError("repository not found")
    _validate(plan, root)
    plan_env = _env_names(plan.get("pass_env"), "plan.pass_env")
    results = []
    for case in plan["cases"]:
        command = case["argv"]
        pass_env = sorted(set(plan_env) | set(_env_names(case.get("pass_env"), "case.pass_env")))
        record = {"id": case["id"], "pair_id": case["pair_id"], "role": case["role"],
                  "argv": [_scrub(x) for x in command], "executed": False,
                  "expected_exit": case.get("expected_exit", 0),
                  "pass_env": pass_env, "tests_ran": None}
        if allow_exec:
            cwd = _working_directory(root, case.get("cwd", "."))
            offenders = _dotenv_offenders(root)
            if cwd != root:
                offenders = offenders + _dotenv_offenders(cwd)
            if offenders and not allow_dotenv:
                record.update({"executed": False, "status": "blocked-dotenv",
                               "matched_expected_exit": False,
                               "dotenv_files": sorted(set(offenders)),
                               "reason": "a .env file would be auto-loaded into the test "
                                         "environment; pass --allow-dotenv only after confirming "
                                         "it holds no secrets"})
                results.append(record)
                continue
            env = {k: v for k, v in os.environ.items() if k in ENV_ALLOWLIST}
            secret_values = []
            for name in pass_env:
                if name in os.environ:
                    env[name] = os.environ[name]
                    secret_values.append(os.environ[name])
            try:
                rc, raw_out, raw_err, timed_out = _run_case(
                    command, cwd, case.get("timeout_sec", 30), env)
                out_text, out_trunc = _decode(raw_out or b"")
                err_text, err_trunc = _decode(raw_err or b"")
                if timed_out:
                    record.update({"executed": True, "timed_out": True, "status": "timed-out",
                                   "matched_expected_exit": False,
                                   "stdout": _scrub(out_text, secret_values),
                                   "stderr": _scrub(err_text, secret_values),
                                   "truncated": out_trunc or err_trunc})
                else:
                    zero = _zero_tests(command, rc, out_text + "\n" + err_text)
                    record.update({"executed": True, "exit_code": rc, "timed_out": False,
                                   "tests_ran": not zero,
                                   "status": "no-tests-ran" if zero else "ran",
                                   "matched_expected_exit": (rc == record["expected_exit"]) and not zero,
                                   "stdout": _scrub(out_text, secret_values),
                                   "stderr": _scrub(err_text, secret_values),
                                   "truncated": out_trunc or err_trunc})
            except OSError as exc:
                record.update({"executed": False, "status": "launch-error",
                               "error": _scrub(str(exc)), "matched_expected_exit": False})
        results.append(record)
    ok = allow_exec and all(r.get("matched_expected_exit") and not r.get("timed_out")
                            and r.get("status") not in ("no-tests-ran", "blocked-dotenv", "launch-error")
                            for r in results)
    source_revision, source_status = _checkout_identity(root)
    return {"schema": 1, "source_revision": source_revision,
            "source_status": source_status,
            "mode": "executed" if allow_exec else "dry-run",
            "result": "experiments-conformed" if ok else ("not-executed" if not allow_exec else "incomplete"),
            "cases": results, "pairs": len({x["pair_id"] for x in results}),
            "notice": "Even passing paired experiments only show the named commands met exit expectations. "
                      "A selector that matched zero tests is reported no-tests-ran, never a pass. Inspect "
                      "assertions, source integrity, realistic setup, impact and chain state before calling "
                      "a finding verified."}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True, help="local JSON plan")
    parser.add_argument("--repo", required=True, help="disposable target checkout")
    parser.add_argument("--allow-exec", action="store_true", help="opt in to executing argv; no shell used")
    parser.add_argument("--allow-dotenv", action="store_true",
                        help="permit running when a .env file is present (confirm it holds no secrets first)")
    parser.add_argument("--out", help="write private JSON execution record")
    args = parser.parse_args(argv)
    try:
        plan = json.loads(Path(args.plan).read_text(encoding="utf-8"))
        report = execute(plan, args.repo, args.allow_exec, args.allow_dotenv)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    payload = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    if args.out:
        Path(args.out).write_text(payload, encoding="utf-8")
        print(json.dumps({"file": args.out, "result": report["result"]}))
    else:
        print(payload, end="")
    return 1 if args.allow_exec and report["result"] != "experiments-conformed" else 0


if __name__ == "__main__":
    sys.exit(main())
