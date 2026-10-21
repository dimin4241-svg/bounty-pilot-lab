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

# The target checkout is untrusted: its .git/config can name an fsmonitor or hooks program
# that git would run even for a read-only `ls-files` or `status`.
GIT_HARDENING = ("--no-optional-locks", "-c", "core.fsmonitor=false",
                 "-c", "core.hooksPath=/dev/null")

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
# Short-option letters that take inline code, and letters whose value is the rest of the
# cluster or the next word, per interpreter. Options are read up to the script or module, so
# `python3 -m pytest -c pytest.ini` passes and `python3 -Ic code` or `bash -lc code` does not.
CODE_LETTERS = {"python": "c", "node": "ep", "nodejs": "ep", "bun": "ep", "deno": "",
                "perl": "eE", "ruby": "e", "php": "rRBE", "lua": "e"}
VALUE_LETTERS = {"python": "WXQ", "node": "rC", "nodejs": "rC", "bun": "r", "perl": "IMmdDxlC0",
                 "ruby": "IrCEFKTWx", "php": "dcfzt", "lua": "l"}
LONG_CODE_OPTIONS = ("--eval", "--print", "--eval-file", "--command")
SHELL_VALUE_OPTIONS = {"-o", "+o", "-O", "+O", "--rcfile", "--init-file"}
# Commands that run another command unchanged. Detection, the shell guard and the gate read
# the command they wrap, so `env forge test` and `timeout 60 forge test` are still forge.
WRAPPERS = {"env", "timeout", "nice", "nohup", "stdbuf", "time", "ionice"}
WRAPPER_VALUE_OPTIONS = {"env": {"-u", "--unset", "-C", "--chdir"},
                         "timeout": {"-k", "-s", "--kill-after", "--signal"},
                         "nice": {"-n", "--adjustment"},
                         "stdbuf": {"-i", "-o", "-e"},
                         "time": {"-f", "--format", "-o", "--output"},
                         "ionice": {"-c", "-n", "-p", "-P", "-u", "--class", "--classdata"}}
MARKER_MAX_CHARS = 200

FINDING_ID = re.compile(r"BP-[0-9]{3,}")
ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")

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
# Secrets smuggled through a query string (dRPC names its key `dkey`).
QUERY_SECRET = re.compile(
    r'(?i)([?&](?:api[_-]?key|apikey|d?key|token|secret|access[_-]?token|auth)=)([^&\s"\']+)')
# Chainstack's node URLs carry the key as the whole path.
CHAINSTACK_URL = re.compile(r'(?i)\b((?:[a-z0-9-]+\.)+p2pify\.com/)([A-Za-z0-9_\-]{12,})')
# `https://user:password@host` and `https://:password@host`.
URL_USERINFO = re.compile(r'(?i)\b((?:https?|wss?)://[^/\s:@"\']*:)([^/\s@"\']+)(@)')
# A 32-byte hex value assigned to a key-like name: ETH_KEY=0x..., DEPLOYER_PK=...
HEX_KEY_ASSIGNMENT = re.compile(
    r'(?i)(\b[A-Za-z0-9_]*(?:key|pk|priv|signer|deployer|wallet)[A-Za-z0-9_]*["\']?\s*[:=]\s*'
    r'["\']?)((?:0x)?[0-9a-f]{64})\b')


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


def unwrap(argv):
    """The command a wrapper (env, timeout, nice, nohup, stdbuf, time, ionice) runs.

    `env -S` splits one string into a command line, which is a shell in all but name, so it
    is refused rather than unwrapped.
    """
    argv = list(argv)
    for _ in range(8):
        if not argv:
            return argv
        base = Path(argv[0]).name.lower()
        if base not in WRAPPERS:
            return argv
        takes = WRAPPER_VALUE_OPTIONS.get(base, set())
        idx = 1
        while idx < len(argv):
            word = argv[idx]
            if word == "--":
                idx += 1
                break
            if base == "env" and (word in ("-S", "--split-string") or word.startswith("-S")
                                  or word.startswith("--split-string")):
                raise ValueError("env -S splits a string into a command line; give the test "
                                 "binary and its arguments as argv")
            if word in takes:
                idx += 2
                continue
            if word.startswith("-") and len(word) > 1:
                idx += 1
                continue
            if base == "env" and "=" in word:
                idx += 1
                continue
            break
        if base == "timeout":
            idx += 1    # the duration
        argv = argv[idx:]
    return argv


def _leading_options(args, value_options=()):
    """Options before the first operand (script, module, file): those belong to the program."""
    found, idx = [], 0
    while idx < len(args):
        word = args[idx]
        if word == "--" or not word.startswith(("-", "/", "+")) or word in ("-", "/"):
            break
        found.append(word)
        idx += 2 if word in value_options else 1
    return found


def _reject_shell(argv):
    argv = unwrap(argv)
    if not argv:
        raise ValueError("argv names a wrapper with no command")
    base = Path(argv[0]).name.lower()
    stem = base[:-4] if base.endswith(".exe") else base
    if base in SHELLS or stem in SHELLS:
        # PowerShell takes -Command anywhere on its line; a POSIX shell reads options up to
        # the script, and what follows the script is that script's own arguments.
        words = (argv[1:] if stem in ("powershell", "pwsh")
                 else _leading_options(argv[1:], SHELL_VALUE_OPTIONS))
        for word in words:
            low = word.lower()
            if low in SHELL_CODE_FLAGS:
                raise ValueError("argv runs an inline shell command; name a real test binary "
                                 "instead")
            if stem in ("powershell", "pwsh"):
                name = "-" + low.lstrip("-/")
                if len(name) > 1 and any(full.startswith(name) for full in
                                         ("-command", "-encodedcommand", "-ec",
                                          "-commandwithargs", "-cwa")):
                    raise ValueError("argv runs an inline PowerShell command; name a real test "
                                     "binary instead")
            elif low.startswith("-") and not low.startswith("--") and "c" in low[1:]:
                # `bash -lc`, `sh -ec`, `zsh -xc`: a cluster that carries -c.
                raise ValueError("argv runs an inline shell command (" + word + "); name a real "
                                 "test binary instead")
        return
    stem = re.sub(r"[0-9.]+$", "", stem) or stem    # python3.12, lua5.4
    if stem not in INTERPRETERS:
        return
    if stem == "deno" and any(word in ("eval", "repl") for word in argv[1:2]):
        raise ValueError("argv runs inline interpreter code (deno eval); run a test file instead")
    code, values = CODE_LETTERS.get(stem, ""), VALUE_LETTERS.get(stem, "")
    takes_value = {"-" + letter for letter in values} | {"--require", "--import", "--loader",
                                                          "--conditions"}
    for word in _leading_options(argv[1:], takes_value):
        low = word.lower()
        if low in INTERPRETER_CODE_FLAGS or any(low == opt or low.startswith(opt + "=")
                                                for opt in LONG_CODE_OPTIONS):
            raise ValueError("argv runs inline interpreter code (-c/-e); run a test module or "
                             "file instead")
        if not word.startswith("-") or word.startswith("--"):
            continue
        for letter in word[1:]:
            if letter in code:
                raise ValueError("argv runs inline interpreter code (" + word + "); run a test "
                                 "module or file instead")
            if letter in values or (stem == "python" and letter == "m"):
                break   # the rest of the cluster is this option's value


def _validate(plan, root):
    if not isinstance(plan, dict):
        raise ValueError("plan must be a JSON object")
    _env_names(plan.get("pass_env"), "plan.pass_env")
    finding = plan.get("finding_id")
    if finding is not None and (not isinstance(finding, str) or not FINDING_ID.fullmatch(finding)):
        raise ValueError("finding_id must name the findings.json record this plan tests (BP-001)")
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
        if case.get("expect_tests_marker") is not None:
            _marker(case["expect_tests_marker"])
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
    text = CHAINSTACK_URL.sub(lambda m: m.group(1) + _REDACT, text)
    text = URL_USERINFO.sub(lambda m: m.group(1) + _REDACT + m.group(3), text)
    text = HEX_KEY_ASSIGNMENT.sub(lambda m: m.group(1) + _REDACT, text)
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


def _counts(pattern, text):
    return [int(n) for n in re.findall(pattern, text)]


def _marker(value):
    """Compile a case's expect_tests_marker, refusing one that empty output would satisfy."""
    if not isinstance(value, str) or not value.strip() or len(value) > MARKER_MAX_CHARS:
        raise ValueError("expect_tests_marker must be a nonempty regex of at most %d "
                         "characters" % MARKER_MAX_CHARS)
    try:
        pattern = re.compile(value, re.M)
    except re.error as exc:
        raise ValueError("expect_tests_marker is not a valid regex: " + str(exc))
    if pattern.search("") or pattern.search("\n"):
        raise ValueError("expect_tests_marker matches empty output, so it would show nothing")
    return pattern


def _subcommand(argv):
    """The first operand after the program (`test` in `cargo +nightly test`), or ''."""
    for word in argv[1:]:
        if word.startswith(("-", "+")):
            continue
        return word
    return ""


def _json_documents(text):
    """The output as one JSON object, or the JSON objects it prints one per line."""
    stripped = text.strip()
    try:
        whole = json.loads(stripped)
    except ValueError:
        whole = None
    if isinstance(whole, dict):
        return [whole]
    found = []
    for line in stripped.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            value = json.loads(line)
        except ValueError:
            continue
        if isinstance(value, dict):
            found.append(value)
    return found


def _cargo_zero(argv, low):
    """Zero unless a unit or integration harness executed a test; doc-tests are not the PoC.

    Cargo prints its `Running <binary>` and `Doc-tests <crate>` headers on stderr and libtest
    prints `running N tests` on stdout, so the two cannot be interleaved after capture. Cargo
    runs every test binary before any doc-test, though, so the first blocks belong to the
    binaries it announced. With `-q` there are no headers; a block is then a doc-test block
    when every test it names is a `path - item (line N)` doc-test. A block's own `test result:`
    line decides what executed: an `#[ignore]`d test is announced by `running 1 test` and then
    reported `0 passed; 0 failed; 1 ignored`, which asserted nothing.
    """
    if "--no-run" in argv or "--doc" in argv:
        return True
    blocks = re.split(r"(?m)^running (\d+) tests?$", low)
    counts = [int(n) for n in blocks[1::2]]
    bodies = blocks[2::2]
    if not counts:
        return True
    executed = []
    for count, body in zip(counts, bodies):
        result = re.search(r"test result: \w+\. (\d+) passed; (\d+) failed", body)
        executed.append(int(result.group(1)) + int(result.group(2)) if result else count)
    binaries = len(re.findall(r"(?m)^\s*running (?!\d+ tests?$)\S", low))
    if binaries:
        return sum(executed[:binaries]) == 0
    ran = 0
    for count, body in zip(executed, bodies):
        names = re.findall(r"(?m)^test (.+?) \.\.\. ", body)
        if names and all(re.search(r" - .* \(line \d+\)$", name) for name in names):
            continue
        ran += count
    return ran == 0


def _mocha_zero(argv, text, low):
    """Mocha, Hardhat (2 and 3) and the ts-mocha scripts `anchor test` runs: `N passing`.

    `--dry-run` reports every test passing without running one. The JSON reporter prints a
    `stats` object instead of the spec summary.
    """
    if "--dry-run" in argv:
        return True
    reporter = ""
    for idx, word in enumerate(argv):
        if word in ("--reporter", "-R") and idx + 1 < len(argv):
            reporter = argv[idx + 1].lower()
        elif word.startswith("--reporter="):
            reporter = word.split("=", 1)[1].lower()
    if reporter == "json":
        for document in _json_documents(text):
            stats = document.get("stats")
            if isinstance(stats, dict):
                passes, failures = stats.get("passes"), stats.get("failures")
                if isinstance(passes, int) and isinstance(failures, int):
                    return passes + failures == 0
        return True
    passing = _counts(r"\b(\d+) passing\b", low)
    failing = _counts(r"\b(\d+) failing\b", low)
    if passing or failing:
        return sum(passing) + sum(failing) == 0
    jest = re.findall(r"(?m)^\s*tests:\s+(.*\b\d+ total\b.*)$", low)
    if jest:
        # `Tests: 1 skipped, 1 total` executed nothing; only passed and failed count.
        return sum(sum(_counts(r"\b(\d+) (?:passed|failed)\b", line)) for line in jest) == 0
    # No summary at all: whatever ran, it reported no test result.
    return True


def _forge_zero(argv, text, low):
    words = [word.lower() for word in argv]
    if "--list" in words or "-l" in words:
        return True     # lists the tests and runs none
    if "no tests match the provided pattern" in low or "no tests found in project" in low:
        return True
    if "--json" in words:
        executed = None
        for document in _json_documents(text):
            for suite in document.values():
                results = suite.get("test_results") if isinstance(suite, dict) else None
                if not isinstance(results, dict):
                    continue
                executed = executed or 0
                executed += sum(1 for result in results.values() if isinstance(result, dict)
                                and result.get("status") in ("Success", "Failure"))
        if executed is not None:
            return executed == 0
    summary = re.findall(r"(\d+) tests passed, (\d+) failed, (\d+) skipped", low)
    if summary:
        # Every test skipped (vm.skip) is a run that asserted nothing.
        return all(int(passed) + int(failed) == 0 for passed, failed, _ in summary)
    if "ran " not in low and "test suite" not in low:
        return True
    return False


def _go_zero(argv, text, low):
    words = [word.lower() for word in argv]
    if any(word in ("-list", "--list") or word.startswith(("-list=", "--list="))
           for word in words):
        return True
    if "-json" in words or "--json" in words:
        ran = 0
        for line in text.splitlines():
            try:
                event = json.loads(line)
            except ValueError:
                continue
            if isinstance(event, dict) and event.get("Test") and \
                    event.get("Action") in ("pass", "fail"):
                ran += 1
        return ran == 0
    if re.search(r"(?m)^\s*--- (?:pass|fail)", low):
        return False
    if any(word in ("-v", "--v") or word.startswith(("-v=", "-test.v")) for word in words):
        return True     # -v printed no PASS or FAIL line: everything matched was skipped
    # Without -v a test that called t.Skip prints the same `ok` line as one that passed.
    return True


def _pytest_zero(argv, returncode, low):
    words = [word.lower() for word in argv]
    if returncode == 5:
        return True
    if any(word in ("--collect-only", "--co", "--setup-plan", "--setup-only") for word in words):
        return True
    if "no tests ran" in low or "collected 0 items" in low or re.search(r"\b0 selected\b", low):
        return True
    summaries = [line for line in low.splitlines()
                 if re.search(r"\b\d+ (?:passed|failed|skipped|deselected|xfailed|xpassed|"
                              r"errors?)\b", line) and re.search(r"\bin [\d.]+s\b", line)]
    if not summaries:
        return True     # -qq or -p no:terminal: nothing says a test executed
    line = summaries[-1]
    return sum(_counts(r"\b(\d+) (?:passed|failed|xfailed|xpassed)\b", line)) == 0


def _unittest_zero(low):
    ran = _counts(r"\bran (\d+) tests? in\b", low)
    if not ran or not any(ran) or "no tests ran" in low:
        return True
    skipped = sum(_counts(r"\bskipped=(\d+)", low))
    return sum(ran) - skipped <= 0


def _detect(argv, returncode, text):
    """(tool, zero) for a recognised test runner, or (None, None) for anything else."""
    argv = unwrap(argv)
    if not argv:
        return None, None
    base = Path(argv[0]).name.lower()
    names = {Path(arg).name.lower() for arg in argv}
    low = ANSI.sub("", text).lower()
    plain = ANSI.sub("", text)
    sub = _subcommand(argv)
    if "forge" in base and sub in ("test", "t"):
        return "forge", _forge_zero(argv, plain, low)
    if "cargo" in base and sub in ("test", "t"):
        return "cargo", _cargo_zero(argv, low)
    if re.fullmatch(r"go(?:[0-9][\w.]*)?", base) and sub == "test":
        return "go", _go_zero(argv, plain, low)
    if base.startswith("pytest") or "pytest" in argv:
        return "pytest", _pytest_zero(argv, returncode, low)
    if "unittest" in argv and (base.startswith("python") or base == "py"):
        return "unittest", _unittest_zero(low)
    if (base == "move" or base in ("sui", "aptos", "iota") and "move" in argv) and "test" in argv:
        totals = _counts(r"total tests: (\d+)", low)
        return "move", not totals or not any(totals)
    if ("mocha" in names or "_mocha" in names or "ts-mocha" in names
            or (("hardhat" in names or "anchor" in names) and "test" in argv)):
        if "anchor" in names and re.search(r"\brunning \d+ tests?\b", low):
            # An Anchor workspace whose test script is `cargo test`.
            return "anchor-cargo", _cargo_zero(argv, low)
        return "mocha", _mocha_zero(argv, plain, low)
    return None, None


def read_test_output(argv, returncode, text, marker=None):
    """How a case's output reads: (status, detection, note).

    status is `ran`, `no-tests-ran` or `unknown-runner`. Detection fails closed: a runner this
    module does not recognise is `unknown-runner` - its output was never read, so it never
    counts as a test that ran - unless the plan case names an `expect_tests_marker`, a regex
    the output must match (for TAP output, `^ok \\d+ `). For a recognised runner the marker is
    an extra condition, never a substitute for the tool's own count.
    """
    pattern = _marker(marker) if marker is not None else None
    tool, zero = _detect(argv, returncode, text)
    plain = ANSI.sub("", text)
    if tool is None:
        if pattern is None:
            return ("unknown-runner", "none",
                    "this runner's output is not one the runner can read; name a recognised test "
                    "command (forge, cargo, go, pytest, unittest, mocha/hardhat, anchor, move) or "
                    "set expect_tests_marker on the case to a regex its output prints only when "
                    "a test executed")
        if pattern.search(plain):
            return "ran", "marker", "expect_tests_marker matched the output"
        return "no-tests-ran", "marker", "expect_tests_marker did not match the output"
    if zero:
        words = [word.lower() for word in unwrap(argv)]
        if tool == "go" and not any(w in ("-v", "-json", "--json") or w.startswith("-v=")
                                    for w in words):
            return ("no-tests-ran", tool, "go test without -v prints the same line for a skipped "
                    "test as for a passing one; add -v so the runner can see --- PASS")
        return ("no-tests-ran", tool, "the tool's own output shows no test executed (none "
                "matched, all were skipped or ignored, or the command only listed tests)")
    if pattern is not None and not pattern.search(plain):
        return "no-tests-ran", tool + "+marker", "expect_tests_marker did not match the output"
    return "ran", tool, ""


def _zero_tests(argv, returncode, text):
    """True unless the output shows a test executed: zero matched, all skipped, or unread."""
    return read_test_output(argv, returncode, text)[0] != "ran"


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
        rev = subprocess.run(["git", *GIT_HARDENING, "-C", str(root), "rev-parse", "HEAD"],
                             capture_output=True, text=True, timeout=5, check=True).stdout.strip()
        status = subprocess.run(["git", *GIT_HARDENING, "-C", str(root), "status", "--porcelain"],
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
        resolved_cwd = _working_directory(root, case.get("cwd", "."))
        record = {"id": case["id"], "pair_id": case["pair_id"], "role": case["role"],
                  "argv": [_scrub(x) for x in command], "cwd": case.get("cwd", "."),
                  # The directory the command ran in, normalised: "." and "./" are one place,
                  # so a control cannot differ from its candidate by spelling alone.
                  "cwd_resolved": resolved_cwd.relative_to(root).as_posix() or ".",
                  "executed": False,
                  "expected_exit": case.get("expected_exit", 0),
                  "pass_env": pass_env, "tests_ran": None}
        if case.get("expect_tests_marker") is not None:
            record["expect_tests_marker"] = case["expect_tests_marker"]
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
                    status, detection, note = read_test_output(
                        command, rc, out_text + "\n" + err_text,
                        case.get("expect_tests_marker"))
                    ran = status == "ran"
                    record.update({"executed": True, "exit_code": rc, "timed_out": False,
                                   "tests_ran": ran, "status": status,
                                   "test_detection": detection,
                                   "matched_expected_exit": (rc == record["expected_exit"]) and ran,
                                   "stdout": _scrub(out_text, secret_values),
                                   "stderr": _scrub(err_text, secret_values),
                                   "truncated": out_trunc or err_trunc})
                    if note:
                        record["test_detection_note"] = note
            except OSError as exc:
                record.update({"executed": False, "status": "launch-error",
                               "error": _scrub(str(exc)), "matched_expected_exit": False})
        results.append(record)
    ok = allow_exec and all(r.get("matched_expected_exit") and not r.get("timed_out")
                            and r.get("status") not in ("no-tests-ran", "unknown-runner",
                                                        "blocked-dotenv", "launch-error")
                            for r in results)
    source_revision, source_status = _checkout_identity(root)
    return {"schema": 1, "finding_id": plan.get("finding_id"),
            "source_revision": source_revision,
            "source_status": source_status,
            "mode": "executed" if allow_exec else "dry-run",
            "result": "experiments-conformed" if ok else ("not-executed" if not allow_exec else "incomplete"),
            "cases": results, "pairs": len({x["pair_id"] for x in results}),
            "test_detection": "Each case's output is read by its own tool's rules (test_detection names "
                              "them). A selector that matched zero tests, or whose tests were all skipped "
                              "or ignored, is no-tests-ran; a command whose output this runner cannot read "
                              "is unknown-runner unless the case sets expect_tests_marker, a regex its "
                              "output must match. Neither ever counts as a pass.",
            "notice": "Even passing paired experiments only show the named commands met exit expectations. "
                      "A selector that matched zero tests is reported no-tests-ran, never a pass. Inspect "
                      "assertions, source integrity, realistic setup, impact and chain state before calling "
                      "a finding verified."}


def write_case_logs(report, out):
    """Write each executed case's scrubbed output next to `out` and name the file in the case.

    `<out stem>.<case id>.log` holds exactly what the result records as stdout and stderr, so a
    finding's evidence.log_path can cite the candidate's log without anyone copying it by hand.
    """
    out = Path(out)
    stem = out.name[:-5] if out.name.endswith(".json") else out.name
    written = []
    for case in report.get("cases", []):
        if not case.get("executed"):
            continue
        name = stem + "." + re.sub(r"[^A-Za-z0-9_.-]", "_", str(case["id"])) + ".log"
        body = ("$ " + " ".join(case.get("argv", [])) + "\n" + case.get("stdout", "")
                + ("\n" if case.get("stdout") and not case["stdout"].endswith("\n") else "")
                + case.get("stderr", ""))
        (out.parent / name).write_text(body, encoding="utf-8")
        case["log_file"] = name
        written.append(name)
    return written


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
    if args.out:
        logs = write_case_logs(report, args.out)
        payload = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
        Path(args.out).write_text(payload, encoding="utf-8")
        print(json.dumps({"file": args.out, "result": report["result"], "logs": logs}))
        return 1 if args.allow_exec and report["result"] != "experiments-conformed" else 0
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 1 if args.allow_exec and report["result"] != "experiments-conformed" else 0


if __name__ == "__main__":
    sys.exit(main())
