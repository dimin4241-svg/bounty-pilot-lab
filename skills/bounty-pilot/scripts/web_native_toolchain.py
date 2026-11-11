#!/usr/bin/env python3
"""Explicitly opted-in local Web research toolchain integrations.

Runs an installed CodeQL, Schemathesis or Playwright CLI only for validated
operator-owned fixtures. HTTP Garden is a verified local observation import,
never Docker startup. External sites, arbitrary commands/arguments, shell
execution, remote OpenAPI references and credential-bearing environment
variables are unsupported. No OS-level network sandbox: use a disposable
host/container with egress blocked for third-party tool execution.

Offline plan checking is the default. Native execution requires --execute,
an explicit owned-fixture attestation, strict local paths, and private outputs.
Tool output is summarized, NOT treated as confirmed findings.
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

MODES = frozenset(("codeql", "schemathesis", "playwright", "http-garden-import"))
SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA64 = re.compile(r"^[0-9a-f]{64}$")
IDENT = re.compile(r"^[A-Za-z0-9_.:-]{1,100}$")
LOOP = re.compile(r"^http://127\.0\.0\.1:([0-9]{4,5})$")
SAFE_REL = re.compile(r"^[A-Za-z0-9_./-]{1,240}$")
MAX_INPUT = 4_000_000
MAX_REPORT = 5_000_000
MAX_JSON_SCHEMA = 800_000
COMMAND_TIMEOUT = 180


def _unique(pairs):
    obj = {}
    for k, value in pairs:
        if k in obj:
            raise ValueError("duplicate JSON key")
        obj[k] = value
    return obj


def _read(path, limit=MAX_INPUT):
    p = Path(path).expanduser()
    if p.is_symlink() or not p.is_file() or p.stat().st_size > limit:
        raise ValueError("bounded regular non-symlink JSON required")
    return json.loads(p.read_text(encoding="utf-8"), object_pairs_hook=_unique)


def _write_new(path, obj):
    p = Path(path).expanduser()
    if p.exists() or p.is_symlink():
        raise ValueError("output file must be new")
    p.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(p), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(obj, f, sort_keys=True, ensure_ascii=False, indent=2)
        f.write("\n")


def _local_dir(path):
    p = Path(path).expanduser()
    if not p.is_absolute() or p.is_symlink() or not p.is_dir():
        raise ValueError("absolute regular directory required")
    return p.resolve(strict=True)


def _file(path, *, suffix=None, root=None, max_bytes=MAX_INPUT):
    p = Path(path).expanduser()
    if (not p.is_absolute() or p.is_symlink() or not p.is_file() or
            p.stat().st_size > max_bytes or (suffix and p.suffix not in suffix)):
        raise ValueError("absolute bounded non-symlink file required")
    resolved = p.resolve(strict=True)
    if root:
        # The fixture root is canonical but the caller's absolute path can
        # pass through an OS-level alias such as macOS /var -> /private/var.
        # Compare *resolved* ancestry for containment, while checking symlink
        # directories only *after* entering the owned root. Reject symlink
        # hops introduced inside that root, even when they point back inside.
        canonical_root = Path(root).resolve(strict=True)
        if resolved == canonical_root or canonical_root not in resolved.parents:
            raise ValueError("file must be contained within owned fixture directory")
        within_root = False
        for ancestor in reversed(p.parents):
            canonical_ancestor = ancestor.resolve(strict=True)
            if canonical_ancestor == canonical_root:
                if within_root and ancestor.is_symlink():
                    raise ValueError("symlink directory is forbidden")
                within_root = True
            elif within_root:
                if (ancestor.is_symlink() or
                        canonical_root not in canonical_ancestor.parents):
                    raise ValueError("symlink directory is forbidden")
        if not within_root:
            raise ValueError("file path does not traverse owned fixture root")
    return resolved


def _origin(value):
    if not isinstance(value, str):
        raise ValueError("literal loopback origin required")
    m = LOOP.fullmatch(value)
    if not m or not 1024 <= int(m.group(1)) <= 65535 or (
            value != "http://127.0.0.1:" + str(int(m.group(1)))):
        raise ValueError("only canonical http://127.0.0.1:PORT supported")
    return value


def _rel_path(value):
    if (not isinstance(value, str) or not SAFE_REL.fullmatch(value) or
            not value.startswith("/") or value.startswith("//") or
            "//" in value or any(x in (".", "..") for x in value.split("/"))):
        raise ValueError("unambiguous local ASCII path required")
    return value


def _owned(doc, mode):
    if not isinstance(doc, dict) or doc.get("schema_version") != 1:
        raise ValueError("toolchain plan schema_version=1 required")
    if doc.get("mode") != mode or doc.get("attestation") != "I_CONTROL_THIS_LOCAL_FIXTURE":
        raise ValueError("toolchain mode and explicit ownership attestation required")
    if doc.get("max_seconds") is None or type(doc["max_seconds"]) is not int or (
            not 5 <= doc["max_seconds"] <= COMMAND_TIMEOUT):
        raise ValueError("bounded 5..180 second timeout required")
    return doc


def _validate_schema(schema):
    if (not isinstance(schema, dict) or
            not isinstance(schema.get("openapi"), str) or
            not schema["openapi"].startswith("3.") or
            not isinstance(schema.get("paths"), dict) or
            not 1 <= len(schema["paths"]) <= 50):
        raise ValueError("small OpenAPI 3 fixture document required")
    if schema.get("webhooks") or schema.get("callbacks"):
        raise ValueError("webhooks are not supported in owned fixture profile")
    n = 0

    def walk(value):
        nonlocal n
        n += 1
        if n > 30000:
            raise ValueError("OpenAPI schema too complex")
        if isinstance(value, dict):
            for key, child in value.items():
                if key == "$ref" and (not isinstance(child, str) or
                                      not child.startswith("#/")):
                    raise ValueError("only internal OpenAPI $ref supported")
                if key in ("servers", "externalDocs", "callbacks", "webhooks"):
                    if key == "servers":
                        if child != []:
                            raise ValueError("schema servers must be empty; CLI overrides origin")
                    else:
                        raise ValueError("external URI/callback metadata forbidden")
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(schema)
    for path, definition in schema["paths"].items():
        _rel_path(path)
        if not isinstance(definition, dict):
            raise ValueError("invalid path operation map")
        for method, spec in definition.items():
            if method.lower() in ("get", "post", "put", "patch", "delete"):
                if not isinstance(spec, dict):
                    raise ValueError("invalid OpenAPI operation")
                if spec.get("callbacks"):
                    raise ValueError("callback operation forbidden")
    return len(schema["paths"])


def _git_head(repo):
    cmd = ["git", "--no-optional-locks", "-c", "core.fsmonitor=false",
           "-c", "core.hooksPath=/dev/null", "-C", str(repo),
           "rev-parse", "--verify", "HEAD^{commit}"]
    try:
        run = subprocess.run(cmd, text=True, capture_output=True, timeout=5,
                             check=False, env=_env())
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError("could not inspect pinned source checkout") from exc
    if run.returncode:
        raise ValueError("source root is not a pinned Git checkout")
    return run.stdout.strip()


def _env(home=None):
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
           "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
           "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
           "NODE_OPTIONS": "", "PYTHONNOUSERSITE": "1",
           "NO_PROXY": "127.0.0.1", "no_proxy": "127.0.0.1"}
    if home:
        env.update({"HOME": home, "XDG_CONFIG_HOME": home,
                    "TMPDIR": home})
    return env


def check(doc):
    if not isinstance(doc, dict) or doc.get("mode") not in MODES:
        raise ValueError("select one supported toolchain mode")
    mode = doc["mode"]
    _owned(doc, mode)
    base = {"mode": mode, "max_seconds": doc["max_seconds"]}
    if mode == "codeql":
        if set(doc) != {"schema_version", "mode", "attestation", "max_seconds",
                        "repo", "source_commit", "local_query"}:
            raise ValueError("CodeQL plan fields invalid")
        repo = _local_dir(doc["repo"])
        commit = doc["source_commit"]
        if not isinstance(commit, str) or not SHA40.fullmatch(commit):
            raise ValueError("pinned source 40-hex commit required")
        query = _file(doc["local_query"], suffix=(".ql", ".qls"),
                      max_bytes=200000)
        if query == repo or repo in query.parents:
            raise ValueError("trusted CodeQL queries must not come from target checkout")
        base.update({"repo": str(repo), "source_commit": commit,
                     "local_query": str(query)})
    elif mode == "schemathesis":
        if set(doc) != {"schema_version", "mode", "attestation", "max_seconds",
                        "origin", "fixture_dir", "openapi_file", "seed",
                        "max_examples", "phases"}:
            raise ValueError("Schemathesis plan fields invalid")
        base["origin"] = _origin(doc["origin"])
        root = _local_dir(doc["fixture_dir"])
        schema = _file(doc["openapi_file"], root=root, suffix=(".json",),
                       max_bytes=MAX_JSON_SCHEMA)
        _validate_schema(_read(schema, MAX_JSON_SCHEMA))
        if type(doc["seed"]) is not int or not 0 <= doc["seed"] <= 2147483647:
            raise ValueError("deterministic Schemathesis seed required")
        if type(doc["max_examples"]) is not int or not 1 <= doc["max_examples"] <= 10:
            raise ValueError("Schemathesis generated examples must be <=10")
        if doc["phases"] not in ("stateful", "examples", "fuzzing", "examples,stateful"):
            raise ValueError("bounded Schemathesis phases required")
        base.update({"fixture_dir": str(root), "openapi_file": str(schema),
                     "seed": doc["seed"], "max_examples": doc["max_examples"],
                     "phases": doc["phases"]})
    elif mode == "playwright":
        if set(doc) != {"schema_version", "mode", "attestation", "max_seconds",
                        "origin", "owner_path", "outsider_path",
                        "scalar_selector", "browser_module"}:
            raise ValueError("Playwright plan fields invalid")
        base["origin"] = _origin(doc["origin"])
        base["owner_path"] = _rel_path(doc["owner_path"])
        base["outsider_path"] = _rel_path(doc["outsider_path"])
        if base["owner_path"] == base["outsider_path"]:
            raise ValueError("separate owned and outsider fixture URLs required")
        selector = doc["scalar_selector"]
        if not isinstance(selector, str) or not re.fullmatch(r"#[A-Za-z][A-Za-z0-9_-]{0,79}", selector):
            raise ValueError("only simple #id scalar selector allowed")
        # Trust boundary: resolve the operator-installed package explicitly,
        # not any node_modules supplied by target source.
        mod = _local_dir(doc["browser_module"])
        if (mod.name != "node_modules" or (mod / "playwright").is_symlink()
                or not (mod / "playwright").is_dir()):
            raise ValueError("Playwright must be installed in isolated trusted node_modules")
        base.update({"scalar_selector": selector, "browser_module": str(mod)})
    else:
        if set(doc) != {"schema_version", "mode", "attestation", "max_seconds",
                        "observation_file", "garden_commit", "garden_checkout"}:
            raise ValueError("Garden observation import plan fields invalid")
        p = _file(doc["observation_file"], suffix=(".json",), max_bytes=MAX_INPUT)
        commit = doc["garden_commit"]
        if not isinstance(commit, str) or not SHA40.fullmatch(commit):
            raise ValueError("pinned Garden commit required")
        checkout = _local_dir(doc["garden_checkout"])
        base.update({"observation_file": str(p), "garden_commit": commit,
                     "garden_checkout": str(checkout)})
    return base


def _execute(cmd, timeout, cwd, scratch):
    # No shell expansion, user arguments, inherited credentials, or target
    # supplied executable paths. Tool resolution uses operator PATH only.
    try:
        run = subprocess.run(cmd, cwd=str(cwd), env=_env(str(scratch)),
                             text=True, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, timeout=timeout,
                             check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError("local toolchain unavailable or timed out") from exc
    # Do not persist raw logs: Schemathesis/Playwright/CodeQL can include
    # credentials, response bodies or other private source data.
    return {"exit_code": run.returncode,
            "stdout_sha256": hashlib.sha256(
                (run.stdout or "").encode("utf-8")).hexdigest(),
            "stdout_bytes": len((run.stdout or "").encode("utf-8"))}


def _sarif_summary(path):
    data = _read(path, MAX_REPORT)
    if not isinstance(data, dict) or not isinstance(data.get("runs"), list):
        raise ValueError("CodeQL did not produce valid SARIF")
    signals = []
    for run in data["runs"][:5]:
        for result in run.get("results", [])[:500]:
            rule = result.get("ruleId")
            locations = result.get("locations") or []
            if not isinstance(rule, str) or len(rule) > 160 or not locations:
                continue
            physical = locations[0].get("physicalLocation", {})
            location = physical.get("artifactLocation", {})
            uri = location.get("uri", "")
            region = physical.get("region", {})
            if not isinstance(uri, str) or len(uri) > 240 or (
                    uri.startswith("/") or "://" in uri or "%" in uri or
                    ":" in uri or ".." in uri.split("/")):
                continue
            line = region.get("startLine")
            if type(line) is not int or not 1 <= line <= 1000000:
                continue
            signals.append({"rule": rule, "source_path": uri, "line": line,
                            "status": "STATIC_CODEQL_SIGNAL_UNVERIFIED"})
    return {"signals": signals[:300], "count": len(signals)}


def _schemathesis_summary(path):
    report = _read(path, MAX_REPORT)
    # Never expose request/response secrets from third-party report formats.
    return {"raw_report_sha256": hashlib.sha256(
        path.read_bytes()).hexdigest(),
        "report_present": isinstance(report, dict),
        "findings_verified": 0}


def run_native(plan, output_path, *, execute=False):
    meta = check(plan)
    mode = meta["mode"]
    out = Path(output_path).expanduser()
    if out.exists() or out.is_symlink():
        raise ValueError("report must be a new file")
    if not execute:
        return {"schema_version": 1, "mode": mode, "status": "PLAN_VALIDATED_NOT_EXECUTED",
                "native_calls": 0, "external_network_authorized": False,
                "reported_vulnerabilities": 0}
    if mode == "http-garden-import":
        if _git_head(Path(meta["garden_checkout"])) != meta["garden_commit"]:
            raise ValueError("garden checkout changed since pinned revision")
        # An existing owned-lab observation format is the only accepted
        # Garden evidence contract; this does NOT prove Garden ran it.
        src = _read(meta["observation_file"])
        spec = __import__("importlib.util").util.spec_from_file_location(
            "bp_http_boundary_import",
            Path(__file__).with_name("web_http_boundary.py"))
        module = __import__("importlib.util").util.module_from_spec(spec)
        spec.loader.exec_module(module)
        result = module.compare(src)
        return {"schema_version": 1, "mode": mode,
                "status": "SAVED_PARSER_OBSERVATIONS_REVIEWED_NOT_ATTESTED",
                "garden_commit": meta["garden_commit"],
                "observation_sha256": hashlib.sha256(
                    Path(meta["observation_file"]).read_bytes()).hexdigest(),
                "comparison": result, "native_calls": 0,
                "confirmed_vulnerabilities": 0}
    if mode == "codeql" and _git_head(Path(meta["repo"])) != meta["source_commit"]:
        raise ValueError("source checkout changed since pinned revision")
    exe = {"codeql": "codeql", "schemathesis": "st", "playwright": "node"}[mode]
    binary = shutil.which(exe)
    if not binary:
        raise ValueError("required native tool is not installed in the operator PATH")
    with tempfile.TemporaryDirectory(prefix="bp-web-native-") as scratch_str:
        scratch = Path(scratch_str)
        if mode == "codeql":
            db = scratch / "source-db"
            sarif = scratch / "result.sarif"
            first = _execute(
                [binary, "database", "create", str(db),
                 "--language=javascript-typescript", "--build-mode=none",
                 "--source-root=" + meta["repo"], "--threads=2"],
                meta["max_seconds"], scratch, scratch)
            if first["exit_code"]:
                raise ValueError("CodeQL database creation failed")
            second = _execute(
                [binary, "database", "analyze", str(db), meta["local_query"],
                 "--format=sarifv2.1.0", "--output=" + str(sarif),
                 "--threads=2"],
                meta["max_seconds"], scratch, scratch)
            if second["exit_code"]:
                raise ValueError("CodeQL analysis failed")
            observed = _sarif_summary(sarif)
            executions = [first, second]
        elif mode == "schemathesis":
            report = scratch / "report.json"
            cmd = [binary, "run", meta["openapi_file"],
                   "--url", meta["origin"], "--phases", meta["phases"],
                   "--max-examples", str(meta["max_examples"]),
                   "--seed", str(meta["seed"]),
                   "--workers", "1", "--request-timeout", "2",
                   "--max-redirects", "0", "--request-retries", "0",
                   "--output-sanitize", "true",
                   "--report-json-path", str(report)]
            outcome = _execute(cmd, meta["max_seconds"], scratch, scratch)
            observed = (_schemathesis_summary(report) if report.exists()
                        else {"report_present": False, "findings_verified": 0})
            executions = [outcome]
        else:
            script = Path(__file__).with_name("web_playwright_local.cjs")
            payload = scratch / "browser-plan.json"
            payload.write_text(json.dumps({
                "origin": meta["origin"],
                "owner_path": meta["owner_path"],
                "outsider_path": meta["outsider_path"],
                "scalar_selector": meta["scalar_selector"]}), encoding="utf-8")
            result = scratch / "browser-results.json"
            outcome = _execute(
                [binary, str(script), meta["browser_module"],
                 str(payload), str(result)], meta["max_seconds"],
                scratch, scratch)
            if outcome["exit_code"] or not result.exists():
                raise ValueError("local Playwright browser run failed")
            observed = _read(result, 50000)
            if not isinstance(observed, dict) or set(observed) != {
                    "schema_version", "mode", "owner", "outsider",
                    "blocked_external_requests"}:
                raise ValueError("Playwright emitted invalid controlled observation")
            executions = [outcome]
    return {"schema_version": 1, "mode": mode,
            "status": "LOCAL_TOOL_EXECUTED_OUTPUT_UNVERIFIED",
            "observations": observed, "tool_executions": executions,
            "native_calls": len(executions), "confirmed_vulnerabilities": 0,
            "limitations": ("Installed third-party executables are not independently "
                            "sandboxed by this Python wrapper. All source and endpoints "
                            "must be operator-owned, trusted and run in a disposable "
                            "OS-level network-restricted environment. Reports are "
                            "static test observations, not exploit or payout proof.")}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--plan", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--execute", action="store_true",
                   help="opt-in native tool execution on owned local fixture")
    args = p.parse_args(argv)
    try:
        plan = _read(args.plan)
        report = run_native(plan, args.out, execute=args.execute)
        _write_new(args.out, report)
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        p.error(str(exc))
    print(json.dumps({"out": args.out, "mode": report["mode"],
                      "status": report["status"],
                      "confirmed_vulnerabilities": 0}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
