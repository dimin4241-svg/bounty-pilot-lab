#!/usr/bin/env python3
"""Native Web3 evidence capture: run paired tests twice, bind actual output to a pinned Git HEAD.

IMPORTANT: subprocess tests ARE executable untrusted target code. This runner does not
provide network isolation; require a real external sandbox and an explicit opt-in.
The results bind emitted claims to executed test transcripts, NOT to genuine security facts.
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import scenario_runner
import web3_advanced
import web3_research

PREFIX = "BP_NATIVE_OBSERVATION_V1 "
REV = re.compile(r"[0-9a-f]{40}\Z")
SAFE = re.compile(r"BP-[0-9]{3,}\Z")
GIT = ("--no-optional-locks", "-c", "core.fsmonitor=false",
       "-c", "core.hooksPath=/dev/null", "-c", "core.pager=cat")
MODES = {"business-invariants", "signed-intent-mirror", "authz", "wallet-intent"}
MAX_MARKER = 10_000


def _git(root, *words):
    result = subprocess.run(["git", *GIT, "-C", str(root), *words],
                            capture_output=True, check=True, timeout=15)
    return result.stdout.decode("utf-8", "replace").strip()


def _fingerprint(root):
    result = subprocess.run(["git", *GIT, "-C", str(root),
                             "diff", "--binary", "--no-ext-diff", "--no-textconv",
                             "HEAD", "--"],
                            capture_output=True, check=True, timeout=20)
    if len(result.stdout) > 8_000_000:
        raise ValueError("tracked source diff over 8 MB")
    return hashlib.sha256(result.stdout).hexdigest()


def _private(path, obj):
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(obj, stream, indent=2, sort_keys=True, ensure_ascii=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def _hash(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=True).encode("ascii")).hexdigest()


def _marker(record, pair_id, role):
    if (record.get("status") != "ran" or not record.get("matched_expected_exit") or
            not record.get("tests_ran") or not record.get("executed") or
            record.get("truncated") or record.get("timed_out")):
        raise ValueError("test did not execute and pass with complete output: " + role)
    found = []
    for line in (record.get("stdout", "") + "\n" + record.get("stderr", "")).splitlines():
        if not line.startswith(PREFIX):
            continue
        payload = line[len(PREFIX):]
        if len(payload) > MAX_MARKER:
            raise ValueError("observation marker too large")
        data = json.loads(payload, object_pairs_hook=web3_advanced.pairs_unique)
        if (not isinstance(data, dict) or set(data) !=
                {"schema_version", "pair_id", "role", "observation"} or
                type(data["schema_version"]) is not int or data["schema_version"] != 1 or
                data["pair_id"] != pair_id or data["role"] != role or
                not isinstance(data["observation"], dict) or
                "trace_sha256" in data["observation"]):
            raise ValueError("marker fields do not match approved plan")
        found.append(data["observation"])
    if len(found) != 1:
        raise ValueError("expected exactly one native observation marker per case: " + role)
    obs = dict(found[0])
    # Binds this *claim* to the captured, redacted command output.
    obs["trace_sha256"] = hashlib.sha256((record.get("stdout", "") + "\n" +
                                          record.get("stderr", "")).encode("utf-8")).hexdigest()
    return obs


def collect(config, root, out, execute=False, isolated=False, network_isolated=False):
    config = web3_advanced.obj(config, "capture configuration",
                               ("schema_version", "source_revision", "finding_id",
                                "operation", "environment", "invariant", "equivalence_basis",
                                "scenario", "bound_fields", "runner_plan"))
    if type(config.get("schema_version")) is not int or config["schema_version"] != 1:
        raise ValueError("invalid capture schema_version")
    revision = web3_advanced.txt(config.get("source_revision"),
                                 "source_revision", 40, REV)
    finding = web3_advanced.txt(config.get("finding_id"), "finding_id", 96, SAFE)
    operation = config.get("operation")
    if operation not in MODES:
        raise ValueError("unsupported operation")
    if config.get("environment") not in ("native-local", "anvil-local", "mock-local"):
        raise ValueError("unknown local environment")
    invariant = web3_advanced.txt(config.get("invariant"), "invariant", 500)
    basis = web3_advanced.txt(config.get("equivalence_basis"), "equivalence_basis", 500)
    if operation == "business-invariants":
        if config.get("scenario") not in ("trade-asset", "fee-sign", "deposit-finality"):
            raise ValueError("business scenario required")
        if "bound_fields" in config:
            raise ValueError("bound_fields not used for business")
    elif operation in ("wallet-intent", "signed-intent-mirror"):
        if "scenario" in config:
            raise ValueError("scenario applies only to business")
        fields = web3_advanced.bounded(config.get("bound_fields"), "bound_fields", 15)
        valid = web3_advanced.BINDINGS if operation == "signed-intent-mirror" else web3_research.FIELD
        if len(fields) != len(set(fields)) or any(not isinstance(x, str) or x not in valid for x in fields):
            raise ValueError("invalid bound_fields")
    elif "bound_fields" in config or "scenario" in config:
        raise ValueError("authz does not accept scenario/bound_fields")
    plan = web3_advanced.obj(config.get("runner_plan"), "runner_plan")
    if plan.get("finding_id") != finding or len(plan.get("cases", [])) != 2:
        raise ValueError("runner_plan must contain one candidate/control pair")
    pair_ids = {item.get("pair_id") for item in plan["cases"] if isinstance(item, dict)}
    roles = {item.get("role") for item in plan["cases"] if isinstance(item, dict)}
    if pair_ids != {finding} or roles != {"candidate", "negative-control"}:
        raise ValueError("runner pair roles/IDs mismatch")
    # Refuse arbitrary passthrough env, which may leak secret credentials.
    if plan.get("pass_env") or any(item.get("pass_env") for item in plan["cases"]):
        raise ValueError("pass_env is forbidden for Web3 capture; use secret-free fixtures")
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("checkout must be an actual non-symlink directory")
    root = root.resolve()
    if Path(_git(root, "rev-parse", "--show-toplevel")).resolve() != root:
        raise ValueError("checkout must be Git root")
    if _git(root, "rev-parse", "HEAD") != revision:
        raise ValueError("checkout HEAD differs from pinned source_revision")
    scenario_runner._validate(plan, root)
    if not execute:
        return {"status": "DRY_RUN_ONLY", "source_revision": revision,
                "pair_id": finding, "test_cases": len(plan["cases"]),
                "confirmed_vulnerabilities": 0}
    if not (isolated and network_isolated):
        raise ValueError("execution requires external isolation and network-isolation confirmation")
    if root in (Path("/").resolve(), Path.home().resolve()):
        raise ValueError("unsafe checkout root")
    before = _git(root, "status", "--porcelain", "--untracked-files=no")
    if before:
        raise ValueError("checkout contains tracked changes")
    baseline_diff = _fingerprint(root)
    evidence = Path(out).expanduser().resolve()
    if evidence == root or root in evidence.parents:
        raise ValueError("output must be outside source checkout")
    evidence.mkdir(mode=0o700, parents=False, exist_ok=False)
    observations = []
    manifests = []
    for round_no in (1, 2):
        report = scenario_runner.execute(plan, root, allow_exec=True, allow_dotenv=False)
        if (report.get("source_revision") != revision or
                report.get("result") != "experiments-conformed"):
            raise ValueError("runner did not establish passing native tests")
        row = {}
        for record in report["cases"]:
            role = record["role"]
            if role in row:
                raise ValueError("duplicate executed role")
            row[role] = _marker(record, finding, role)
        if set(row) != {"candidate", "negative-control"}:
            raise ValueError("incomplete executed pair")
        observations.append(row)
        _private(evidence / ("native-round-%d.json" % round_no), report)
        manifests.append({"round": round_no, "report_sha256": _hash(report),
                          "markers": {role: _hash(row[role]) for role in sorted(row)}})
        if _git(root, "rev-parse", "HEAD") != revision or _fingerprint(root) != baseline_diff:
            raise ValueError("source revision or tracked files changed during execution")
    def values(row):
        return {k: {f: v for f, v in row[k].items() if f != "trace_sha256"} for k in sorted(row)}
    if values(observations[0]) != values(observations[1]):
        raise ValueError("non-reproducible observations over two native rounds")
    case = {"id": finding, "invariant": invariant, "equivalence_basis": basis,
            "candidate": observations[0]["candidate"],
            "negative_control": observations[0]["negative-control"]}
    if "scenario" in config:
        case["scenario"] = config["scenario"]
    if "bound_fields" in config:
        case["bound_fields"] = config["bound_fields"]
    doc = {"schema_version": 1, "source_revision": revision,
           "environment": config["environment"], "cases": [case]}
    if operation == "business-invariants":
        assessment = web3_advanced.compare_business(doc)
    elif operation == "signed-intent-mirror":
        assessment = web3_advanced.compare_intent(doc)
    else:
        assessment = web3_research.observe(doc, operation)
    _private(evidence / "native-observations.json", doc)
    _private(evidence / "differential.json", assessment)
    outcome = {"schema_version": 1, "status": "CAPTURED_NATIVE_TEST_OUTPUT",
               "pinned_revision": revision, "pair_id": finding, "mode": operation,
               "rounds": manifests, "observation_file_sha256": _hash(doc),
               "differential_leads": assessment["leads"],
               "confirmed_vulnerabilities": 0,
               "source_unchanged": (_git(root, "rev-parse", "HEAD") == revision and
                                     _fingerprint(root) == baseline_diff),
               "limitations": "Native commands were run in an operator-confirmed external sandbox; "
                              "this process cannot enforce network isolation, attest command "
                              "assertions, guarantee negative-control validity or establish harm."}
    _private(evidence / "capture-manifest.json", outcome)
    return outcome


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--out", help="new private evidence directory for execution")
    parser.add_argument("--allow-exec", action="store_true")
    parser.add_argument("--isolated-workspace-confirmed", action="store_true")
    parser.add_argument("--network-isolated-confirmed", action="store_true")
    args = parser.parse_args(argv)
    try:
        cfg = web3_advanced.json_file(args.config)
        result = collect(cfg, args.repo, args.out, execute=args.allow_exec,
                         isolated=args.isolated_workspace_confirmed,
                         network_isolated=args.network_isolated_confirmed)
        print(json.dumps(result, indent=2))
        return 0
    except (ValueError, OSError, subprocess.SubprocessError) as err:
        parser.error(str(err))


if __name__ == "__main__":
    sys.exit(main())
