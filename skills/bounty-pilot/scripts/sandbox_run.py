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



# --- Phase 6: opt-in, pinned Foundry mutation campaign inside Docker ---
# Only the Docker child executes Forge. GitHub-hosted CI tests command
# construction and mocks Forge; real native runs belong on self-hosted Mac.
import hashlib
import importlib.util
import json
import shutil
import tempfile

MATCH_CONTRACT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,79}$")
MAX_CAMPAIGN_MUTANTS = 12


def _mutant_lib():
    spec = importlib.util.spec_from_file_location(
        "bp_mutation_core", Path(__file__).with_name("harness_gen.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def build_mutation_command(repo, catalog, out, image, test_contract,
                           *, max_mutants=8, docker="docker", uid=None, gid=None):
    """Never execute here; construct a fixed non-networked, read-only target mount."""
    if not IMAGE_RE.fullmatch(image):
        raise ValueError("immutable Docker image digest required")
    if not isinstance(docker, str) or not docker or "/" in docker or "\\" in docker:
        raise ValueError("Docker CLI program name only")
    if not MATCH_CONTRACT.fullmatch(test_contract):
        raise ValueError("fixed safe Foundry test-contract identifier required")
    if type(max_mutants) is not int or not 1 <= max_mutants <= MAX_CAMPAIGN_MUTANTS:
        raise ValueError("maximum 1..12 mutants per native campaign")
    uid = os.getuid() if uid is None else uid
    gid = os.getgid() if gid is None else gid
    if not isinstance(uid, int) or not isinstance(gid, int) or uid <= 0 or gid < 0:
        raise ValueError("non-root Docker identity required")
    root = _path(repo, "--repo", True)
    source = _path(catalog, "--catalog", False)
    output = Path(out).expanduser()
    if output.exists() or output.is_symlink() or output.suffix != ".json":
        raise ValueError("fresh JSON mutation evidence path required")
    parent = _path(output.parent, "--out parent", True)
    helpers = Path(__file__).resolve().parent
    if root == parent or root in parent.parents or parent in root.parents:
        raise ValueError("mutation evidence must be outside the checkout")
    return [
        docker, "run", "--rm", "--pull=never",
        "--network=none", "--cap-drop=ALL", "--security-opt=no-new-privileges",
        "--read-only", "--pids-limit=256", "--memory=4g", "--cpus=2",
        "--user=" + str(uid) + ":" + str(gid),
        "--tmpfs=/tmp:rw,nosuid,nodev,size=2g",
        "--workdir=/tmp",
        "--mount=type=bind,src=" + str(root) + ",dst=/target,readonly",
        "--mount=type=bind,src=" + str(source) + ",dst=/input/catalog.json,readonly",
        "--mount=type=bind,src=" + str(parent) + ",dst=/evidence",
        "--mount=type=bind,src=" + str(helpers) + ",dst=/pilot,readonly",
        "--env=HOME=/tmp", "--env=FOUNDRY_HOME=/tmp",
        "--env=BPL_MUTATION_SANDBOX=1",
        "--entrypoint=python3", image,
        "/pilot/sandbox_run.py", "__inside_mutation",
        "--repo", "/target", "--catalog", "/input/catalog.json",
        "--out", "/evidence/" + output.name, "--test-contract", test_contract,
        "--max-mutants", str(max_mutants)
    ]


def _bounded_copy(source, destination):
    # Never follow links, copy git metadata, vendor caches, or secret files.
    total = 0
    count = 0
    banned_dirs = {".git", "node_modules", "out", "cache", "artifacts",
                   ".venv", "venv", "target", ".next"}
    destination.mkdir(parents=True, exist_ok=False)
    for base, dirs, files in os.walk(str(source), followlinks=False):
        where = Path(base)
        good = []
        for name in sorted(dirs):
            src = where / name
            if src.is_symlink():
                raise ValueError("symlink directories cannot enter native mutant sandbox")
            if name not in banned_dirs:
                good.append(name)
        dirs[:] = good
        rel = where.relative_to(source)
        target = destination / rel
        target.mkdir(parents=True, exist_ok=True)
        for name in sorted(files):
            p = where / name
            if p.is_symlink():
                raise ValueError("symlink files cannot enter native mutant sandbox")
            if name.startswith(".env") or name.endswith((".pem", ".key")):
                continue
            count += 1
            if count > 5000 or p.stat().st_size > 3000000:
                raise ValueError("bounded native mutation source tree required")
            total += p.stat().st_size
            if total > 120000000:
                raise ValueError("native mutation source exceeds 120MB")
            shutil.copyfile(str(p), str(target / name))


def _forge(command, workdir, timeout=90):
    if not shutil.which("forge"):
        raise ValueError("pinned Docker image must already contain forge")
    environment = {"PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
                   "HOME": "/tmp", "FOUNDRY_HOME": "/tmp"}
    try:
        result = subprocess.run(
            ["forge"] + command, cwd=str(workdir), env=environment,
            text=True, capture_output=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"exit_code": None, "sha256": None, "output_bytes": 0,
                "timeout_or_missing": True}
    output = (result.stdout or "") + (result.stderr or "")
    passed_matches = [int(v) for v in re.findall(
        r"(?i)\b(\d+)\s+tests?\s+passed\b", output)]
    passed_matches += [int(v) for v in re.findall(
        r"(?i)\b(\d+)\s+passed\s*;", output)]
    test_count = max(passed_matches) if passed_matches else len(
        re.findall(r"(?m)^\s*\[PASS\]", output))
    handler_metrics = []
    for signature, count, reverted in re.findall(
            r"(?m)^\s*([A-Za-z_][A-Za-z0-9_]*\([^)]*\))\s+(\d+)\s+(\d+)\s*$",
            output):
        c, r = int(count), int(reverted)
        if c > 0 and 0 <= r <= c:
            handler_metrics.append({"handler": signature[:100], "calls": c,
                                    "reverts": r,
                                    "revert_fraction": round(r / c, 4)})
    return {"exit_code": result.returncode,
            "sha256": hashlib.sha256(output.encode("utf-8")).hexdigest(),
            "output_bytes": len(output.encode("utf-8")),
            "test_count": test_count,
            "handler_metrics": handler_metrics[:60],
            "timeout_or_missing": False}


def _line_coverage(lcov, relative, line):
    if not lcov.is_file() or lcov.stat().st_size > 15000000:
        return None
    matched = False
    observed = []
    for row in lcov.read_text(encoding="utf-8").splitlines():
        if row.startswith("SF:"):
            name = row[3:].replace("\\", "/").lstrip("./")
            matched = name == relative or name.endswith("/" + relative)
        elif row.startswith("DA:") and matched:
            parts = row[3:].split(",")
            if len(parts) >= 2 and parts[0].isdigit() and parts[1].isdigit():
                if int(parts[0]) == line:
                    observed.append(int(parts[1]))
    return max(observed) > 0 if observed else None


def _validate_source_mutant(catalog, mutant, root):
    lib = _mutant_lib()
    relative = mutant["path"]
    file = lib._phase6_source(root, relative, {".sol"})
    data = file.read_bytes()
    if hashlib.sha256(data).hexdigest() != mutant["source_sha256"]:
        raise ValueError("source does not match sealed pre-mutation digest")
    lines = data.decode("utf-8").splitlines(keepends=True)
    number = mutant["line"]
    if type(number) is not int or not 1 <= number <= len(lines):
        raise ValueError("source mutation line outside file")
    original = lines[number - 1]
    if original != mutant["before_line"] or hashlib.sha256(
            original.encode("utf-8")).hexdigest() != mutant["before_sha256"]:
        raise ValueError("mutant line changed after precommit")
    valid = lib._phase6_line_mutants(original.rstrip("\r\n"))
    ending = original[len(original.rstrip("\r\n")):]
    if (mutant["operator"], mutant["after_line"]) not in [
            (kind, replacement + ending) for kind, replacement in valid]:
        raise ValueError("mutant is not generated by fixed operator table")
    expected_id = "mut-" + lib._phase6_digest(
        [catalog["source_revision"], relative, number, mutant["operator"],
         original, mutant["after_line"]])[:20]
    if mutant["id"] != expected_id:
        raise ValueError("mutant ID does not match source patch")
    return relative, number, lines


def run_inside_mutations(repo, catalog_path, out, test_contract, max_mutants):
    if (os.environ.get("BPL_MUTATION_SANDBOX") != "1" or
            not Path("/.dockerenv").exists()):
        raise ValueError("native mutant runner is Docker-only; use mutation-campaign")
    if (str(repo) != "/target" or str(catalog_path) != "/input/catalog.json" or
            not str(out).startswith("/evidence/") or
            not MATCH_CONTRACT.fullmatch(test_contract)):
        raise ValueError("fixed mounted internal paths and safe contract required")
    lib = _mutant_lib()
    catalog = lib._phase6_read(catalog_path, 5000000)
    if catalog.get("mode") != "sealed-mutant-precommit" or (
            lib._phase6_digest({k: v for k, v in catalog.items()
                                if k != "catalog_sha256"}) !=
            catalog.get("catalog_sha256")):
        raise ValueError("sealed deterministic catalog mismatch")
    root, commit = lib._phase6_git(repo)
    if commit != catalog["source_revision"]:
        raise ValueError("native checkout revision differs from precommitted mutants")
    mutants = catalog.get("mutants")
    if not isinstance(mutants, list) or not 1 <= len(mutants) <= 96:
        raise ValueError("invalid sealed mutant manifest")
    if type(max_mutants) is not int or not 1 <= max_mutants <= MAX_CAMPAIGN_MUTANTS:
        raise ValueError("Docker mutation execution limit 1..12")
    selected = mutants[:max_mutants]
    for mutant in selected:
        _validate_source_mutant(catalog, mutant, root)
    with tempfile.TemporaryDirectory(prefix="bp-native-mutation-", dir="/tmp") as tmp:
        work = Path(tmp)
        baseline_src = work / "baseline"
        _bounded_copy(root, baseline_src)
        baseline_build = _forge(["build", "--offline"], baseline_src)
        baseline_test = (_forge(["test", "--offline", "--match-contract", test_contract],
                                baseline_src) if baseline_build["exit_code"] == 0
                         else {"exit_code": None})
        passed = (baseline_test.get("exit_code") == 0 and
                  baseline_test.get("test_count", 0) > 0)
        records = []
        if passed:
            for mutant in selected:
                mutated_repo = work / mutant["id"]
                _bounded_copy(root, mutated_repo)
                file = mutated_repo / mutant["path"]
                contents = file.read_text(encoding="utf-8").splitlines(keepends=True)
                contents[mutant["line"] - 1] = mutant["after_line"]
                file.write_text("".join(contents), encoding="utf-8")
                comp = _forge(["build", "--offline"], mutated_repo)
                if comp["exit_code"] == 0:
                    outcome = _forge(
                        ["test", "--offline", "--match-contract", test_contract],
                        mutated_repo)
                    coverage = _forge(["coverage", "--offline", "--report", "lcov",
                                       "--match-contract", test_contract], mutated_repo)
                    reached = (_line_coverage(mutated_repo / "lcov.info",
                                              mutant["path"], mutant["line"])
                               if coverage["exit_code"] == 0 else None)
                else:
                    outcome = {"exit_code": None, "sha256": None}
                    reached = None
                evidence = hashlib.sha256(json.dumps(
                    [comp, outcome, reached], sort_keys=True
                ).encode("utf-8")).hexdigest()
                records.append({
                    "mutant_id": mutant["id"], "compiled": comp["exit_code"] == 0,
                    "line_reached": reached, "state_diverged": None,
                    "property_failed": None, "negative_control_passed": None,
                    "evidence_sha256": evidence,
                    "unclassified_test_exit_code": outcome.get("exit_code"),
                    "native_test_output_sha256": outcome.get("sha256")})
        report = {
            "schema_version": 1, "mode": "offline-sandbox-mutation-receipts",
            "source_revision": commit, "catalog_sha256": catalog["catalog_sha256"],
            "baseline": {"compiled": baseline_build["exit_code"] == 0,
                         "property_tests_passed": passed,
                         "build_output_sha256": baseline_build.get("sha256"),
                         "test_output_sha256": baseline_test.get("sha256"),
                         "test_count": baseline_test.get("test_count", 0),
                         "handler_metrics": baseline_test.get("handler_metrics", []),
                         "high_revert_warning": [
                             x["handler"] for x in baseline_test.get("handler_metrics", [])
                             if x["calls"] >= 10 and x["revert_fraction"] >= 0.8]},
            "results": records, "model_calls": 0,
            "confirmed_vulnerabilities": 0,
            "notice": ("Real pinned Docker/Forge tests were executed, but test failures "
                       "are unclassified. Native coverage is best-effort, and observed "
                       "state divergence/negative controls require separate independent "
                       "review. Do not count a mutant as killed from exit status alone.")
        }
        if Path(out).exists() or Path(out).is_symlink():
            raise ValueError("new evidence output file required")
        fd = os.open(str(out), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(report, stream, ensure_ascii=False, sort_keys=True, indent=2)
            stream.write("\n")
        return report


def _mutation_cli(argv):
    parser = argparse.ArgumentParser(description="Pinned offline Docker Foundry mutations")
    if argv and argv[0] == "__inside_mutation":
        p = argparse.ArgumentParser()
        p.add_argument("--repo", required=True)
        p.add_argument("--catalog", required=True)
        p.add_argument("--out", required=True)
        p.add_argument("--test-contract", required=True)
        p.add_argument("--max-mutants", type=int, default=8)
        a = p.parse_args(argv[1:])
        result = run_inside_mutations(
            a.repo, a.catalog, a.out, a.test_contract, a.max_mutants)
        print(json.dumps({"status": result["mode"], "mutants": len(result["results"]),
                          "baseline_passed": result["baseline"]["property_tests_passed"]}))
        return 0 if result["baseline"]["property_tests_passed"] else 2
    if argv and argv[0] == "mutation-campaign":
        parser.add_argument("--repo", required=True)
        parser.add_argument("--catalog", required=True)
        parser.add_argument("--out", required=True)
        parser.add_argument("--image", required=True)
        parser.add_argument("--test-contract", required=True)
        parser.add_argument("--max-mutants", type=int, default=8)
        parser.add_argument("--docker", default="docker")
        a = parser.parse_args(argv[1:])
        try:
            command = build_mutation_command(
                a.repo, a.catalog, a.out, a.image, a.test_contract,
                max_mutants=a.max_mutants, docker=a.docker)
            return subprocess.run(command, stdin=subprocess.DEVNULL,
                                  check=False).returncode
        except (ValueError, OSError) as exc:
            parser.error(str(exc))
    raise ValueError("unknown mutation mode")


def main(argv=None):
    args = list(__import__("sys").argv[1:] if argv is None else argv)
    if args and args[0] in ("mutation-campaign", "__inside_mutation"):
        return _mutation_cli(args)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, help="disposable target checkout; writable INSIDE Docker")
    parser.add_argument("--plan", required=True, help="approved candidate/control JSON plan")
    parser.add_argument("--out", required=True, help="new private output JSON outside --repo")
    parser.add_argument("--image", required=True, help="trusted locally installed Docker image by sha256 digest")
    parser.add_argument("--docker", default="docker", help="Docker CLI executable name")
    args = parser.parse_args(argv)
    try:
        command = build_command(args.repo, args.plan, args.out, args.image, docker=args.docker)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    try:
        return subprocess.run(command, stdin=subprocess.DEVNULL, check=False).returncode
    except OSError as exc:
        parser.error("could not start Docker: " + str(exc))


if __name__ == "__main__":
    raise SystemExit(main())
