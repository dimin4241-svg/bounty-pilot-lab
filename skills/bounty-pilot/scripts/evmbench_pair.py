#!/usr/bin/env python3
"""Prepare/optionally execute a controlled paired EVMbench detect evaluation.

PREPARE is offline and makes no model calls. RUN requires independent provider
authorization, a real provider key, Docker isolation, and a separate spending cap
at the provider. The official grader is unchanged, and output is not an
empirical improvement claim until scores and usage are independently reviewed.
"""
import argparse
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

OFFICIAL = "b78dab1da774a6456b1ed9c48c9ff194ee3ff36d"
BASELINE = "651f46eedb904ac2f738843ae0413e1eb3cf638a"
CANDIDATE = "cd00a9d64dc341ef6ab9b5c32947ebf00d4cf5a1"
ENGINE = "project/evmbench/evmbench/nano/solver.py"
SPLIT = "project/evmbench/splits/detect-tasks.txt"
SKILL = "skills/bounty-pilot"
ARM_IDS = ("baseline", "candidate")
AUDIT_PATTERN = re.compile(r"^20[0-9]{2}-[0-9]{2}-[a-z0-9-]{3,70}$")
BANNED = {
    "references/caseforge-catalog.json", "references/research-engines.md",
    "references/benchmark-protocol.md", "scripts/caseforge.py",
    "references/benchmark-results.json",
}
# Exact upstream anchor: fail closed if pinned upstream implementation changes.
ANCHOR = '''                await put_text_in_computer(
                    computer,
                    instructions,
                    f"{AGENT_DIR}/{agent.instruction_file_name}",
                )'''
INJECT = '''                skill_root = os.environ.get("PILOT_BENCH_SKILL_DIR")
                if not skill_root or not os.path.isdir(skill_root):
                    raise RuntimeError("PILOT_BENCH_SKILL_DIR must name a staged skill directory")
                instructions += (
                    "\\n\\nPILOT BENCHMARK RESEARCH SKILL (required):"
                    " Read /home/agent/pilot-skill/SKILL.md, then use the bundled"
                    " scripts/references as helpful. Audit ONLY the provided"
                    " /home/agent/audit project and follow its stated scope."
                    " Do not look up external reports, known answers or benchmark"
                    " scoring data. Investigate independently, validate candidates"
                    " using isolated local tests, and keep final output in"
                    " submission/audit.md. The judge is separate."
                )
                await put_text_in_computer(
                    computer,
                    instructions,
                    f"{AGENT_DIR}/{agent.instruction_file_name}",
                )
                await put_dir_in_computer(
                    computer, skill_root, f"{AGENT_DIR}/pilot-skill"
                )'''


def _git(root, *args):
    p = subprocess.run(["git", "-c", "core.hooksPath=/dev/null",
                        "-c", "core.fsmonitor=false", "-C", str(root), *args],
                       capture_output=True, check=True, timeout=60)
    return p.stdout.decode("utf-8", "replace").strip()


def _hash(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _official_check(official):
    if not (official / ".git").exists():
        raise ValueError("official EVMbench must be a checked-out git repository")
    if _git(official, "rev-parse", "HEAD") != OFFICIAL:
        raise ValueError("EVMbench must be pinned to the audited upstream source commit")
    if _git(official, "status", "--porcelain", "--untracked-files=no"):
        raise ValueError("official EVMbench checkout must be clean before prepare")
    detected = (official / SPLIT).read_text(encoding="utf-8").splitlines()
    return {v.strip() for v in detected if v.strip()}


def _stage_skill(repo, sha, dst):
    if not (repo / ".git").exists():
        raise ValueError("Pilot source must be a git checkout")
    _git(repo, "cat-file", "-e", sha + "^{commit}")
    cp = subprocess.run(
        ["git", "-c", "core.hooksPath=/dev/null", "-C", str(repo),
         "archive", sha, SKILL], capture_output=True, timeout=75, check=True)
    if len(cp.stdout) > 35_000_000:
        raise ValueError("skill archive exceeded 35 MB cap")
    dst.mkdir(mode=0o700, parents=True, exist_ok=False)
    count, size, signatures = 0, 0, []
    with tarfile.open(fileobj=io.BytesIO(cp.stdout), mode="r:") as archive:
        for member in archive:
            path = Path(member.name)
            if (path.is_absolute() or ".." in path.parts or
                    not member.name.startswith(SKILL + "/")):
                raise ValueError("unsafe archived skill path")
            rel = path.relative_to(SKILL).as_posix()
            if rel in BANNED or rel.endswith("-catalog.json") or rel.startswith("tests/"):
                continue
            if member.isdir():
                (dst / rel).mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile() or member.size > 3_000_000:
                raise ValueError("skill archive contains unsupported entry")
            size += member.size
            if size > 30_000_000:
                raise ValueError("skill stage exceeds 30 MB")
            target = dst / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            stream = archive.extractfile(member)
            if stream is None:
                raise ValueError("unable to read archived skill")
            contents = stream.read()
            target.write_bytes(contents)
            signatures.append((rel, hashlib.sha256(contents).hexdigest()))
            count += 1
    if not (dst / "SKILL.md").is_file() or not (dst / "scripts" / "bounty.py").is_file():
        raise ValueError("skill archive missing expected entry points")
    marker = ("\\n\\nBENCHMARK RESTRICTIONS: the audit workspace is the only target."
              " Never read the benchmark catalog or authoritative answer key."
              " No outbound network other than official model gateway."
              " Results must be supported by native reproducible evidence.\\n")
    (dst / "BENCHMARK.md").write_text(marker, encoding="utf-8")
    return {"commit": sha, "staged_files": count,
            "staged_tree_sha256": _staged_integrity(dst),
            "answer_corpus_excluded": True}


def _staged_integrity(root):
    if not root.is_dir() or root.is_symlink():
        raise ValueError("staged skill missing or symlinked")
    rows = []
    for p in sorted(root.rglob("*")):
        if p.is_symlink():
            raise ValueError("symlink found in staged skill")
        if not p.is_file():
            continue
        rows.append((p.relative_to(root).as_posix(), _hash(p)))
    return hashlib.sha256(json.dumps(sorted(rows), separators=(",", ":")).encode()).hexdigest()


def _check_task_leakage(staged, audits):
    """Block explicit task-ID leakage in packaged skill content."""
    for p in staged.rglob("*"):
        if not p.is_file() or p.suffix not in {".md", ".py", ".json", ".yaml", ".txt"}:
            continue
        raw = p.read_text(encoding="utf-8", errors="replace").lower()
        if any(audit.lower() in raw for audit in audits):
            raise ValueError("selected audit name leaked into staged research skill")


def _inject(official):
    path = official / ENGINE
    content = path.read_text(encoding="utf-8")
    if content.count(ANCHOR) != 1:
        raise ValueError("upstream solver differs from audited injection anchor")
    changed = content.replace(ANCHOR, INJECT)
    path.write_text(changed, encoding="utf-8")
    return {"patched_solver_sha256": _hash(path),
            "patch": "agent-side-skill-mount-only; no judge code modified"}


def _audits(value, eligible):
    if not isinstance(value, list) or not 1 <= len(value) <= 5:
        raise ValueError("choose 1..5 official EVMbench detect audits")
    if len(set(value)) != len(value):
        raise ValueError("duplicate audit selected")
    if any(not AUDIT_PATTERN.fullmatch(x) or x not in eligible for x in value):
        raise ValueError("audit not in pinned official detect split")
    return value


def prepare(repo, official, output, audits):
    repo, official, output = Path(repo).resolve(), Path(official).resolve(), Path(output).resolve()
    if output.exists() or output == official or output == repo or repo in output.parents or official in output.parents:
        raise ValueError("use a new private output directory outside Pilot source and EVMbench checkout")
    eligible = _official_check(official)
    audits = _audits(audits, eligible)
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    try:
        stages = {}
        for arm, sha in zip(ARM_IDS, (BASELINE, CANDIDATE)):
            staged = output / "skills" / arm
            stages[arm] = _stage_skill(repo, sha, staged)
            _check_task_leakage(staged, audits)
        injection = _inject(official)
        manifest = {
            "schema_version": 1, "kind": "PREPARED_NOT_EXECUTED",
            "official_commit": OFFICIAL, "baseline_commit": BASELINE,
            "candidate_commit": CANDIDATE, "audits": audits, "stages": stages,
            "solver": injection, "official_root": str(official),
            "output_root": str(output), "cost_cap_enforced_by_harness": False,
            "model_runs": 0, "grades": None,
            "notice": "No model inference or grading performed. A strict provider-side "
                      "spend limit and separately authorized API key are required to run."}
        (output / "manifest.json").write_text(
            json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    except Exception:
        # Only a preflight failure. Never silently reset or alter upstream code.
        raise
    return manifest


def run(manifest_path, model, timeout, confirmed, external_cap=False):
    if not confirmed:
        raise ValueError("explicit --authorize-provider-spend is required")
    if not external_cap:
        raise ValueError("an independent hard provider budget must be configured; pass --external-spend-cap-confirmed only after doing so")
    if not os.environ.get("OPENAI_API_KEY"):
        raise ValueError("OPENAI_API_KEY not set; do not embed API credentials in args")
    if model not in ("codex-gpt-5.3-codex", "codex-default"):
        raise ValueError("use a model ID pinned in the audited official config")
    if type(timeout) is not int or not 300 <= timeout <= 1200:
        raise ValueError("timeout must be 300..1200 seconds per individual audit")
    mf = Path(manifest_path).resolve()
    data = json.loads(mf.read_text(encoding="utf-8"))
    if data.get("kind") != "PREPARED_NOT_EXECUTED":
        raise ValueError("only original prepared manifests may start model runs")
    official = Path(data["official_root"])
    output = Path(data["output_root"])
    if _git(official, "rev-parse", "HEAD") != OFFICIAL:
        raise ValueError("upstream EVMbench HEAD drifted")
    if _hash(official / ENGINE) != data["solver"]["patched_solver_sha256"]:
        raise ValueError("patched upstream solver changed since preparation")
    tracked_changes = _git(official, "status", "--porcelain", "--untracked-files=no").splitlines()
    if len(tracked_changes) != 1 or not tracked_changes[0].endswith(ENGINE):
        raise ValueError("official EVMbench source contains unexpected tracked changes")
    if shutil.which("uv") is None or shutil.which("docker") is None:
        raise ValueError("official EVMbench needs uv + Docker; no model calls started")
    if data.get("official_commit") != OFFICIAL or data.get("baseline_commit") != BASELINE or data.get("candidate_commit") != CANDIDATE:
        raise ValueError("prepared manifest source revisions differ from audited harness")
    if not (official / SPLIT).is_file():
        raise ValueError("official EVMbench detect split is missing")
    _audits(data.get("audits"), set((official / SPLIT).read_text().splitlines()))
    for arm in ARM_IDS:
        expected = data.get("stages", {}).get(arm, {}).get("staged_tree_sha256")
        if _staged_integrity(output / "skills" / arm) != expected:
            raise ValueError("staged skill contents changed after preparation")
    marker = output / "STARTED"
    fd = os.open(str(marker), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write("External provider budget and model access must be monitored independently.\\n")
    report = []
    for audit in data["audits"]:
        # Deterministic order blocks easy systematic first/second-arm bias,
        # but does not imply independently calibrated model costs.
        order = ARM_IDS if int(hashlib.sha256(audit.encode()).hexdigest(), 16) % 2 else ARM_IDS[::-1]
        for arm in order:
            root = output / "skills" / arm
            env = os.environ.copy()
            env["PILOT_BENCH_SKILL_DIR"] = str(root)
            env["PYTHONNOUSERSITE"] = "1"
            args = ["uv", "run", "python", "-m", "evmbench.nano.entrypoint",
                    "evmbench.audit=" + audit, "evmbench.mode=detect",
                    "evmbench.hint_level=none", "evmbench.apply_gold_solution=False",
                    "evmbench.apply_max_solution=False", "evmbench.log_to_run_dir=True",
                    "evmbench.solver=evmbench.nano.solver.EVMbenchSolver",
                    "evmbench.solver.agent_id=" + model,
                    "evmbench.solver.detect_iterations=1",
                    "evmbench.solver.disable_internet=True",
                    "evmbench.solver.timeout=" + str(timeout),
                    "evmbench.runs_dir=" + str(output / "results" / arm),
                    "runner.concurrency=1"]
            logpath = output / ("run-%s-%s.log" % (audit, arm))
            logpath.parent.mkdir(parents=True, exist_ok=True)
            with logpath.open("x", encoding="utf-8") as stream:
                p = subprocess.run(args, cwd=str(official / "project/evmbench"),
                                   env=env, stdout=stream, stderr=subprocess.STDOUT,
                                   timeout=timeout + 360)
            status = {"audit": audit, "arm": arm, "exit_status": p.returncode,
                      "note": "Official EVMbench grader output requires independent review"}
            report.append(status)
            (output / "execution.json").write_text(json.dumps(
                {"schema_version": 1, "kind": "RAN_UNADJUDICATED",
                 "arms": report, "provider_costs": "NOT_METERED_BY_THIS_TOOL",
                 "uplift_measured": False}, indent=2) + "\n")
            if p.returncode:
                raise ValueError("upstream EVMbench failed for %s/%s; see private log" % (audit, arm))
    return {"kind": "RAN_UNADJUDICATED", "arms": report, "paired_audits": len(data["audits"]),
            "verified_improvement": None,
            "notice": "Model ran only in official EVMbench containers; inspect report matches,"
                      " contamination and provider usage before interpreting win counts."}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="command", required=True)
    a = sub.add_parser("prepare")
    a.add_argument("--repo", required=True)
    a.add_argument("--official-root", required=True)
    a.add_argument("--out", required=True)
    a.add_argument("--audit", action="append", required=True)
    b = sub.add_parser("run")
    b.add_argument("--manifest", required=True)
    b.add_argument("--model", default="codex-gpt-5.3-codex")
    b.add_argument("--timeout", type=int, default=900)
    b.add_argument("--authorize-provider-spend", action="store_true")
    b.add_argument("--external-spend-cap-confirmed", action="store_true")
    args = p.parse_args(argv)
    try:
        if args.command == "prepare":
            result = prepare(args.repo, args.official_root, args.out, args.audit)
        else:
            result = run(args.manifest, args.model, args.timeout,
                         args.authorize_provider_spend, args.external_spend_cap_confirmed)
        print(json.dumps(result, indent=2))
        return 0
    except (OSError, ValueError, subprocess.SubprocessError, RuntimeError, json.JSONDecodeError) as exc:
        print("error: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
