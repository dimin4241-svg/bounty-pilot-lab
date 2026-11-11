#!/usr/bin/env python3
"""Convert a verified *planning* Web campaign into existing Bounty Pilot agent jobs.

Requires a previously initialized, private Bounty Pilot run whose pinned Git
commit equals the offline Web campaign revision. Emits one immutable
source-minimal Markdown bundle per shortlisted lead and asks the existing
agent_dispatch to create independent-blind (two or three fresh-session)
jobs. NO model executable is started and no network request is made.

The Bounty Pilot agent dispatch supports Claude's per-job --max-budget-usd,
but cost limits are not universally enforced for Codex/OpenCode/DeepSeek.
This bridge therefore budgets every replica conservatively and explicitly
refuses planning if total estimated cap exceeds the campaign's ceiling.
"""
import argparse
import hashlib
import importlib.util
import json
import math
import os
import re
import subprocess
import sys
from pathlib import Path

SHA40 = re.compile(r"^[a-f0-9]{40}$")
LEAD = re.compile(r"^lead-[a-f0-9]{20}$")
MAX_JOBS = 12
CHECKS = (
    "Verify actual authentication identity and object ownership.",
    "Trace full source reachability and all middleware/role guards.",
    "Reproduce with two independent owned or explicitly authorized accounts.",
    "Require matched negative controls and a protected state outcome.",
    "Compare against published fixes, advisories and earlier project reports.",
    "Request independent reviewer objections before writing a submission."
)


def _unique(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise ValueError("duplicate JSON key")
        d[k] = v
    return d


def _load(path):
    p = Path(path).expanduser()
    if p.is_symlink() or not p.is_file() or p.stat().st_size > 3_000_000:
        raise ValueError("bounded local JSON input required")
    return json.loads(p.read_text(encoding="utf-8"), object_pairs_hook=_unique)


def _loader(name):
    script = Path(__file__).with_name(name + ".py")
    spec = importlib.util.spec_from_file_location("bp_bridge_" + name, script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _git_head(root):
    try:
        r = subprocess.run(["git", "-C", str(root), "--no-optional-locks",
                            "rev-parse", "--verify", "HEAD^{commit}"],
                           text=True, capture_output=True, timeout=6,
                           env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
                           check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError("cannot verify local target Git commit") from exc
    if r.returncode != 0:
        raise ValueError("target Git checkout unavailable")
    return r.stdout.strip()


def _validate_campaign(doc, replicas):
    if (not isinstance(doc, dict) or doc.get("schema_version") != 1 or
            doc.get("mode") != "web-hunt-loop" or
            doc.get("state") not in (
                "OFFLINE_REVIEW_QUEUE_NOT_EXECUTED",
                "CONTROLLED_LOCAL_EFFECT_REPLAY_UNVERIFIED") or
            doc.get("confirmed_vulnerabilities") != 0 or
            doc.get("real_model_calls") != 0 or
            doc.get("ready_to_submit") is not False):
        raise ValueError("only unverified, no-model owned-Web campaign")
    if type(replicas) is not int or replicas not in (2, 3):
        raise ValueError("independent blind review needs 2 or 3 replicas")
    revision = doc.get("source_revision")
    if not isinstance(revision, str) or not SHA40.fullmatch(revision):
        raise ValueError("pinned campaign source revision required")
    preflight = doc.get("program_policy")
    if (not isinstance(preflight, dict) or
            preflight.get("status") != "OFFLINE_PREFLIGHT_NOT_PERMISSION" or
            not isinstance(preflight.get("checks"), list) or
            not preflight["checks"] or
            any(x.get("allowed_by_saved_preflight") is not True
                for x in preflight["checks"])):
        raise ValueError("scope preflight must be explicit and all plan rows pass")
    jobs = doc.get("review_jobs")
    if not isinstance(jobs, list) or not 1 <= len(jobs) <= MAX_JOBS:
        raise ValueError("one to twelve reviewed Web work orders required")
    if len(jobs) * replicas > 24:
        raise ValueError("too many independent jobs for existing dispatcher")
    budget = doc.get("budget")
    if not isinstance(budget, dict):
        raise ValueError("bounded campaign budget required")
    per = budget.get("max_usd_per_job")
    total = budget.get("max_usd_total")
    if (type(per) not in (int, float) or type(total) not in (int, float) or
            not math.isfinite(per) or not math.isfinite(total) or
            not 0 < per <= 10 or not 0 <= total <= 100):
        raise ValueError("finite, explicit USD planning limits required")
    if len(jobs) * replicas * per > total + 0.000001:
        raise ValueError("independent replica plan exceeds campaign USD budget")
    ids = set()
    for job in jobs:
        if not isinstance(job, dict) or not LEAD.fullmatch(job.get("candidate_id", "")):
            raise ValueError("unexpected Web candidate ID")
        if job["candidate_id"] in ids:
            raise ValueError("duplicate work order")
        ids.add(job["candidate_id"])
        if job.get("automatically_invoked") is not False:
            raise ValueError("already executed or untrusted job")
        if job.get("planned_max_usd") != per:
            raise ValueError("campaign job cost changed since planning")
    return jobs, round(per, 6), round(total, 6)


def _source_excerpt(root, source_file, code_anchor):
    """Only bounded local source context explicitly approved for an agent bundle."""
    if source_file == "captured-http":
        return "No source file is available for this owned HAR status observation."
    rel = Path(source_file)
    if rel.is_absolute() or ".." in rel.parts or rel.suffix not in (
            ".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".rs"):
        raise ValueError("relative supported source file required")
    p = root / rel
    if p.is_symlink() or not p.is_file() or p.stat().st_size > 100_000:
        raise ValueError("bounded regular source file required")
    if not p.resolve(strict=True).is_relative_to(root):
        raise ValueError("source file escapes pinned checkout")
    data = p.read_bytes()
    try:
        content = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("source excerpt must be UTF-8") from exc
    match = re.search(r":([0-9]{1,6})$", code_anchor)
    if not match:
        return "No precise source line available; do not claim code was reviewed."
    line = int(match.group(1))
    rows = content.splitlines()
    if line < 1 or line > len(rows):
        raise ValueError("source line outside pinned file")
    left, right = max(1, line - 6), min(len(rows), line + 6)
    masked = []
    for n in range(left, right + 1):
        text = rows[n - 1]
        if re.search(
                r"(secret|password|api.?key|authorization|private.?key|"
                r"access.?token|refresh.?token|bearer|mnemonic|seed.?phrase)",
                text, re.I):
            text = "[REDACTED_SECRET_LIKE_LINE]"
        if len(text) > 240:
            text = text[:240] + " [TRUNCATED]"
        masked.append(str(n) + ": " + text)
    return ("Pinned source SHA-256: " + hashlib.sha256(data).hexdigest() +
            "\nSOURCE SNIPPET:\n" + "\n".join(masked) + "\n")


def prepare(campaign, run_dir, replicas=2, include_source_excerpts=False):
    jobs, per, ceiling = _validate_campaign(campaign, replicas)
    # Import existing dispatch utilities without creating a subprocess or
    # loading executable source from the target checkout.
    import sys
    src = str(Path(__file__).resolve().parent)
    sys.path.insert(0, src)
    try:
        bounty = _loader("bounty")
        dispatch = _loader("agent_dispatch")
    finally:
        sys.path.pop(0)
    run, meta = dispatch._private_run(run_dir)
    repo = Path(meta.get("target_root", "")).expanduser().resolve()
    if not repo.is_dir() or repo == run or repo in run.parents:
        raise ValueError("invalid Bounty Pilot target checkout")
    commit = _git_head(repo)
    if (meta.get("commit") != campaign["source_revision"] or
            commit != campaign["source_revision"]):
        raise ValueError("campaign and Bounty run must share exact current Git revision")
    manifest = run / "bundles" / "manifest.json"
    if manifest.exists() or manifest.is_symlink():
        raise ValueError("use a fresh Bounty run; existing bundles cannot be overwritten")
    if (run / "agents" / "dispatch.json").exists():
        raise ValueError("existing independent-dispatch state must not be overwritten")
    rows, paths = [], []
    base = run / "bundles"
    base.mkdir(parents=True, exist_ok=True)
    for index, job in enumerate(jobs):
        cid = job["candidate_id"]
        for field in ("source_file", "code_anchor", "invariant_id",
                      "trust_boundary_id", "claimed_effect_id"):
            if not isinstance(job.get(field), str) or not re.fullmatch(
                    r"[A-Za-z0-9_./:-]{1,160}", job[field]):
                raise ValueError("bounded source/invariant label required")
        if job["source_file"].startswith("/") or ".." in job["source_file"].split("/"):
            raise ValueError("source path must be relative to checkout")
        lens = "webhunt-" + cid.removeprefix("lead-")
        name = "webhunt-%02d.md" % (index + 1)
        path = base / name
        excerpt = (_source_excerpt(repo, job["source_file"], job["code_anchor"])
                   if include_source_excerpts else
                   "No source excerpt provided; review only the candidate metadata.")
        context = (
            "# Independent Web/API research candidate\n\n"
            "This is NOT a confirmed vulnerability and NEVER authorizes "
            "testing any external site.\n\n"
            "Project: " + campaign["project"] + "\n"
            "Pinned Git revision: " + campaign["source_revision"] + "\n"
            "Candidate ID: " + cid + "\n"
            "Owned local checkout: " + str(repo) + "\n"
            "Candidate source: " + job["source_file"] + "\n"
            "Source or captured route anchor: " + job["code_anchor"] + "\n"
            "Hypothesis invariant: " + job["invariant_id"] + "\n"
            "Trust boundary: " + job["trust_boundary_id"] + "\n"
            "Claimed effect (unverified): " + job["claimed_effect_id"] + "\n"
            "Approved local source context:\n" + excerpt + "\n"
            "Strategy: inspect ONLY this supplied bundle; do not call services "
            "or execute unreviewed target instructions.\n"
            "Research controls:\n" +
            "".join("- " + x + "\n" for x in CHECKS) +
            "\nDeliver only a review with source:line evidence, "
            "unverified assumptions, independent PoC requirements "
            "and whether this is likely a duplicate. Do not make up "
            "runtime observations, severity or bounty payout.\n")
        fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(context)
        relative = "bundles/" + name
        paths.append(relative)
        rows.append({"lens": lens, "bundle": relative,
                     "bytes": len(context.encode("utf-8"))})
    # Use the existing native manifest rather than inventing a
    # parallel job state incompatible with agent_dispatch.
    bounty._record_dispatch(run, commit, None, rows)
    labels = [row["lens"] for row in rows]
    scheduled = dispatch.plan(str(run), mode="independent-blind",
                              lenses=labels, replicas=replicas)
    return {
        "schema_version": 1,
        "mode": "web-hunt-dispatch-bridge",
        "status": "INDEPENDENT_JOBS_PLANNED_NOT_EXECUTED",
        "source_revision": commit, "candidate_count": len(jobs),
        "replicas_per_candidate": replicas,
        "dispatch_job_count": len(scheduled["jobs"]),
        "dispatch_plan_id": scheduled["plan"]["plan_id"],
        "dispatch_state_file": scheduled["state_file"],
        "max_planned_usd": round(len(jobs) * replicas * per, 6),
        "campaign_usd_ceiling": ceiling, "actual_spend_usd": 0,
        "provider_sessions_started": 0, "network_requests": 0,
        "evidence_reviewed": False,
        "note": ("Run each CLI job separately with provider-supported cost and "
                 "sandbox controls. Claude CLI supports --max-budget-usd; "
                 "other providers require separate billing safeguards. "
                 "These are source-review jobs only, not vulnerability proof.")
    }


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--campaign", required=True)
    p.add_argument("--run", required=True,
                   help="new private Bounty run previously created by bounty.py init")
    p.add_argument("--replicas", choices=(2, 3), type=int, default=2)
    p.add_argument("--include-source-excerpts", action="store_true",
                   help="explicit opt-in for bounded redacted owned source snippets")
    a = p.parse_args(argv)
    try:
        result = prepare(_load(a.campaign), a.run, a.replicas,
                         include_source_excerpts=a.include_source_excerpts)
    except (ValueError, OSError, TypeError, KeyError, json.JSONDecodeError) as exc:
        p.error(str(exc))
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
