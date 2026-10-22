#!/usr/bin/env python3
"""Independent, artifact-backed evidence gate for a single Bounty Pilot finding.

The verifier reads a separate reviewer record and re-checks local source, paired test results,
and cited artifacts. It never writes findings.json or promotes a finding. Its three evidence
levels are intentionally distinct: SOURCE_CONFIRMED, POC_REPRODUCED, IMPACT_VERIFIED.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import bounty  # noqa: E402

HEX = re.compile(r"[0-9a-f]{7,64}", re.I)
FINDING_ID = re.compile(r"BP-[0-9]{3,}")
GIT_HARDENING = ("--no-optional-locks", "-c", "core.fsmonitor=false", "-c",
                 "core.hooksPath=/dev/null", "--no-pager")
MAX_TEXT = 2_000_000


def _load_helper(name):
    path = SCRIPTS / (name + ".py")
    spec = importlib.util.spec_from_file_location("bp_evidence_" + name, path)
    if spec is None or spec.loader is None:
        raise ValueError("cannot load verifier dependency " + name)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _git(root, *args):
    return subprocess.run(["git", *GIT_HARDENING, "-C", str(root), *args],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30,
                          env={**os.environ, "GIT_TERMINAL_PROMPT": "0"}, check=False)


def _revision(root):
    result = _git(root, "rev-parse", "HEAD")
    return result.stdout.decode("utf-8", "replace").strip() if result.returncode == 0 else None


def _digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _run_file(run, relative):
    if not isinstance(relative, str) or not relative or Path(relative).is_absolute():
        return None
    raw = run / relative
    try:
        if raw.is_symlink() or any(parent.is_symlink() for parent in raw.parents if parent != run):
            return None
        resolved = raw.resolve()
        if run not in resolved.parents or not resolved.is_file() or resolved.stat().st_size > MAX_TEXT:
            return None
        return resolved
    except (OSError, RuntimeError):
        return None


def _target_anchor(root, anchor):
    if not isinstance(anchor, dict):
        return False, "anchor must be an object"
    relative, line, quote = anchor.get("path"), anchor.get("line"), anchor.get("quote")
    if not isinstance(relative, str) or Path(relative).is_absolute() or ".." in Path(relative).parts:
        return False, "anchor path must be repository-relative"
    target = root / relative
    try:
        resolved = target.resolve()
        if target.is_symlink() or root not in resolved.parents or not resolved.is_file():
            return False, "anchor source is missing or outside the checkout"
        if target.stat().st_size > MAX_TEXT:
            return False, "anchor source exceeds size limit"
        lines = resolved.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        return False, "anchor source could not be read: " + str(exc)
    if type(line) is not int or not 1 <= line <= len(lines):
        return False, "anchor line is outside source"
    if not isinstance(quote, str) or not quote.strip():
        return False, "anchor needs an exact quote"
    actual = "\n".join(lines[max(0, line - 2):min(len(lines), line + 1)])
    if quote not in actual:
        return False, "quoted source text is not present around the cited line"
    return True, str(resolved.relative_to(root)) + ":" + str(line)


def _scope_anchor(run, root, anchor):
    if isinstance(anchor, dict) and isinstance(anchor.get("artifact_path"), str):
        artifact = _run_file(run, anchor.get("artifact_path"))
        quote, line = anchor.get("quote"), anchor.get("line")
        if artifact is None or not isinstance(quote, str) or not quote.strip():
            return False
        lines = artifact.read_text(encoding="utf-8", errors="replace").splitlines()
        if type(line) is not int or not 1 <= line <= len(lines):
            return False
        return quote in "\n".join(lines[max(0, line - 2):min(len(lines), line + 1)])
    valid, _ = _target_anchor(root, anchor)
    return valid


def _decision(review, key, accepted):
    obj = review.get(key)
    return isinstance(obj, dict) and obj.get("decision") in accepted


def _dispatch_reading(run, job_id, invocation_id):
    """Resolve a reading to the completed provider session recorded by the dispatcher."""
    path = run / "agents" / "dispatch.json"
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None, "dispatch state is missing or unreadable"
    meta = bounty.read_json(run / "run.json")
    if not isinstance(state, dict) or state.get("run_id") != meta.get("run_id"):
        return None, "dispatch state belongs to another run"
    jobs = state.get("jobs")
    job = jobs.get(job_id) if isinstance(jobs, dict) else None
    if not isinstance(job, dict) or job.get("status") != "completed":
        return None, "bound dispatch job is not completed"
    result = job.get("latest_result")
    if not isinstance(result, dict) or result.get("invocation_id") != invocation_id:
        return None, "bound invocation is not the job's saved result"
    attempts = job.get("attempts") if isinstance(job.get("attempts"), list) else []
    attempt = next((row for row in attempts if isinstance(row, dict) and
                    row.get("invocation_id") == invocation_id), None)
    if (not isinstance(attempt, dict) or attempt.get("status") != "completed" or
            not attempt.get("fresh_process") or attempt.get("resume_requested")):
        return None, "bound invocation lacks a completed fresh-process record"
    session_id = attempt.get("provider_session_id")
    if not isinstance(session_id, str) or not session_id.strip():
        return None, "provider did not report a session ID"
    output = _dispatch_output_file(run, result.get("reading_file"))
    if output is None or _digest(output) != result.get("reading_sha256"):
        return None, "bound reading is missing or differs from its dispatch digest"
    text = output.read_text(encoding="utf-8", errors="replace")
    marker = re.match(r"^<!-- BP_AGENT_RESULT v[0-9]+ job=[^ ]+ attempt=[0-9]+ "
                      r"invocation=[^ ]+ bundle_sha256=[0-9a-f]+ -->\n", text)
    if not marker:
        return None, "bound reading is missing its dispatcher provenance header"
    return {"job_id": job_id, "invocation_id": invocation_id,
            "provider": attempt.get("provider"), "provider_session_id": session_id,
            "payload": text[marker.end():]}, None


def _dispatch_output_file(run, value):
    """Dispatch state stores absolute paths; constrain them back to this run before reading."""
    if not isinstance(value, str) or not value:
        return None
    raw = Path(value)
    candidate = raw if raw.is_absolute() else run / raw
    try:
        resolved = candidate.resolve()
        root = run.resolve()
        resolved.relative_to(root)
        cursor = candidate
        while cursor != root:
            if cursor.is_symlink():
                return None
            cursor = cursor.parent
        if candidate.is_symlink():
            return None
        if not resolved.is_file() or resolved.stat().st_size > MAX_TEXT:
            return None
        return resolved
    except (OSError, RuntimeError, ValueError):
        return None


def _check_dispatch_sessions(run, review, review_text):
    bindings = review.get("session_bindings")
    if not isinstance(bindings, dict):
        return False, [], ["session_bindings must identify the actual producer and reviewer dispatch jobs"]
    resolved, errors = {}, []
    for role in ("producer", "reviewer"):
        binding = bindings.get(role)
        job_id = binding.get("job_id") if isinstance(binding, dict) else None
        invocation_id = binding.get("invocation_id") if isinstance(binding, dict) else None
        if not isinstance(job_id, str) or not isinstance(invocation_id, str):
            errors.append(role + " session binding needs job_id and invocation_id")
            continue
        actual, error = _dispatch_reading(run, job_id, invocation_id)
        if error:
            errors.append(role + " session binding: " + error)
            continue
        if review.get(role + "_id") != job_id:
            errors.append(role + "_id must equal the bound dispatch job id")
        resolved[role] = actual
    if set(resolved) == {"producer", "reviewer"}:
        producer, reviewer = resolved["producer"], resolved["reviewer"]
        if producer["job_id"] == reviewer["job_id"] or \
                producer["invocation_id"] == reviewer["invocation_id"]:
            errors.append("producer and reviewer must be different dispatched invocations")
        if (producer["provider"], producer["provider_session_id"]) == \
                (reviewer["provider"], reviewer["provider_session_id"]):
            errors.append("producer and reviewer reused the same provider session")
        if reviewer["payload"] != review_text:
            errors.append("review JSON must be the exact output saved for the bound reviewer session")
    return not errors, list(resolved.values()), errors


def _check_review_anchors(root, review, key):
    obj = review.get(key)
    anchors = obj.get("anchors") if isinstance(obj, dict) else None
    if not isinstance(anchors, list) or not anchors:
        return [], [key + " requires at least one cited source anchor"]
    ok, errors = [], []
    for index, anchor in enumerate(anchors):
        valid, result = _target_anchor(root, anchor)
        if valid:
            ok.append(result)
        else:
            errors.append(key + ".anchors[" + str(index) + "]: " + result)
    return ok, errors


def verify(run_dir, finding_id, review_path):
    run = Path(run_dir).expanduser().resolve()
    marker = run / "run.json"
    if not marker.is_file():
        raise ValueError("--run must be a private Bounty Pilot run")
    meta = bounty.read_json(marker)
    bounty.require_private_output(run, meta.get("target_root"), what="evidence verifier --run")
    root = Path(meta.get("target_root", "")).resolve()
    if not root.is_dir():
        raise ValueError("run target checkout is unavailable")
    if not FINDING_ID.fullmatch(finding_id):
        raise ValueError("invalid finding id")
    findings = bounty.read_json(run / "findings.json")
    matches = [row for row in findings if isinstance(row, dict) and row.get("id") == finding_id]
    if len(matches) != 1:
        raise ValueError("finding id must resolve to exactly one findings.json row")
    finding = matches[0]
    raw_review_file = Path(review_path).expanduser()
    if raw_review_file.is_symlink():
        raise ValueError("--review must not be a symlink")
    review_file = raw_review_file.resolve()
    try:
        review_file.relative_to(run)
    except ValueError as exc:
        raise ValueError("--review must be inside the private run") from exc
    if not review_file.is_file() or review_file.stat().st_size > MAX_TEXT:
        raise ValueError("--review must be a regular JSON file under the size limit")
    review_raw = review_file.read_text(encoding="utf-8")
    marker = re.match(r"^<!-- BP_AGENT_RESULT v[0-9]+ job=[^ ]+ attempt=[0-9]+ "
                      r"invocation=[^ ]+ bundle_sha256=[0-9a-f]+ -->\n", review_raw)
    review_text = review_raw[marker.end():] if marker else review_raw
    review = json.loads(review_text)
    if not isinstance(review, dict) or review.get("schema") != 1:
        raise ValueError("review record requires schema=1")

    errors, checks = [], {}
    current = _revision(root)
    finding_revision = str(finding.get("revision", "")).lower()
    source_confirmed = bool(current and HEX.fullmatch(finding_revision)
                            and (current.startswith(finding_revision) or finding_revision.startswith(current)))
    if not source_confirmed:
        errors.append("finding revision does not match target checkout HEAD")
    affected = finding.get("affected_paths") if isinstance(finding.get("affected_paths"), list) else []
    if source_confirmed and affected:
        diff = _git(root, "diff", "--quiet", "--no-ext-diff", "--no-textconv", current,
                    "--", *[str(path) for path in affected])
        cached = _git(root, "diff", "--cached", "--quiet", "--no-ext-diff", "--no-textconv",
                      current, "--", *[str(path) for path in affected])
        if diff.returncode not in (0, 1) or cached.returncode not in (0, 1):
            errors.append("could not establish source integrity for affected paths")
            source_clean = False
        else:
            source_clean = diff.returncode == 0 and cached.returncode == 0
            if not source_clean:
                errors.append("affected source paths differ from the pinned commit in the working tree or index")
    else:
        source_clean = False
    checks["source_commit"] = {"status": "confirmed" if source_confirmed else "unconfirmed",
                                "revision": current, "affected_source_unchanged": source_clean}

    source_anchors, anchor_errors = _check_review_anchors(root, review, "source_review")
    errors.extend(anchor_errors)
    source_review_ok = (_decision(review, "source_review", {"confirmed"}) and
                        bool(source_anchors) and source_clean)
    checks["source_review"] = {"status": "confirmed" if source_review_ok else "unconfirmed",
                               "anchors": source_anchors}

    producer = review.get("producer_id")
    reviewer = review.get("reviewer_id")
    dispatch_independent, dispatch_sessions, dispatch_errors = _check_dispatch_sessions(
        run, review, review_text)
    independent = (isinstance(producer, str) and producer.strip() and isinstance(reviewer, str)
                   and reviewer.strip() and producer != reviewer and review.get("independent") is True
                   and dispatch_independent)
    if not independent:
        errors.extend(dispatch_errors or ["review must bind distinct producer and reviewer CLI sessions"])
    checks["independence"] = {"status": "confirmed" if independent else "unconfirmed",
                              "producer_id": producer, "reviewer_id": reviewer,
                              "dispatch_sessions": dispatch_sessions,
                              "dispatch_binding_errors": dispatch_errors}

    gate = _load_helper("experiment_gate")
    try:
        entry = gate.load_ledger(run)[0].get(finding_id)
        result = gate.read_result(run, entry.get("result_path")) if entry else None
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        entry, result = None, None
        errors.append("paired experiment artifact unavailable: " + str(exc))
    if not isinstance(result, dict) or result.get("mode") != "executed":
        result = None
        errors.append("no executed paired experiment artifact")

    pairs, command_by_role = {}, {"candidate": set(), "negative-control": set()}
    log_files_ok = False
    source_revision_ok = bool(result and isinstance(result.get("source_revision"), str) and
                              current and (current.startswith(result["source_revision"]) or
                                           result["source_revision"].startswith(current)))
    if result and not source_revision_ok:
        errors.append("paired experiment source revision does not match checkout HEAD")
    if result:
        paired_ok, paired_reason = gate._paired_result(result)
        if not paired_ok:
            errors.append("paired experiment gate rejected result: " + paired_reason)
        for case in result.get("cases", []):
            if not isinstance(case, dict):
                continue
            pair_id, role = case.get("pair_id"), case.get("role")
            if role not in command_by_role or not isinstance(pair_id, str):
                continue
            pairs.setdefault(pair_id, set()).add(role)
            if isinstance(case.get("argv"), list):
                command_by_role[role].add(json.dumps(case["argv"], sort_keys=True))
        conforming = [case for case in result.get("cases", []) if isinstance(case, dict) and
                      case.get("pair_id") in pairs and case.get("executed") is True and
                      case.get("tests_ran") is True and case.get("timed_out") is False and
                      case.get("status") == "ran" and case.get("exit_code") == 0 and
                      case.get("matched_expected_exit") is True]
        log_files_ok = True
        result_parent = Path(entry.get("result_path", "")).parent if isinstance(entry, dict) else Path()
        for case in result.get("cases", []):
            if not isinstance(case, dict) or case.get("role") not in command_by_role:
                continue
            log_name = case.get("log_file")
            log_path = _run_file(run, str(result_parent / log_name) if isinstance(log_name, str) else None)
            argv = case.get("argv")
            stdout, stderr = case.get("stdout", ""), case.get("stderr", "")
            if (not isinstance(argv, list) or not all(isinstance(word, str) for word in argv) or
                    not isinstance(stdout, str) or not isinstance(stderr, str)):
                log_files_ok = False
                errors.append("paired execution case has malformed argv or output")
                continue
            expected_log = ("$ " + " ".join(argv) + "\n" + stdout
                            + ("\n" if stdout and not stdout.endswith("\n") else "") + stderr)
            if log_path is None or log_path.read_text(encoding="utf-8", errors="replace") != expected_log:
                log_files_ok = False
                errors.append("paired execution log is missing or differs from the recorded case output")
        pair_roles_ok = all(roles == {"candidate", "negative-control"} for roles in pairs.values())
        repeatable = len(pairs) >= 2 and pair_roles_ok and all(
            len(command_by_role[role]) == 1 for role in command_by_role)
        all_cases = sum(len(roles) for roles in pairs.values())
        result_ok = (paired_ok and repeatable and len(conforming) == all_cases and source_revision_ok and log_files_ok and
                     result.get("result") == "experiments-conformed")
    else:
        repeatable, result_ok = False, False
    if not repeatable:
        errors.append("reproduction requires at least two identical candidate/control pairs")
    if result and not result_ok:
        errors.append("paired logs do not show all repeated candidate and negative-control tests passing")
    checks["paired_execution"] = {"status": "confirmed" if result_ok else "unconfirmed",
                                   "repeated_pairs": len(pairs),
                                   "candidate_commands": len(command_by_role["candidate"]),
                                   "control_commands": len(command_by_role["negative-control"]),
                                   "saved_logs_match_result": log_files_ok,
                                   "result_path": entry.get("result_path") if isinstance(entry, dict) else None}

    # Assertion text must occur in a distinct private PoC artifact. A reviewer must state which
    # candidate and negative-control assertion the source test actually makes.
    assertion_rows = review.get("assertions")
    assertion_ok = True
    if not isinstance(assertion_rows, dict):
        assertion_rows, assertion_ok = {}, False
    for role in ("candidate", "negative-control"):
        item = assertion_rows.get(role)
        artifact = _run_file(run, item.get("poc_path") if isinstance(item, dict) else None)
        needle = item.get("quote") if isinstance(item, dict) else None
        if artifact is None or not isinstance(needle, str) or not needle.strip():
            assertion_ok = False
            errors.append(role + " assertion needs a run-local PoC path and exact assertion quote")
        else:
            body = artifact.read_text(encoding="utf-8", errors="replace")
            if needle not in body:
                assertion_ok = False
                errors.append(role + " assertion quote is absent from its PoC artifact")
            evidence = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
            claimed_property = evidence.get("assertion")
            if role == "candidate" and (not isinstance(claimed_property, str) or
                                         item.get("property") != claimed_property):
                assertion_ok = False
                errors.append("candidate assertion property must exactly match evidence.assertion")
            if role == "negative-control":
                if not isinstance(claimed_property, str) or item.get("property") != claimed_property:
                    assertion_ok = False
                    errors.append("negative-control must exercise the same property")
                if not isinstance(item.get("expected"), str) or not item["expected"].strip():
                    assertion_ok = False
                    errors.append("negative-control assertion needs its expected protected outcome")
    checks["assertions"] = {"status": "confirmed" if assertion_ok else "unconfirmed"}

    reach_anchors, reach_errors = _check_review_anchors(root, review, "reachability")
    errors.extend(reach_errors)
    reach_ok = (_decision(review, "reachability", {"confirmed"}) and bool(reach_anchors) and
                isinstance(review.get("ordered_steps"), list) and len(review["ordered_steps"]) >= 2 and
                all(isinstance(step, str) and step.strip() for step in review["ordered_steps"]))
    if not reach_ok:
        errors.append("reachability needs confirmed source anchors and an ordered, multi-step trace")
    checks["reachability"] = {"status": "confirmed" if reach_ok else "unconfirmed",
                              "anchors": reach_anchors,
                              "ordered_steps": review.get("ordered_steps", [])}

    impact = review.get("impact")
    impact_ok = False
    if isinstance(impact, dict) and impact.get("decision") == "confirmed":
        evidence = _run_file(run, impact.get("artifact_path"))
        quote = impact.get("quote")
        evidence_text = evidence.read_text(encoding="utf-8", errors="replace") if evidence else ""
        if impact.get("kind") == "economic":
            try:
                raw_loss, raw_cost = impact.get("victim_loss"), impact.get("attacker_cost")
                if isinstance(raw_loss, bool) or isinstance(raw_cost, bool):
                    raise ValueError("boolean is not an economic amount")
                loss = float(raw_loss)
                cost = float(raw_cost)
                impact_ok = loss > 0 and cost >= 0 and isinstance(impact.get("unit"), str) and bool(impact["unit"].strip())
            except (TypeError, ValueError):
                impact_ok = False
        elif impact.get("kind") == "liveness":
            repeated = impact.get("repeated_failures", 0)
            impact_ok = (type(repeated) is int and repeated >= 2 and
                         impact.get("recovery") == "failed" and
                         isinstance(impact.get("recovery_test"), str) and bool(impact["recovery_test"].strip()))
        impact_ok = bool(impact_ok and evidence and isinstance(quote, str) and quote.strip() and quote in evidence_text)
    if not impact_ok:
        errors.append("impact needs an independently confirmed quantified loss or repeated recovery failure with a run-local artifact quote")
    checks["impact"] = {"status": "confirmed" if impact_ok else "unconfirmed",
                         "kind": impact.get("kind") if isinstance(impact, dict) else None,
                         "artifact_path": impact.get("artifact_path") if isinstance(impact, dict) else None}

    scope_ok = _decision(review, "scope", {"in-scope"}) and isinstance(review.get("scope_anchor"), dict)
    if scope_ok:
        scope_ok = _scope_anchor(run, root, review["scope_anchor"])
    if not scope_ok:
        errors.append("scope decision requires an in-scope verdict and a valid source/program-rule anchor")
    checks["scope"] = {"status": "confirmed" if scope_ok else "unconfirmed"}

    deployment = review.get("deployment")
    deployment_ok = isinstance(deployment, dict) and deployment.get("decision") == "matched"
    if deployment_ok:
        deployment_file = _run_file(run, deployment.get("artifact_path"))
        deployment_quote = deployment.get("quote")
        deployment_ok = bool(deployment_file and isinstance(deployment_quote, str) and
                             deployment_quote.strip() in deployment_file.read_text(encoding="utf-8", errors="replace"))
    if not deployment_ok:
        errors.append("deployed-state review requires a matched deployment and run-local artifact quote")
    checks["deployment"] = {"status": "confirmed" if deployment_ok else "unconfirmed"}

    stages = {
        "SOURCE_CONFIRMED": bool(source_confirmed and source_review_ok),
        "POC_REPRODUCED": bool(source_confirmed and source_review_ok and result_ok and assertion_ok),
        "IMPACT_VERIFIED": bool(source_confirmed and source_review_ok and result_ok and assertion_ok and
                                 reach_ok and impact_ok and scope_ok and deployment_ok and independent),
    }
    status = {name: "passed" if ok else "not-confirmed" for name, ok in stages.items()}
    return {"schema": 1, "finding_id": finding_id, "status": status,
            "can_mark_verified": all(stages.values()), "reviewer_id": reviewer,
            "producer_id": producer, "target_root": str(root), "current_revision": current,
            "review_sha256": _digest(review_file), "checks": checks, "errors": errors,
            "notice": "This gate validates artifact shape, exact anchors, repeated paired execution and independent review metadata. It cannot prove that a test expresses the intended protocol property; reviewers remain responsible for semantics. It never changes findings.json."}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", required=True)
    parser.add_argument("--finding", required=True)
    parser.add_argument("--review", required=True, help="separate independent-review JSON record")
    parser.add_argument("--out", help="write new report; existing files are never overwritten")
    parser.add_argument("--gate", action="store_true", help="exit 1 unless all evidence stages pass")
    args = parser.parse_args(argv)
    try:
        result = verify(args.run, args.finding, args.review)
    except (OSError, ValueError, KeyError, json.JSONDecodeError, subprocess.SubprocessError) as exc:
        parser.error(str(exc))
    if args.out:
        path = Path(args.out)
        if path.exists():
            parser.error("refusing to overwrite output: " + str(path))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"out": str(path), "can_mark_verified": result["can_mark_verified"]}))
    else:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    return 1 if args.gate and not result["can_mark_verified"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
