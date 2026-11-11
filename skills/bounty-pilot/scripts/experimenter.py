#!/usr/bin/env python3
"""Draft bounded native experiments from a strong finding, without inventing passing PoCs.

`draft` creates a deliberately failing test skeleton and a source-anchored experiment brief.
`plan` binds existing candidate/control test selectors to safe argv for scenario_runner.py.
Neither action runs target code. Execution remains an explicit scenario_runner --allow-exec step.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import bounty  # noqa: E402


def _helper(name):
    spec = importlib.util.spec_from_file_location("bp_experimenter_" + name,
                                                   SCRIPTS / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def draft(run_dir, finding_id, stack, out_dir):
    run = Path(run_dir).expanduser().resolve()
    meta = bounty.read_json(run / "run.json")
    bounty.require_private_output(run, meta.get("target_root"), what="experimenter --run")
    root = Path(meta["target_root"]).resolve()
    rows = bounty.read_json(run / "findings.json")
    matches = [row for row in rows if isinstance(row, dict) and row.get("id") == finding_id]
    if len(matches) != 1:
        raise ValueError("finding id must match exactly one findings.json record")
    finding = matches[0]
    if finding.get("status") not in ("hypothesis", "needs-evidence"):
        raise ValueError("experiment drafts are only for open hypotheses")
    affected = []
    for relative in finding.get("affected_paths", []):
        if not isinstance(relative, str) or Path(relative).is_absolute() or ".." in Path(relative).parts:
            continue
        target = root / relative
        if target.is_file() and not target.is_symlink():
            affected.append({"path": relative, "sha256": bounty._sha256_file(target)})
    if not affected:
        raise ValueError("finding has no readable, repository-relative affected source file")
    dest = Path(out_dir).expanduser().resolve()
    bounty.require_private_output(dest, root, what="experimenter --out-dir")
    dest.mkdir(parents=True, exist_ok=True)
    if any(dest.iterdir()):
        raise ValueError("output directory must be empty; preserving existing experiment work")
    evidence = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
    invariant = evidence.get("assertion") if isinstance(evidence.get("assertion"), str) else ""
    steps = finding.get("steps") if isinstance(finding.get("steps"), list) else []
    entry = finding.get("entry_point") if isinstance(finding.get("entry_point"), str) else ""
    # Placeholders are deliberately labelled and the resulting source always fails until filled.
    scaffold_finding = {"id": finding_id, "invariant": invariant or "TODO: cite the violated invariant",
                        "entry_point": entry or "TODO: cite the reachable entry point",
                        "attacker_capabilities": finding.get("attacker_capabilities") or "TODO: state unprivileged capability",
                        "steps": steps if steps else ["TODO: reachable setup", "TODO: ordered attack action"]}
    scaffold = _helper("poc_scaffold")
    ident, source, notes = scaffold.scaffold(scaffold_finding, stack)
    basename = "test_bp_" + ident
    source_path = dest / (basename + scaffold.KINDS[stack])
    metadata_path = dest / (basename + ".json")
    source_path.write_text(source, encoding="utf-8")
    metadata_path.write_text(json.dumps(notes, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    brief = {"schema": 1, "finding_id": finding_id,
             "target_revision": finding.get("revision"), "target_root": str(root),
             "source_files": affected, "attacker_capabilities": finding.get("attacker_capabilities"),
             "preconditions": finding.get("preconditions"), "ordered_steps": steps,
             "claimed_impact": finding.get("impact"),
             "invariant": invariant or None, "entry_point": entry or None,
             "question": (finding.get("next_experiment") or {}).get("question"),
             "method": (finding.get("next_experiment") or {}).get("method"),
             "expected_evidence": (finding.get("next_experiment") or {}).get("expected_evidence"),
             "native_test_skeleton": source_path.name, "status": "draft-incomplete-not-executed",
             "candidate_assertion": "TODO: assert measurable invariant violation or victim effect",
             "negative_control": "TODO: same reachable path with protection restored or attacker capability removed",
             "repeatability": "run candidate and control at least twice on the same pinned source revision",
             "notice": "This draft reuses the finding's claims as unverified inputs. The generated test deliberately fails. Do not edit target source to make it pass."}
    brief_path = dest / "experiment.json"
    brief_path.write_text(json.dumps(brief, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return {"status": "draft-incomplete-not-executed", "brief": str(brief_path),
            "test_skeleton": str(source_path), "metadata": str(metadata_path)}


def plan(spec, stack):
    if not isinstance(spec, dict) or not isinstance(spec.get("finding_id"), str) or \
            not re.fullmatch(r"BP-[0-9]{3,}", spec["finding_id"]):
        raise ValueError("spec.finding_id must name a Bounty Pilot finding")
    if not isinstance(spec.get("source_revision"), str) or \
            not re.fullmatch(r"[0-9a-fA-F]{7,64}", spec["source_revision"]):
        raise ValueError("spec.source_revision must pin the unmodified source commit")
    if not isinstance(spec.get("invariant"), str) or not spec["invariant"].strip():
        raise ValueError("spec.invariant must state the property asserted by candidate and control")
    if not isinstance(spec.get("equivalence_basis", ""), str):
        raise ValueError("equivalence_basis must be a documentation/spec citation or empty")
    if spec.get("kind") == "differential" and not spec.get("equivalence_basis", "").strip():
        raise ValueError("differential plans require a protocol specification or documented invariant as equivalence_basis")
    fuzz = _helper("native_fuzz_plan")
    result = fuzz.plan(spec, stack)
    result.update({"finding_id": spec["finding_id"], "source_revision": spec["source_revision"],
                   "invariant": spec["invariant"],
                   "equivalence_basis": spec.get("equivalence_basis"),
                   "generation_status": "commands-not-run",
                   "notice": "This plan invokes existing tests only. Differential cases must compare the operations and assert the documented equivalence inside their native tests; the runner does not decide protocol equivalence. Confirm assertions and source pin, then review argv before scenario_runner.py --allow-exec."})
    return result



# --- Phase 6: mutation sensitivity and same-trace counterfactual review ---
import hashlib
import os


def _phase6_digest(obj):
    return hashlib.sha256(json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")).hexdigest()


def assess_mutations(catalog, observations):
    """Score only reached, observably divergent, controlled source mutants.

    Receipts are operator/runner supplied; this does not authenticate a native
    forge test. A surviving mutant with no state divergence is NOT a weak
    property; it may be behaviorally equivalent or improperly driven.
    """
    if (not isinstance(catalog, dict) or
            catalog.get("mode") != "sealed-mutant-precommit"):
        raise ValueError("sealed deterministic mutation catalog required")
    expected = _phase6_digest({k: v for k, v in catalog.items()
                               if k != "catalog_sha256"})
    if catalog.get("catalog_sha256") != expected:
        raise ValueError("mutation catalog digest mismatch")
    if (not isinstance(observations, dict) or
            observations.get("schema_version") != 1 or
            observations.get("catalog_sha256") != expected or
            observations.get("source_revision") != catalog["source_revision"]):
        raise ValueError("receipts must bind the exact sealed source revision")
    baseline = observations.get("baseline")
    if (not isinstance(baseline, dict) or
            baseline.get("compiled") is not True or
            baseline.get("property_tests_passed") is not True):
        raise ValueError("passing baseline compile and property suite required")
    mutants = catalog.get("mutants")
    if not isinstance(mutants, list) or not 1 <= len(mutants) <= 96:
        raise ValueError("1..96 deterministic sealed mutants required")
    ids = {m["id"] for m in mutants}
    if len(ids) != len(mutants):
        raise ValueError("duplicate mutant identifiers in catalog")
    receipts = observations.get("results")
    if not isinstance(receipts, list) or len(receipts) > len(mutants):
        raise ValueError("bounded native mutation receipts required")
    records = {}
    for row in receipts:
        required = {"mutant_id", "compiled", "line_reached", "state_diverged",
                    "property_failed", "negative_control_passed", "evidence_sha256"}
        native_optional = {"unclassified_test_exit_code", "native_test_output_sha256"}
        if (not isinstance(row, dict) or not required <= set(row) or
                not set(row) <= required | native_optional):
            raise ValueError("exact mutation observation schema required")
        ident = row["mutant_id"]
        if ident not in ids or ident in records:
            raise ValueError("unknown or duplicate mutant receipt")
        for key in ("compiled", "line_reached", "state_diverged",
                    "property_failed", "negative_control_passed"):
            if row[key] is not None and type(row[key]) is not bool:
                raise ValueError("observations require boolean or null values")
        if (not isinstance(row["evidence_sha256"], str) or
                not re.fullmatch(r"[a-f0-9]{64}", row["evidence_sha256"])):
            raise ValueError("each receipt needs a bounded evidence digest")
        records[ident] = row
    classes = {}
    results = []
    for mutant in mutants:
        row = records.get(mutant["id"])
        if row is None:
            status = "NOT_RUN"
        elif row["compiled"] is False:
            status = "NONVIABLE_COMPILE"
        elif row["compiled"] is not True:
            status = "COMPILE_UNKNOWN"
        elif row["line_reached"] is False:
            status = "UNREACHED_BY_CAMPAIGN"
        elif row["line_reached"] is not True:
            status = "REACHABILITY_UNKNOWN"
        elif row["state_diverged"] is False:
            status = "POSSIBLY_EQUIVALENT_OR_WEAK_STATE_ORACLE"
        elif row["state_diverged"] is not True:
            status = "INFECTION_UNKNOWN"
        elif row["negative_control_passed"] is not True:
            status = "NEGATIVE_CONTROL_NOT_VERIFIED"
        elif row["property_failed"] is True:
            status = "OPERATOR_REPORTED_KILLED"
        elif row["property_failed"] is False:
            status = "OPERATOR_REPORTED_REACHED_INFECTED_SURVIVOR"
        else:
            status = "PROPERTY_OUTCOME_UNKNOWN"
        classes[status] = classes.get(status, 0) + 1
        results.append({"id": mutant["id"], "operator": mutant["operator"],
                        "status": status, "observations_verified_by_tool": False})
    killed = classes.get("OPERATOR_REPORTED_KILLED", 0)
    survived = classes.get("OPERATOR_REPORTED_REACHED_INFECTED_SURVIVOR", 0)
    denominator = killed + survived
    return {
        "schema_version": 1, "mode": "mutation-assessment",
        "status": "OPERATOR_REPORTED_METRICS_NOT_INDEPENDENTLY_VERIFIED",
        "source_revision": catalog["source_revision"],
        "catalog_sha256": expected, "mutants_total": len(mutants),
        "observations_count": len(records), "classifications": classes,
        "reached_infected_observed": denominator,
        "mutation_detection_fraction": (
            round(killed / denominator, 6) if denominator else None),
        "results": results, "native_execution_verified_by_tool": False,
        "confirmed_vulnerabilities": 0,
        "warning": ("No mutation score if coverage or behavioral infection "
                    "is unknown. Equivalent mutants are not auto-classified. "
                    "All receipt booleans are operator supplied; repeat in "
                    "the isolated native sandbox before claiming measured effectiveness.")
    }


def evaluate_model_counterfactual(original, proposed_fix, trace):
    """Use existing deterministic state-model replay on identical transitions."""
    helper = _helper("scenario_fuzz")
    old = helper.replay_trace(original, trace)
    new = helper.replay_trace(proposed_fix, trace)
    passes = (old["status"] == "MODEL_INVARIANT_VIOLATED" and
              new["status"] == "NO_MODEL_VIOLATION_ON_THIS_TRACE")
    return {
        "schema_version": 1, "mode": "same-trace-model-counterfactual",
        "original": old, "proposed_fix": new,
        "same_trace_passes_on_model": passes,
        "native_original_executed": False, "native_patch_executed": False,
        "root_cause_verified": False, "fix_safe": False,
        "note": ("A model-only contrast locates a transition worth investigating. "
                 "Independently replay on unchanged and patched native checkouts "
                 "and run normal regression tests before claiming causality.")
    }


def _phase6_write(path, payload):
    dest = Path(path)
    if dest.is_symlink() or dest.exists():
        raise ValueError("mutation/counterfactual report must be new")
    dest.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(dest), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(payload, stream, sort_keys=True, ensure_ascii=False, indent=2)
        stream.write("\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    create = sub.add_parser("draft", help="make an incomplete native PoC and experiment brief")
    create.add_argument("--run", required=True)
    create.add_argument("--finding", required=True)
    create.add_argument("--stack", choices=("solidity", "rust", "python", "go"), required=True)
    create.add_argument("--out-dir", required=True)
    measure = sub.add_parser("mutation-score", help="strict mutation quality on source-pinned reviewed receipts")
    measure.add_argument("--catalog", required=True)
    measure.add_argument("--receipts", required=True)
    measure.add_argument("--out", required=True)
    counter = sub.add_parser("counterfactual", help="replay identical model steps on original and proposed fix")
    counter.add_argument("--original", required=True)
    counter.add_argument("--proposed-fix", required=True)
    counter.add_argument("--trace", required=True)
    counter.add_argument("--out", required=True)
    pair = sub.add_parser("plan", help="bind existing candidate/control tests to safe commands")
    pair.add_argument("--spec", required=True)
    pair.add_argument("--stack", choices=("foundry", "cargo", "pytest", "go"), required=True)
    pair.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    try:
        if args.action == "draft":
            report = draft(args.run, args.finding, args.stack, args.out_dir)
            print(json.dumps(report, ensure_ascii=False, indent=2))
        elif args.action == "mutation-score":
            report = assess_mutations(
                json.loads(Path(args.catalog).read_text(encoding="utf-8")),
                json.loads(Path(args.receipts).read_text(encoding="utf-8")))
            _phase6_write(args.out, report)
            print(json.dumps({"out": args.out, "mutation_detection_fraction":
                              report["mutation_detection_fraction"],
                              "verified": False}))
        elif args.action == "counterfactual":
            report = evaluate_model_counterfactual(
                json.loads(Path(args.original).read_text(encoding="utf-8")),
                json.loads(Path(args.proposed_fix).read_text(encoding="utf-8")),
                json.loads(Path(args.trace).read_text(encoding="utf-8")))
            _phase6_write(args.out, report)
            print(json.dumps({"out": args.out, "model_only":
                              report["same_trace_passes_on_model"]}))
        else:
            report = plan(json.loads(Path(args.spec).read_text(encoding="utf-8")), args.stack)
            output = Path(args.out)
            if output.exists():
                raise ValueError("refusing to overwrite plan output")
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            print(json.dumps({"out": str(output), "cases": len(report["cases"]), "status": "not-executed"}))
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
