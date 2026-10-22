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


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    create = sub.add_parser("draft", help="make an incomplete native PoC and experiment brief")
    create.add_argument("--run", required=True)
    create.add_argument("--finding", required=True)
    create.add_argument("--stack", choices=("solidity", "rust", "python", "go"), required=True)
    create.add_argument("--out-dir", required=True)
    pair = sub.add_parser("plan", help="bind existing candidate/control tests to safe commands")
    pair.add_argument("--spec", required=True)
    pair.add_argument("--stack", choices=("foundry", "cargo", "pytest", "go"), required=True)
    pair.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    try:
        if args.action == "draft":
            report = draft(args.run, args.finding, args.stack, args.out_dir)
            print(json.dumps(report, ensure_ascii=False, indent=2))
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
