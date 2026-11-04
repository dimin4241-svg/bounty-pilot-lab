#!/usr/bin/env python3
"""Bounded, feedback-guided native replay campaign for AVRE leads.

Never generates executable code or sends transactions. It runs only explicitly
reviewed candidate and negative-control commands through scenario_runner, and
only with opt-in execution in externally enforced isolation. Observations from
target tests are untrusted until independently checked against source/asserts.
"""
import argparse
import hashlib
import importlib.util
import json
import os
import re
import sys
from collections import Counter
from decimal import Decimal, InvalidOperation
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("bp_research_runner", HERE / "scenario_runner.py")
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)

MARKER = "BP_LAB_OBSERVATION="
IDENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,79}$")
SHA = re.compile(r"^[0-9a-f]{40,64}$")
MAX_VARIANTS = 32
MAX_ROUNDS = 3


def _strict_amount(value, label):
    if not isinstance(value, str) or len(value) > 70:
        raise ValueError(label + " must be an exact decimal string")
    try:
        amount = Decimal(value)
    except InvalidOperation as exc:
        raise ValueError(label + " is not decimal") from exc
    if not amount.is_finite():
        raise ValueError(label + " is nonfinite")
    return amount


def _observation(case, variant, role):
    if not case.get("executed") or case.get("status") != "ran" or not case.get("matched_expected_exit"):
        return None, "native-test-did-not-conform"
    raw = str(case.get("stdout", "")) + "\n" + str(case.get("stderr", ""))
    matches = [line[len(MARKER):] for line in raw.splitlines() if line.startswith(MARKER)]
    if len(matches) != 1 or len(matches[0]) > 4096:
        return None, "missing-or-ambiguous-structured-observation"
    try:
        obj = json.loads(matches[0])
    except (ValueError, TypeError):
        return None, "invalid-observation-json"
    if not isinstance(obj, dict) or obj.get("variant") != variant or obj.get("role") != role:
        return None, "observation-binding-mismatch"
    if type(obj.get("violated")) is not bool or not isinstance(obj.get("property_id"), str) \
            or not IDENT.fullmatch(obj["property_id"]):
        return None, "observation-property-invalid"
    victim_loss = obj.get("victim_loss", "0")
    attacker_delta = obj.get("attacker_delta", "0")
    try:
        _strict_amount(victim_loss, "victim_loss")
        _strict_amount(attacker_delta, "attacker_delta")
    except ValueError:
        return None, "invalid-exact-economic-amounts"
    state = obj.get("state_digest", "")
    if not isinstance(state, str) or (state and not re.fullmatch(r"[0-9a-f]{64}", state)):
        return None, "state-digest-invalid"
    return {"variant": variant, "role": role, "property_id": obj["property_id"],
            "violated": obj["violated"], "victim_loss": victim_loss,
            "attacker_delta": attacker_delta, "state_digest": state}, None


def _validate(manifest, root):
    if not isinstance(manifest, dict) or manifest.get("schema_version") != 1:
        raise ValueError("manifest schema_version must be 1")
    revision, checkout_status = runner._checkout_identity(root)
    if not SHA.fullmatch(manifest.get("source_revision", "")) or revision != manifest["source_revision"]:
        raise ValueError("source_revision must match current pinned checkout HEAD")
    variants = manifest.get("variants")
    if not isinstance(variants, list) or not 1 <= len(variants) <= MAX_VARIANTS:
        raise ValueError("variants must contain between 1 and 32 explicit experiments")
    ids = []
    for item in variants:
        if not isinstance(item, dict) or not IDENT.fullmatch(item.get("id", "")):
            raise ValueError("invalid variant id")
        ids.append(item["id"])
        if not IDENT.fullmatch(item.get("family", "")):
            raise ValueError("variant family is required")
        if type(item.get("priority", 1)) not in (int, float) or not 0 <= item.get("priority", 1) <= 10:
            raise ValueError("priority must be a finite number 0..10")
        cases = item.get("cases")
        if not isinstance(cases, list) or len(cases) != 2:
            raise ValueError("each variant must have exactly two test cases")
        if len({case.get("role") for case in cases if isinstance(case, dict)}) != 2:
            raise ValueError("variant needs candidate and negative-control")
        pair = {"schema_version": 1, "cases": cases}
        runner._validate(pair, root)
        if any(case.get("expected_exit", 0) != 0 for case in cases):
            raise ValueError("native assertions must pass normally (expected_exit 0)")
    if len(ids) != len(set(ids)):
        raise ValueError("variant ids must be unique")
    return checkout_status


def _order(pending, seen_families, seen_states):
    # Exploration balances research priority and previously untested families.
    return sorted(pending, key=lambda row: (
        -(float(row.get("priority", 1)) + (1.5 if row["family"] not in seen_families else 0)),
        row["id"]))


def run(manifest, repo, max_variants=12, rounds=2, execute=False,
        isolation_attested=False, no_network_attested=False, allow_dirty_poc=False):
    root = Path(repo).expanduser().resolve()
    if type(max_variants) is not int or not 1 <= max_variants <= MAX_VARIANTS:
        raise ValueError("max_variants must be 1..32")
    if type(rounds) is not int or not 2 <= rounds <= MAX_ROUNDS:
        raise ValueError("rounds must be 2 or 3")
    status = _validate(manifest, root)
    if execute and not (isolation_attested and no_network_attested):
        raise ValueError("execution requires independently enforced isolated, network-blocked environment attestation")
    if execute and status != "clean" and not allow_dirty_poc:
        raise ValueError("executing in a dirty checkout requires explicit allow_dirty_poc and source review")
    pending = list(manifest["variants"])
    examined, seen_families, seen_states = [], set(), set()
    for _ in range(min(max_variants, len(pending))):
        item = _order(pending, seen_families, seen_states)[0]
        pending.remove(item)
        seen_families.add(item["family"])
        repetitions, errors, observations = [], [], []
        for repeat in range(rounds):
            result = runner.execute({"schema_version": 1, "cases": item["cases"]}, root,
                                    allow_exec=execute, allow_dotenv=False)
            repetitions.append(result)
            if result.get("source_revision") != manifest["source_revision"]:
                errors.append("source revision changed during replay")
                break
            by_role = {case["role"]: case for case in result["cases"]}
            paired = {}
            if execute:
                for role in ("candidate", "negative-control"):
                    observation, error = _observation(by_role[role], item["id"], role)
                    if error:
                        errors.append(role + ":" + error)
                    else:
                        paired[role] = observation
                        if observation["state_digest"]:
                            seen_states.add(observation["state_digest"])
            if len(paired) == 2:
                if paired["candidate"]["property_id"] != paired["negative-control"]["property_id"]:
                    errors.append("candidate/control property IDs differ")
                observations.append(paired)
        witnessed = (execute and not errors and len(observations) == rounds and
                     all(p["candidate"]["violated"] and not p["negative-control"]["violated"]
                         for p in observations) and
                     len({p["candidate"]["property_id"] for p in observations}) == 1)
        examined.append({
            "id": item["id"], "family": item["family"],
            "hypothesis_id": item.get("hypothesis_id"),
            "status": ("local-witness-needs-independent-review" if witnessed else
                       "not-executed" if not execute else "inconclusive-or-refuted"),
            "observations": observations, "errors": sorted(set(errors)),
            "rounds": repetitions,
            "provenance": "scenario_runner-native-tests; untrusted test markers",
            "next_experiment": ("Review the assertions, actual chain state, profit and minimality"
                                if witnessed else "Fix preconditions/marker or inspect the negative control"),
        })
        # A witness does not stop the campaign: the remaining explicit variants
        # can falsify generality or show an intended boundary.
    return {
        "schema_version": 1, "source_revision": manifest["source_revision"],
        "checkout_status": status, "execution": "local-native" if execute else "dry-run",
        "selected": len(examined), "remaining": len(pending),
        "seen_families": sorted(seen_families), "distinct_state_digests": len(seen_states),
        "witness_count": sum(row["status"] == "local-witness-needs-independent-review" for row in examined),
        "experiments": examined,
        "deferred_variants": [x["id"] for x in pending],
        "notice": ("Native test markers are untrusted observations, not independent proof. "
                   "The engine selects from explicitly supplied tests; it cannot fabricate "
                   "a valid harness. All executions require external isolation and network denial. "
                   "No confirmed finding, deployment match, net profit or bounty severity inferred.")}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--max-variants", type=int, default=12)
    parser.add_argument("--rounds", type=int, default=2)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--isolation-attested", action="store_true")
    parser.add_argument("--no-network-attested", action="store_true")
    parser.add_argument("--allow-dirty-poc", action="store_true")
    args = parser.parse_args(argv)
    manifest_path = Path(args.manifest).expanduser()
    if manifest_path.is_symlink() or manifest_path.stat().st_size > 2_000_000:
        parser.error("manifest must be a regular non-symlink file <=2 MB")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    output = Path(args.out).expanduser()
    if output.is_symlink() or output.exists():
        parser.error("output must be create-only")
    if output.resolve() == Path(args.repo).resolve() or Path(args.repo).resolve() in output.resolve().parents:
        parser.error("output must be outside target checkout")
    report = run(manifest, args.repo, args.max_variants, args.rounds, args.execute,
                 args.isolation_attested, args.no_network_attested, args.allow_dirty_poc)
    fd = os.open(str(output), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(report, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
    print(json.dumps({"out": str(output), "witness_count": report["witness_count"],
                      "selected": report["selected"], "execution": report["execution"]}))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
        print("Error: " + str(exc), file=sys.stderr)
        sys.exit(2)
