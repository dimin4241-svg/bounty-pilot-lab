#!/usr/bin/env python3
"""Deterministic property-blind mutation bank and independently authored property scoring.

This is an EXACT, bounded state-MODEL evaluation lab, not a Solidity
compiler mutation campaign and never production exploit proof. Generate and
seal operator-domain mutants BEFORE authoring properties. Keep the private
bank hidden from the author. Later evaluate original/mutant executions with
actual reachable prefix attempts, baseline controls, per-property outcomes,
and bounded equivalence classification. No eval, network or model calls.
"""
import argparse
import copy
import hashlib
import importlib.util
import json
import os
import re
import sys
from collections import deque
from pathlib import Path

MAX_BYTES = 3_000_000
SHA = re.compile(r"^[a-f0-9]{64}$")
ID = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,79}$")
OPERATORS = ("skip-write", "reverse-arithmetic", "off-by-one",
             "remove-guard", "boundary-shift")
TIERS = ("confirmed_requirement", "industry_assumption", "hypothesis")
KINDS = ("protocol_specification", "external_documentation",
         "independent_test", "industry_rule", "research_hypothesis")


def _mod(name):
    spec = importlib.util.spec_from_file_location(
        "bpl_mutation_" + name, Path(__file__).with_name(name + ".py"))
    obj = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)
    return obj


def _json(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True,
                      separators=(",", ":"), allow_nan=False)


def _sha(value):
    return hashlib.sha256(_json(value).encode("ascii")).hexdigest()


def _pairs(pairs):
    value = {}
    for k, v in pairs:
        if k in value:
            raise ValueError("duplicate JSON key")
        value[k] = v
    return value


def _read(path):
    p = Path(path).expanduser()
    if p.is_symlink() or not p.is_file() or p.stat().st_size > MAX_BYTES:
        raise ValueError("only bounded, regular, non-symlink JSON files")
    return json.loads(p.read_text(encoding="utf-8"),
                      parse_constant=lambda _: (_ for _ in ()).throw(
                          ValueError("non-finite JSON number")),
                      object_pairs_hook=_pairs)


def _save_new(path, value):
    p = Path(path).expanduser()
    if p.is_symlink() or p.exists():
        raise ValueError("refusing to overwrite private artifact")
    p.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(p), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(json.dumps(value, ensure_ascii=False, indent=2,
                                sort_keys=True, allow_nan=False) + "\n")


def _validate_model(model):
    if not isinstance(model, dict) or "invariants" in model:
        raise ValueError("mutation bank input must contain no properties/invariants")
    if set(model) != {"state", "actors", "actions"}:
        raise ValueError("model fields must be exactly state, actors and actions")
    fuzz = _mod("scenario_fuzz")
    fuzz.actions_for(model)
    if fuzz._find_float(model) is not None:
        raise ValueError("exact numeric model only, no floats")
    for action in model["actions"]:
        if set(action) - {"name", "actor", "guards", "effects"}:
            raise ValueError("unexpected model action field")
        for step in action.get("guards", []):
            if not isinstance(step, dict) or set(step) != {"path", "op", "value"}:
                raise ValueError("invalid model guard")
            if step["op"] not in fuzz.OPS:
                raise ValueError("unsupported guard operator")
        for step in action["effects"]:
            if not isinstance(step, dict) or set(step) != {"path", "op", "value"}:
                raise ValueError("invalid model effect")
            if step["op"] not in fuzz.EFFECTS:
                raise ValueError("unsupported model effect operator")
    return fuzz


def _mutations(model):
    """Fixed domain operator registry; this function NEVER reads a property."""
    rows = []
    for i, action in enumerate(model["actions"]):
        for j, effect in enumerate(action["effects"]):
            change = copy.deepcopy(effect)
            if effect["op"] in ("set", "add", "sub", "append", "remove"):
                change.update({"op": "set", "value": {"path": effect["path"]}})
                if change != effect:
                    rows.append((i, "effects", j, "skip-write", change))
            if effect["op"] in ("add", "sub"):
                change = dict(effect, op=("sub" if effect["op"] == "add" else "add"))
                rows.append((i, "effects", j, "reverse-arithmetic", change))
                amount = effect["value"]
                if (type(amount) is int and 1 <= abs(amount) <= 1000000):
                    change = dict(effect, value=amount + 1)
                    rows.append((i, "effects", j, "off-by-one", change))
        for j, guard in enumerate(action.get("guards", [])):
            if len(action.get("guards", [])) > 1:
                rows.append((i, "guards", j, "remove-guard", None))
            else:
                # Keep a single guard slot but make its condition trivially
                # true via a self-comparison; reachability is measured later.
                rows.append((i, "guards", j, "remove-guard",
                             {"path": guard["path"], "op": "eq",
                              "value": {"path": guard["path"]}}))
            opposite = {"lt": "le", "le": "lt", "gt": "ge",
                        "ge": "gt", "eq": "ne", "ne": "eq"}[guard["op"]]
            rows.append((i, "guards", j, "boundary-shift",
                         dict(guard, op=opposite)))
    return rows


def bank(model, max_mutants=40):
    fuzz = _validate_model(model)
    if type(max_mutants) is not int or not 1 <= max_mutants <= 60:
        raise ValueError("max_mutants must be 1..60")
    candidates = _mutations(model)
    generated = []
    for i, (action, section, index, operator, edit) in enumerate(candidates):
        mutant = copy.deepcopy(model)
        if edit is None:
            del mutant["actions"][action][section][index]
        else:
            mutant["actions"][action][section][index] = edit
        if mutant == model:
            continue
        try:
            _validate_model(mutant)
        except (ValueError, KeyError, TypeError):
            continue
        row = {"id": "m%03d" % (len(generated) + 1),
               "action_index": action, "section": section,
               "step_index": index, "operator": operator,
               "original_action_name": model["actions"][action]["name"],
               "mutant_model": mutant}
        row["mutant_sha256"] = _sha(mutant)
        generated.append(row)
        if len(generated) >= max_mutants:
            break
    if not generated:
        raise ValueError("no valid deterministic domain mutations generated")
    payload = {
        "schema_version": 1, "mode": "private-property-blind-state-model-bank",
        "operator_registry": list(OPERATORS), "source_model_sha256": _sha(model),
        "source_model": copy.deepcopy(model),
        "mutants": generated,
        "properties_seen_during_generation": False,
        "native_target_executed": False,
        "author_must_not_mount_bank": True,
        "limitations": ("Models are abstract state models, not deployed contracts. "
                        "Mutation operators are deterministic and independent of the "
                        "property author, but this tool cannot enforce physical isolation.")
    }
    payload["bank_sha256"] = _sha(payload)
    return payload


def _verify_bank(data):
    if (not isinstance(data, dict) or
            data.get("mode") != "private-property-blind-state-model-bank" or
            data.get("schema_version") != 1 or
            data.get("operator_registry") != list(OPERATORS) or
            data.get("properties_seen_during_generation") is not False):
        raise ValueError("invalid or non-blind mutation bank")
    digest = data.get("bank_sha256")
    clone = dict(data)
    clone.pop("bank_sha256", None)
    if not isinstance(digest, str) or digest != _sha(clone):
        raise ValueError("mutation bank SHA-256 seal invalid")
    model = data["source_model"]
    _validate_model(model)
    if _sha(model) != data["source_model_sha256"]:
        raise ValueError("original model changed")
    mutants = data["mutants"]
    expected = bank(model, len(mutants))
    if len(expected["mutants"]) != len(mutants):
        raise ValueError("mutation catalogue changed")
    for row, standard in zip(mutants, expected["mutants"]):
        if row != standard:
            raise ValueError("mutants were edited after generation")
    return model, mutants


def author_brief(evidence):
    """Build a model-facing brief from *external intent* only.

    Does not read target implementation, mutation operators, mutant bank
    or published bug truth. The operator must give this to a genuinely
    separate agent; the script cannot attest to process-level isolation.
    """
    if (not isinstance(evidence, dict) or set(evidence) != {
            "schema_version", "target_label", "observable_state_fields",
            "independent_sources"} or evidence["schema_version"] != 1):
        raise ValueError("intent brief needs exact source manifest")
    label = evidence["target_label"]
    if not isinstance(label, str) or not ID.fullmatch(label):
        raise ValueError("opaque target label required")
    fields = evidence["observable_state_fields"]
    docs = evidence["independent_sources"]
    if (not isinstance(fields, list) or not 1 <= len(fields) <= 50 or
            any(not isinstance(x, str) or not
                re.fullmatch(r"[A-Za-z][A-Za-z0-9_.]{0,99}", x) for x in fields)):
        raise ValueError("bounded observable field names required")
    if not isinstance(docs, list) or not 1 <= len(docs) <= 12:
        raise ValueError("1..12 independent documents")
    sources, ids = [], set()
    for d in docs:
        if not isinstance(d, dict) or set(d) != {
                "source_ref", "source_kind", "text", "reviewer_confirmed"}:
            raise ValueError("source must have exact fields")
        ident, kind, content = d["source_ref"], d["source_kind"], d["text"]
        if (not isinstance(ident, str) or not ID.fullmatch(ident) or
                ident in ids or kind not in KINDS or
                not isinstance(content, str) or
                not 20 <= len(content) <= 2500 or
                type(d["reviewer_confirmed"]) is not bool):
            raise ValueError("source contents or identity invalid")
        if re.search(r"(?i)(api[_-]?key|private[_-]?key|mnemonic|bearer\s+\S+|"
                     r"password\s*[:=])", content):
            raise ValueError("never hand secrets to model intent author")
        ids.add(ident)
        sources.append({"source_ref": ident, "source_kind": kind,
                        "source_sha256": hashlib.sha256(
                            content.encode("utf-8")).hexdigest(),
                        "text": content,
                        "operator_review_asserted": d["reviewer_confirmed"]})
    return {"schema_version": 1, "mode": "independent-property-author-brief",
            "target_label": label,
            "observable_state_fields": list(fields),
            "independent_sources": sources,
            "instructions": [
                "You are a PROPERTY AUTHOR; you must NOT see the target source code, mutant bank, mutants, known vulnerability descriptions or their patches.",
                "Extract at most 15 falsifiable behavioral invariants using only these independent specifications, field meanings and accounting identities.",
                "Categorize each as confirmed_requirement, industry_assumption or hypothesis; do not upgrade a hypothesis to confirmed without independent reviewer evidence.",
                "Return a strict JSON object with schema_version=1, author_role=separate_property_author, bank_visible_to_author=false, rules=[{id,invariant,provenance}].",
                "Each invariant is a data-only rule accepted by invariant_check.py: kind=compare/conservation/unique with paths and exact integer/decimal-string constants, no code or Python.",
                "Each provenance object contains tier, source_kind, source_ref, source_sha256, supporting_excerpt (exact quotation from this document), reviewer_confirmed (boolean).",
                "Do not invent observable state fields or silently assert implementation-specific behavior as protocol intent.",
                "No property is proven solely by passing a model or killing a controlled mutant."
            ],
            "mutant_bank_visible": False,
            "source_code_visible": False, "llm_calls": 0,
            "limitations": "Operator-supplied external intent; no model invoked and physical isolation cannot be proved."}


def _properties(spec):
    if (not isinstance(spec, dict) or set(spec) != {
            "schema_version", "author_role", "bank_visible_to_author",
            "rules"} or spec["schema_version"] != 1 or
            spec["author_role"] != "separate_property_author" or
            spec["bank_visible_to_author"] is not False):
        raise ValueError("require separate property-author declaration")
    rules = spec["rules"]
    if not isinstance(rules, list) or not 1 <= len(rules) <= 30:
        raise ValueError("one to thirty source-annotated rules")
    ids = set()
    invariant_rules = []
    for item in rules:
        if not isinstance(item, dict) or set(item) != {
                "id", "invariant", "provenance"}:
            raise ValueError("property record must bind invariant to provenance")
        ident = item["id"]
        if not isinstance(ident, str) or not ID.fullmatch(ident) or ident in ids:
            raise ValueError("unique bounded invariant id required")
        ids.add(ident)
        src = item["provenance"]
        if not isinstance(src, dict) or set(src) != {
                "tier", "source_kind", "source_ref", "source_sha256",
                "supporting_excerpt", "reviewer_confirmed"}:
            raise ValueError("property provenance fields invalid")
        tier, kind = src["tier"], src["source_kind"]
        if tier not in TIERS or kind not in KINDS:
            raise ValueError("unknown property basis")
        if (tier == "confirmed_requirement" and
                kind not in ("protocol_specification", "external_documentation",
                             "independent_test")):
            raise ValueError("confirmed requirement needs external evidence basis")
        if tier == "confirmed_requirement" and src["reviewer_confirmed"] is not True:
            raise ValueError("claimed confirmed requirement must be operator reviewed")
        if type(src["reviewer_confirmed"]) is not bool:
            raise ValueError("reviewer flag must be boolean")
        if (not isinstance(src["source_ref"], str) or not
                ID.fullmatch(src["source_ref"]) or
                not isinstance(src["source_sha256"], str) or
                not SHA.fullmatch(src["source_sha256"]) or
                not isinstance(src["supporting_excerpt"], str) or
                not 10 <= len(src["supporting_excerpt"]) <= 500):
            raise ValueError("source reference, SHA-256 and excerpt required")
        rule = item["invariant"]
        if not isinstance(rule, dict) or rule.get("id") != ident:
            raise ValueError("invariant ID mismatch")
        # A user's metadata may not substitute for independently reviewed
        # facts; still validate data-only syntax with the actual engine.
        invariant_rules.append(copy.deepcopy(rule))
    return invariant_rules


def _fingerprint_state(state):
    return _sha(state)


def _fields_diff(before, after):
    if before is None or after is None:
        return ["action_enabled_or_reverted"]
    paths = []
    def walk(left, right, prefix):
        if len(paths) >= 12:
            return
        if isinstance(left, dict) and isinstance(right, dict):
            for key in sorted(set(left) | set(right)):
                walk(left.get(key), right.get(key),
                     prefix + "." + str(key) if prefix else str(key))
        elif left != right:
            paths.append(prefix)
    walk(before, after, "")
    return paths[:12]


def _replay(model, trace, fuzz):
    state = copy.deepcopy(model["state"])
    expanded = {(name, actor): rule
                for name, actor, rule in fuzz.actions_for(model)}
    for label, actor in trace:
        rule = expanded.get((label, actor))
        if rule is None:
            return None
        state = fuzz.transition(state, rule)
        if state is None:
            return None
    return state


def _baseline_walk(model, fuzz, depth, max_states):
    possible = fuzz.actions_for(model)
    queue = deque([(copy.deepcopy(model["state"]), [])])
    seen = {_fingerprint_state(model["state"])}
    attempts, traces = 0, []
    truncation = False
    while queue:
        state, trace = queue.popleft()
        if len(trace) >= depth:
            continue
        for name, actor, rule in possible:
            attempts += 1
            trial = trace + [(name, actor)]
            nxt = fuzz.transition(state, rule)
            # Include unsuccessful attempts as guard/operator coverage
            traces.append((trial, nxt))
            if nxt is not None:
                digest = _fingerprint_state(nxt)
                if digest not in seen:
                    if len(seen) >= max_states:
                        truncation = True
                        break
                    seen.add(digest)
                    queue.append((nxt, trial))
        if truncation:
            break
    return traces, len(seen), attempts, truncation


def score(bank_data, property_spec, depth=4, max_states=300):
    source, mutants = _verify_bank(bank_data)
    rules = _properties(property_spec)
    if type(depth) is not int or not 1 <= depth <= 6:
        raise ValueError("depth must be 1..6")
    if type(max_states) is not int or not 1 <= max_states <= 3000:
        raise ValueError("max_states must be 1..3000")
    fuzz = _mod("scenario_fuzz")
    checker = _mod("invariant_check")
    traces, visited, attempted, truncated = _baseline_walk(
        source, fuzz, depth, max_states)
    if not traces:
        raise ValueError("no actual model actions attempted")
    rule_set = {"invariants": rules}
    baseline_failures = []
    states = [source["state"]]
    for trace, original_result in traces:
        if original_result is not None:
            states.append(original_result)
    for state in states:
        result = checker.evaluate(rule_set, state)
        if result["summary"]["fail"] or result["summary"]["unknown"]:
            baseline_failures.append({
                "state_sha256": _sha(state),
                "status": "BASELINE_INVARIANT_FAILURE_OR_UNKNOWN"})
            break
    if baseline_failures:
        return {"schema_version": 1,
                "status": "INVALID_BASELINE_PROPERTY_OR_MODEL",
                "baseline_failures": baseline_failures,
                "mutation_results": [], "denominator_validated": 0,
                "kill_rate": None, "target_executed": False,
                "bank_sha256": bank_data["bank_sha256"]}
    rows = []
    for mutant in mutants:
        m = mutant["mutant_model"]
        index = mutant["action_index"]
        action = source["actions"][index]
        base_action_name = action["name"]
        reached, divergence, caught = False, False, False
        witness = None
        detectors = []
        for trace, baseline in traces:
            # Mutations target the original action, but the source may
            # expand one action per actor; match the actor-aware names.
            if not any(t[0] == base_action_name or
                       t[0].startswith(base_action_name.replace("{actor}", ""))
                       for t in trace):
                continue
            reached = True
            changed = _replay(m, trace, fuzz)
            if baseline == changed:
                continue
            divergence = True
            if changed is None:
                if witness is None:
                    witness = {"first_divergent_trace": [
                        {"action": name, "actor": actor} for name, actor in trace],
                        "changed_fields": ["action_enabled_or_reverted"]}
                continue
            result = checker.evaluate(rule_set, changed)
            failed = [r["id"] for r in result["results"] if r["status"] == "fail"]
            if failed:
                caught = True
                detectors = sorted(set(detectors + failed))
                witness = {"first_divergent_trace": [
                    {"action": name, "actor": actor} for name, actor in trace],
                    "changed_fields": _fields_diff(baseline, changed),
                    "mutant_state_sha256": _sha(changed)}
                break
            if witness is None:
                witness = {"first_divergent_trace": [
                    {"action": name, "actor": actor} for name, actor in trace],
                    "changed_fields": _fields_diff(baseline, changed),
                    "mutant_state_sha256": _sha(changed)}
        status = ("NOT_REACHED" if not reached else
                  "OBSERVATIONALLY_EQUIVALENT_WITHIN_BOUNDS" if not divergence else
                  "KILLED_BY_PROPERTY" if caught else
                  "REACHED_DIFFERENT_BEHAVIOR_NOT_CAUGHT")
        rows.append({
            "mutant_id": mutant["id"], "operator": mutant["operator"],
            "source_action_index": index, "status": status,
            "mutation_action_attempted": reached,
            "behavioral_difference_observed": divergence,
            "property_kill_observed": caught,
            "property_ids_that_killed": detectors,
            "first_divergence": witness})
    eligible = [x for x in rows if x["status"] in (
        "KILLED_BY_PROPERTY", "REACHED_DIFFERENT_BEHAVIOR_NOT_CAUGHT")]
    killed = sum(x["status"] == "KILLED_BY_PROPERTY" for x in eligible)
    metrics = {"generated": len(rows), "not_reached": sum(
        x["status"] == "NOT_REACHED" for x in rows),
        "observationally_equivalent_within_bounds": sum(
            x["status"] == "OBSERVATIONALLY_EQUIVALENT_WITHIN_BOUNDS"
            for x in rows),
        "reached_changed_behavior": len(eligible),
        "caught": killed, "survived": len(eligible) - killed}
    return {
        "schema_version": 1, "mode": "property-blind-mutation-evaluation",
        "status": ("BOUNDED_EXPLORATION_INCOMPLETE" if truncated else
                   "LOCAL_STATE_MODEL_MUTATION_EVALUATION"),
        "bank_sha256": bank_data["bank_sha256"],
        "property_spec_sha256": _sha(property_spec),
        "property_provenance": [{
            "id": p["id"], "tier": p["provenance"]["tier"],
            "source_kind": p["provenance"]["source_kind"],
            "operator_review_asserted": p["provenance"]["reviewer_confirmed"]}
            for p in property_spec["rules"]],
        "depth": depth, "visited_states": visited,
        "baseline_action_attempts": attempted,
        "bounded_search_truncated": truncated,
        "metrics": metrics,
        "denominator_validated": len(eligible) if not truncated else 0,
        "kill_rate": (round(killed / len(eligible), 4)
                      if eligible and not truncated else None),
        "mutation_results": rows,
        "target_executed": False, "confirmed_vulnerabilities": 0,
        "real_model_calls": 0,
        "limitations": ("Independent property author and reviewer are operator "
                        "assertions, not cryptographic proof. A bounded model "
                        "mutation difference is not a Solidity target exploit. "
                        "Mutation equivalence is ONLY observational under the "
                        "listed depth/states; no unconditional equivalence is "
                        "claimed. Unreached and equivalent mutations are not "
                        "counted against property efficacy.")}
        

def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    subs = p.add_subparsers(dest="cmd", required=True)
    author_p = subs.add_parser("author-brief", help="prepare external-intent-only property author task")
    author_p.add_argument("--sources", required=True)
    author_p.add_argument("--out", required=True)
    bank_p = subs.add_parser("bank", help="create sealed model mutants without properties")
    bank_p.add_argument("--model", required=True)
    bank_p.add_argument("--out", required=True)
    bank_p.add_argument("--max-mutants", type=int, default=40)
    score_p = subs.add_parser("score", help="score separately authored source-backed invariants")
    score_p.add_argument("--bank", required=True)
    score_p.add_argument("--property-spec", required=True)
    score_p.add_argument("--out", required=True)
    score_p.add_argument("--depth", type=int, default=4)
    score_p.add_argument("--max-states", type=int, default=300)
    a = p.parse_args(argv)
    try:
        if a.cmd == "author-brief":
            result = author_brief(_read(a.sources))
        elif a.cmd == "bank":
            result = bank(_read(a.model), a.max_mutants)
        else:
            result = score(_read(a.bank), _read(a.property_spec),
                           a.depth, a.max_states)
        _save_new(a.out, result)
    except (OSError, ValueError, TypeError, KeyError, OverflowError,
            json.JSONDecodeError) as exc:
        p.error(str(exc))
    print(json.dumps({
        "out": a.out, "status": result.get("status", result["mode"]),
        "mutants": (len(result["mutants"]) if a.cmd == "bank" else
                    len(result["mutation_results"]) if a.cmd == "score" else 0),
        "confirmed_vulnerabilities": 0}))
    return 0 if a.cmd in ("bank", "author-brief") or result["status"] == (
        "LOCAL_STATE_MODEL_MUTATION_EVALUATION") else 2


if __name__ == "__main__":
    sys.exit(main())
