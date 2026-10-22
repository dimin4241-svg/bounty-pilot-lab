#!/usr/bin/env python3
"""Paired blind-benchmark comparison from bounty.py backtest_score 'scored' records.

No ground truth is fetched; inputs MUST already come from separately sealed hunts.
Unknown cases/versions or mismatched truth are errors, not silently dropped misses.
"""
import argparse
import json
from pathlib import Path

SEV = {"critical", "high"}

def normalize(case):
    if case.get("state") != "scored":
        raise ValueError("each case must be fully scored by the existing blind backtest")
    pin = case.get("pinned_commit")
    ident = case.get("case")
    if not isinstance(pin, str) or not pin or not isinstance(ident, str) or not ident:
        raise ValueError("scored backtest requires name and pinned commit")
    truth = {}
    found = set()
    for x in case.get("rediscovered", []):
        key = x["id"]
        if key in truth:
            raise ValueError("duplicated ground-truth ID")
        truth[key] = x["severity"]
        found.add(key)
    for x in case.get("missed", []):
        key = x["id"]
        if key in truth:
            raise ValueError("duplicated ground-truth ID")
        truth[key] = x["severity"]
    if case.get("published_findings") != len(truth):
        raise ValueError("published finding count differs from scored truth")
    if not case.get("sealed_at"):
        raise ValueError("unsealed report")
    return (ident, pin), truth, found

def _arm_metadata(value, name):
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ValueError(name + " metadata must be a JSON object")
    for key in ("model", "budget_limit_usd", "actual_cost_usd", "elapsed_seconds",
                "input_tokens", "output_tokens", "unique_mechanisms", "cost_coverage"):
        if key in value and key.endswith(("usd", "seconds", "tokens")):
            number = value[key]
            if number is not None and (isinstance(number, bool) or
                                       not isinstance(number, (int, float)) or number < 0):
                raise ValueError(name + "." + key + " must be a non-negative number or null")
    if "unique_mechanisms" in value and not (
            isinstance(value["unique_mechanisms"], list) and
            all(isinstance(item, str) for item in value["unique_mechanisms"])):
        raise ValueError(name + ".unique_mechanisms must be a string array")
    return value


def compare(baseline, candidate, baseline_metadata=None, candidate_metadata=None):
    if not isinstance(baseline, list) or not isinstance(candidate, list):
        raise ValueError("baseline/candidate must be JSON arrays of fully scored cases")
    def index(rows):
        result = {}
        for row in rows:
            key, truth, found = normalize(row)
            if key in result:
                raise ValueError("duplicate case and commit")
            result[key] = (truth, found)
        return result
    before, after = index(baseline), index(candidate)
    if set(before) != set(after) or not before:
        raise ValueError("baseline and candidate must contain same nonempty pinned cases")
    per_case, wins, losses, ties = [], 0, 0, 0
    total, n_before, n_after = 0, 0, 0
    for key in sorted(before):
        bt, bf = before[key]
        ct, cf = after[key]
        if bt != ct:
            raise ValueError("ground truth/severities differ between paired cases: " + key[0])
        severe = {ident for ident, severity in bt.items() if severity in SEV}
        found_before = bf & severe
        found_after = cf & severe
        total += len(severe)
        n_before += len(found_before)
        n_after += len(found_after)
        delta = len(found_after) - len(found_before)
        wins += delta > 0
        losses += delta < 0
        ties += delta == 0
        per_case.append({"case": key[0], "commit": key[1],
                         "high_critical_total": len(severe),
                         "baseline_found": len(found_before),
                         "candidate_found": len(found_after),
                         "gained_ids": sorted(found_after - found_before),
                         "lost_ids": sorted(found_before - found_after)})
    baseline_metadata = _arm_metadata(baseline_metadata, "baseline")
    candidate_metadata = _arm_metadata(candidate_metadata, "candidate")
    metadata = {"available": bool(baseline_metadata and candidate_metadata),
                "baseline": baseline_metadata, "candidate": candidate_metadata,
                "cost_efficiency": "unknown"}
    if baseline_metadata and candidate_metadata:
        bm, cm = baseline_metadata.get("model"), candidate_metadata.get("model")
        bb, cb = baseline_metadata.get("budget_limit_usd"), candidate_metadata.get("budget_limit_usd")
        bc, cc = baseline_metadata.get("actual_cost_usd"), candidate_metadata.get("actual_cost_usd")
        metadata["model_parity"] = bool(bm and cm and bm == cm)
        metadata["budget_cap_parity"] = bb is not None and cb is not None and bb == cb
        if isinstance(bc, (int, float)) and isinstance(cc, (int, float)) and bc > 0 and cc > 0:
            metadata["cost_delta_usd"] = round(cc - bc, 8)
            metadata["spend_parity_10_percent"] = abs(cc - bc) <= 0.10 * max(bc, cc)
            metadata["baseline_rediscoveries_per_usd"] = round(n_before / bc, 6)
            metadata["candidate_rediscoveries_per_usd"] = round(n_after / cc, 6)
            metadata["cost_efficiency"] = "measured-provider-reported-cost"
        else:
            metadata["cost_efficiency"] = "unknown-provider-cost-not-reported"
        metadata["mechanism_counts"] = {
            "baseline": len(set(baseline_metadata["unique_mechanisms"]))
            if isinstance(baseline_metadata.get("unique_mechanisms"), list) else None,
            "candidate": len(set(candidate_metadata["unique_mechanisms"]))
            if isinstance(candidate_metadata.get("unique_mechanisms"), list) else None,
            "meaning": "only unique mechanisms explicitly adjudicated and supplied by the reviewer count"}
    enough_cases = len(per_case) >= 5
    comparable_spend = bool(metadata.get("model_parity") and metadata.get("budget_cap_parity") and
                             metadata.get("spend_parity_10_percent") and
                             metadata.get("cost_efficiency") == "measured-provider-reported-cost")
    if not enough_cases or not comparable_spend:
        recommendation = "inconclusive-collect-more-controlled-data"
    elif wins > losses and n_after > n_before:
        recommendation = "candidate-earns-another-held-out-round; keep it opt-in"
    elif losses > wins or n_after < n_before:
        recommendation = "baseline-performed-better; do-not-enable-candidate-by-default"
    else:
        recommendation = "no-measured-advantage; keep experimental-mode-opt-in"
    return {"schema": 1, "method": "paired-blind-scored-counts",
            "cases": len(per_case), "high_critical_truth": total,
            "baseline_rediscovered": n_before, "candidate_rediscovered": n_after,
            "delta": n_after - n_before, "case_wins": wins, "case_losses": losses,
            "case_ties": ties, "details": per_case,
            "efficiency_metadata": metadata, "strategy_recommendation": recommendation,
            "precision_measured": False, "payout_prediction": False,
            "notice": "A positive result is not yet robust evidence of improvement: blinded/held-out selection, contamination, tool budget, model, runtime and manual decision quality must be controlled. No true-negative data or private duplicate visibility."}

def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--baseline", required=True, help="JSON array of prior scored backtest results")
    p.add_argument("--candidate", required=True, help="JSON array of 0.9 scored backtest results")
    p.add_argument("--baseline-metadata", help="JSON model/budget/cost/mechanism accounting for baseline arm")
    p.add_argument("--candidate-metadata", help="JSON model/budget/cost/mechanism accounting for candidate arm")
    p.add_argument("--out")
    a = p.parse_args(argv)
    try:
        b = json.loads(Path(a.baseline).read_text(encoding="utf-8"))
        c = json.loads(Path(a.candidate).read_text(encoding="utf-8"))
        bm = json.loads(Path(a.baseline_metadata).read_text(encoding="utf-8")) if a.baseline_metadata else None
        cm = json.loads(Path(a.candidate_metadata).read_text(encoding="utf-8")) if a.candidate_metadata else None
        report = compare(b, c, bm, cm)
    except (ValueError, OSError, KeyError, json.JSONDecodeError) as exc:
        p.error(str(exc))
    body = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    if a.out:
        Path(a.out).write_text(body, encoding="utf-8")
        print(json.dumps({"out": a.out, "delta": report["delta"]}))
    else:
        print(body, end="")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
