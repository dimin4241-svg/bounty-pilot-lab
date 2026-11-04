#!/usr/bin/env python3
"""Exact-decimal frontier over *measured* local economic attack experiments.

Never fabricate liquidity, prices, attacker access, flash-loan availability or
profitability outside tested points. Input values are untrusted until a native
fork test and a distinct reviewer check their assertions/provenance.
"""
import argparse
import json
import os
import re
from decimal import Decimal, InvalidOperation
from pathlib import Path

HEX = re.compile(r"^[0-9a-f]{40,64}$")
COST_FIELDS = ("manipulation_cost", "protocol_fees", "slippage_cost",
               "gas_cost", "funding_cost", "unrecovered_capital")


def amount(value, name):
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise ValueError(name + " must be exact decimal string or integer")
    try:
        result = Decimal(str(value))
    except InvalidOperation as exc:
        raise ValueError(name + " is invalid decimal") from exc
    if not result.is_finite() or result < 0:
        raise ValueError(name + " must be finite and nonnegative")
    return result


def analyze(measurements, available_capital=None):
    if not isinstance(measurements, dict) or measurements.get("schema_version") != 1:
        raise ValueError("expected schema_version=1")
    revision = measurements.get("source_revision")
    if not isinstance(revision, str) or not HEX.fullmatch(revision):
        raise ValueError("pinned source_revision is required")
    scenarios = measurements.get("scenarios")
    if not isinstance(scenarios, list) or not 1 <= len(scenarios) <= 2000:
        raise ValueError("scenarios must be 1..2000 measured points")
    if available_capital is not None:
        available_capital = amount(available_capital, "available_capital")
    seen = set()
    points = []
    for case in scenarios:
        if not isinstance(case, dict) or not isinstance(case.get("id"), str):
            raise ValueError("scenario needs id")
        ident = case["id"]
        if not ident or ident in seen:
            raise ValueError("scenario ids must be unique and nonempty")
        seen.add(ident)
        required = ("capital_required", "gross_extraction", "victim_loss",
                    "accessible_liquidity", *COST_FIELDS)
        if not all(key in case for key in required):
            raise ValueError("scenario " + ident + " is missing exact amounts")
        numeric = {key: amount(case[key], ident + "." + key) for key in required}
        costs = sum((numeric[key] for key in COST_FIELDS), Decimal(0))
        net = numeric["gross_extraction"] - costs
        flags = []
        if case.get("native_test_executed") is not True:
            flags.append("native execution not demonstrated")
        if case.get("paired_control_passed") is not True:
            flags.append("equivalent protected negative control not demonstrated")
        if case.get("capital_restored") is not True:
            flags.append("capital restoration not demonstrated")
        if case.get("position_closed") is not True:
            flags.append("attack position not closed")
        if case.get("unprivileged_reachability_verified") is not True:
            flags.append("unprivileged reachability unverified")
        if case.get("real_chain_state_verified") is not True:
            flags.append("pinned live contract state unverified")
        if numeric["gross_extraction"] > numeric["accessible_liquidity"]:
            flags.append("gross extraction exceeds measured accessible liquidity")
        if available_capital is not None and numeric["capital_required"] > available_capital:
            flags.append("required capital exceeds stated accessible budget")
        if numeric["victim_loss"] <= 0:
            flags.append("no positive victim loss at this measurement")
        if net <= 0:
            flags.append("nonpositive net at this measurement")
        eligible = not flags
        points.append({
            "id": ident, "capital_required": str(numeric["capital_required"]),
            "gross_extraction": str(numeric["gross_extraction"]),
            "victim_loss": str(numeric["victim_loss"]),
            "calculated_costs": str(costs), "net_before_tax": str(net),
            "conditions_met_by_supplied_observations": eligible,
            "flags": flags,
            "evidence": case.get("evidence"),
        })
    feasible = [p for p in points if p["conditions_met_by_supplied_observations"]]
    by_capital = sorted(feasible, key=lambda p: (Decimal(p["capital_required"]),
                                                -Decimal(p["net_before_tax"]), p["id"]))
    by_profit = sorted(feasible, key=lambda p: (-Decimal(p["net_before_tax"]),
                                               Decimal(p["capital_required"]), p["id"]))
    return {
        "schema_version": 1, "source_revision": revision,
        "unit": measurements.get("unit", "unspecified"),
        "measured": len(points), "positive_points_under_supplied_assumptions": len(feasible),
        "min_capital_positive_point": by_capital[0]["id"] if by_capital else None,
        "best_net_positive_point": by_profit[0]["id"] if by_profit else None,
        "points": points,
        "capital_budget": str(available_capital) if available_capital is not None else None,
        "classification": "UNVERIFIED_MEASUREMENT_FRONTIER",
        "notice": ("Discrete comparison of supplied values only, not a global optimizer, "
                   "profit proof, attacker funding source, mainnet exploit or severity claim. "
                   "A complete, identical-state native replay and reviewer are required. "
                   "Untested capital sizes and liquidity states remain unknown.")}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--measurements", required=True)
    parser.add_argument("--available-capital")
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    source = Path(args.measurements).expanduser()
    if not source.is_file() or source.is_symlink() or source.stat().st_size > 5_000_000:
        parser.error("measurements must be a regular <=5MB local file")
    result = analyze(json.loads(source.read_text(encoding="utf-8")), args.available_capital)
    target = Path(args.out).expanduser()
    if target.exists() or target.is_symlink():
        parser.error("output must be create-only")
    fd = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(result, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(json.dumps({"out": str(target), "positive_points_under_supplied_assumptions":
                      result["positive_points_under_supplied_assumptions"]}))


if __name__ == "__main__":
    main()
