#!/usr/bin/env python3
"""Metamorphic economic test planning and exact measurement comparison for AVRE."""
import re


METAMORPHIC_FAMILIES = (
    {"id": "batch_vs_split", "signals": r"deposit|stake|supply|mint",
     "relation": "deposit(A+B) versus deposit(A) + deposit(B)",
     "expected_formula": "equal aggregate assets/shares after documented fees and rounding"},
    {"id": "large_vs_small_exit", "signals": r"withdraw|unstake|redeem|burn",
     "relation": "one large withdrawal versus multiple smaller withdrawals",
     "expected_formula": "equal total user proceeds and aggregate reserve change within documented rounding"},
    {"id": "shares_vs_assets", "signals": r"shares|assets|convertToAssets|convertToShares|previewDeposit|previewRedeem",
     "relation": "share-denominated versus asset-denominated route",
     "expected_formula": "equivalent value at the same pinned exchange-rate state"},
    {"id": "reward_transfer_order", "signals": r"claim|reward|checkpoint|transfer",
     "relation": "claim-before-transfer versus transfer-before-claim",
     "expected_formula": "ownership and reward weight follow the documented snapshot semantics"},
    {"id": "repay_route", "signals": r"repay|debt|borrow|liquidat",
     "relation": "repayment through alternate assets/shares routes",
     "expected_formula": "debt reduction equals applied repayment after documented fees and rounding"},
    {"id": "alternate_route", "signals": r"router|route|bridge|relayer|adapter|fallback",
     "relation": "equivalent operation through primary and alternate execution routes",
     "expected_formula": "the same authorized intent produces equivalent net accounting"},
)


def generate_plans(symbols, limit=100):
    if type(limit) is not int or not 1 <= limit <= 2000:
        raise ValueError("economic plan limit must be between 1 and 2000")
    plans, seen = [], set()
    for symbol in symbols:
        text = (str(symbol.get("symbol", "")) + " " +
                " ".join(symbol.get("reads_approx", []))).lower()
        for family in METAMORPHIC_FAMILIES:
            if not re.search(family["signals"], text):
                continue
            key = (family["id"], symbol.get("path"), symbol.get("symbol"))
            if key in seen:
                continue
            seen.add(key)
            plans.append({
                "family": family["id"], "relation": family["relation"],
                "expected_formula": family["expected_formula"],
                "equivalence_basis_required": True,
                "allowed_tolerance_required": True,
                "measurement_unit_required": True,
                "entry_point": {"path": symbol.get("path"), "symbol": symbol.get("symbol"),
                                "line": symbol.get("line")},
                "source_signals": sorted(set(re.findall(family["signals"], text))),
                "candidate_case": "execute both sides from equivalent pinned initial snapshots",
                "negative_control": "repeat with a documented guard/design condition restored",
                "status": "metamorphic_test_plan",
                "notice": "A nonzero difference is not a vulnerability until specification, fees, rounding, attacker control, reachability, and victim impact are established.",
            })
            if len(plans) >= limit:
                return plans
    return plans


def _amount(value, label):
    if type(value) is not int or value < 0:
        raise ValueError(label + " must be a nonnegative integer in the stated smallest unit")
    return value


def compare_measurements(document, current_revision, scope_decision):
    """Compare candidate/control balance deltas from a pinned, locally supplied test artifact.

    The result describes a measured discrepancy only. It does not infer that the discrepancy is
    unauthorized, profitable, exploitable, or contrary to the protocol's intended economics.
    """
    if not isinstance(document, dict) or document.get("schema_version") != 1:
        raise ValueError("economic measurements require schema_version: 1")
    revision = document.get("source_revision")
    if not isinstance(revision, str) or not re.fullmatch(r"[0-9a-fA-F]{40,64}", revision):
        raise ValueError("measurements must pin a full source_revision")
    if revision.lower() != current_revision.lower():
        raise ValueError("measurement source_revision does not match the analyzed HEAD")
    rows = document.get("comparisons")
    if not isinstance(rows, list) or len(rows) > 500:
        raise ValueError("comparisons must be an array of at most 500 paired observations")
    output, ids = [], set()
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise ValueError("comparison %d must be an object" % index)
        ident = row.get("id")
        basis, unit = row.get("equivalence_basis"), row.get("unit")
        if not isinstance(ident, str) or not ident or ident in ids:
            raise ValueError("comparison IDs must be nonempty and unique")
        ids.add(ident)
        if not isinstance(basis, str) or not basis.strip():
            raise ValueError(ident + " needs a specification-backed equivalence_basis")
        if not isinstance(unit, str) or not unit.strip():
            raise ValueError(ident + " needs a measurement unit")
        if scope_decision.get("classification") != "IN_SCOPE":
            status = "OUT_OF_SCOPE" if scope_decision.get("classification") == "RELATED_OUT_OF_SCOPE" else "NEEDS_EVIDENCE"
        else:
            status = "NEEDS_EVIDENCE"
        tolerance = _amount(row.get("tolerance", 0), ident + ".tolerance")
        deltas = {}
        for side in ("candidate", "control"):
            values = row.get(side)
            if not isinstance(values, dict):
                raise ValueError(ident + "." + side + " must include before and after")
            before = _amount(values.get("before"), ident + "." + side + ".before")
            after = _amount(values.get("after"), ident + "." + side + ".after")
            deltas[side] = after - before
        difference = abs(deltas["candidate"] - deltas["control"])
        output.append({
            "id": ident, "family": row.get("family", "unspecified"),
            "equivalence_basis": basis, "unit": unit, "tolerance": tolerance,
            "candidate_balance_delta": deltas["candidate"],
            "control_balance_delta": deltas["control"],
            "absolute_difference": difference,
            "measurement_result": "exceeds_declared_tolerance" if difference > tolerance else "within_declared_tolerance",
            "attacker_control": row.get("attacker_control", "not supplied"),
            "initial_state_digest": row.get("initial_state_digest"),
            "candidate_log_digest": row.get("candidate_log_digest"),
            "control_log_digest": row.get("control_log_digest"),
            "classification": status,
            "actual_impact": None,
            "missing_checks": ["verify both runs start from equivalent pinned states",
                               "confirm documented fee, rounding, decimal and time tolerances",
                               "establish attacker control and reachable public path",
                               "attribute any measured loss to an in-scope victim"],
            "notice": "Measured delta only; not a confirmed economic vulnerability or loss claim.",
        })
    return {"schema_version": 1, "source_revision": revision,
            "scope": scope_decision, "comparisons": output,
            "summary": {"cases": len(output),
                        "exceeds_tolerance": sum(x["measurement_result"] == "exceeds_declared_tolerance" for x in output),
                        "within_tolerance": sum(x["measurement_result"] == "within_declared_tolerance" for x in output)},
            "notice": "The evaluator compares exact integer deltas. It does not decide whether a difference is permitted by design or economically exploitable."}
