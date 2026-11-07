#!/usr/bin/env python3
"""Deterministic deep-audit planner: 1..3 cash flows, 3..4 relevant lenses.

Runs no target code and makes no severity/novelty claims. An agent supplies a
reviewed model of flows and explicit eligibility; this planner chooses where
bounded native experiments and independent adversarial review should go.
"""
import argparse
import json
import os
import re
import sys
from decimal import Decimal, InvalidOperation
from pathlib import Path

SHA = re.compile(r"^[0-9a-f]{40}([0-9a-f]{24})?$")
IDENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,79}$")
LENSES = {
    "vault": ("rounding-map", "state-invariants", "seam", "economic-differential"),
    "lending": ("oracle-listing", "state-invariants", "rounding-map", "economic-differential"),
    "amm": ("rounding-map", "v4-hook", "seam", "economic-differential"),
    "bridge": ("bridge-message", "identity-context", "failure-recovery", "sequence-mutation"),
    "wallet": ("wallet", "smart-account", "identity-context", "sequence-mutation"),
    "staking": ("state-invariants", "rounding-map", "sequence-mutation", "failure-recovery"),
    "governance": ("governance-capture", "identity-context", "sequence-mutation", "seam"),
    "generic": ("seam", "state-invariants", "sequence-mutation", "economic-differential"),
}


def _money(value):
    if not isinstance(value, (str, int)) or isinstance(value, bool) or len(str(value)) > 50:
        raise ValueError("value_at_risk_usd must be exact nonnegative decimal")
    try:
        number = Decimal(str(value))
    except InvalidOperation as exc:
        raise ValueError("invalid value_at_risk_usd") from exc
    if not number.is_finite() or number < 0:
        raise ValueError("value_at_risk_usd must be finite and nonnegative")
    return number


def plan(spec, flows_limit=3, lenses_limit=4, native_budget=12):
    if not isinstance(spec, dict) or spec.get("schema_version") != 1:
        raise ValueError("schema_version=1 required")
    revision = spec.get("source_revision")
    if not isinstance(revision, str) or not SHA.fullmatch(revision):
        raise ValueError("pinned source_revision required")
    if type(flows_limit) is not int or not 1 <= flows_limit <= 3:
        raise ValueError("flows_limit must be 1..3")
    if type(lenses_limit) is not int or not 3 <= lenses_limit <= 4:
        raise ValueError("lenses_limit must be 3..4")
    if type(native_budget) is not int or not 1 <= native_budget <= 32:
        raise ValueError("native_budget must be 1..32")
    flows = spec.get("flows")
    if not isinstance(flows, list) or not 1 <= len(flows) <= 100:
        raise ValueError("1..100 described flows required")
    rows, seen = [], set()
    for flow in flows:
        if not isinstance(flow, dict) or not isinstance(flow.get("id"), str) or not IDENT.fullmatch(flow["id"]):
            raise ValueError("each flow requires a safe id")
        if flow["id"] in seen:
            raise ValueError("duplicate flow id")
        seen.add(flow["id"])
        kind = flow.get("kind")
        if kind not in LENSES:
            raise ValueError("unsupported flow kind: " + str(kind))
        if flow.get("in_scope") is not True:
            continue
        risk = _money(flow.get("value_at_risk_usd", "0"))
        permissions = flow.get("unprivileged_reachable")
        if permissions not in (True, False, None):
            raise ValueError("unprivileged_reachable must be true/false/null")
        freshness = flow.get("changed_since_audit")
        if freshness not in (True, False, None):
            raise ValueError("changed_since_audit must be true/false/null")
        known = flow.get("known_duplicate")
        if known not in (True, False, None):
            raise ValueError("known_duplicate must be true/false/null")
        # Risk is a ranking signal, not a payout prediction. Never mark a
        # zero-value availability issue as harmless merely because no TVL exists.
        score = min(risk, Decimal("100000000")) / Decimal("1000000")
        if permissions is True:
            score += 15
        if freshness is True:
            score += 15
        if known is True:
            score -= 100
        if permissions is None:
            score -= 5
        rows.append({"id": flow["id"], "kind": kind, "score": score,
                     "value_at_risk_usd": str(risk), "permissions": permissions,
                     "freshness": freshness, "known_duplicate": known,
                     "entrypoints": flow.get("entrypoints", [])})
    selected = sorted(rows, key=lambda r: (-r["score"], r["id"]))[:flows_limit]
    if not selected:
        raise ValueError("no in-scope flows")
    for row in selected:
        row["score"] = str(row["score"])
        row["lenses"] = list(LENSES[row["kind"]][:lenses_limit])
        row["next_steps"] = [
            "Write actor/state model with external dependencies and trust boundaries",
            "Construct one specific falsifiable hypothesis per chosen lens",
            "Prepare pinned local candidate and protected negative-control test",
            "Run bounded native experiments through exploit_loop.py only in enforced isolation",
            "Verify exact-value/victim oracle and have a separate reviewer refute the witness",
        ]
    return {"schema_version": 1, "source_revision": revision, "mode": "deep",
            "flows_examined": len(flows), "flows_selected": selected,
            "native_variant_budget": native_budget,
            "stop_conditions": ["No new state coverage after two bounded native rounds",
                                "The alleged consequence is excluded by published scope",
                                "The mechanism matches a documented, unresolved duplicate",
                                "Independent negative control reproduces the same signal"],
            "execution": "planning-only",
            "notice": ("No code, ABI or funds are analyzed automatically here. "
                       "Ranks operator-supplied risk facts; estimates are not findings. "
                       "Native work remains opt-in on a pinned isolated local fork.")}


def _read(path):
    p = Path(path).expanduser()
    if p.is_symlink() or not p.is_file() or p.stat().st_size > 2_000_000:
        raise ValueError("spec must be regular non-symlink JSON <=2MB")
    return json.loads(p.read_text(encoding="utf-8"))


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--spec", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--flows", type=int, default=3)
    p.add_argument("--lenses", type=int, default=4)
    p.add_argument("--native-budget", type=int, default=12)
    a = p.parse_args(argv)
    out = Path(a.out).expanduser()
    if out.exists() or out.is_symlink():
        p.error("output must be create-only")
    try:
        result = plan(_read(a.spec), a.flows, a.lenses, a.native_budget)
    except (ValueError, TypeError, KeyError, OSError, json.JSONDecodeError) as exc:
        p.error(str(exc))
    out.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(out), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(result, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
    print(json.dumps({"out": str(out), "flows": len(result["flows_selected"]),
                      "execution": result["execution"]}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
