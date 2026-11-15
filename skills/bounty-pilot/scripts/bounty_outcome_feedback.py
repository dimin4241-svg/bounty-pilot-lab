#!/usr/bin/env python3
"""Feedback scorecard from adjudicated Bounty Pilot report outcomes (offline).

No payout prediction: only user-provided disposition records, currencies and
effort. Pending reports are excluded from adjudicated success denominators.
"""
import argparse
import json
import os
import re
import sys
from collections import defaultdict
from decimal import Decimal, InvalidOperation
from pathlib import Path

ID = re.compile(r"[A-Za-z0-9_.:-]{1,100}\Z")
CURRENCY = re.compile(r"[A-Z]{3}\Z")
STATUSES = {"submitted", "pending", "accepted", "paid", "duplicate",
            "invalid", "informational", "rejected", "out-of-scope"}
CLOSED = STATUSES - {"submitted", "pending"}
MAX_CASES = 5000


def _number(value, name):
    if not isinstance(value, str):
        raise ValueError(name + " must be exact decimal string")
    try:
        num = Decimal(value)
    except InvalidOperation as exc:
        raise ValueError(name + " invalid decimal") from exc
    if not num.is_finite() or num < 0 or num > Decimal("100000000"):
        raise ValueError(name + " out of bounds")
    return num


def analyze(document):
    if not isinstance(document, dict) or document.get("schema_version") != 1:
        raise ValueError("feedback schema_version 1 required")
    reports = document.get("reports")
    if not isinstance(reports, list) or len(reports) > MAX_CASES:
        raise ValueError("bounded reports array required")
    seen = set()
    groups = defaultdict(lambda: {"all": 0, "adjudicated": 0, "accepted": 0,
                                  "paid": 0, "duplicate": 0,
                                  "hours": Decimal(0),
                                  "payout": defaultdict(Decimal)})
    for row in reports:
        if not isinstance(row, dict):
            raise ValueError("report must be object")
        key, method, status = row.get("report_id"), row.get("method"), row.get("status")
        if not isinstance(key, str) or not ID.fullmatch(key) or key in seen:
            raise ValueError("duplicate or invalid report id")
        if not isinstance(method, str) or not ID.fullmatch(method):
            raise ValueError("invalid method")
        if status not in STATUSES:
            raise ValueError("invalid disposition")
        seen.add(key)
        hours = _number(row.get("research_hours"), "research_hours")
        amount = _number(row.get("payout_amount"), "payout_amount")
        currency = row.get("currency")
        if not isinstance(currency, str) or not CURRENCY.fullmatch(currency):
            raise ValueError("ISO currency required")
        if status != "paid" and amount:
            raise ValueError("payout only counted when status is paid")
        group = groups[method]
        group["all"] += 1
        group["hours"] += hours
        if status in CLOSED:
            group["adjudicated"] += 1
        if status in {"accepted", "paid"}:
            group["accepted"] += 1
        if status == "paid":
            group["paid"] += 1
            group["payout"][currency] += amount
        if status == "duplicate":
            group["duplicate"] += 1
    result = []
    for method, group in sorted(groups.items()):
        closed = group["adjudicated"]
        result.append({
            "method": method, "reports": group["all"], "adjudicated": closed,
            "accepted_or_paid": group["accepted"], "paid": group["paid"],
            "duplicates": group["duplicate"],
            "duplicate_rate_of_adjudicated": (
                str((Decimal(group["duplicate"]) / Decimal(closed)).quantize(
                    Decimal("0.0001"))) if closed else None),
            "accepted_or_paid_rate_of_adjudicated": (
                str((Decimal(group["accepted"]) / Decimal(closed)).quantize(
                    Decimal("0.0001"))) if closed else None),
            "research_hours": str(group["hours"]),
            "observed_paid_totals": {k: str(v) for k, v in
                                     sorted(group["payout"].items())},
        })
    return {
        "schema_version": 1, "engine": "bounty-outcome-feedback",
        "groups": result, "total_reports": len(reports),
        "claims": "operator-entered outcomes, not independently confirmed",
        "predicted_future_payout": False,
        "limitations": ["open reports excluded from adjudicated denominator",
                        "no confidence intervals with small samples",
                        "currencies not converted or combined",
                        "selection bias and severity variations unadjusted"],
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--history", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    try:
        p = Path(a.history)
        if p.is_symlink() or not p.is_file() or p.stat().st_size > 2 * 1024 * 1024:
            raise ValueError("bounded regular history JSON required")
        report = analyze(json.loads(p.read_text("utf-8")))
        out = Path(a.out)
        if out.exists() or out.is_symlink() or not out.parent.is_dir():
            raise ValueError("output must be a new file")
        fd = os.open(str(out), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(report, f, sort_keys=True, indent=2)
            f.write("\n")
        print(json.dumps({"total_reports": report["total_reports"],
                          "predicted_future_payout": False}))
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print("Error: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
