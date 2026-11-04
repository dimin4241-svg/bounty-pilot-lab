#!/usr/bin/env python3
"""Compare layered completion semantics and measured balance effects.

All observations are investigator-supplied local traces; classifications are
review leads, never automatic vulnerability reports. In particular an outer
extrinsic success is *not* assumed to imply every batch item succeeded.
"""
import argparse
import json
import os
from decimal import Decimal, InvalidOperation
from pathlib import Path


def _decimal(value, label):
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise ValueError(label + " must use an exact string or integer")
    try:
        x = Decimal(str(value))
    except InvalidOperation as exc:
        raise ValueError(label + " invalid") from exc
    if not x.is_finite():
        raise ValueError(label + " nonfinite")
    return x


def analyze(doc):
    if not isinstance(doc, dict) or doc.get("schema_version") != 1:
        raise ValueError("schema_version=1 required")
    rows = doc.get("observations")
    if not isinstance(rows, list) or not 1 <= len(rows) <= 1000:
        raise ValueError("observations must be 1..1000 entries")
    results = []
    for item in rows:
        if not isinstance(item, dict) or not isinstance(item.get("id"), str) or not item["id"]:
            raise ValueError("observation id required")
        nested = item.get("nested_results", [])
        if not isinstance(nested, list) or any(x not in ("success", "failure", "unknown") for x in nested):
            raise ValueError("nested_results must be success/failure/unknown")
        kind = item.get("ack_semantics")
        if kind not in ("final-settlement", "submitted-only", "unknown"):
            raise ValueError("ack_semantics must explicitly describe what acknowledgment means")
        if type(item.get("ack_success")) is not bool:
            raise ValueError("ack_success must be a boolean")
        flags, assumptions = [], []
        if kind == "final-settlement" and item["ack_success"] and "failure" in nested:
            flags.append("final-success-acknowledged-with-nested-failure")
        if kind == "submitted-only" and item["ack_success"] and "failure" in nested:
            assumptions.append("submission acknowledgment may precede per-item failure by design")
        if "unknown" in nested:
            assumptions.append("unknown nested completion states")
        expected, observed = item.get("expected_asset_delta"), item.get("observed_asset_delta")
        if expected is not None or observed is not None:
            if expected is None or observed is None:
                assumptions.append("incomplete asset delta pair")
            else:
                delta_expected = _decimal(expected, "expected_asset_delta")
                delta_observed = _decimal(observed, "observed_asset_delta")
                tol = _decimal(item.get("asset_tolerance", "0"), "asset_tolerance")
                if tol < 0:
                    raise ValueError("asset_tolerance must be nonnegative")
                if abs(delta_expected - delta_observed) > tol:
                    flags.append("asset-effect-diverges-from-declared-expectation")
        owner, receiver = item.get("entitlement_owner"), item.get("effective_receiver")
        if isinstance(owner, str) and isinstance(receiver, str) and owner and receiver and owner != receiver:
            if item.get("delegation_or_transfer_authorized") is False:
                flags.append("cross-actor-rights-transfer-needs-review")
            elif item.get("delegation_or_transfer_authorized") is not True:
                assumptions.append("delegation/transfer authorization unknown")
        results.append({"id": item["id"], "candidate_signals": flags, "uncertainties": assumptions,
                        "classification": "REVIEW_LEAD" if flags else "NO_CONTRADICTION_IN_SUPPLIED_OBSERVATION",
                        "source": item.get("source"), "source_revision": item.get("source_revision"),
                        "scope": item.get("scope", "unverified")})
    return {"schema_version": 1, "cases": len(results),
            "leads": sum(bool(r["candidate_signals"]) for r in results),
            "results": results,
            "notice": ("Compared supplied semantic outcomes only. No proof of runtime source, "
                       "attacker control, finality, actual loss or report eligibility. "
                       "Intentional partial batch success and queued acknowledgments must be "
                       "distinguished from final settlement.")}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--observations", required=True)
    p.add_argument("--out", required=True)
    a = p.parse_args(argv)
    source = Path(a.observations).expanduser()
    if not source.is_file() or source.is_symlink() or source.stat().st_size > 3_000_000:
        p.error("observation file must be a regular <=3MB local file")
    result = analyze(json.loads(source.read_text(encoding="utf-8")))
    dest = Path(a.out).expanduser()
    if dest.exists() or dest.is_symlink():
        p.error("--out must be create-only")
    fd = os.open(str(dest), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(result, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(json.dumps({"out": str(dest), "leads": result["leads"]}))


if __name__ == "__main__":
    main()
