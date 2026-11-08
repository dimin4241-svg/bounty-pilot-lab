#!/usr/bin/env python3
"""Offline, conservative differential review of financial state transitions.

NO HTTP/RPC, signatures, wallet operations, exploit construction, or production
execution. Input observations are entirely researcher-supplied; a differential
lead is not a vulnerability, valid transaction, proven economic loss or payout.
"""
import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path

MAX_INPUT = 2_000_000
HEX40 = re.compile(r"^[0-9a-fA-F]{40}$")
HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")
DOMAINS = ("cex-custody", "rollup-l2", "restaking-lst", "perps",
           "launchpad", "prediction-market", "airdrop", "data-availability",
           "lottery-vrf")


def integer(obj, key, minimum=None):
    value = obj.get(key)
    if type(value) is not int or (minimum is not None and value < minimum):
        raise ValueError("%s must be an integer%s" % (
            key, " >= %d" % minimum if minimum is not None else ""))
    return value


def boolean(obj, key):
    value = obj.get(key)
    if type(value) is not bool:
        raise ValueError("%s must be boolean" % key)
    return value


def string(obj, key):
    value = obj.get(key)
    if not isinstance(value, str) or not 1 <= len(value) <= 160:
        raise ValueError("%s must be a nonempty bounded string" % key)
    return value


def _cex(o):
    a0, h0 = integer(o, "available_before", 0), integer(o, "held_before", 0)
    a1, h1 = integer(o, "available_after", 0), integer(o, "held_after", 0)
    inflow = integer(o, "settled_inflow", 0)
    outflow = integer(o, "settled_outflow", 0)
    settled = integer(o, "settlement_count", 0)
    attempted = boolean(o, "same_operation_id")
    confirmed = boolean(o, "deposit_finalized")
    credit = integer(o, "deposit_credit", 0)
    reviewed = string(o, "reviewed_destination")
    signed = string(o, "authorized_destination")
    v = []
    if a0 + h0 + inflow != a1 + h1 + outflow:
        v.append("funds-conservation")
    if settled > 1 and attempted:
        v.append("duplicate-withdrawal-settlement")
    if not confirmed and credit:
        v.append("unfinalized-deposit-credit")
    if reviewed != signed:
        v.append("withdrawal-destination-binding")
    return v, {"expected_total": a0 + h0 + inflow,
               "observed_total": a1 + h1 + outflow}


def _rollup(o):
    executions = integer(o, "execution_count", 0)
    source_finalized = boolean(o, "source_finalized")
    proof = boolean(o, "proof_verified")
    challenge = boolean(o, "challenge_window_closed")
    origin = boolean(o, "origin_and_alias_bound")
    payload = boolean(o, "payload_bound")
    invalidated = boolean(o, "message_invalidated")
    v = []
    if executions > 1:
        v.append("message-replayed")
    if executions and not (source_finalized and proof and challenge):
        v.append("unfinalized-message-executed")
    if executions and not (origin and payload):
        v.append("message-domain-or-payload-unbound")
    if executions and invalidated:
        v.append("challenged-message-executed")
    return v, {"executions": executions}


def _restaking(o):
    shares = integer(o, "total_shares_including_exit_queue", 1)
    queued = integer(o, "queued_shares", 0)
    if queued > shares:
        raise ValueError("queued_shares exceeds total_shares")
    assets = integer(o, "assets_after_slash", 0)
    paid = integer(o, "observed_exit_payout", 0)
    burned = integer(o, "burned_exit_shares", 0)
    no_flows = boolean(o, "no_other_asset_flows")
    if not no_flows:
        raise ValueError("restaking scenario needs independently excluded unrelated flows")
    v = []
    fair = queued * assets // shares
    if paid > fair:
        v.append("exit-payout-exceeds-post-slash-entitlement")
    if burned < queued and paid:
        v.append("paid-exit-with-unburned-queued-shares")
    if burned > queued:
        v.append("exit-burns-other-owners-shares")
    return v, {"maximum_exit_payout": fair, "observed_exit_payout": paid}


def _perps(o):
    margin = integer(o, "margin_collateral", 0)
    size = integer(o, "signed_base_position")
    entry = integer(o, "entry_price", 0)
    mark = integer(o, "mark_price", 0)
    maintenance = integer(o, "maintenance_bps", 0)
    if maintenance > 10000:
        raise ValueError("maintenance_bps must be <=10000")
    funding = integer(o, "funding_paid")
    closed_funding = boolean(o, "funding_is_closed_system")
    funding_net = integer(o, "net_funding_across_all_participants")
    executed_liquidation = boolean(o, "liquidation_executed")
    # Prices are integers in a declared matching scale; signed_base_position is
    # a whole number of base units. Do not infer decimals or oracle credibility.
    pnl = size * (mark - entry)
    equity = margin + pnl - funding
    requirement = abs(size) * mark * maintenance // 10000
    v = []
    if executed_liquidation and equity >= requirement:
        v.append("healthy-account-liquidated")
    if closed_funding and funding_net != 0:
        v.append("closed-system-funding-not-conserved")
    return v, {"equity": equity, "maintenance_requirement": requirement}


def _launchpad(o):
    actual = integer(o, "actual_tokens_out", 0)
    minimum = integer(o, "minimum_tokens_out", 0)
    succeeded = boolean(o, "purchase_succeeded")
    v = ["min-output-bypassed"] if succeeded and actual < minimum else []
    return v, {"actual_out": actual, "min_out": minimum}


def _prediction(o):
    escrow = integer(o, "settlement_collateral", 0)
    redeemed = integer(o, "total_redeemed", 0)
    finalized = boolean(o, "outcome_finalized")
    v = []
    if redeemed > escrow:
        v.append("market-payout-exceeds-collateral")
    if redeemed and not finalized:
        v.append("payout-before-outcome-finality")
    return v, {"available_collateral": escrow, "redeemed": redeemed}


def _airdrop(o):
    allocated = integer(o, "leaf_allocation", 0)
    claimed = integer(o, "cumulative_claimed", 0)
    uses = integer(o, "claim_count", 0)
    single = boolean(o, "single_use_leaf")
    domain = boolean(o, "campaign_and_chain_bound")
    v = []
    if claimed > allocated:
        v.append("claimed-above-merkle-allocation")
    if single and uses > 1:
        v.append("single-use-leaf-replayed")
    if claimed and not domain:
        v.append("unbound-claim-domain")
    return v, {"claimed": claimed, "allocated": allocated}


def _da(o):
    settled = boolean(o, "settlement_accepted")
    commitment = boolean(o, "commitment_verified")
    available = boolean(o, "data_availability_verified")
    provenance = boolean(o, "origin_domain_verified")
    v = []
    if settled and not (commitment and available):
        v.append("settlement-without-availability-evidence")
    if settled and not provenance:
        v.append("settlement-without-domain-binding")
    return v, {}


def _lottery(o):
    paid = boolean(o, "prize_paid")
    proof = boolean(o, "vrf_proof_verified")
    request = boolean(o, "randomness_request_bound")
    consumed = integer(o, "claim_count_for_single_prize", 0)
    v = []
    if paid and not (proof and request):
        v.append("payout-without-bound-vrf-proof")
    if consumed > 1:
        v.append("single-prize-replayed")
    return v, {}


CHECKS = {"cex-custody": _cex, "rollup-l2": _rollup,
          "restaking-lst": _restaking, "perps": _perps,
          "launchpad": _launchpad, "prediction-market": _prediction,
          "airdrop": _airdrop, "data-availability": _da, "lottery-vrf": _lottery}


def _case(row):
    if not isinstance(row, dict):
        raise ValueError("each case must be an object")
    name = string(row, "id")
    domain = string(row, "domain")
    if domain not in CHECKS:
        raise ValueError("unknown domain " + domain)
    revision = string(row, "source_revision")
    digest = string(row, "initial_state_digest")
    if not HEX40.fullmatch(revision) or not HEX64.fullmatch(digest):
        raise ValueError("source_revision must be 40 hex and state digest 64 hex")
    candidate = row.get("candidate")
    control = row.get("negative_control")
    if not isinstance(candidate, dict) or not isinstance(control, dict):
        raise ValueError("paired candidate and negative_control are required")
    # These are declarations supplied by the researcher, NOT independently
    # authenticated native receipts. Still block inconsistent claims.
    for label, item in (("candidate", candidate), ("negative_control", control)):
        if item.get("source_revision") != revision or item.get("initial_state_digest") != digest:
            return {"id": name, "domain": domain, "status": "inconclusive-binding",
                    "blockers": [label + ":different-source-or-initial-state"],
                    "candidate_violations": [], "control_violations": []}
    c, cm = CHECKS[domain](candidate)
    k, km = CHECKS[domain](control)
    if c and not k:
        status = "differential-lead-needs-native-verification"
    elif c and k:
        status = "not-isolated-control-also-violates"
    else:
        status = "no-differential-violation"
    return {"id": name, "domain": domain, "status": status,
            "candidate_violations": sorted(c), "control_violations": sorted(k),
            "candidate_measurements": cm, "control_measurements": km,
            "source_revision": revision, "initial_state_digest": digest,
            "evidence_level": "unverified-researcher-supplied"}


def evaluate(doc):
    if not isinstance(doc, dict) or doc.get("schema_version") != 1:
        raise ValueError("schema_version=1 is required")
    rows = doc.get("cases")
    if not isinstance(rows, list) or not 1 <= len(rows) <= 250:
        raise ValueError("cases must be a nonempty list <=250")
    results, seen = [], set()
    for row in rows:
        r = _case(row)
        if r["id"] in seen:
            raise ValueError("duplicate case id")
        seen.add(r["id"])
        results.append(r)
    return {"schema_version": 1, "execution": "offline-analysis-only",
            "case_count": len(results),
            "differential_leads": sum(x["status"] == "differential-lead-needs-native-verification" for x in results),
            "results": results,
            "notice": ("Inputs, native execution, initial-state digests, prices, scope and "
                       "real-world exploitability are not independently verified. A lead is "
                       "never proof of a vulnerability, funds at risk or payout.")}


def _pairs_only(items):
    obj = {}
    for k, v in items:
        if k in obj:
            raise ValueError("duplicate JSON key: " + k[:80])
        obj[k] = v
    return obj


def load(path):
    p = Path(path).expanduser()
    if p.is_symlink() or not p.is_file() or p.stat().st_size > MAX_INPUT:
        raise ValueError("input must be a regular non-symlink file <=2MB")
    return json.loads(p.read_text(encoding="utf-8"), object_pairs_hook=_pairs_only)


def store(path, result):
    p = Path(path).expanduser()
    if p.is_symlink() or p.exists():
        raise ValueError("output must not exist (no overwrite)")
    p.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, sort_keys=True, indent=2)
        f.write("\n")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--input", required=True, help="private paired-observations JSON")
    ap.add_argument("--out", required=True, help="new private JSON result outside checkout")
    args = ap.parse_args(argv)
    try:
        result = evaluate(load(args.input))
        store(args.out, result)
    except (ValueError, OSError, TypeError, KeyError) as err:
        ap.error(str(err))
    print(json.dumps({"cases": result["case_count"], "differential_leads": result["differential_leads"],
                      "execution": result["execution"], "out": args.out}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
