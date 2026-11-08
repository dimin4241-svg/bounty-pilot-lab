#!/usr/bin/env python3
"""Deterministic, disconnected reference state machines for four money flows.

These are toy *specification* models for test design, never production emulators.
They do not simulate real network finality, oracle correctness, EVM gas,
transaction signature validity or matching engines. Compare their expected
transitions with real native harness receipts before asserting a vulnerability.
No network, RPC, wallet access, trading or production API calls.
"""
import argparse
import copy
import json
import os
import sys
from pathlib import Path


class Rejected(Exception):
    pass


def amount(obj, field, minimum=1):
    v = obj.get(field)
    if type(v) is not int or v < minimum:
        raise Rejected("%s must be integer >=%d" % (field, minimum))
    return v


def name(obj, field):
    value = obj.get(field)
    if not isinstance(value, str) or not 1 <= len(value) <= 100:
        raise Rejected("%s must be nonempty text" % field)
    return value


def truth(obj, field):
    v = obj.get(field)
    if type(v) is not bool:
        raise Rejected("%s must be explicit boolean" % field)
    return v


def owner(state, ident, field="accounts"):
    if ident not in state[field]:
        raise Rejected("unknown owned account (no authorization inferred): " + ident)
    return state[field][ident]


def cex(st, event):
    op = name(event, "op")
    if op == "deposit":
        ident = name(event, "id")
        receiver = name(event, "account")
        amt = amount(event, "amount")
        final = truth(event, "finalized")
        if ident in st["seen_deposits"]:
            raise Rejected("deposit replay")
        if not final:
            raise Rejected("cannot credit unfinalized deposit")
        owner(st, receiver)
        st["seen_deposits"].append(ident)
        st["accounts"][receiver]["available"] += amt
        st["custody"] += amt
    elif op == "withdraw_request":
        ident = name(event, "id")
        receiver = name(event, "account")
        amt = amount(event, "amount")
        shown = name(event, "reviewed_destination")
        authorized = name(event, "authorized_destination")
        if shown != authorized:
            raise Rejected("signed withdrawal destination not user-reviewed")
        if ident in st["withdrawals"]:
            raise Rejected("request id already used")
        acc = owner(st, receiver)
        if acc["available"] < amt:
            raise Rejected("insufficient available funds")
        acc["available"] -= amt
        acc["held"] += amt
        st["withdrawals"][ident] = {
            "account": receiver, "amount": amt, "destination": authorized,
            "status": "pending"}
    elif op in ("withdraw_settle", "withdraw_cancel"):
        ident = name(event, "id")
        row = st["withdrawals"].get(ident)
        if row is None or row["status"] != "pending":
            raise Rejected("withdrawal missing or already finalized")
        acc = owner(st, row["account"])
        amt = row["amount"]
        if acc["held"] < amt:
            raise Rejected("held balance shortfall")
        acc["held"] -= amt
        if op == "withdraw_settle":
            if st["custody"] < amt:
                raise Rejected("custody shortfall")
            st["custody"] -= amt
            row["status"] = "settled"
        else:
            acc["available"] += amt
            row["status"] = "cancelled"
    elif op == "transfer":
        ident = name(event, "id")
        src, dst = name(event, "source"), name(event, "destination")
        amt = amount(event, "amount")
        if ident in st["transfers"]:
            raise Rejected("idempotency key already committed")
        a, b = owner(st, src), owner(st, dst)
        if a["available"] < amt:
            raise Rejected("insufficient available funds")
        a["available"] -= amt
        b["available"] += amt
        st["transfers"].append(ident)
    else:
        raise Rejected("unsupported custody action")
    total = sum(x["available"] + x["held"] for x in st["accounts"].values())
    if total != st["custody"]:
        raise Rejected("custody conservation violated")
    return {"liabilities": total, "custody": st["custody"]}


def rollup(st, event):
    op = name(event, "op")
    ident = name(event, "id")
    if op == "post":
        if ident in st["messages"]:
            raise Rejected("message id already used")
        st["messages"][ident] = {
            "origin": name(event, "origin"), "destination": name(event, "destination"),
            "payload_digest": name(event, "payload_digest"),
            "source_finalized": truth(event, "source_finalized"),
            "proof_verified": False, "challenge_closed": False,
            "invalidated": False, "executed": False}
    else:
        item = st["messages"].get(ident)
        if not item:
            raise Rejected("message missing")
        if op == "prove":
            if item["invalidated"] or not truth(event, "proof_verified"):
                raise Rejected("valid proof required")
            item["proof_verified"] = True
        elif op == "close_challenge":
            if item["invalidated"] or not truth(event, "challenge_window_closed"):
                raise Rejected("challenge still open")
            item["challenge_closed"] = True
        elif op == "invalidate":
            if item["executed"]:
                raise Rejected("cannot retroactively erase settled effect")
            item["invalidated"] = True
        elif op == "execute":
            if item["executed"]:
                raise Rejected("message replay")
            if item["invalidated"] or not all(
                    item[k] for k in ("source_finalized", "proof_verified",
                                      "challenge_closed")):
                raise Rejected("proof, finality or challenge condition not satisfied")
            if (name(event, "origin") != item["origin"] or
                    name(event, "destination") != item["destination"] or
                    name(event, "payload_digest") != item["payload_digest"]):
                raise Rejected("message origin/alias/payload mismatch")
            item["executed"] = True
        else:
            raise Rejected("unsupported rollup operation")
    return {"consumed_messages": sum(1 for x in st["messages"].values() if x["executed"])}


def restaking(st, event):
    op = name(event, "op")
    if op == "stake":
        addr = name(event, "account")
        amt = amount(event, "amount")
        owner(st, addr, "available_shares")
        current = st["total_shares"]
        assets = st["assets"]
        minted = amt if current == 0 else (amt * current // assets if assets else 0)
        if minted <= 0:
            raise Rejected("zero minted shares or missing backing")
        st["available_shares"][addr] += minted
        st["total_shares"] += minted
        st["assets"] += amt
    elif op == "queue_exit":
        ident = name(event, "id")
        addr = name(event, "account")
        count = amount(event, "shares")
        if ident in st["exits"]:
            raise Rejected("duplicate exit id")
        available = owner(st, addr, "available_shares")
        if available < count:
            raise Rejected("insufficient unqueued shares")
        st["available_shares"][addr] -= count
        st["exits"][ident] = {"account": addr, "shares": count, "status": "pending"}
    elif op == "slash":
        reduction = amount(event, "amount")
        if reduction > st["assets"]:
            raise Rejected("slash exceeds assets")
        st["assets"] -= reduction
    elif op == "settle_exit":
        ident = name(event, "id")
        row = st["exits"].get(ident)
        if row is None or row["status"] != "pending":
            raise Rejected("exit absent or already settled")
        count = row["shares"]
        total = st["total_shares"]
        if not total:
            raise Rejected("no remaining shares")
        payout = count * st["assets"] // total
        st["total_shares"] -= count
        st["assets"] -= payout
        row["status"] = "settled"
        row["payout"] = payout
        response = {"payout": payout}
    else:
        raise Rejected("unsupported restaking action")
    outstanding = (sum(st["available_shares"].values()) +
                   sum(r["shares"] for r in st["exits"].values()
                       if r["status"] == "pending"))
    if outstanding != st["total_shares"] or st["assets"] < 0:
        raise Rejected("share conservation violated")
    return dict(response if op == "settle_exit" else {},
                assets=st["assets"], total_shares=st["total_shares"])


def perps(st, event):
    op = name(event, "op")
    if op == "funding":
        payer, payee = name(event, "payer"), name(event, "receiver")
        amt = amount(event, "amount")
        a = owner(st, payer, "margins")
        owner(st, payee, "margins")
        if a < amt:
            raise Rejected("insufficient funding margin")
        st["margins"][payer] -= amt
        st["margins"][payee] += amt
        return {"funding_paid": amt, "margin_total": sum(st["margins"].values())}
    if op == "liquidation_check":
        who = name(event, "account")
        pos = owner(st, who, "positions")
        mark = amount(event, "mark_price")
        m = st["margins"][who]
        size, entry = pos["size"], pos["entry_price"]
        equity = m + size * (mark - entry)
        req = abs(size) * mark * st["maintenance_bps"] // 10000
        return {"equity": equity, "maintenance_requirement": req,
                "eligible": equity < req}
    raise Rejected("unsupported perps operation")


ENGINES = {"cex-custody": cex, "rollup-l2": rollup,
           "restaking-lst": restaking, "perps": perps}


def prepare(domain, initial):
    if domain not in ENGINES:
        raise ValueError("unsupported simulation domain")
    if not isinstance(initial, dict):
        raise ValueError("initial state must be object")
    st = copy.deepcopy(initial)
    if domain == "cex-custody":
        st.setdefault("seen_deposits", [])
        st.setdefault("withdrawals", {})
        st.setdefault("transfers", [])
        if type(st.get("custody")) is not int or st["custody"] < 0:
            raise ValueError("custody must be nonnegative integer")
        for k, row in st.get("accounts", {}).items():
            if (not isinstance(row, dict) or
                    any(type(row.get(field)) is not int or row[field] < 0
                        for field in ("available", "held"))):
                raise ValueError("invalid account balances")
        if sum(v["available"] + v["held"] for v in st["accounts"].values()) != st["custody"]:
            raise ValueError("initial custody does not match liabilities")
        if st["withdrawals"] or st["transfers"] or st["seen_deposits"]:
            raise ValueError("initial example may not preseed operation receipts")
    elif domain == "rollup-l2":
        if st.get("messages") != {}:
            raise ValueError("rollup simulator starts with no messages")
    elif domain == "restaking-lst":
        if not isinstance(st.get("available_shares"), dict) or st.get("exits") != {}:
            raise ValueError("restaking requires available_shares and empty exits")
        if any(type(x) is not int or x < 0 for x in st["available_shares"].values()):
            raise ValueError("invalid shares")
        if type(st.get("assets")) is not int or st["assets"] < 0:
            raise ValueError("invalid assets")
        if type(st.get("total_shares")) is not int or (
                sum(st["available_shares"].values()) != st["total_shares"]):
            raise ValueError("initial share conservation failed")
    elif domain == "perps":
        if (not isinstance(st.get("positions"), dict) or
                not isinstance(st.get("margins"), dict) or
                set(st["positions"]) != set(st["margins"])):
            raise ValueError("positions and margin accounts must match")
        if (type(st.get("maintenance_bps")) is not int or
                not 0 <= st["maintenance_bps"] <= 10000):
            raise ValueError("invalid maintenance threshold")
        if any(type(m) is not int or m < 0 for m in st["margins"].values()):
            raise ValueError("invalid margins")
        if any(type(p.get("size")) is not int or
               type(p.get("entry_price")) is not int or p["entry_price"] < 0
               for p in st["positions"].values()):
            raise ValueError("invalid position")
    return st


def simulate(doc):
    if not isinstance(doc, dict) or doc.get("schema_version") != 1:
        raise ValueError("schema_version=1 required")
    domain = doc.get("domain")
    st = prepare(domain, doc.get("initial"))
    events = doc.get("actions")
    if not isinstance(events, list) or not 1 <= len(events) <= 200:
        raise ValueError("actions must be list of 1..200")
    receipts = []
    for i, event in enumerate(events):
        if not isinstance(event, dict):
            raise ValueError("action must be object")
        proposed = copy.deepcopy(st)
        try:
            extra = ENGINES[domain](proposed, event)
            st = proposed
            receipts.append({"index": i, "op": event.get("op"),
                             "status": "accepted", "observations": extra})
        except Rejected as exc:
            receipts.append({"index": i, "op": event.get("op"),
                             "status": "rejected-by-reference-model",
                             "reason": str(exc)})
    return {"schema_version": 1, "domain": domain,
            "execution": "disconnected-local-reference-model",
            "accepted": sum(r["status"] == "accepted" for r in receipts),
            "rejected": sum(r["status"] != "accepted" for r in receipts),
            "receipts": receipts, "final_state": st,
            "notice": ("This is a synthetic expectation, not a replay of a target "
                       "or a native financial operation. A model rejection is not a "
                       "proven real exploit. Verify against unmodified scoped source "
                       "and an independent honest negative control.")}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--input", required=True)
    p.add_argument("--out", required=True)
    args = p.parse_args(argv)
    try:
        source = Path(args.input).expanduser()
        if source.is_symlink() or not source.is_file() or source.stat().st_size > 2_000_000:
            raise ValueError("input must be a local regular JSON <=2MB")
        result = simulate(json.loads(source.read_text(encoding="utf-8")))
        target = Path(args.out).expanduser()
        if target.is_symlink() or target.exists():
            raise ValueError("output exists")
        target.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(target), os.O_WRONLY | os.O_EXCL | os.O_CREAT, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False, sort_keys=True)
            f.write("\n")
    except (ValueError, TypeError, KeyError, OSError) as exc:
        p.error(str(exc))
    print(json.dumps({"domain": result["domain"], "accepted": result["accepted"],
                      "rejected": result["rejected"], "out": args.out}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
