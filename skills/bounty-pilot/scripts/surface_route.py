#!/usr/bin/env python3
"""Offline protocol-shape routing and explicit evidence gaps, not a scanner.

Every selection is user/operator asserted, never inferred from a marketing
name or one file extension. Native stacks without an implemented adapter are
marked methodology-only and must not be counted as executable coverage.
"""
import argparse
import json
import os
import sys
from pathlib import Path

MATRIX = {
    "cex-custody": (
        "custody balances; deposit confirmation/reorg; pending withdrawal, address binding, idempotency, API key and MFA scope",
        "two owned accounts and a disposable local DB/queue/worker emulator; no production withdrawals", "offline-transition-model"),
    "rollup-l2": (
        "L1 derivation; source finality; message origin and address aliasing; challenge/fault proof; forced inclusion; escape hatch",
        "pinned L1+L2 devnets, mock proof/challenge controls, messenger receipts and replay state", "offline-transition-model"),
    "restaking-lst": (
        "queued shares across slashing, beacon withdrawals, withdrawal credentials, delegation and validator churn",
        "local fork with queued exits and slash/no-slash paired trajectories; account for every pending claim",
        "offline-transition-model"),
    "perps": (
        "funding, mark/index price binding, collateral, liquidation partial fill, ADL and insurance deficit",
        "native matching-engine simulation with fixed-point math and paired market trajectories",
        "offline-transition-model"),
    "cdp-stablecoin": (
        "collateral auctions, redemption priority, PSM peg exposure, bad-debt and oracle freshness",
        "local vault/PSM simulation with honest price and changed price paired controls", "methodology-only"),
    "launchpad": (
        "bonding-curve rounding, migration boundary, minOut, fees and liquidity bootstrapping",
        "offline pricing fixture; native instruction/contract test for quote versus execution", "offline-transition-model"),
    "prediction-market": (
        "resolution oracle finality, winning outcome mapping, split/merge and escrow exhaustion",
        "local outcome settlement test with unresolved market and alternative resolution controls",
        "offline-transition-model"),
    "airdrop": (
        "Merkle leaf encoding, campaign/chain binding, claim nonce, cumulative accounting, vesting and revocation",
        "two-campaign leaf collision/replay tests with native Merkle verifier and negative proof",
        "offline-transition-model"),
    "lottery-vrf": (
        "VRF callback ownership, request-to-round binding, callback retries, jackpot double claim",
        "deterministic local VRF consumer mocks; never manipulate production randomness",
        "offline-transition-model"),
    "data-availability": (
        "sampling and availability proof binding, blob commitments, DA withholding, bridge/light-client finality",
        "pinned commitment/proof fixtures and local verifier; mock missing blob negative control",
        "offline-transition-model"),
    "light-client-bridge": (
        "header state root, validator set/weights, proof encoding, reorg depth, replay by chain and height",
        "pinned header/proof fixture with malformed cross-domain and honest controls",
        "methodology-only"),
    "ton": (
        "FunC/Tact asynchronous bounce, send modes, partial execution and jetton wallet discovery",
        "TON Sandbox/Blueprint and message trace replay; never assume EVM atomicity",
        "methodology-only"),
    "hyperliquid": (
        "HyperCore vs HyperEVM clearing/custody, asset bridge, stale exchange metadata and dual accounting",
        "chain-specific core/execution fixture; compare HyperCore and HyperEVM receipts",
        "methodology-only"),
    "fuel-sway": (
        "Fuel UTXO predicate ownership, asset ID, receipts, variable outputs and state access",
        "forc or Fuel local node with precise Sway compiler/VM versions and receipt checks",
        "methodology-only"),
    "near": (
        "NEAR asynchronous receipts, callback predecessor, promise result, storage deposits and refunds",
        "near-workspaces local sandbox; two-receipt partial failure and retry tests",
        "methodology-only"),
    "stacks-clarity": (
        "Clarity response handling, tx-sender versus contract-caller, postconditions and PoX",
        "Clarinet tests with explicit trait, principals and postcondition controls",
        "methodology-only"),
    "algorand": (
        "group transaction binding, rekey, clawback, ASA freeze and inner transaction minimum balance",
        "AlgoKit sandbox/TEAL AVM simulation with group and signed-transaction negative controls",
        "methodology-only"),
    "aleo": (
        "private record ownership, transition/public/private state, nullifiers and proving-key binding",
        "Leo/snarkVM local tests with synthetic records and independently verified public outputs",
        "methodology-only"),
    "bitcoin-bitvm": (
        "UTXO scripts, sighash flags, timelocked challenges, peg-in/out, witness malleability and operator veto",
        "regtest and transaction witness vectors; trace every dispute game timeout",
        "methodology-only"),
    "tee-fhe": (
        "SGX attestation identity, key rotation, sealed state rollback, encrypted result authorization",
        "mock attestation/rollback fixture; hardware measurement and side-channel claims need independent testing",
        "methodology-only"),
    "offchain-indexer": (
        "subgraph/reorg, confirmed versus optimistic state, keeper queues, retries, stale DB and signer divergence",
        "local DB and reorg event sequence with worker replay and authoritative on-chain control",
        "methodology-only"),
    "gas-resource-dos": (
        "EVM return bomb, 63/64 gas forwarding, bounded loops, queue liveness and retry gas ceiling",
        "local gas measurements and valid/invalid batch controls; never DoS public endpoints",
        "methodology-only"),
}


def select(shapes):
    if not isinstance(shapes, list) or not shapes:
        raise ValueError("at least one --shape required")
    if len(shapes) > 22 or len(shapes) != len(set(shapes)):
        raise ValueError("too many or duplicate shapes")
    unknown = sorted(set(shapes) - set(MATRIX))
    if unknown:
        raise ValueError("unknown shape(s): " + ", ".join(unknown))
    rows = []
    for shape in shapes:
        focus, evidence, support = MATRIX[shape]
        rows.append({"shape": shape, "review_focus": focus,
                     "required_native_evidence": evidence,
                     "implementation": support,
                     "scope_and_deployment_check_required": True,
                     "finding_status": "no-finding-research-plan-only"})
    return {"schema_version": 1, "mode": "offline-routing-only",
            "shapes": rows, "count": len(rows),
            "notice": ("A routing entry is not an implemented native adapter, a proven "
                       "issue, an in-scope asset, or evidence of payable impact. "
                       "Explicitly mark methodology-only directions in coverage.md.")}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--shape", action="append", choices=sorted(MATRIX),
                   help="explicitly reviewed target shape; repeatable")
    p.add_argument("--list", action="store_true", help="print known shapes and implementation levels")
    p.add_argument("--out", help="new private JSON file")
    args = p.parse_args(argv)
    if args.list:
        result = {k: MATRIX[k][2] for k in sorted(MATRIX)}
    else:
        try:
            result = select(args.shape or [])
        except ValueError as exc:
            p.error(str(exc))
    result_txt = json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.out:
        dest = Path(args.out).expanduser()
        if dest.is_symlink() or dest.exists():
            p.error("output exists; refusing overwrite")
        dest.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(dest), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(result_txt)
        print(json.dumps({"out": str(dest), "shapes": len(args.shape or []),
                          "mode": "offline-routing-only"}))
    else:
        print(result_txt, end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
