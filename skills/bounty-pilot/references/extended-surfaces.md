# Extended shapes, runtime adapters and difficult seams

This is a **methodology index**, NOT a claim that native adapters exist for
all technologies. Check actual bounty scope and explicit exclusions. Do not
load-test live services, brute-force, or test other users' accounts.

## L2/rollups

* **Derivation:** trace L1 calldata/blobs into batches and output state roots.
  Check batch origin, data availability and L1 reorgs.
* **Withdrawals:** compare sender address across L1/L2 aliasing, replay
  protection, proof target and payload, dispute/fault proof challenge windows,
  and early finalization.
* **Forced inclusion/escape:** enumerate delayed inbox, censored messages,
  fee and emergency pause conditions; demonstrate local inclusion/control.
* Evidence: pinned L1+L2 devnets, independent invalid-proof and honest
  controls. The toy simulator is not an OP Stack fraud-proof verifier.

## Restaking and LSTs

* Trace queue -> slash -> claim epochs. Pending shares must absorb slashing
  when the real protocol's economic model requires it.
* Include withdrawal credentials, beacon proof freshness, delegated operator
  and validator slashing; separately check how rewards accrue.
* Native evidence requires realistic beacon fixture and claim ownership.

## Perpetuals

* Funding long/short/insurance flows; mark/index divergence and staleness.
* Partial liquidations, keeper fees, ADL ordering, bad debt, cross margin
  and collateral haircuts; compare precise units and native risk parameters.
* The simulator uses whole units for checkability, not production fixed point.

## CDPs, launchpads, predictions, airdrops, games

* **CDP/stablecoins:** PSM mint/redeem, auctions, depeg, debt ceiling,
  oracle staleness, redemption queue and collateral quality.
* **Bonding curves/launchpads:** quote vs execution minOut, curve boundary,
  fee changes and liquidity migration; calibrate with native exact arithmetic.
* **Prediction markets:** outcome authority/finality, split/merge,
  over-redemption, collateral exhaustion.
* **Merkle and vesting:** leaf encoding, chain/campaign domain separation,
  partial claims, duplicate indexes, delegated claims.
* **VRF and lotteries:** callback authority, request-to-round binding,
  refund and one-time payout.

## Data availability and light-client bridges

Do not confuse header/validity proofs with data availability. Examine
blob/shard commitments, sampling, withholding, reorg depth, light-client
validator updates, proof serialization and message-domain binding.

## Ecosystems currently requiring native adapters

| Ecosystem | Main boundary | Native evidence | Implementation |
| --- | --- | --- | --- |
| TON FunC/Tact | bounce, send modes, async messages | Blueprint sandbox | Methodology only |
| HyperCore/HyperEVM | custody, clearing, two ledgers | native receipts from both | Methodology only |
| Fuel/Sway | UTXO, asset IDs, predicates | forc/fuel-core | Methodology only |
| NEAR | promises, receipts, callback refunds | near-workspaces | Methodology only |
| Stacks/Clarity | principal, response and postconditions | Clarinet | Methodology only |
| Algorand/AVM | transaction group, rekey, ASA | AlgoKit | Methodology only |
| Aleo/Leo | private record, nullifier, public binding | Leo/snarkVM | Methodology only |
| Bitcoin/BitVM | UTXO, peg, sighash, challenge windows | Bitcoin regtest | Methodology only |
| TEE/FHE | attestation, rollback, authorization | local measured tests | Methodology only |

Do not translate EVM rules mechanically to other VMs. Document absent
native tools in coverage.md, source revisions and explicit assumptions.

## Off-chain indexers, keeper and gas denial of service

* Verify optimistic indexer/cache state against canonical chain state,
  durable DB/worker queues, reorg rewinds and signer authorization.
* Measure return-data bombs, EVM 63/64 gas forwarding, bounded loops and
  retry cost in isolated local forks with valid and negative controls.
* A delayed worker is not automatically a denial of service or payable bug.

Use the offline surface_route.py catalog for focused routing. No entry alone
asserts scope permission, exploitability, payout or risk severity.
