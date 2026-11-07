# Adapter — Cosmos SDK app chains, CometBFT, IBC and Cosmos EVM

Route here when a `go.mod` pulls `github.com/cosmos/cosmos-sdk`, `cometbft/cometbft`,
`cosmos/ibc-go`, `cosmos/evm` or an Ethermint/Evmos fork. The entry points are messages routed to
module keepers through an ante-handler pipeline, plus BeginBlock/EndBlock hooks that run on every
block with nobody paying for them. Contracts deployed on a CosmWasm chain are a separate component:
read `adapters/rust-cosmwasm.md` for them and treat the wasm module as the boundary. Pair this file
with the `node-client` lens and `adapters/go.md`.

## 0. Find what the chain actually runs

Most app chains are forks of the SDK, ibc-go, CometBFT or Cosmos EVM, pinned in `go.mod` and often
with `replace` directives to a team fork. Read the live binary version from the chain's own
release, match it to a tag, and read that tag's `go.mod`. Then check the N-day risk: a security fix
upstream that the fork never took is the cheapest finding on this stack.

```sh
python3 $S nday-scan --repo <checkout> --upstream cosmos-sdk=<upstream-clone> --out <run>/nday-scan.json
```

`references/nday-scan.md` describes the output. A fix present upstream and absent in the pinned
fork is a lead until you show it reachable on the fork's configuration.

## Checklist

- **Ante handler, fees and gas.** Every message type must pass fee deduction, signature and
  sequence checks. Look for message types or nested messages (`authz.MsgExec`, ICA, gov proposals,
  EVM-wrapped Cosmos messages) that skip a decorator, and for gas that is consumed after the work
  it meters.
- **BeginBlock / EndBlock.** Any loop over user-growable state (unbonding queues, auctions,
  expiring orders) is unbounded work nobody pays for; any panic there halts the chain. Trace the
  panic to the process: a recovered panic in a message handler is a failed transaction, a panic in
  a block hook is a halt.
- **Determinism.** Go map iteration, floats, `time.Now()`, goroutines, and anything read from the
  local node rather than from state produce an app hash that differs between validators. That is a
  chain halt, not a bug in one node.
- **Bank, staking, vesting and locked balances.** Spendable versus total balance, vesting accounts,
  delegated and unbonding amounts, module accounts, and blocked addresses. A module that reads one
  of these where it meant another moves locked value.
- **Precompiles bridging EVM and module state.** The highest-paying recent surface on this stack.
  Check that EVM balances and bank balances stay in sync across a call, that reentrancy across the
  boundary is handled (an EVM callback into a precompile mid-operation), and above all the revert
  semantics: **an EVM revert does not automatically revert module state** written by a precompile
  earlier in the same call. Write the snapshot/commit sequence down and test a revert after a
  successful precompile write.
- **IBC.** Channel and port ownership, packet authentication, who may relay, ack and timeout
  handling that refunds exactly once, and denom tracing (a voucher denom that collides with a
  native one, a path that unwinds to the wrong escrow). Callbacks and middleware add their own
  entry points.
- **Governance parameter changes.** Which parameters a proposal can set, and whether a legal value
  disables a guard (a zero rate limit, an empty allowlist, a maximum that admits overflow). See the
  `governance-capture` lens when voting power can be bought.
- **Upgrades and migrations.** Store migrations that skip a module, a version map that misses a
  key, state interpreted differently after the upgrade height.
- **CometBFT.** Blocksync, mempool and p2p ingress with peer-supplied lengths; a crafted message
  that crashes or stalls every node is a network-level DoS, which some programs pay and many cap.

## Proof standard

A native test in the chain's own simulation or integration framework, or a local testnet with the
exact binary. For a halt, show every validator reaching the same failure; for a precompile issue,
show the bank and EVM views diverging after the sequence, with a negative control.

## Precedents worth reading

- Cosmos EVM chains, August 2026: a flaw exploited after an upstream fix, reported by The Hacker
  News and BlockSec — [The Hacker News](https://thehackernews.com/2026/08/cosmos-evm-flaw-exploited-after-cosmos.html),
  [BlockSec](https://blocksec.com/blog/defi-security-incidents-cosmos-evm-moonwell).
- Astroport on Neutron, September 2026 (secondary source):
  [Blockhertz](https://blockhertz.com/blog/blockchain-security-report-october-2026).

Both are also backtest cases in `holdout-2026.md`; if you are running one of them as a blind case,
do not open these links.
