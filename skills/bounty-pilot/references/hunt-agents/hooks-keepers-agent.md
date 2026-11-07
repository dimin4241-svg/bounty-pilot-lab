# Hooks and keepers agent — code that runs on someone else's behalf

A Uniswap v4 hook runs inside every swap and liquidity change on any pool that names it, and a
public keeper runs whatever parameters it is handed against positions it does not own. Both are
written as if only the intended caller arrives. **Your question is: who can make this code act, on
whose assets, with parameters chosen by whom?**

## Procedure — Uniswap v4 hooks

1. **Check the caller on every callback.** Each `before*` and `after*` function must be callable
   only by the `PoolManager`; quote the modifier and read its body. Cork, May 2025, roughly $12M:
   `beforeSwap` was callable without validation, combined with attacker-parameterised markets.
2. **Check hook-to-pool binding.** Anyone can initialise a pool whose `PoolKey` names an existing
   hook. Does the hook check the key against pools it expects, or does it trust the currencies,
   fee and tick spacing it is handed? A hook holding state or funds per pool must key it by
   `PoolId` and reject unknown pools.
3. **Follow delta accounting.** Every `settle`, `take`, `sync` and returned delta: does the hook
   leave a non-zero delta another caller can claim, or return a delta that charges the swapper
   more than the quote showed?
4. **Read dynamic fees.** Who may change the fee, within what bounds, and whether it can change
   between a quote and the swap. 0x has reported hooks switching fees between 0% and 18%, which
   an aggregator routing through the pool passes on to its users.
5. **Look for liquidity griefing.** `beforeAddLiquidity` or `afterRemoveLiquidity` that can be made
   to revert for other users, locking their positions, or that charges withdrawal fees an
   attacker can raise.
6. **Check upgradeability.** A hook behind a proxy can change behaviour under every pool that
   names it; note who controls the upgrade and whether pools can opt out.

## Procedure — keepers, multicall and standing approvals

7. **Enumerate public keeper entry points.** `multicall`, `execute`, `performUpkeep`, `harvest`,
   `rebalance`, `liquidate` and anything an automation network calls. For each, list the
   parameters and mark which set a price, recipient, route, hook, pool or slippage bound. A
   report from Sep 2026, roughly $7.73M in rsETH: a public Keeper Multicall redirected a Safe's v4
   LP module to a malicious hook. Treat that account as reported, and look for its shape.
8. **Check what the keeper acts on.** Does it act on behalf of positions, vaults or Safe modules it
   did not create, and does it check that the caller is the owner or a registered keeper?
9. **Game the rewards.** Keeper incentives paid per call, per amount or per position: can the
   caller create the work it is paid for, or call in an order that pays twice?
10. **Find standing approvals.** Routers, bots, zaps and extensions that hold allowances from
    users and expose a call whose `from`, `token` or `target` the caller chooses. jaredfromsubway's
    MEV bot, Jun 2026, roughly $15M: unconsumed allowances were drained. Ekubo's Starknet
    extension, May 2026, $1.4M: missing validation let an attacker drain existing ERC20 approvals.

## Where the money is

- A hook callback with no `PoolManager` check, or one that trusts an attacker-created `PoolKey`.
- A hook delta that leaves value claimable by the next caller.
- A public keeper whose parameters choose the recipient, route or hook for someone else's assets.
- A router or extension that pulls from any address that once approved it.

## Proof standard

Quote the missing caller or binding check, then show it in a local or fork test: initialise a pool
with the target hook and an attacker-chosen key, call the keeper with attacker-chosen parameters,
or pull from an address with a live allowance. For live allowances, read them on chain at a pinned
block and give the total at risk.

## What does not pay

- A hook owner setting a high fee on their own pool is the design, unless an unprivileged actor
  can change it or a router misrepresents it.
- Keeper ordering and sandwiching that the design accepts as MEV.
- A trusted keeper role passing bad parameters; the finding is when the role is public or takeable.
