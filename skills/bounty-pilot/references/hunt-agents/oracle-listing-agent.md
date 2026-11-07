# Oracle and listing agent — who signs the price, and what it costs to move it

A lending market is a promise that every price it reads is both authentic and expensive to move.
Pull oracles break the first half: a verifier that accepts a report it should not. Listings break
the second: a collateral factor applied to a token whose price costs less to move than the market
lends against it. **Your question is: for each price consumer, can the attacker supply the report,
or cheaply move the thing it reports on?**

## Procedure

1. **List every price consumer.** Each call that reads a price, rate or exchange value: the
   function, the feed id, the feed type (push aggregator, pull oracle, TWAP, exchange rate,
   internal order book) and the asset it prices. One row each.
2. **For pull oracles, read the verifier, not the wrapper.** Fill these from quoted code:
   - **Signature threshold:** is the number of valid signatures compared with a minimum, and is
     that minimum non-zero? Bonzo on Hedera, Jul 2026, roughly $9M: the Supra pull verifier
     accepted zero signatures.
   - **Signer set:** who may update it, and are duplicate signers counted once?
   - **Staleness and timestamp direction:** is a report from the future rejected, or only one from
     the past? Ostium, Jul 2026, roughly $23.75M: validly signed reports with attacker-chosen future
     timestamps entered through a trusted `PriceUpKeep` forwarder, and positions were looped in
     `executeBatch`.
   - **Confidence:** for Pyth, is `conf` read and bounded relative to `price`?
   - **Decimals and exponent:** is the per-feed `expo` or decimals applied, or assumed?
   - **Fallbacks and circuit breakers:** what happens when the primary reverts, and can an
     attacker force the fallback?
   - **L2 sequencer uptime:** is the uptime feed checked, with a grace period after restart?
3. **For each listed collateral, compute the listing economics.** Collateral factor times a
   manipulable price, against the liquidity depth that price comes from and the supply and borrow
   caps. Measure the depth at a pinned block, compute cost to move and extraction with the
   `economics` lens method and `scripts/economic_frontier.py`, and state the net figure.
4. **Check every cap for a bypass.** A supply cap enforced in `mint` but not on a direct token
   transfer or donation to the market contract, an exchange rate that counts raw balance, a cap
   read from a stale snapshot. Moonwell, Aug 2026, $9.1M: MAMO at 50% collateral factor, its
   Chainlink feed pumped 40x, and the supply cap was bypassed by transferring directly to `mMAMO`.
5. **Check self-pricing.** A venue that prices collateral from its own order book lets a seller on
   that book set the collateral value. On Oct 10 2025, Binance priced USDe, wBETH and BNSOL from
   its own order book and USDe printed $0.65 there.
6. **Check the listing path itself.** Who may list a market, with which parameters, and whether a
   newly listed asset can be borrowed against before its oracle or caps are set.

## Where the money is

- A pull verifier with a threshold that can be zero, or a timestamp check in one direction only.
- A thin-liquidity token with a collateral factor and caps that make pumping it profitable:
  Tectonic on Cronos, Aug 2026, $75–125M (TONIC pumped 100x in 20 minutes on $1.3M of liquidity,
  then borrowed across 16 markets); Nostra, Sep 2026, $3.5M; YieldBlox on Stellar, Feb 2026, $10M.
- A cap enforced on the deposit function but not on the balance the market actually counts.
- A derivative collateral (principal tokens, LP tokens, wrappers) priced by a formula that ignores
  how it trades. Loopscale, Apr 2025, involved PT collateral pricing.
- A listing path an attacker can reach. Drift, Apr 2026: fake collateral was listed after an admin
  takeover, which is admin compromise rather than a listing bug, but it shows what a listing
  permission is worth.

## Proof standard

For verifier findings: quote the check and the missing bound, then show a crafted report accepted
in a local or fork test against the real verifier contract. For listing economics: live depth,
caps and collateral factors read at a pinned block, the cost to move the price, the extraction,
and the net figure, ideally as a fork test that prints the attacker's balance before and after.

## What does not pay

- "The oracle could be manipulated with unlimited capital" with no measured cost and profit.
- Many programs exclude market manipulation and oracle manipulation outright, or require a flash
  loan. Read the program's exclusions and emit the LEAD tagged `likely-excluded` with the clause.
- Governance setting a bad collateral factor is admin behaviour unless an unprivileged actor
  reaches the listing path.
