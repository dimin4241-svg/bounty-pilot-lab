# Rounding map — direction x repeatability

A single call's rounding error is a wei and reads as harmless, so it gets read, agreed with and
closed. The bug is never the one rounding: it is the **direction** (does the remainder go to the
caller or to the protocol?) multiplied by **repeatability** (can the caller take that step many
times, in one transaction, with borrowed capital, for less than the drift it creates?). This is
the class reviewers miss most: the EVMbench re-evaluation (arXiv 2603.10795) measured rounding and
multi-step classes detected about 4% of the time by AI agents. `rounding-map` turns it into a
ranked reading list. Every row is a lead; none is a finding.

## When to run

Any target with value conversions that a caller can trigger repeatedly:

- vaults and share accounting (ERC4626 and look-alikes, staking receipts, LP tokens);
- AMMs, especially stableswap / weighted invariant math and any `batchSwap` surface;
- lending indexes and accumulators (scaled balances, `rayDiv`/`rayMul`, borrow/supply indexes);
- exchange rates that can be moved by a donation, and empty or first-depositor markets;
- anything that exposes `multicall`, `batch*`, a loop over a caller-supplied array, or flash loans.

## Command

```
python3 $S rounding-map --repo <checkout> --scope src --out <run>/rounding-map.json
```

`--scope` is repeatable. `--solc <build-info.json>` reads `input.sources[*].content` instead of the
checkout (nothing else from that file is used). Test, mock and script paths (`*.t.sol`, `*.s.sol`,
`test/`, `mocks/`, `script/`) are skipped and listed in `skipped`. Target source is read as text and
never compiled or executed.

## Reading the output

- `sites[]`: file, line, contract, function, `kind`, `direction` (`down|up|half|unknown`), the
  expression and statement, `feeds` (`out|in|shares-minted|shares-burned|state|unknown`) with
  `feed_via` showing the name flow (through a return into a caller, or an argument into a callee),
  `verdict` (`favors_user|needs_reading|favors_protocol`), `repeatable`, `entry_points`, `context`
  (flash-loan surface, empty-market branch without virtual shares / offset / dead shares).
- `functions[]`: per function, lexical value `direction` (`user-receives|user-pays|mixed|unknown`)
  with its evidence, `repeatable`, `batching_evidence` and `limiters` (per-block guards, minimum
  amount checks).
- Rows are ranked: favors_user + repeatable, then needs_reading + repeatable, then favors_user,
  needs_reading, favors_protocol. `summary.omitted` / `omitted_by_tier` count what `--limit` cut.

The favour rule is the standard convention, round against the user: rounding **down** must not
feed what the user pays or shares burned from them, rounding **up** must not feed what they
receive or shares minted to them. `half` (Wad/Ray math) and unresolved directions are
`needs_reading`.

## Triage, per favors_user + repeatable row

1. **Compute the per-iteration drift symbolically.** Write the expression with the rounding made
   explicit (`floor(a * S / A)`) and find the input that maximises the error relative to the
   amount — often 1 wei, or an amount just below the next integer quotient. Note what the drift
   moves: the attacker's balance, the share price for everyone else, an invariant, an index.
2. **Find the cheapest loop.** In order: a native batch (`batchSwap`, `multicall`, a loop over an
   array argument), a self-`delegatecall`, a flash loan that funds many iterations in one
   transaction, then plain repeated transactions. Write down per-iteration gas.
3. **Check what limits it.** Minimum amounts, per-block guards, fees charged per call, a fee that
   intentionally offsets the rounding (the convention is sometimes broken on purpose), and
   empty-market defences (virtual shares, decimals offset, dead shares). Quote each line.
4. **Measure it.** Fill `templates/RepetitionDrift.t.sol`: `_once()` is one micro-operation, the
   candidate asserts net attacker profit > 0 after costs, the negative control runs the same loop at
   the documented minimum or with the rounding fixed and asserts no profit. A passing candidate
   proves only its own assertions.
5. **Escalate via the `repetition` amplifier** (`escalate.md`), then `timing` for empty-market
   shapes and `other-parties-funds` when the drift is paid by other holders.

For `needs_reading` rows, resolve the direction first (read the library, or the caller-supplied
`Rounding` argument) and re-apply the favour rule by hand.

## Incident shapes this is calibrated on

Loss figures are approximate; cite the protocol's own post-mortem in a report.

| Incident | Shape |
| --- | --- |
| Balancer v2, Nov 2025 (~$128M) | `_upscale` rounds down; 65 micro `batchSwap` GIVEN_OUT steps in one transaction deflated invariant D. Trail of Bits flagged the rounding in 2021 but could not prove it — single-call reasoning. |
| Bunni, Sep 2025 ($8.4M) | rounding direction in the withdraw idle-balance update, amplified by flash-loaned repetition. |
| Yearn yETH, Nov 2025 (~$9M) | stableswap solver math; a huge mint from dust. |
| zkLend, Feb 2025 ($9.5M) | accumulator inflated in an empty market, then a rounding repeated. |
| Resupply, Jun 2025 | exchange rate rounding to 0 after a donation. |

## Limits

- **Lexical.** Comments and strings are stripped and braces matched; there is no type checking,
  overload resolution or inheritance linearisation. Call flow is matched by name, so it can both
  over- and under-connect. A `favors_user` row can be wrong; an absent row proves nothing.
- **Hidden math.** Inline `assembly` division, math in libraries outside `--scope` or not in the
  checkout, and rounding chosen by a runtime argument are not resolved (the last shows as
  `unknown` with a note).
- **Solidity only.** Vyper, Move, Rust (Solana/CosmWasm/Substrate) and Cairo are not parsed; a
  target in those languages gets an empty map, and the notice says nothing was scanned.
- **No profit claim.** A favourable rounding is exploitable only if one repetition costs less than
  the drift it creates. Only the measured RepetitionDrift pair, on unmodified source at the
  deployed revision, speaks to that.
