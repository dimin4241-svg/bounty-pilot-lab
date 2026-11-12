# Economic conservation as a `scenario_fuzz` sequence search

`invariant_check.py` has always supported a `conservation` rule kind: a weighted
sum of state paths must equal an expected value. `scenario_fuzz.py` has always
done bounded BFS over any JSON action model built from the same invariant
schema. Nothing new needed building to combine them — the gap was that no
reference or fixture ever actually exercised `conservation` through a
multi-step sequence search; `tests/test_stateful.py`'s own conservation
example only checks one static snapshot.

This matters because the real-world lesson from Balancer V2, Cetus and
Arcus-class incidents is the same shape every time: an operation passes every
individual check, but the *sequence* lets the sum of what the system now
*reflects* across accounts/ledgers diverge from what was actually deposited.
A single-snapshot check can confirm a conservation violation once you already
have the bad snapshot; it cannot *find* the sequence that produces one.

## Worked example: a retried transfer double-credits one subaccount

`economic-subaccount-retry-credit.candidate.json` models a user with two
subaccounts (`trading`, `savings`) and one pending transfer of 30 between
them. `apply_transfer` is correctly idempotency-gated on `transfer_applied`.
`retry_apply_transfer` represents a duplicate delivery of the same transfer
instruction (a retried queue message, a re-delivered worker job) — its guard
only checks that a transfer has already happened, not that *this specific*
instruction hasn't already been processed, so it re-credits `savings` without
a matching debit from `trading`. BFS finds `apply_transfer -> retry_apply_transfer`
at depth 2, landing on `trading=70, savings=60` against a conservation
invariant of `trading + savings == 100`. A depth-1 search finds nothing in
either model: `apply_transfer` alone correctly preserves the sum, and
`retry_apply_transfer` cannot fire before a transfer has been applied once —
the violation is genuinely about the order, not about either action alone.

`economic-subaccount-retry-credit.control.json` differs only in that
`apply_transfer` also sets `idempotency_marked`, and `retry_apply_transfer`'s
guard additionally requires `idempotency_marked == 0`; once a transfer has
been applied, no further call can satisfy both guards. No counterexample
within bounds.

Run either pair:

```sh
S=skills/bounty-pilot/scripts/scenario_fuzz.py
T=skills/bounty-pilot/templates/stateful
python3 "$S" --model "$T/economic-subaccount-retry-credit.candidate.json" \
             --control "$T/economic-subaccount-retry-credit.control.json" --depth 4
```

Same caveat as `references/web-sequence-models.md` and `stateful-search.md`:
`candidate-only-model-counterexample` is a lead for a native experiment, never
a deployed finding. `scenario_fuzz` reports the first observed broken model
state, not a proven source-level cause (`intent-mutation-phase6.md`).

## Writing your own conservation model

1. Identify every place value can be *reflected* (a displayed balance, a
   ledger row, a per-market position) versus the one or two places real,
   external value actually enters or leaves. Conservation holds over the
   reflected places; it is checked against the external ones.
2. Use `weight` on `conservation` terms for anything that isn't a flat 1:1
   contribution — fees, haircuts, a share price, a rounding direction. The
   existing `rounding_map.py` and `financial-transitions.md` shapes are the
   place to look for which direction a given protocol is supposed to round.
3. Model at least two subaccounts, markets or ledgers, and at least one
   action whose guard is the *only* thing standing between "idempotent" and
   "replayable" — that gap is where every incident in this class actually
   lived (Balancer's repeated-operation rounding drift, Arcus's subaccount
   transfer accounting, Cetus's dependency-level overflow check).
4. Confirm depth-1 alone finds nothing, the same way the ATO and payment
   examples in `web-sequence-models.md` do — a single action tripping the
   invariant means the model is wrong, not that the sequence claim is real.
5. Write the fixed-model counterpart before trusting the candidate's result
   (`test_economic_sequence_models.py` is the harness that keeps both honest
   going forward).
