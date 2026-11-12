# Multi-step Web ATO/payment sequence models for `scenario_fuzz`

`scenario_fuzz.py` is domain-agnostic: it does bounded BFS over any JSON state
model made of actors, guarded actions and numeric/identity invariants
(`stateful-search.md`, `stateful-harness.md`). It is not Solidity-specific.
Nothing new needed building for Web ATO and payment sequences; what was
missing was worked examples showing the technique applied to that domain.

This closes the gap `web-business-lab` cannot: `web_business_lab.analyze()`
only *reviews* an already-captured candidate/control trace pair the operator
chose in advance. It never *searches* for the violating order of actions
itself. The two models below show `scenario_fuzz` doing exactly that search:
neither individual action is wrong on its own, only a specific order is.

Both are paired candidate (bug present) / control (bug fixed) models, same
convention as `web_business_fixture.py`'s defective/fixed SQLite pairs. Run
either pair with:

```sh
S=skills/bounty-pilot/scripts/scenario_fuzz.py
T=skills/bounty-pilot/templates/stateful
python3 "$S" --model "$T/web-ato-session-fixation.candidate.json" \
             --control "$T/web-ato-session-fixation.control.json" --depth 3
```

A `model-counterexample` on the candidate plus `no-model-counterexample-within-bounds`
on the control is `candidate-only-model-counterexample`: the trace is a lead to
go build a native experiment from, never a deployed finding. See the identical
caveat in `stateful-search.md` and `intent-mutation-phase6.md`'s note on
`scenario_fuzz`'s `causal_root_proven:false`.

## Worked example 1: session fixation after an email change

A session issued before an account's email changes must not still be able to
change credentials afterward — the classic post-password-reset-should-logout-
other-sessions class, generalized to any sensitive account field.

`web-ato-session-fixation.candidate.json`: `owner_change_email` only bumps
`email_version`; it never touches `sessions.old.valid`. `attacker_use_old_session`
is guarded on `sessions.old.valid == 1` **and** `email_version != sessions.old.
issued_at_email_version` — i.e. it only matters once the owner has actually
changed email since the session was issued. BFS finds the two-step trace
`owner_change_email -> attacker_use_old_session` at depth 2; a depth-1 search
(the session alone, before any email change) correctly finds nothing, because
using your own still-valid session is ordinary, not a bug.

`web-ato-session-fixation.control.json` differs only in that `owner_change_email`
also sets `sessions.old.valid` to 0, so the same attacker action can never fire
after an email change. No counterexample within bounds.

## Worked example 2: a stale webhook reactivates a cancelled subscription

`web-payment-stale-webhook.candidate.json`: `cancel_subscription` correctly
flips `entitlement_active` off and clears `payment_confirmed_for_current_term`.
`late_webhook_reactivates` only requires `cancelled == 1` — it re-grants
entitlement without re-checking that term's payment status. BFS finds
`cancel_subscription -> late_webhook_reactivates` at depth 2; depth 1 alone
(a webhook before any cancellation, i.e. an ordinary first activation) finds
nothing in either model, so the counterexample is genuinely about the order.

`web-payment-stale-webhook.control.json` adds `payment_confirmed_for_current_term
== 1` to the same guard; cancellation clears that flag, so a late webhook can
never satisfy it again without a fresh, real payment confirmation.

This is deliberately a different mechanism from `web_business_lab`'s existing
`cancellation-stale` and `event-replay` rules, which each review one captured
event in isolation. Nothing stops this reference's shape from also being
expressed as a 15th `web_business_lab` rule later; it is kept here first
because the finding depends on the *sequence*, which that engine does not
search for on its own.

## Writing your own model for a real target

1. Pick the two or three actions you suspect interact badly (a status change
   plus a later effect that should have been blocked by it).
2. Represent only the state fields the invariant and guards actually need —
   not the whole schema. Use integers (`0`/`1`), never booleans or floats, in
   any field a guard or effect touches (`_decimal()` rejects both).
3. Write the invariant as something that holds trivially at the start and
   breaks only on the sequence you are testing for, the way both examples
   above use a counter that starts and stays at `0` until the bad order fires.
   Running the model at `--depth 1` first and confirming it finds nothing is
   cheap insurance against a single action triggering the "violation" on its
   own, which would make the sequence claim false.
4. Write the fixed-model counterpart before trusting the candidate's result;
   a candidate-only counterexample on both is a modelling bug, not a finding
   (see `test_web_sequence_models.py` for the harness that caught exactly that
   mistake in an earlier draft of these two fixtures).
5. Treat the result exactly as `stateful-search.md` and `verify-tools.md`
   already instruct: a model trace is a hypothesis for a native experiment,
   never evidence on its own.
