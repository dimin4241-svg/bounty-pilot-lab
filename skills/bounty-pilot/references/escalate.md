# Escalation — the ladder a record climbs before it closes

Hunters stop at the first consequence they notice. A record that reads "griefing only" or
"informational" is frequently an unfinished loss-of-funds record, and programs pay by impact class,
so the unfinished part is the paid part. In a backtest of this skill, several readings found a real
defect and closed it at its cheapest consequence: the mechanism was right and the class was wrong.

The rule this stage enforces: **a record is not closed at a low impact class until every amplifier
has been tried and the failures are anchored.**

## Where this stage sits

After the hunt passes, **before** adjudication (stage 4), over every record the passes produced,
including the demoted ones. It is not adversarial. This is still the hunter's stance — you are deepening your own claim, not
auditing it. Do not refute anything here, do not soften a path because triage will object to it,
and do not drop a record because you now suspect a guard. That is stage 4, it has written gates,
and it needs the claim at full strength to judge it at all. What this stage asks for is the
opposite of caution: every amplifier tried, every failure written down with evidence.

## The amplifier ladder

Six amplifiers, in this order, worked on every record.

**1. `repetition`.** Can the step be taken many times — across blocks, or inside one transaction
with borrowed capital? Dust that compounds is not dust. *Shape:* a rounding step that favours the
caller by one wei per deposit, looped until the share price is materially off; a per-call discount
repeated across a flash-loaned position a thousand times the attacker's own. *Anchor for blocked:*
the quoted bound — a rate limit, a cumulative cap, a minimum deposit that makes the loop
unprofitable. "Gas would cost too much" is an anchor only with the per-iteration cost and the
iteration count written out.

**2. `other-parties-funds`.** Does the same defect reach a shared pool, a second market, another
user's balance, a pooled escrow? This is the single most common upgrade from "self-harm, not
reportable" to a paid finding, and the amplifier most often skipped. *Shape:* a miscalculation that
only shortchanges the caller on the solo path but runs against the shared reserve through the
pooled vault; a self-inflicted bad debt the insurance fund absorbs; a user-chosen parameter written
into a global index every depositor reads. *Anchor for blocked:* the quoted code keeping the effect
inside the caller's own accounting, shown by the grep over every writer of that state.

**3. `composition`.** Combine it with another record from **this same run**, including the demoted
and refuted ones. The `seam` lens does this across records; here you do it for one record against
everything else the run holds. *Shape:* this record supplies the reachability a record demoted as
"unreachable state" lacked, or the impact a record demoted as "no impact" lacked, or the two share
one aggregate and cross a cap neither crosses alone. *Anchor for blocked:* the records you tried,
by id and surface, and the state, actor or dependency they do not share. "Nothing else is related"
is not an anchor; the list of what you checked is.

**4. `become-the-trusted-party`.** Can the attacker take the role, or set the value, the mechanism
treats as trusted? A guard is only as strong as the holder of its key, and a parameter "set at
deployment" is attacker-set when deployment is permissionless. *Shape:* a factory anyone can call,
so the attacker owns the market whose oracle, fee recipient or collateral list the guard trusts; a
registry entry an unprivileged function writes; a user-supplied hook called with this contract's
authority; a trusted-forwarder slot still zero, so `address(0)` passes. *Anchor for blocked:* the
quoted guard on every path that writes the trusted value, plus the live read of its current value
at the in-scope address and a pinned block. A source default is not the deployed value.

**5. `timing`.** Is there a window where the mechanism behaves differently — an epoch boundary,
during a pause, across an upgrade, on an empty or first-depositor market, after a role rotation?
*Shape:* the first depositor sets the share ratio and the rounding favours them permanently; a
reward index read across the rollover before it is checkpointed; a withdrawal queued before an
upgrade and settled against the new storage layout; a pause that blocks liquidation but not
borrowing. *Anchor for blocked:* the quoted line that closes the window — the checkpoint written
before the read, the dead-shares mint, a pause covering both sides.

**6. `freeze-instead-of-theft`.** When funds cannot be taken, can they be locked? Permanent,
unprivileged denial of other users' funds is its own impact class; place it with
`impact-classes.md` rather than inventing a severity. *Shape:* a value pushed into a range where
every later withdrawal reverts; a queue entry nothing clears and nothing skips; a monotonic index
compared against a cap; a poisoned element every other user's exit iterates over. *Anchor for
blocked:* the recovery path, read and quoted — the sweep, the skip, the per-user exit that avoids
the poisoned state. Do not assume a recovery exists because a protocol this size would surely have
one.

## The recording rule

Every amplifier gets a result: `reached`, `blocked` or `not-applicable`. `reached` and `blocked`
each need an `anchor`, one of the four kinds adjudication uses — quoted code, quoted specification,
a named test, or a live chain read at a pinned block. An unanchored `blocked` is not a result, it
is an assumption, and it is the assumption that filed the record one class too low to begin with.
`not-applicable` takes one sentence saying why the amplifier does not apply here; it is for "this
protocol has no shared pool", never for "I did not get to it".

Each amplifier carries exactly one result. The submission gate requires the completed ladder; until
then `queue` lists the missing amplifiers on every open lead, and flags a record refuted without a
single amplifier tried as a weak refusal — a mechanism dropped at its cheapest consequence.

## The ceiling rule

Put the highest impact class the evidence genuinely reaches in `ceiling`, and in `ceiling_evidence`
name what stopped it from going higher: the amplifier that came back `blocked` and the anchor that
blocked it. Write the next class up as a limitation, the way `impact-classes.md` asks — "this would
be insolvency if X, which I did not establish." Under- and overclaiming are the same mistake in
opposite directions: overclaiming gets the whole report read with suspicion, underclaiming gets
paid at the lower class, and nobody argues you upward.

## What this stage must not do

- Do not grant the attacker privileges the world does not grant, and do not call an amplifier
  reached because an admin could enable it.
- Do not assume a configuration nobody deployed. A parameter value that makes the amplifier work is
  a live read or it is not evidence.
- Do not chain through an out-of-scope component without saying so in the anchor; that is an
  eligibility problem to record now, not a surprise for triage.
- Do not manufacture a victim. "Someone might deposit there" is not another party's funds.

A blocked amplifier honestly recorded is worth more than a reached one that needs a fictional
precondition: the first is coverage the next pass can trust, the second is what makes a triage
engineer read your other three findings differently.

## Worked examples

A record that climbs, on `other-parties-funds`:

```json
"escalation": {
  "attempted": [
    {"amplifier": "repetition", "result": "reached", "anchor": "code: src/Vault.sol:214 deposit() has no per-block or cumulative bound"},
    {"amplifier": "other-parties-funds", "result": "reached", "anchor": "code: src/Vault.sol:231 the rounding writes totalAssets, read by every redeem() at :298"},
    {"amplifier": "composition", "result": "not-applicable", "anchor": "no other record in this run touches totalAssets or the share price"},
    {"amplifier": "become-the-trusted-party", "result": "blocked", "anchor": "code: src/Vault.sol:88 asset is immutable, constructor-set, no setter"},
    {"amplifier": "timing", "result": "reached", "anchor": "code: src/Vault.sol:201 no minimum initial deposit; the first depositor sets the ratio"},
    {"amplifier": "freeze-instead-of-theft", "result": "not-applicable", "anchor": "the defect moves value; it reaches no path that reverts"}
  ],
  "ceiling": "direct-theft-of-funds",
  "ceiling_evidence": "repetition plus other-parties-funds: the per-deposit rounding is unbounded and lands in the shared totalAssets every redeemer prices against, so later depositors' assets are the source. Filed as griefing before the ladder ran."
}
```

A record that correctly stays low, every amplifier blocked:

```json
"escalation": {
  "attempted": [
    {"amplifier": "repetition", "result": "blocked", "anchor": "code: src/Staking.sol:144 one claim per epoch, lastClaim checked at :149"},
    {"amplifier": "other-parties-funds", "result": "blocked", "anchor": "code: src/Staking.sol:160 debited from the caller's own pending; no writer of rewardPool on this path"},
    {"amplifier": "composition", "result": "blocked", "anchor": "tried BP-004 (src/Epoch.sol:72) and BP-007 (src/Fees.sol:40); neither reads lastClaim or pending"},
    {"amplifier": "become-the-trusted-party", "result": "blocked", "anchor": "live: rewardSigner at 0xabc… block 21,440,118 is the program's multisig; setter is onlyOwner at :310"},
    {"amplifier": "timing", "result": "blocked", "anchor": "code: src/Staking.sol:138 the index is checkpointed before the read on both branches"},
    {"amplifier": "freeze-instead-of-theft", "result": "blocked", "anchor": "code: src/Staking.sol:172 claim() skips a zero pending balance; unstake() at :205 never reads pending"}
  ],
  "ceiling": "informational",
  "ceiling_evidence": "self-harm only, bounded to one claim per epoch, with no path to shared funds. This would be theft of unclaimed yield if the shortfall were credited to another account, which it is not."
}
```

The second record is a result, not a failure: it closes the mechanism with evidence, so no later
pass spends a reading re-deriving it, and nothing in the report is inflated to carry it.
