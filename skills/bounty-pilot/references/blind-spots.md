# Blind spots — where review does not look at all

`misses.md` audits the work you did. This file is about work nobody does, on either side: the
surfaces a reviewer never opens because there is no file to open, the shapes an automated reviewer
cannot see because it reads for intent rather than for difference, and the surface your own run
closed with a blocker nobody reproduced (§8).

Use it when a target is already heavily audited and the ordinary lenses came back empty. A clean
result from this file is still worth writing down: it closes a surface nobody else has closed.

## 1. Controls that exist only as live configuration

Some of a protocol's most powerful guards have **no source representation at all**. They are set
once by an operator after deployment, never appear in a diff, and are therefore never reviewed.
Enumerate them deliberately and read every one on chain:

- Cross-chain messaging: trusted remotes / peers per destination, the send and receive library,
  the verifier set (DVN / oracle / relayer), required and optional thresholds, confirmations,
  enforced options, the delegate that may change all of it.
- Oracles: which feed is registered for which asset, heartbeat and deviation, fallbacks.
- Access: who actually holds each role, whether the admin is an EOA, a multisig or a timelock,
  and what the timelock delay really is.
- Economic bounds: caps, rate limits, fee parameters, reserve ratios, pause flags, allowlists —
  and whether an allowlist is populated at all.
- Upgrade authority: the implementation behind every proxy and who may change it.

**The characteristic bug is asymmetry, not absence.** The first corridor, market or chain is
configured carefully by the engineer who built it; the one added six months later inherits
defaults. So never check one and generalise: enumerate every destination, every market, every
chain, and diff the configurations against each other. A single corridor on a default verifier
set, beside five on a custom one, is the finding.

**Make the enumeration terminate before you count it.** Scanning an id space — destination ids,
market ids, asset ids — gives a partial answer until it finishes, and a partial answer written
down becomes a false fact. Extend the range until at least two empty bands past the last hit, and
never record a count from a scan that is still running. A real case: a peer scan read mid-flight
showed three corridors; the finished scan over a wider range showed five, and the two extra ones
were the late additions the lens exists to find.

**Derive every identifier, never recall it.** Chain ids, endpoint ids, selector values, token
decimals: looking one up from memory and writing the conclusion on top of it produces a confident
false statement. Read it from the chain or compute it. A real case: an endpoint id recalled
incorrectly produced the note "this chain is not connected" about a corridor that was fully wired
and carrying 25M of supply.

**Follow the pointer to the end.** A proxy is not the code. A beacon is not the code. If a read of
the implementation slot returns zero, that is a failed read, not an unused beacon — call
`implementation()` and compare what you actually find. A real case: a prior pass recorded a beacon
implementation as `0x0`, so the logic contract holding user reserves was never compared to source
at all; calling the getter returned a live implementation whose version string did not match the
in-scope source.

Write the readings down as a table even when they are all identical — that table is the evidence
for a closed surface, and it is cheap to produce.

## 2. Derived constants are never recomputed

Any constant that is the output of a formula gets read as a name, not as a value. Recompute it:

- ERC-7201 namespace slots: `keccak256(abi.encode(uint256(keccak256(ns)) - 1)) & ~bytes32(0xff)`.
  Check the literal against the namespace string in its own comment — including trailing
  characters and case. Two namespaces that collide alias two structs onto one slot.
- EIP-712 domain separators and type hashes, permit type strings.
- Function and event selector constants written as literals.
- Precomputed CREATE2 addresses, merkle roots, bitmasks, packed-struct offsets.

One pass of `cast keccak` settles each one. Mismatches are rare and catastrophic, which is exactly
why nobody looks.

## 3. The odd one out

Most lenses ask "is this correct?". This one asks "**why is this one different?**", and it is the
highest-yield question in a mature codebase, because mature code is consistent and the bug is the
inconsistency.

Build the table first, then read the outlier:

- Every handler in a dispatch switch — which ones check authorisation, and which one does not?
- Every implementation of an interface — do they all validate the same preconditions?
- Every call site of a helper — does one pass a different flag, skip a guard, use a wider type?
- The same contract on another chain — one value configured differently.

Two live examples of the shape: one message handler out of several performing no connection check
while its siblings do; one sender implementation signing the payload a server returned while every
other sender signs the caller's own. Both were invisible to a per-function review and obvious in a
table.

For Solidity, `impact-plan` builds the first version of that table from the compiler AST and
writes it to `odd-one-out.json`: writers of a state variable missing a guard the other writers carry,
functions that update one of two variables normally updated together, and name-paired siblings
(deposit/withdraw, stake/unstake, borrow/repay) whose guards or writes differ, plus authorisation
hooks such as `_authorizeUpgrade` that check nothing. It compares functions within one deployed
contract, counts modifier arguments, treats a modifier as implied only by the checks the modifier
itself performs, and does not count `msg.sender` passed as an argument as a sender check. It sees
modifiers, `require`/`revert` conditions and internal helper checks, not intent, and its writes are
path-insensitive, so many entries are deliberate — about three in four on a realistic project. Read
each one and record the decision in `odd-one-out-review.json`. It does not see dispatch switches, other chains or
off-chain code — build those tables by hand.

## 4. The authoritative value was available and something else was used

A specific, recurring shape worth its own search: the platform already computed the trustworthy
value, it is in scope, and the code re-derives a weaker one instead.

- An origin, sender or caller identity re-obtained by asking the untrusted party rather than taken
  from the frame the runtime gives you.
- A user-supplied address used where `msg.sender` was available.
- A price, balance or amount re-read after validation instead of using the validated value.
- A length, index or id recomputed from attacker-controlled input beside a canonical one.
- **A field's provenance replaced by the text it renders to.** The authoritative fact is *where a
  value came from* — its declared path, its type, the formatter the schema gave it — and the code
  compares the string a human was meant to read instead. Two values with opposite economic meanings
  that stringify alike then satisfy each other's checks. Beyond a signing screen the same shape is:
  token identity by `symbol()` rather than by address, an address compared in its truncated or
  checksummed display form, an amount compared after decimal formatting, a signing domain matched
  by name instead of by typehash, an alert or a nonce deduplicated on message text.

Search for the authoritative accessor, then find the places that do not use it.

### A cosmetic fix is how this one arrives

The provenance test is rarely attacked; it is *refactored away*, by someone fixing a complaint that
a value appears twice on screen. The commit says it changes nothing — and it changes what the code
knows.

The public case, Trezor Core's Ethereum clear signing. The summary omits the transaction's own
outgoing value when a field of the display format already shows it, and until July 2026 "already
shows it" was a question about the field's declared source:

```python
value_shown_as_amount_field = any(
    fd.path == ContainerPath.Value
    and isinstance(fd.get_formatter(), AmountFormatter)
    for fd in display_format.field_definitions
)
```

The removed comment stated the invariant outright: "A `@.value` field formatted any other way still
gets its own summary line." `ce2282bd` — "fix(clear_signing): double display of amount. / - compare
rendered strings now. / [no changelog]", closing an issue about an amount shown twice — replaced it
with:

```python
if amount is not None and formatted == amount:
    value_shown_as_field = True
```

Any unrelated field that happens to render to the same string now suppresses the native debit's
summary line. The author announced the mechanism change in the commit body and opted out of the
changelog, which is the highest-signal line in the repository and the one nothing reads.

**The sweep, and why it needs full history:**

```sh
python3 <skill-dir>/scripts/cosmetic_regression.py --repo <checkout> \
    --path <confirmation/display/signing paths> [--all-commits]
```

Measured over that repository's whole history: 19,288 commits, 2,559 touching the signing and UI
paths, **1,168 passed the commit-message funnel and the diff classifier returned exactly one
candidate** — that commit, with `- fd.path == ContainerPath.Value` and
`+ if amount is not None and formatted == amount:` as its anchors. The message funnel alone passes
46% of commits and is a cost control, not evidence; the diff shape is the instrument.

A pass over this same repository found none of it, because its checkout was `--depth 1`: one commit,
shallow and grafted, so every history lens could only answer empty and the run recorded the silence
as coverage. `capability-probe` now measures this as the `commit-history` evidence kind and the sweep
refuses to produce an empty candidate list from such a checkout, reporting a `blocker` with the
measured depth instead. Full history is nearly free — `git clone --filter=blob:none --bare` carried
all 19,288 commits in 23 MB.

**Then price it before writing it up.** A suppressed confirmation on its own is the bottom of a
vendor's ladder — the two published payouts closest to this shape were 400 and 650 USD. What moves
it is the loss route: which deployed contract turns the hidden field into a transfer, and who ends
up holding what. Build that route, or file the cheap one knowingly.

Sibling generators for the same surface: §12 aims at the accept-set rather than at a commit, and
§13 at a suppression gate with no witness. Between the three, four of those six bugs are covered;
this sweep alone covers none of them.

**One caution on writing these up here.** A finding of this shape that is under coordinated
disclosure belongs in the run directory, not in this file: the public commit, the public issue and
the public diff are citable, the exploit construction is not.

## 5. Safety that rests on a dependency's implementation detail

When a guard holds only because of *how the current version of a library happens to be written*,
record it as fragile even if it is correct today.

The pattern: a contract disables an interface by overriding its entry points, but the base class
has one more entry point that is safe only because it delegates to an overridden one. Correct now;
silently broken by a library upgrade that implements it directly.

Report it at the severity it has today — usually informational — but say what makes it fragile,
and check whether the project pins the dependency.

## 6. State that only exists between versions

A single-commit review cannot see an upgrade. Compare the audited baseline, the in-scope commit and
the deployed implementation:

- Storage layout across every upgrade. Namespaced (ERC-7201) storage makes collision structurally
  impossible — establish that it is actually used throughout before relying on it, then say so.
- A variable removed between versions: harmless if `immutable` (it lives in bytecode), a shift of
  every following slot if it was storage.
- Initializers and reinitializer versions on the new implementation.
- Values written by the old implementation that the new one reads with a different meaning.

## 7. Code that is deployed but is not in the repository

Every audit covers what is in the repository, so the gap is not a file somebody skimmed — it is code
no report could have contained. It arrives three ways, and all three are cheap to check.

**First, read the functions out of the bytecode.** Source is not required to learn what a deployed
contract accepts:

```sh
python3 $S selectors --rpc <url> --address <addr> --abi <the-interface-you-do-have.json>
python3 $S selectors --code <runtime.hex> --signatures <your-signature-list.txt>
```

It walks the dispatcher and returns the 4-byte selectors it compares against, naming the ones that
match a known signature and listing the rest first, because the unnamed ones are the surface nobody
published. `verify-deployment` now attaches the same lead to its own result and evidence file, so a
`partial` or `mismatch` comes with the question "which functions differ?" already answered.

Hold it to what it is: **a selector list is not reachability, not semantics and not a severity.** A
name is a hypothesis to confirm against source or an on-chain read. The dispatcher is invisible when
a contract routes in hand-written assembly, computes selectors at runtime or keeps them in a data
table (Vyper's `--optimize codesize`), and a selector handled *inside* a fallback is never dispatched
at all — OpenZeppelin's `TransparentUpgradeableProxy` compares `msg.sig` against `upgradeToAndCall`
in its fallback, so that admin entry point is real and absent from any selector list. The lead never
sets `deployment_status`, and no gate reads it.

**Deleted, not decommissioned.** A commit removes a contract from `src/` and its address from the
deployment configs in the same change. The contract is still live, still holds whatever the commit
was avoiding, and no longer appears at HEAD for any later reviewer to find. Collect every address
from `deployments/*.json`, `script/config/*.json`, deploy scripts and docs, then ask of each whether
a contract by that name still exists in the in-scope source. Check the reverse too: the address a
repository records may no longer be the one in use, so read the pointer from the contract that
consumes it rather than from the file.

**Several generations live at once.** Where a factory or deployer mints instances over time, more
than one implementation can be in service simultaneously. Enumerate the instances through the
registry that owns them and group them by `eth_getCode` length rather than inspecting one and
generalising. In a live run 51 active farms resolved to two distinct implementation sizes, and
neither matched the in-scope source at any optimizer setting — so an invariant campaign built from
that source, with genuinely non-vacuous coverage, was exercising code that runs nowhere. That is a
limitation on every conclusion drawn from the source, and it has to be written next to those
conclusions, not in a footnote.

**A newer implementation than the repository has.** The deployed contract is a later revision the
team never published. Before claiming this, sweep the compiler: build the source at each optimizer
setting the project uses elsewhere, because the spread across that range can exceed 50% and the
direction is not fixed — aggressive inlining at a high `runs` can make the runtime *larger* than an
unoptimized build. One free cross-check: a deployer must embed the creation code of what it deploys,
so it can never be smaller than that contract's deployed runtime; measuring an instance larger than
its supposed deployer proves more than one generation has been used.

Where the deployed implementation is in no in-scope repository, a defect in it is probably not an
in-scope asset. Record that in `scope.md` and frame any record on the in-scope seam instead — the
audited contract that grants authority to the unpublished one. Raising the discrepancy itself with
the project is worth doing regardless of payout.

## 8. A surface closed by a blocker nobody reproduced

The cheapest way to lose a surface is to write one sentence about it. "Cannot build", "no archive
access", "tool unavailable" are read by every later pass as closed ground, and nothing in this
workflow attacks them — triage is pointed at findings, not at blockers. So a wrong blocker deletes
coverage silently, and the deletion compounds with every pass that inherits it.

The case that set the rule: a subagent reported that a monorepo's farming stack "cannot be
installed — no root package.json, no workspaces". The orchestrator carried that into the run record
unverified, and three passes went by with no test ever executed against the highest-paying
contracts in scope. The root `package.json` existed and declared the workspaces; the subagent had
copied one subproject out of the monorepo, so the package manager correctly went to the public
registry for a sibling that only exists locally. The claim was true of the directory it was run in
and false of the project, and no later pass was in a position to notice the difference.

Three mechanisms carry this now, and none of them is expensive:

- **Record the output, not the conclusion.** `next_experiment.blocker` takes an object:
  `blocker.claim`, plus `blocker.command` and `blocker.output_excerpt` — what the shell actually
  printed — and `blocker.attempted_alternative`, the cheaper route you tried before giving up. With
  a command and an excerpt the blocker is reproduced; without them it is unverified, and
  `queue --run` lists it under `unverified_blockers`. `evidence.md` has the field shapes.
- **Probe before the hunt, not after.** `capability-probe` writes `capabilities.json` at Stage 1:
  the toolchains and versions this run has, the build and test files the checkout really contains,
  whether a root manifest exists and what workspaces it declares, and how deep the RPC's archive
  goes. A genuine constraint found there is a boundary the hunt is aimed inside; found later it is
  a parked candidate. It is also what refutes a blocker like the one above on the spot
  (`intake.md`).
- **Count the floor before saying "exhausted".** `coverage-floor` compares the in-scope file list
  against what the run recorded, so a surface a blocker deleted reappears as an unexamined path
  instead of as silence (`passes.md`).

Spend one minute on the hypothesis that the cause is your own setup — the wrong directory, a
missing lockfile, a public registry asked for a local sibling, an endpoint that is simply not an
archive node — before the blocker enters the record at all. When one is lifted, say which pass
recorded it and what the real cause was.

## 9. The cliff at a scale nobody's fixtures ever reach

Every test fixture picks the smallest number that exercises the code: two signers, three members,
one market, a handful of entries. Auditors inherit those fixtures, and reviewers reason about the
loop body rather than the loop bound. So a limit that only bites far up the growth curve is read by
nobody — not because it is subtle, but because no execution anyone has ever run gets near it.

In a live run this was the single confirmed High among a long stretch of zero-yield targets: in a
Solana multisig, per-proposal vote records are stored in vectors sized by the member count, and past
roughly **106 members** the proposal account can no longer be written. Creating or approving
proposals then fails — and for an *autonomous* multisig, shrinking the membership itself requires a
proposal, so the configuration is permanently stuck. One member adding colleagues reaches it. The
number 106 appears nowhere in the source: it falls out of the account layout, and every test in the
repository uses two or three members.

How to run this lens:

- For each unbounded collection in persisted state, ask what the account, struct or transaction
  size becomes at the largest membership the system itself permits — then compare that against the
  platform's real limits (account size and realloc steps, transaction and instruction size, call
  stack depth, gas or compute budget per block). Compute the crossover, do not estimate it.
- Find the governing parameter's **own** declared maximum. A bug that needs more than the system
  permits is not a bug; a cliff *below* the permitted maximum is one, and the gap between the two
  is where the finding lives.
- Ask the recovery question second, because that is what sets the severity: once the cliff is
  crossed, who can step back? If the only path to shrinking the parameter runs through the very
  operation the cliff blocks, griefing becomes a permanent freeze — and a freeze is an impact class
  most rubrics pay for. See `escalate.md`, amplifier `freeze-instead-of-theft`.
- Check the fixtures to confirm the blind spot rather than assuming it: grep the tests for the
  parameter and record the largest value any of them uses. A repository whose maximum tested
  membership is three has not tested the hundredth.

This lens also survives the common objection that reaching the scale is unrealistic: growth is
usually the *intended* use of the parameter, so the precondition arrives on its own, and a single
participant can often drive it there deliberately.

## 10. Absent from the deny-list is not the same as reachable

A guard written as a deny-list over an enum invites the obvious move: list the enum, subtract the denied
entries, and treat the remainder as attack surface. That step is wrong often enough to waste a pass, and
it wasted one here. Being undenied only matters if the **executor dispatches it**.

On one target two guards denied three enum entries out of thirty-three, and the undenied remainder
appeared to include every token-moving action. Driving all thirty-three ids through the real executor
showed that four of the most promising — the two broadest take variants, a settle-all and a donate —
were never dispatched at all: they fall through to `revert UnsupportedAction`. The two best exfiltration
primitives did not exist. The deny-list was also *complete* on one of the two pool types for a reason no
enum listing shows: fees there capitalise into pool reserves and are realised only through the single
entry that was denied.

So: enumerate the dispatcher, not the constants file. Then read the guard against it, and when you claim
an omission is exploitable, name the dispatch arm that executes it. The inverse is also a finding — an
enum entry the executor dispatches but no guard mentions, and an enum entry deleted at HEAD that the
deployed revision still dispatches (see §7).

## 11. The delta is where every tool already looks

Sections 1-10 are places review does not look. This one is about where *this skill* does not look,
measured across a run of consecutive targets, because the default aim is itself a heuristic every
automated reviewer shares.

**Hunting the post-audit delta is diff-driven, and so is every scanner.** It is necessary and it is
not where the surviving bugs are. The findings nobody has is usually in code that **did not change
and was audited**, because everyone — auditors included — assumes it is settled. One hunter's only
paid finding across that stretch was in a codebase audited by a well-known firm, and not in a delta.
So aim the delta pass, then deliberately aim a second pass at the *oldest untouched* in-scope file
that moves value.

Three axes stayed unused across every target in that run, and each is also a blind spot of
code-reading review:

1. **Profit, in numbers, before reading code.** Programs increasingly demand it in writing — one
   requires "net impact after subtracting required capital, fees, repayments" and states that "gross
   borrowed funds are not profit" — which is exactly the arithmetic a code-only sweep never does.
   Write the attacker's P&L for the mechanism first; if no parameterisation clears zero, do not read
   the contract. And when a defect *is* real, the measured number is what makes it submittable:
   analysis correctly concluded "no funds are frozen" twice on one mechanism, but only an executed
   harness produced the figure — **4.76% of stake lost per subsequent participant** — that turned a
   shrug into a report.
2. **State you can prepare now so somebody else's later call behaves differently.** The question is
   not "what does this function do" but "which persistent mapping can I write cheaply, and who reads
   it afterwards". Applied once in that run, to a relayer's chained-reference storage, it produced
   the only genuinely live primitive found; never repeated, though every target had persistent
   per-user mappings that qualified. Enumerate them and ask the question of each.
3. **Protocol math under load, not math in a diff.** Reading a pricing or interest-rate delta is not
   testing it. Where the target ships `*.invariant.t.sol` or a `disabled_tests/fuzzing/` directory,
   that harness is free infrastructure — one protocol shipped a 667 KB fuzz corpus the hunt never
   ran. Measure which in-scope contracts that corpus covers: the team's own uncovered set is a
   second, independent gap map alongside the audit one, and on that protocol it was the zappers and
   position managers that had **zero** invariant coverage while an out-of-scope optimizer had 116
   references.

**And verify in-body gates mechanically, never by modifier.** A regex over modifiers mis-flags both
ways. One contract's six external pause functions carried **no modifier at all** and called an
internal `_checkOwner()` as the first statement of each body; a modifier scan reports six unguarded
emergency entry points. Parse each `external` body and assert the check is present:

```sh
python3 - <<'EOF'
import re, io
s = io.open("Target.sol", encoding="utf-8").read()
fns = list(re.finditer(r'function\s+(\w+)\s*\([^)]*\)\s*external[^{]*\{', s))
for i, m in enumerate(fns):
    body = s[m.end(): fns[i+1].start() if i+1 < len(fns) else len(s)]
    print(m.group(1), "_checkOwner" in body)
EOF
```

The inverse trap is §5's: a guard that *looks* live but is never called. A contract overriding OpenZeppelin 4.x's
`_beforeTokenTransfer` while the project's default import is 5.x — where that hook no longer exists
— appears to be a dead blacklist on a live bridged token. Resolve the **parent's** import, not the
project default: in that case a vendored dependency pinned `@openzeppelin/contracts@4.8.3` itself, so
the hook was live and the finding was nothing. The versioned remapping in `foundry.toml` is the tell.

## 12. A summary flow accepts a case it cannot render

When a device recognises a known transaction shape and draws a curated screen instead of the
generic field-by-field one, two sets have to match: what the recogniser **accepts** and what the
curated screen **shows**. Where the accept-set is wider, the host varies a field nobody is shown,
and it does so behind the screen that looks the most trustworthy - the one that says "Stake" rather
than listing forty raw parameters.

The tell that this is the defect and not a cosmetic gap: the fix narrows the *recogniser*. Both
calibration cases were closed by falling back to the generic UI, not by showing more.

```sh
python3 <skill-dir>/scripts/summary_flow_gap.py \
    --summary <module with the recogniser and the curated flow> \
    --instructions <module declaring the accepted types and their fields> \
    [--guard 'is_address_reference|...']
```

Two checks, both keyed on the instruction class and field rather than on the local variable, since
the same instruction is reached as a list, as `xs[0]` and as a loop variable:

- **`unconstrained-unrendered`** - a declared field of an accepted class that the flow never
  mentions, on an object it does not hand whole to the screen. Nothing reads it, nothing shows it,
  the host picks it. Calibrated on Trezor's Solana staking flow, which accepted
  `lockup.epoch` and `lockup.unix_timestamp` and displayed neither: a lockup in the distant future
  loses access to the funds. Fixed by `5a5305091`.
- **`reference-used-by-value`** - an address-typed field read as `x.field[0]`, the resolved half of
  the pair, where no guard on that path names `x.field`. Where an address may be an address-table
  reference, the first element is the *table's* address. Calibrated on
  `fix(core): solana transfer showing LUT address`.

Three refinements decide whether this is an instrument or noise, and all three come from the
calibration:

1. **A `[0]` read that only feeds a comparison is self-limiting** - a table reference makes the
   comparison fail, so the flow falls back instead of misleading. Only a read that becomes a value
   the flow carries is a lead; the rest go to `notes`.
2. **A recogniser that renders nothing is not judged** - which of its accepted fields are invisible
   is decided at its call site. It gets a note.
3. **A guard, or a read, inside a predicate the flow calls counts for the flow** - one level,
   because that is how these flows are written: the recogniser guards, the renderer trusts it.

The run that matters most is the one against a **partial** fix. Trezor's first patch guarded one of
three identical accounts; the generator still reports the other two, and the second patch
(`cd6e7596b`, "for more ALT references") is what closed them. A generator that went quiet on the
first patch would have been worse than nothing. `tests/fixtures/summary-flow-gap/s2-partial.py` is
that revision, asserted on its own.

### A lead is not a finding: what must be true for the field to differ?

A row says the screen does not show a field. It does not say the field can *differ from its benign
value* in a transaction anyone can build, and that is the first thing triage asks. Three steps, in
this order, and all of them cheap:

1. **Name the benign value, and what it takes to depart from it.** Usually the field equals the
   signer, or a derived address, or a fixed program - write down the condition under which it does
   not.
2. **Follow that condition out of this module.** It is almost never answered where the lead is. Look
   for a check at the entry point, a *different* screen that fires in exactly that case, and the
   rule the device is relying on the chain to enforce. A field can be absent from one screen because
   another screen covers the only case where it matters.
3. **Then price the counterfactual.** If departing from the benign value needs a capability that
   already produces the same outcome by itself, the invisible field adds nothing.

The worked case is the only lead this generator produced against live firmware, and it dies at step
2 - which is the useful kind of death, because it dies for everyone and for good. Trezor's curated
Solana token-transfer screen shows recipient, token, amount and fee, while the program definition
for the same instruction declares `source_account` as "From" and `owner` as "Owner" with
`default_value_to_hide: "signer"` - so the generic path shows "From" always and "Owner" whenever it
is not the signer. The curated path shows neither and never compares `owner` to the signer. Step 1:
the benign value is `owner == signer`. Step 2, in a different file: for `owner != signer` the
authority has to sign the instruction itself, so the transaction needs two signatures **by
construction**, and the device shows a "requires N signers" screen before the curated flow ever
runs. No parameterisation is left in which the curated screen is drawn for a debit the user's own
key authorises alone from an account that key does not control.

Note what step 2 cost and what it saved: two greps in files the generator never reads, against a
lead that looked live. Note also what it did **not** do - it did not invalidate the row. The
show-set really is missing the field; the generator's job ended where it should.

Where this came from: of the six confirmation-suppression bugs Trezor fixed in 2.12.5 and 2.13.0,
the cosmetic-regression sweep in §4 catches **none** - five were never regressions at all, the field
was never shown from the commit that added the feature. Each needs its own generator; this is the
first of them, and it covers two of the six.

## 13. A confirmation suppressed on a proxy for having shown it

A flow shows a field in one place and later decides whether to show it again - or at all - by
asking something else: a host-supplied index, a count, a flag from the request. The question it
means to ask is *did the user already see this?*, and the only value that can answer it is one
written where the showing happened. An input cannot: the display path has `continue`s, early
returns and branches the input knows nothing about.

The calibration case is Trezor's Monero flow, and its own commit message states the mechanism:
"integrated_indices is host-supplied and never validated, so an index naming an output the
confirmation loop skips left the payment id on no screen while it was still folded into the signed
transaction." The output loop showed the payment id only for outputs the host named, and skipped
change and dummy outputs with `continue`. The standalone payment-id screen was then suppressed by
`not tsx_data.integrated_indices`. The fix tracks `payment_id_shown` where the output is confirmed
and gates on that - a witness instead of a proxy (`9558d1cbf`).

```sh
python3 <skill-dir>/scripts/suppression_witness.py --source <module> [--source <module> ...]
```

Four discriminators, each of which exists because without it the check floods:

- **A gate on the field the call displays is a precondition, not a suppression.**
  `if unlock_time is not None: await confirm_unlock_time(unlock_time)` is correct and is not
  reported. Resolving the local copy matters here: `payment_id = tsx_data.payment_id` means a gate
  on `payment_id` is still a gate on the field being shown.
- **A negation is what makes it read as "already handled".** `not x` suppresses; a plain `if x`
  is a precondition and goes to `notes`.
- **A witness is a local written inside a branch or loop body that itself confirms something.**
  That is the only place a value can learn what the display path did.
- **A local computed from the request outside any confirming block is a proxy wearing a local
  name** - `shown = bool(msg.items)` answers the same wrong question - and is reported with the
  expression it came from.

Rank 0 is the calibration shape: the display the gate stands in for sits in a loop a `continue`
can skip. Rank 1 is the same gate over a display that is merely conditional. Measured over 59
confirmation and signing modules of current firmware: **11 leads, none of them rank 0, and 98
notes** - so the sharpest shape is currently absent from that codebase while the broader one is
not.

**What this does not cover, deliberately.** A gate whose witness is real but is *derived from the
rendered text* rather than from the fact of rendering reads as clean here - the flag is written in
the loop that builds the screen, which is exactly where a witness belongs. That shape is §4's
sweep. Between them: §13 catches a gate with no witness at all, §4 catches a witness that is a
string comparison, and §12 catches a field the curated screen never had. The six suppression bugs
Trezor fixed across 2.12.5 and 2.13.0 needed all three and are still not fully covered - §13 takes
one more of them.

The triage step in §12 applies to every row here as well, and it is where most of them will die:
name the benign value, follow the condition out of the module, then price the counterfactual.

## Recording a clean result

For each item above, write the surface, the method, and the readings — not "checked". A closed
surface with evidence is a deliverable, and it is what makes the next pass cheaper rather than a
repeat.
