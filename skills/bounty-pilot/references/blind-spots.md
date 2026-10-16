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

## 4. The authoritative value was available and something else was used

A specific, recurring shape worth its own search: the platform already computed the trustworthy
value, it is in scope, and the code re-derives a weaker one instead.

- An origin, sender or caller identity re-obtained by asking the untrusted party rather than taken
  from the frame the runtime gives you.
- A user-supplied address used where `msg.sender` was available.
- A price, balance or amount re-read after validation instead of using the validated value.
- A length, index or id recomputed from attacker-controlled input beside a canonical one.

Search for the authoritative accessor, then find the places that do not use it.

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
no report could have contained. It arrives three ways, and all three are cheap to check:

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

## Recording a clean result

For each item above, write the surface, the method, and the readings — not "checked". A closed
surface with evidence is a deliverable, and it is what makes the next pass cheaper rather than a
repeat.
