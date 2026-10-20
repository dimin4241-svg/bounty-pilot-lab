# The hunt loop

Passes differ by **what they are aimed at**, not by how hard they try. Repeating one prompt
produces the same findings under new titles, and that is the main way a multi-pass hunt wastes
money. This file settles the aiming, the dispatch mechanics, and when to stop.

Two working hypotheses shape this loop. Independent readings may surface different mechanisms, and
aiming may save effort on a large or heavily audited codebase. Neither should be treated as a
universal law: model outputs can be correlated, and a ranking can hide an unranked path. Record
unique coverage per reading, keep unexamined paths visible, and use held-out cases to decide whether
extra passes earn their cost.

## Stage A — Aim (not a hunt pass)

Four lenses whose job is a ranked surface list, not findings. They are aimed at diffs, manifests,
published documentation and test files rather than at hunting; their bundles still carry the source
so they can check what they rank, and they run once.

```sh
S=<skill-dir>/scripts/bounty.py
python3 $S delta --repo <checkout> --since <audited-commit> --scope <source roots> > <run>/delta.json
python3 $S bundle --repo <checkout> --run <run> --lens aim --scope <source roots> --include <run>/delta.json
```

Dispatch `delta`, `upstream-diff`, `coverage-gap` and `spec-divergence`, one agent each. Their
combined product goes into `coverage.md` as a ranked reading order, and every later pass is given
it. If `--since` has no evidenced baseline, say so and review in full — never call an arbitrary
recent range the post-audit delta.

`spec-divergence` contributes two things: a reading order of the surfaces where the published
documentation promises a protection no code enforces, and the exact quotes behind that ranking,
which later serve as specification anchors on the records and in round 2 of the objection
exchange (`hunt-agents/spec-divergence-agent.md`).

## Choosing lenses — select by behavior and stack

There are more than twenty lenses. Running every one on every target wastes most of the budget on
surfaces the protocol does not have. `<source roots>` below means every directory that holds
in-scope source — `src/`, `contracts/`, `programs/`, a Vyper or Huff tree — not `src/` by habit:
`coverage-floor` lists on-chain source outside the scope you gave it, and that list should be empty
or justified in `scope.md`. Pick by shape, and say in `coverage.md` which you chose and why.

| Target shape | Run first | Then |
| --- | --- | --- |
| Lending / CDP / money market | `economics`, `accounting`, `privileged-path` | `live-reality`, `liveness`, `delta` |
| DEX / AMM / concentrated liquidity | `economics`, `accounting`, `external-call` | `upstream-diff`, `coverage-gap` |
| Vault / ERC-4626 / yield aggregator | `accounting`, `economics`, `external-call` | `privileged-path`, `liveness` |
| Bridge / cross-chain messaging | `integration-auth`, `privileged-path`, `external-call` | `live-reality`, `upgrade` |
| Router / aggregator / zapper | `external-call`, `integration-auth` | `privileged-path`, `accounting`; measure approval exposure, not balance |
| Staking / LST / restaking | `accounting`, `privileged-path`, `economics` | `liveness`, `upgrade` |
| Perps / options / structured | `economics`, `accounting`, `live-reality` | `liveness`, `coverage-gap` |
| Governance / timelock / treasury | `privileged-path`, `upgrade` | `liveness`, `delta` |
| Any fork of a known upstream | `upstream-diff`, `delta` | the shape's own row |
| Any target with a public documentation site, integration guide or SDK | `spec-divergence` | the shape's own row |
| Any upgradeable deployment | `upgrade`, `privileged-path` | the shape's own row |
| Solana / Anchor program | `anchor-account`, `privileged-path`, `economics` | `business-logic`, `temporal-logic` |
| Native Rust worker / keeper / bridge | `recovery-failure`, `semantic-mismatch`, `business-logic` | `temporal-logic`, `composition` |
| Move / Cairo / CosmWasm | `business-logic`, `temporal-logic`, `privileged-path` | `composition`, stack-native adapter |
| Cross-language relayer + contracts | `semantic-mismatch`, `recovery-failure`, `integration-auth` | `composition`, `coverage-gap` |
| Go / Python / TypeScript backend | `privileged-path`, `recovery-failure`, `business-logic` | `semantic-mismatch`, `composition` |
| A website or dApp listed in scope | `web-frontend` (`--lens web`) | the program's web exclusions first |
| Any EVM target | `classic` (Part A always; Part B unless `solidity-auditor` ran) | — |

Two lenses run on essentially every target, because their yield does not depend on the protocol's
shape: **`privileged-path`** (access control and initialization are the categories automated
reviewers measurably miss most, and the largest real losses came from them) and **`coverage-gap`**
(the tests tell you what the authors never checked).

## Stage B — Attack (the hunt passes)

```sh
python3 $S bundle --repo <checkout> --run <run> --lens attack --scope <source roots> --include <run>/delta.json
```

The `attack` group is the six highest-yield mechanism lenses — `privileged-path`, `accounting`,
`integration-auth`, `external-call`, `economics`, `liveness` — plus `classic`, the standard-class
questions (`hunt-agents/classic-agent.md`). The `config` group is `live-reality` and `upgrade`, which
check what is true of the deployment rather than the source. Add `--lens anchor-account` for a
Solana program. Each bundle carries the SOP, the shared rules, that lens's procedure, the impact
ladder, the precedent catalogue, the run context, all in-scope source, and — when the run has them —
the mechanical outputs that lens uses: `impact-paths.json` for `impact-first` and `seam` (and every
lens of the `high-impact` group when that group is bundled), `coverage-priority.json` and
`state-graph.json` for `impact-first` and `seam` only, `odd-one-out.json` for `privileged-path`,
`accounting`, `business-logic`, `classic` and `seam`, and the unexamined entry points of
`function-coverage.json` for `coverage-gap`, `classic` and `seam`. The `classic` bundle also carries the
records already in the run, so it can see what an imported `solidity-auditor` sweep covered. Credentials
found in bundled source are redacted and listed in the result's `redacted_secrets`.

**Pick one base group, then add to it.** The base groups are alternatives, not layers:

| Base | When |
| --- | --- |
| `attack` | The default for EVM targets. |
| `high-impact` | A large value at risk and the goal is loss-of-funds class findings: `impact-first`, `privileged-path`, `accounting`, `external-call`, `integration-auth`, `business-logic`, `economics`, `composition`. |
| `recommended` | Non-EVM or mixed repositories, where the `stack_route.py` shortlist fits the stacks better than the EVM-shaped `attack` group. |

Then add only what the target's shape calls for: `config` when there are deployed addresses,
`logic` when several actions change the same asset, privilege, reward or epoch, `cross-stack` when a
keeper, relayer, signer, API or watcher shares a trust boundary with on-chain code,
`anchor-account` for Solana, and `web` when a website or app is in scope. Lenses named in the shape table but absent from your groups can be
added individually with `--lens <name>`.

**A pass that did not run `bundle` did not bundle its source**, and a lens reading files
opportunistically covers less than a lens handed everything. The command is the mechanic, not a
suggestion.

Dispatch one agent per bundle, each in its own context, up to four concurrent by default. Tell each
agent only: read this bundle and follow it. Independent contexts are the point — agents sharing one
context converge on the first idea and stop being independent reviewers, and an orchestrator that
reads eight bundles itself has performed one reading, not eight.

`bundle` logs what it emitted to `bundles/manifest.json`. `queue` lists any lens assembled and
never read as `unread_bundles`, and the submission gate refuses a run that still has one, because
a lens that was never dispatched is a surface nobody covered.

Three passes by default:

- **Pass 1** runs the selected lenses on the ranked surfaces.
- **Pass 2** runs the same lenses again with `known-hypotheses.md` now in the bundle, so each is
  explicitly hunting past its own earlier output. Drop a lens from pass 2 if its pass-1 reading
  added no mechanism and no coverage.
- **Pass 3** is the `seam` pass (Stage C) over both passes' records, plus a targeted re-read of
  every `open-needs-experiment` lead whose cheapest experiment has now run or been blocked.

> **Where budget allows, dispatch a selected mechanism lens twice in pass 1, in separate
> contexts.** Do this selectively: count distinct mechanisms and new covered paths, not just model
> agreement. Repeated contexts cost real budget and may be correlated. State the readings that ran
> and what unique coverage each added.

## Impact-first scanning

Use `bounty.py impact-plan --solc <compiler-output.json> --out <private-run>`
to inspect compiler-resolved Solidity AST at the exact pinned revision.
Python can use `--repo`. The result is a source-anchored **review queue**,
not full semantic exploit proof. It cannot prove aliases, dynamic dispatch,
modifiers, permissions or market impact. Follow with
`bundle --lens high-impact`, then native PoCs and explicit economic values.
See `references/impact-first.md`.

## Adaptive reading budget

Use `python3 <skill-dir>/scripts/stack_route.py --repo <checkout>` to produce a conservative
runtime inventory and a six-lens shortlist, or `bounty.py bundle --lens recommended` for
bundled independent contexts. The priority is an unvalidated heuristic based on manifests,
not the probability of real vulnerabilities. Track unique surfaces and mechanisms after
passes; stop duplicating a lens if its new coverage is zero. Override automatically chosen
lenses when target facts warrant it, and document omitted necessary analyses.

## Independent stateful logic discovery

Use `--lens logic` for `business-logic`, `temporal-logic`, and `composition`.
These independently inspect source, even when earlier lenses produced **zero** candidates.
Use `--lens cross-stack` for `semantic-mismatch` and `recovery-failure` whenever
multiple runtimes or asynchronous components participate. Apply adapter guidance
(`adapters/`) for the **actual** runtime. `seam` remains a separate recombination
pass over earlier records; it does not replace independent composition search.

Avoid exploding the budget: after the initial ranked pass, choose the single most plausible
hypothesis and run its cheapest decisive native test while the next readings run, rather than
dispatching a second copy of a lens to argue about it.
The lexical `state_graph.py` output can guide selection but is not a reachability graph.

## Evidence-First checkpoint — alongside the passes, not between them

After the first ranked reading pass, run up to three decisive native
candidate/negative-control pairs, or record a genuine blocker plus an attempted
alternative. See evidence-first.md and enforce:

~~~sh
python3 $S experiment-gate --run <run> --limit 3 --gate
~~~

**Start the next pass first, then run these experiments while it reads.** The experiments are
serial work the orchestrator does itself; the pass is parallel agents on other surfaces, and
`known-hypotheses.md` and `saturated.md` already stop it re-reading what is untested. The gate is
mandatory before the run is reported, never before a reading. Placed between passes it delays the
only step that finds bugs: in a live run eight bundles were assembled and `coverage.md` came back
empty, because the budget went to the checkpoint and the readings never happened.

Carrying an untested top-ranked candidate through the whole hunt is still a workflow failure, however
convincing the written hypothesis. The experimental result informs Stage D adjudication; do not
merge hunt and triage roles.

Check scope-audit after every new bundle. If a Solidity-only scope prefix omits
a tracked Rust relayer or keeper, resolve scope and either re-bundle or document
its exclusion before claiming meaningful mixed-stack coverage.

## Stage C — Seams

```sh
python3 $S bundle --repo <checkout> --run <run> --lens seam
```

The `seam` bundle carries the earlier passes' records, including the **demoted and refuted** ones,
and hunts only mechanisms that need two axes at once. This is also where refusals get reconstructed:
a lead demoted for "no impact" and one demoted for "unreachable" are often the same bug, each
supplying what the other lacked.

## Escalation — after the passes, before triage

Between the hunt passes and Stage D, every record climbs the amplifier ladder in `escalate.md`:
`repetition`, `other-parties-funds`, `composition`, `become-the-trusted-party`, `timing`,
`freeze-instead-of-theft`. Each gets `reached`, `blocked` or `not-applicable`, and `reached` and
`blocked` carry an anchor of the same four kinds triage uses. The stage is still the hunter's
stance — it deepens the claim and refutes nothing — and a record closed at a low impact class with
an empty ladder is an unfinished record, not a cheap one. `queue` reports the missing amplifiers
and the submission gate refuses the record.

## Stage D — Triage, two rounds

Findings now meet an agent whose job is to reject them. The full protocol, including the rule that
**objections carry anchors too**, is in `adjudicate.md`.

```sh
python3 $S bundle --repo <checkout> --run <run> --lens triage
```

Round 1: the triage agent emits anchored `OBJECTION` blocks and explicit `CONCEDED` blocks. Round 2:
each objection is answered with its own anchor, and the exchange is recorded on the finding as
`objections[]`. The checker validates the shape; the submission gate refuses a finding with a
sustained objection, or with no triage exchange at all.

Run triage **after** the hunt passes, not between them. A hunter that knows triage is coming next
starts softening its own claims, which is exactly what the separation exists to prevent.

## Between passes — write the floor

After every pass, append one line per investigated mechanism to `known-hypotheses.md`:

```
surface | bug-class | status | one line: why it is closed, or what is still open
```

Status is `closed-refuted`, `closed-verified`, `closed-parked`, `open-needs-experiment` or
`open-blocked`. An `open-…` row names its record's `BP-` id, and that record must be live
(`hypothesis`, `needs-evidence`, `verified` or `parked`); `check` fails on an open row without one.
In the first runs 25 of 30 open rows had no record, so no queue showed them and every later pass
was told the file is closed ground. Include
the mechanisms you looked for and did **not** find — an absence recorded is coverage; an absence
forgotten is a pass spent re-deriving it. Record what you did not reach too: files unread, branches
untraced, dependencies unopened. That list is the honest answer to "what did this cover", and it is
where the next pass aims.

Then add the pass's readings to the run's convergence and rewrite `saturated.md`: the mechanisms
two or more independent readings reported, grouped by file, function and bug class.

```sh
python3 $S converge --run <run> --readings <dir of this pass's raw reading output>
```

`converge` keeps every reading it has seen in the run, so pass 2 adds to pass 1 instead of replacing
it, and a mechanism seen once in each pass is two readings. `--reset` starts the count over. Two
bugs of the same class in two functions of one file are two groups, never one: merging them would
close the second as saturated ground. The **singletons** are the output to act on — `queue` lists
the ones with no record as `unrecorded_singletons`.

A reading whose file has since disappeared still counts, flagged in `missing_sources`
(`--drop-missing` removes it); copies differing only in whitespace count once; raw `solidity-auditor`
output saved beside its own `run-K.md` files is folded into them rather than counted twice. Header
variants such as `**FINDING 1** |` or `### CANDIDATE 3 |` parse, and anything that looks like a
header but does not is listed as skipped. A line whose record is an imported hypothesis nobody has
triaged is marked UNTRIAGED in `saturated.md`, and is not closed ground either.

That list goes into the next pass's bundles beside `known-hypotheses.md`, and `_shared.md` tells
every lens to treat its recorded lines as closed ground. A line marked UNRECORDED is a mechanism
several readings found that has no record yet: record it before the next pass, or it is lost
between the files — a reading spent re-deriving a saturated mechanism under a
new label is a reading spent on nothing. Convergence counts what was reported, not what is true: a
mechanism every reading agreed on can still be invalid.

Update `coverage.md` with which lenses actually ran, how many readings each got and what each
closed. **Which functions were examined** comes from the readings themselves: each ends with
`EXAMINED | path:Contract.function` lines, and `converge` collects them into `examined.json`. A file
row credits the file; only a function named in `examined.json`, a `coverage.md` row, a hypothesis
surface or a record's `affected_paths` credits that function. A lens you could not dispatch is reported, never silently
skipped. Then run:

```sh
python3 $S function-coverage --run <run>
python3 $S queue --run <run>
python3 $S history check --run <run>
```

Run the cheapest decisive queued test while the next pass reads, never as a wait before it. Review same-project history matches
for exact repeats; use them to steer later passes toward distinct root causes. A shared path is not a
reason to drop a lead, and a similar pattern in another repository is context, not a duplicate.

## Stop rules

A pass is not done while a record sits at a low impact class with an empty ladder: run `escalate.md`
over those records first, because the cheapest finding left on the table is one that was already
found. Then stop when any one is true:

- The planned pass count is spent.
- Two consecutive passes produce neither a new mechanism nor new coverage. More reading will not
  help; the open leads need experiments.
- Every lens the shape table calls for has run, the seam pass has run, and `misses.md` is
  answered.
- Every remaining lead is blocked on the same missing capability — a toolchain, an RPC, program
  rules. Report the blocker rather than narrating around it, and reproduce it first: a shared
  blocker closes the whole run, so it is the one claim worth an `output_excerpt`
  (`evidence.md`, `blind-spots.md` §8).

Each of those is a claim about coverage, so none of them is satisfied on your own sense of having
read enough. Measure it:

```sh
python3 $S coverage-floor --repo <checkout> --run <run> --scope <source roots> --gate
python3 $S function-coverage --run <run> --gate
```

`coverage-floor` writes `coverage-floor.json`: the in-scope files compared against what this run
actually recorded — `coverage.md` rows, `known-hypotheses.md` surfaces and `affected_paths` in
`findings.json` — with the examined fraction and the list of what is unexamined.
`function-coverage` does the same one level down, over every external entry point, and ranks the
unexamined ones so that state-writing and value-moving functions come first. A file can be
"examined" while most of its entry points were never named; the second number is the one that
says whether anyone looked. **A run may not
call itself exhausted over an unread majority.** This is a condition on the rules above, not a
replacement for them: on one target a hunt was declared exhausted after eight contracts, and
nothing ever compared that against the in-scope file list. Either read what the floor names, or
write in `coverage.md` which files you are leaving unread and why — the unexamined list is the
honest coverage statement, and it is where a resumed scan aims.

`--gate` fails below `--min-fraction`, default 0.8: a coverage row is cheap at the moment you
declare yourself done, including a "read it, nothing here" row, which is what the table is for, and
the remaining fifth is room for files that genuinely need none. A surface ending in `/` names a
directory; the files under it are reported as `credited_by_directory_only` and do **not** count
toward the floor — one `src/` row once made a whole scope read as examined. A bare name with no
separator credits nothing, because `src` and an invariant called `accounting` are
indistinguishable — except a file name with an extension (`Vault.sol`) that is unique in the scope;
an ambiguous one is reported, not credited. Both floors record digests of their inputs, and `queue`
reports a result as `stale` when the inputs changed after it was computed — rerun it before relying
on the number.

There is no finding quota. Zero verified findings after an honest run is a legitimate result, and
more useful than three inflated ones: say which surfaces you closed and on what evidence.

## Before you report — answer `misses.md`

The last step of the loop is not a pass; it is a check against your own output.
`references/misses.md` lists thirty-three ways a hunt stops short, each with a cheap fix: concluding from
a name, stopping at the first consequence, skipping the privileged path because a checklist said
"do not report admin can rug", never reading the dependency, never checking the compiler, auditing
HEAD when scope is pinned to deployed addresses, dropping leads silently, and letting an unanchored
objection kill a real finding.

Answer every item in writing, including on a run that found nothing. Most are one command or one
paragraph, and each of them is a near-miss that was already paid for.

## Budget, honestly

Three passes over the seven `attack` lenses, with two of them doubled in pass 1, is about 17
readings (9 + 7 + 1 seam), plus 4 aim readings, the escalation pass and triage. Each mechanism bundle contains the full in-scope source, so cost scales with the codebase —
`bundle` reports each bundle's size and warns past 400 KB, where narrowing `--scope` and trusting
the ranking beats handing a lens more than it will read.

If the target is Solidity and `solidity-auditor` is installed, delegate the classic bug-class sweep
to it — in a disposable copy, with `--loop N`, aimed by file names — and spend this loop's passes on
the aimed lenses it has no equivalent for. Bring its output in with `import-findings`; `compare.md`
has the division of labour and the import rules. Do not nest the two orchestrators.

## Carrying work across scans

`known-hypotheses.md` and `findings.json` from a previous run on the same target are inputs to the
next one. On resume, compare the recorded commit with the current one: mechanisms on unchanged code
stay closed, mechanisms on changed code reopen. A refuted record whose cited protection has since
been edited is alive again — rechecking exactly those is one of the most productive things a second
scan does. So are `parked` records: `queue` lists each with its `revive_if`, and a condition that
now holds (deposits grew, scope widened, a program that covers it appeared) makes it fileable.
