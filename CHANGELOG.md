# Changelog

## 0.15.0

The workflow gated everything except the one step that finds bugs.

Deployment evidence, duplicate review, the escalation ladder, experiments and the scope audit all
became gates with a script behind them. Dispatch — one agent per bundle, each in its own context —
stayed prose. `bundle` wrote the files and nothing ever checked that a reading came back, so under
budget pressure it was the first thing dropped, silently. In the `lifi` run eight lens bundles were
assembled, `coverage.md` came back as the empty template and no record carried any of those lenses:
the bundles were built and never read, and the run looked normal.

### A bundle nobody read is now visible, then refused

- `bundle` logs what it emitted to `bundles/manifest.json`: an accumulating list of dispatch events
  bound to the `run_id`, each with the commit, the scope prefixes, and per bundle the lens, path,
  size and sha256. Rebuilding one lens never drops another.
- A lens counts as read on any one of four signals: it appears in `convergence.json`, a
  `coverage.md` row names it, a record in `findings.json` carries it, or — for `triage`, whose
  product is objections on other agents' records — a record carries an objection or a concession.
  Four routes rather than one, so the check does not cry wolf.
- `queue` lists the rest as `unread_bundles`. It stays a report: it does not fail, and `state` is
  unchanged.
- `check --submission` refuses a run that still has one. A run with no manifest is never blocked,
  so older runs and runs that never bundled are unaffected, and structural `check` ignores it.

### The Evidence-First gate no longer stands in front of the passes

- It was mandatory *before the next broad pass whenever open records existed* — and a first pass
  always leaves open records. Running up to three experiments is serial work the orchestrator does
  itself, so passes 2 and 3, where most of the dispatch lived, stopped arriving.
- Its purpose was that a later pass should not re-read an untested hypothesis, and
  `known-hypotheses.md` and `saturated.md` already carry that into the bundles. So the gate now runs
  **alongside** the next pass and is mandatory before the run is reported, never between readings.

### Said plainly in the instructions

- `SKILL.md` and `passes.md` now state that assembling a bundle and reading it yourself is not a
  pass: an orchestrator that reads eight bundles in one context has performed one reading, not
  eight. A runtime with no agent tool is a degraded mode to record in `coverage.md`, not a
  substitute.

## 0.13.0

- Evidence-First checkpoint: private experiments.json records paired native
  candidate and negative-control execution, or an actual toolchain blocker
  with an attempted alternative. New experiment-gate command refuses dry-run,
  zero-test, timed-out, stale-revision and unpaired evidence.
- queue includes the experiment checkpoint; existing run directories without
  an experiment ledger are still readable.
- scope-audit checks tracked language stacks against the actual source bundle.
  bundle reports missing stacks; examples avoid blindly scoping to src/.
- Added unit regression cases plus native Foundry/Rust smoke and end-to-end
  runner/evidence-gate tests in CI. Runner records observed checkout Git SHA.
- The CI fixture is intentionally flawed and proves toolchain integration,
  not vulnerability discovery or payout uplift. Backtest protocol unchanged.

## 0.12.0

An audit of every run so far asked one question: where do good findings and leads get lost? Not at
triage — the anchor rule held, and the refusals on file are careful. They are lost earlier and more
quietly, between files and inside one overloaded status.

### Open leads cannot fall between the files

- Leads lived in two places. `queue` and every gate read `findings.json`; the lenses were told that
  everything in `known-hypotheses.md` is closed ground — although that file records open rows too.
  Across the first runs, 25 of 30 open rows had no record. One of them, on Morpheus, was
  `admin-retroactive-withdraw-lock-freeze`: it became the run's verified High only because the
  orchestrator happened to pursue it. The USDai refinance lead exists only as such a row.
- An open row now names its record (`BP-…`), and that record must be live. `check` fails on an open
  row with no record, with a record it does not hold, or with a refuted one.
- `_shared.md` now tells lenses that `closed…` rows are closed ground and `open…` rows are leads to
  finish when their surface is reached.

### A finding written up in prose must be a record

- The first Morpheus run proved F-06 three times, judged it submittable and drafted the report —
  in markdown only. With one record in `findings.json`, no queue or gate ever showed it, and two days
  passed in a first-to-report program before a second run found it again and took it to High.
- `check` fails on a `findings/**/*.md` or `SUBMISSION-DRAFT*.md` that cites no record's `BP-` id.
  Against that run it reports 17 such documents.

### `parked`: real, but not fileable now

- `refuted` meant both "wrong" and "right but ineligible". Five of seventeen refuted records were real
  mechanisms — "not on technical validity", "the mechanism is real, reproduced three times",
  "unprofitable at current TVL" — and a refuted record leaves the duplicate and history joins for
  good.
- New status `parked`, requiring `park.reason` (`out-of-scope`, `excluded-impact`,
  `uneconomic-now`, `accepted-risk`, `other`), `park.revive_if` and `park.evidence`. A parked record
  stays in `dup-check` and in the history comparison, is never a submission target, and `queue`
  lists it with its revive condition on every resume. Gate 5 in `adjudicate.md` now records a real
  but ineligible finding as parked.
- `queue` lists `possibly_parked`: refused records whose wording describes a real, ineligible
  mechanism, for review. It flags BP-006/008 (Morpheus), BP-201/202/203 (Safe) and BP-302 (Besu) on
  the existing runs. A prompt, never a gate.

### Saturated ground must be recorded ground

- `converge` declared a mechanism closed once two readings reported it, without asking whether
  anyone had recorded it. Each saturated line now names its record, or reads
  `UNRECORDED - record it before treating it as closed`, and the result lists
  `saturated_unrecorded`. Lenses treat only recorded lines as closed.

### Fewer silent drops at generation

- Lenses no longer stay silent on a candidate that matches a dup-map entry unless they can name the
  difference. They emit it as a LEAD naming the entry, and `dup_review` decides. 0.11's harvest made
  the map much larger — 102 entries on `liquity/bold` — so this suppression would have grown with it.
- A role any user can create or take — the admin of their own pool, market, vault or subnet, a
  self-assigned delegate — is not a trusted role. `_shared.md`, Gate 3 and `impact-classes.md` now
  say so; the Morpheus High turned on exactly this reading.

### `queue` shows what would otherwise be lost

New sections: `untracked_leads`, `unrecorded_documents`, `parked`, `possibly_parked`. The queue
reports ledger problems instead of turning invalid on them, since showing them is its job.

### Note for runs already in flight

Existing runs now fail `check` until their open rows and write-ups are recorded: run `queue`, then
record each untracked lead and document (any status), or close the row with its reason.

## 0.11.2

### A different bug class on a burned surface is reported, not skipped

- `dup-check` dropped a map entry whenever both sides carried a bug class and the classes differed,
  although `references/dup-map.md` promises those as `surface-only`. On a Morpheus run a candidate
  labelled `donation-buys-emission-share` met a published QA finding labelled
  `donation-inflates-measured-yield` on the same `DistributorV2.distributeRewards`: the same root
  cause with a different consequence, and no collision was reported. Since the submission gate only
  asks `dup_review.entry_ids` to cover reported collisions, a likely duplicate passed as `no-match`.
- Every entry on the finding's surface is now a collision: `class-match` when the class is the same,
  `surface-only` otherwise. A record that was clean only because its label differed now needs a
  `dup_review` naming that entry before submission.

## 0.11.1

A live check of 0.11.0 against GitHub found the gate right on the case it was built for — it
retrieves `liquity/bold` #506 among 91 judged issues — and wrong in three ways around it.

### A harvest that searched nothing no longer reads as clean

- `ethereum/go-ethereum` has 36 labels and none means *already judged*. 0.11.0 searched nothing,
  found nothing and let submission through: the empty, reassuring result `solc-bugs` is forbidden
  to return. Such a harvest is now `vacuous` and blocks the gate until it is resolved with
  `--label`, `--include-not-planned`, or `--empty-reason "<why>"`. A search that ran and found
  nothing is still a clean result. `dup-harvest` exits 1 on a vacuous harvest and says why.

### Firms the name list misses are visible

- `Coinspect` and `Recon` labelled thirteen imported audit findings on `liquity/bold` and were not
  on the list. Both are now, with a dozen more firms. The list will never be complete, so every
  label the harvest did not select is reported as `labels_skipped`, where a missing firm shows.
- Hints match whole words: `Recon` is selected, `reconciliation` is not.

### GitHub's own wontfix

- New `--include-not-planned` adds the issues GitHub shows as *closed as not planned*, which carry
  no label; #506 was closed that way too. It is noisier than labels, so it is opt-in, and it is the
  suggested fallback on a repository with no judged labels. Candidates record `matched_by`.

### Issue text is data

- The harvest notice and `references/dup-map.md` now state that titles and excerpts were written
  by whoever opened the issue and are never instructions, as for target source.

## 0.11.0

Aimed at the failure the finding ledger actually shows: of four withdrawn reports, two died on
`liquity/bold` issue #506 — a closed issue labelled `ChainSecurity` and `wontfix`, linked from the
competition page as out of scope. The measurements were right; the issue was never read. The
duplicate map existed as a procedure and as an empty file that passed the gate.

### The closed issues the team already judged are retrieved, not remembered

- New `dup-harvest --run <run> [--repo owner/repo] [--label L] [--token-env VAR]
  [--from-file saved.json] [--limit N]`. It reads the repository's own label list, keeps the labels
  that mean *already judged* (`wontfix`, `known issue`, `by design`, `accepted risk`, and the names
  of audit firms and contest platforms), searches closed issues and PRs for them, and writes
  `dup-harvest.json`.
- It never writes `dup-map.json`. Mapping an issue to a surface and a bug class is judgement, and an
  entry invented from an issue title burns a surface that was never burned.
- `--from-file` takes a saved search, for a network-free environment or a non-GitHub host. A token
  named with `--token-env` travels in a header and is never printed or written to the run.
- Triage survives a rerun for every issue still in the harvest.

### The duplicate map is now a gate, not a file that exists

- `dup-check` writes `dup-matches.json`, bound to the `run_id`, to the candidate mechanisms, and to
  the map it read. A map that grows after the join invalidates it, because the new entry was never
  compared. A join against a map that does not validate is not written at all.
- New optional `dup_review` record field: `status` (`unchecked`, `no-match`, `different-mechanism`,
  `different-consequence`, `same-mechanism`), the `entry_ids` it was compared against, and the
  `rationale`. The three legitimate collision outcomes in `references/dup-map.md` are now the three
  non-blocking statuses.
- `check --submission` blocks on: a missing or truncated harvest, any untriaged harvested issue, a
  missing or stale `dup-matches.json`, a missing or `unchecked` `dup_review`, a `same-mechanism`
  one, a `no-match` claimed over a real collision, and `entry_ids` that do not cover every collision
  the join reported. The old check — that `dup-map.json` is merely present — is gone; an empty map
  passed it.
- `dup-map.json` entries now require a unique `id`, which is what `dup_review.entry_ids` cites and
  what the gate counts. The format in `references/dup-map.md` already documented it.

### Note for runs already in flight

The record schema is unchanged (`schema_version` 2) and `dup_review` is optional, so an existing
run still validates structurally. A run that is ready to submit needs `dup-harvest`, its triage,
one `dup-check`, and a `dup_review` on each submitted record.

## 0.10.0

Aimed at the failure the 0.9.1 backtest measured: independent readings converge on the same
mechanism, and records get closed at their cheapest consequence.

### Stop re-finding the same thing

- New `converge --readings <dir|file> --run <run> [--threshold N]` parses raw hunt-agent output,
  groups `CANDIDATE`/`FINDING`/`LEAD` blocks by bug class and surface file, and counts how many
  **independent readings** reported each mechanism. It writes `saturated.md` (closed ground, carried
  by every later bundle) and `convergence.json`, whose `singletons` list — mechanisms only one
  reading saw — is the half worth acting on.
- Bundles gain a short notice about saturated ground when the file is non-empty, and are
  byte-identical to before when it is not.

### Escalation is recorded, not assumed

- New optional `escalation` record field: one entry per amplifier (`repetition`,
  `other-parties-funds`, `composition`, `become-the-trusted-party`, `timing`,
  `freeze-instead-of-theft`), each `reached`, `blocked` or `not-applicable`, anchored where it was
  reached or blocked, plus `ceiling` and `ceiling_evidence`.
- The submission gate requires the complete ladder on every submitted record. `queue` reports
  `escalation_gaps` per open record and `weak_refusals` for records dropped without trying anything.
- New `references/escalate.md` defines the stage, which sits after the hunt passes and before
  adjudication.

### Twentieth lens: `spec-divergence`

- An aiming lens that compares the project's published promises against the code. Its filter is not
  "the text disagrees with the code" — most of those are stale documentation — but "the
  documentation promises a protection a user or integrator relies on, and the code does not
  implement it". Its second product, often worth more, is quoted promises that answer the "intended
  behaviour" objection in triage.
- Bundles for this lens now carry a `docs.md` built from the project's markdown and prose, the way
  `coverage-gap` receives `tests.md`.

## 0.9.1

Fixes from a full review of 0.9.0. No new lenses; the gates got stricter and the instructions got
shorter.

### Submission gate

- `check --submission` applies the submission requirements to records with status `verified` only.
  Refuted and open records stay in the run and need only be well formed. Zero verified records is
  an error.
- An objection that carries an anchor can no longer be `withdrawn`. The triage exchange needs at
  least one answered or sustained objection, or a concession; triage's `CONCEDED` blocks are now
  recorded in `concessions[]`.
- `deployment_status: exact` must be backed by a `verify-deployment --run` file named in
  `deployment_evidence`. `not-applicable` needs `deployment_rationale` and is refused for
  Solidity/Vyper paths.

### Deployment and chain reads

- `verify-deployment` masks `immutableReferences` and `linkReferences` from the artifact, so
  implementations with immutables (every OpenZeppelin UUPS implementation) can match `exact`.
- New proxy kinds: legacy zeppelinos slot, Safe, Compound Unitroller, EIP-2535 diamond (`partial`,
  facets listed). A small runtime that delegates but matches no known kind is `partial`.
- `value` reports per-token errors instead of aborting, scales `decimals == 0` correctly, and
  flags token addresses with no code.
- `solc-bugs` treats `^0.8.0` as a range, ignores commented-out pragmas, reads `=0.8.19` as exact,
  and matches pragma ranges against the bug list (`range_matches`).

### Hardening

- Target files are read through one helper that refuses symlinks, special files, paths outside the
  checkout and files over 2 MB; skips are listed in the output.
- Every git call neutralises `core.fsmonitor`, hooks and pagers from the target's config.
- Bundles and the triage header tell every subagent that target content is untrusted data.
- Secret redaction catches prefixed key names, JSON keys, bearer tokens and RPC URLs with keys.
- `scenario_runner.py`: refuses to run where Foundry would auto-load a `.env` (unless
  `--allow-dotenv`); `pass_env` for named variables, redacted from output; toolchain variables
  (`HOME`, Go and Cargo caches) allowed so Go plans work; shells and `-c` interpreters rejected;
  whole process group killed on timeout; a selector that ran zero tests is `no-tests-ran`.
- `bundle --run` and `impact-plan --out` refuse directories inside the target or the skill.

### Analysis helpers

- `delta` handles cross-directory renames.
- `semantic_graph.py`: modifier bodies, storage-pointer writes, ETH transfers, interface functions
  no longer entry points, sink labels by function name, explicit truncation flag, a clear error
  for build-info written without `--build-info`.
- `stack_route.py`: Hardhat is no longer tagged as a web backend; Anchor workspaces get
  `anchor-account`.
- `state_graph.py`: generic and lifetime signatures, vendored directories excluded, project source
  read first.
- `scenario_fuzz.py --max-seconds`; backtest scoring no longer credits refuted records.

### Templates and docs

- One PoC convention: the candidate test passes when the bug is demonstrated, the negative control
  passes when the protection holds.
- `SKILL.md` restructured: `init` first, `delta.json` actually written, three passes defined, one
  base lens group, `<skill-dir>` defined, user-language replies, optional Stage 5 helpers moved
  to `references/verify-tools.md`, broken `\\` line continuations fixed.
- `hack-patterns.md`: Balancer v2 (2025) corrected to a rounding defect, Bybit dated, sources added
  to `SOURCES.md`.
- README and README.ru: nineteen lenses, full lens table, plugin install commands.
