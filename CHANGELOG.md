# Changelog

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
