# Changelog

## 0.33.0

### Land the work that only existed installed, and stop the two skills colliding

**0.29.0 through 0.32.0 were never released.** AVRE, Ecosystem Intelligence and the attack-chain
review were written straight into `~/.claude/skills/bounty-pilot-lab` and never committed: 4,160
lines in six scripts, three references, one template and two `bounty.py` subcommands, with no
branch, no tag and no backup. The documented install route opens with
`rm -rf ~/.claude/skills/bounty-pilot-lab`, so one reinstall would have deleted all of it. This
release is that installed tree, committed as it stood, plus the manifest and documentation fixes
below. **None of it has a test yet** — the suite is the 0.28.0 suite and mentions none of these
modules, so treat every claim here as unverified by CI.

- **`ecosystem-intel` (new subcommand, `ecosystem_intelligence.py`).** A passive, local inventory
  behind an explicit scope file: tracked files and Git history only, with already-saved public
  archives importable from disk. It makes no network request and emits hypotheses, never findings.
  An omitted entity inherits no permission and active method names are rejected even when a scope
  file lists them. Writes JSON, Markdown, Mermaid and an audit log. Unscoped targets come back
  `UNKNOWN` and it still runs — read the scope field before reading the leads.
- **`avre` (new subcommand, `avre.py` with `avre_sequence.py`, `avre_economics.py`,
  `avre_runtime.py`).** An opt-in local pipeline for sequence-dependent and cross-component
  hypotheses, over nine modules from `impossible-state` to `hypothesis-ranking`. It reuses the
  state graph, the ecosystem inventory, the blind-spot trust review and the scenario runner in
  dry-run mode; it always passes `allow_exec=False`, so it executes no target test, and it queries
  no live service. Its budget is a bounded candidate and sequence count, not a token allowance.
  Scores order a queue and nothing else. Unlike `ecosystem-intel` it refuses outright without an
  `IN_SCOPE` repository rule that matches the checkout's `origin`.
- **`references/ecosystem-attack-chains.md` and `templates/attack-chain-review.md` (new).** Twelve
  patterns for control planes, storage, CI/CD, identity, support, update and worker services.
  `CHECKED_NO_SIGNAL` is only for an artifact actually inspected; anything inaccessible is
  `UNAVAILABLE`, because a source-only review cannot establish that an external system is absent
  or safe.
- **`transition_research.py` (new).** Alternate same-state operations, revoke/restore paths,
  workflow artifact chains, AI-tool boundaries, policy replicas, architecture branches and
  delete/worker lifecycle cues, as low-confidence source leads. Its
  `runtime_reality_handoffs` names scope-only addresses with no source in the checkout; the
  analyzer never queries them.

### The lab and the stable skill no longer compete for the same trigger

- **`description:` rewritten.** It was byte-identical to the stable `bounty-pilot` skill's. An agent
  picks a skill from that line alone, so with both installed the choice was arbitrary and a hunt
  could silently run the older copy. The lab's line now leads with its own tooling — AVRE, the
  ecosystem inventory, attack chains, agent dispatch, blind-spot experiments — and says plainly that
  a plain hunt naming none of them can take either skill.
- **`marketplace.json` agreed with `plugin.json` at last.** 0.28.0 claimed "the installed skill and
  Claude plugin are named `bounty-pilot-lab`" but left the marketplace declaring `bounty-pilot`
  twice, so the README's own `/plugin install bounty-pilot-lab@bounty-pilot-lab` could not resolve
  and the plugin route would have registered the skill under a directory name that contradicts its
  frontmatter. `test_release.py` compared the three `VERSION` files and `plugin.json` but never
  `marketplace.json`, which is why it passed; it now checks that too.
- **Both READMEs** carry the pre-reinstall `diff` and the reason for it, and warn against keeping two
  skills with the same description. The install check they already documented
  (`cat ~/.claude/skills/bounty-pilot-lab/VERSION` matches `VERSION`) was failing at 0.33.0 against
  0.28.0 and now holds.

## 0.28.0

### Make parallel dispatch recoverable and evidence reviews session-bound

- **Concurrent dispatch state is process-safe.** `agent_dispatch.py` serializes state transactions
  with an OS lock and atomic JSON replacement. Four or more worker processes can record updates
  without losing one another's results. `recover` marks a dead local runner failed and retryable;
  a surviving provider child blocks retry.
- **Only completed readings reach convergence.** Nonzero, timed-out, interrupted and malformed
  attempts remain drafts under their attempt folders. Successful readings are staged and published
  after the completion record is committed, with crash recovery for the publish step.
- **Independence is explicit.** Missing provider session IDs yield `independence_unverified`,
  duplicate IDs yield `independence_conflict`, and submission checks block every non-complete
  dispatch plan. Strict evidence reviews bind producer and reviewer outputs to separate completed
  dispatch invocations, provider session IDs and the saved reviewer JSON digest.
- **Lab identity is distinct.** The installed skill and Claude plugin are named `bounty-pilot-lab`.
- **ZCode app bundle compatibility.** When the macOS CLI's expected provider-config path differs
  from the app bundle layout, the runner stages the CLI and bundled config inside the private
  attempt directory without changing the installed app.
- **GitHub Actions now pins Ubuntu 24.04**, exposes manual dispatch, and limits workflow permissions.
  GitHub did not start the previous workflow because the account billing/spending limit blocked
  runner allocation; resolve that account setting before remote Actions can run.
- Added race, process-crash, recovery, session-binding, failed-output and submission-gate tests.

## 0.27.0

### Optional blind-spot lab and independent evidence stages

- **`agent_dispatch.py` (new).** Starts fresh isolated OpenCode, ZCode, Claude Code and Codex CLI
  jobs from checksum-pinned bundles. Independent blind replicas and diverse-strategy passes remain
  separate. Each plan is capped at 24 jobs; costs the provider does not report remain unknown.
  Results, scrubbed logs, token/cost metadata and retry attempts are saved to the private run. Tests
  use fake CLIs; no model calls were made for this release. The OpenCode CLI was not installed in
  the development environment, so its adapter follows the official documented CLI interface.
- **`experimenter.py` and `evidence_verifier.py` (new).** Drafts deliberately failing native test
  skeletons from open findings and binds existing test names to safe argv. The separate verifier
  keeps `SOURCE_CONFIRMED`, `POC_REPRODUCED` and `IMPACT_VERIFIED` distinct, checks commit/source
  identity, repeated candidate/control runs, saved logs, exact anchors and a distinct reviewer
  record, and never edits finding status. `init --strict-evidence-review` opts a run into this gate;
  existing runs retain their prior behavior.
- **`blindspot_engine.py` (new).** Adds opt-in source and artifact review queues for stale legacy
  functions, invalidation-shaped writer/reader edges, instrumented LCOV branch gaps, mutation
  survivors, patch propagation, collected live config, measured capacity cliffs, cross-component
  trust inventories and rejected leads. Missing live reads remain `LIVE_STATE_UNVERIFIED`. These
  are evidence-labelled leads and do not run target code or change finding status. Only
  `live-config --query-live` queries the explicitly configured read-only methods `eth_chainId`,
  `eth_blockNumber` and `eth_call`; no transaction method is available.
- **Blind benchmark accounting.** `bench_compare.py` can compare provider-reported spend, model and
  budget metadata, plus reviewer-adjudicated unique mechanisms. It stays inconclusive without five
  matched cases and comparable reported spend. No held-out blind benchmark has yet been run, so this
  release makes no measured rediscovery or efficiency claim.
- Added detailed workflows in `references/agent-dispatch.md`,
  `references/experimenter.md` and `references/blindspot-engine.md`.

## 0.26.0

### Hand over a PoC the team can rerun, and write the report like a person

- **`poc-bundle` (new), and the submission gate requires it.** For one finding it packs the test,
  the log that test printed, the paired-runner result and any deployment evidence, writes a README
  carrying the original layout (a gist has no directories, so paths are flattened), and with
  `--publish` creates an **unlisted** gist, then compares the gist's file list with the manifest in
  both directions. `check --submission` now blocks a verified record that has no published bundle,
  one bundled in a different run, or one whose gist does not match file for file. `queue` reports
  the bundles with the command to delete each one.
  - **A credential anywhere in the bundle is a refusal, not a redaction**, because a redacted PoC
    does not run. The scan is the one the record gates already use.
  - **Preparing is the default; publishing is one explicit flag.** `gh gist create` is secret by
    default and has no `--secret` flag, so `--public` is never passed.
  - The README pins the commit the **PoC ran at**, not the one the run was opened at.
  - An unlisted gist is **not** access-controlled. The link belongs in the private report and
    nowhere else, and `poc-gists.json` carries the exact `gh gist delete` command for when the
    finding is triaged. An unfixed bug with a live PoC URL is a disclosure with extra steps.

- **`references/report.md` rewritten around voice.** Programs are explicitly delaying triage over
  LLM-generated submissions, and practitioners report AI pushing duplicate rates up, so a report
  that reads as generated gets skimmed and batch-closed whatever is in it. The file now opens with
  why that is, then names the tells in a table with what to write instead — the greeting, the
  Executive Summary over three sentences, "could potentially", "leverage", bold on every other
  sentence, emoji severity markers, one-row tables, the restated impact, the Conclusion section,
  sections filled only because the template has them. Two get their own paragraphs: hedging in the
  impact sentence, and claiming a severity the rubric does not give. It asks for English, short
  active sentences, first person for what you did, numbers instead of adjectives, a file and line
  on every claim about the code, and under about two pages — the PoC carries the proof. A
  before-you-send checklist closes it. The no-automatic-submission rule and the
  individually-excluded-composition guidance are unchanged.

21 regression tests in `tests/test_poc_gist.py`; 20 fail on `2ab8637` and the 21st is the control.
Publishing is tested through an injected `gh`, so no test creates a gist or touches the network.
898 tests green on Python 3.9 and 3.15.

**This newly fails an old run**, on purpose: a verified record with no published PoC bundle.

## 0.25.0

### Tier 2: a mechanism instead of a theme, and the three layers nothing was reading

- **Every block now carries `mechanism:`** — one sentence naming what is specifically wrong,
  specific enough that reading the named function could prove it false. `_shared.md` gains the
  contract with four worked not-a-mechanism/mechanism pairs and the test that settles it: could a
  reader disprove this sentence by reading the code? `converge` counts blocks without one and
  reports any reading that has none as a `theme_sweep`; `queue` lists them. **Why:** the measured
  failure of an agent doing this job is a plausible report organised around themes that misses
  the bug — the same model finds 50.7% of graded bugs given only the file and 92.6% given the
  mechanism, and this skill's own spec-divergence, business-logic and coverage-gap lenses
  produced 91 structured blocks and no survivors of their own.

- **`node-client` (new lens, group `node`).** The node, client, runtime, precompile or prover:
  untrusted ingress to its first parser, wire-supplied lengths that size allocations, panics on
  the block-processing path, determinism where consensus reads it, unmetered block hooks. Six of
  the seven largest public bounties ever paid were in this layer, and about a fifth of one
  platform's lifetime payout value went to blockchain and DLT targets. `stack_route.py` selects
  it for Go, native-Rust and Substrate stacks and drops it entirely otherwise, so a
  contracts-only target never gets a lens that would read nothing. Its discipline is the rule
  that cost this skill a report: **trace the panic to the process** before calling it a crash.

- **`secrets-artifacts` (new lens, group `artifacts`).** What the project published without
  meaning to: served bundles and source maps, packaged mobile and desktop clients, container and
  CI artifacts, and the history behind the checkout. One of the two confirmed Highs in the ledger
  came from this class, found by accident outside the pipeline because no lens looked. The lens
  never uses a credential it finds — the finding is that the value is published and what the
  service's own permission model says it would authorise.

- **`wallet` (new lens, group `wallet-app`).** Extension, mobile, desktop and hardware companion
  apps, after four wallet hunts with no wallet lens. Every finding in the class is one sentence:
  the user saw A and signed B, or an origin that should not have been able to ask, asked. Its
  bundle carries the web sources when the target ships them and the ordinary source tree
  otherwise, saying which. It leads with the exclusion that decides the class: a precondition of
  a compromised host pays nothing on every programme in it, so the entry point has to be remote.

16 regression tests in `tests/test_tier2.py`; 15 fail on `b6ee81f` and the 16th is the control.
877 tests green on Python 3.9 and 3.15.

## 0.24.0

### Tier 1 of the 2026-10-21 design: hunt the audit gap, price duplicates first, check your own citations

Three readings — 49 of my own runs, a blind-spot review of the skill, and the published data on
post-audit exploits and AI-auditor benchmarks — agreed on one diagnosis. **The bottleneck is
novelty, not detection.** Output per reading had gone up (~2.9 to ~4.3 blocks) while eleven of the
first twelve decided reports came back duplicate or known and none paid. The design is in the
private run notes; this release is its first tier.

- **`audit-gap` (new).** Every in-scope file ranked by whether anybody reviewed *this version* of
  it: `never-audited`, `changed-after-audit`, `audited-stale` (an untouched file whose audit is at
  least `--stale-days` old, 365 by default), `audited-recent`. `sequence_surfaces` lists the
  deployment, migration and upgrade files whatever their band. Reads `audited_revision` from
  `program.json`, or `--audited` repeated; with no baseline every file is `no-baseline`, which is
  an unknown and not a pass. It is handed to the `delta`, `coverage-gap`, `upstream-diff` and
  `spec-divergence` bundles, and `queue` reports the bands. **Why:** of 68 exploited protocols that
  had an audit, 67.6% by count and 94.4% of the loss came through paths outside every audit scope,
  and the in-scope cases hit audits with a median age of 18 months.

- **`novelty-risk` (new).** Per live record, before the experiment budget: searches issues, pull
  requests and their review comments for the record's own function names and class, lists the
  repository's security advisories, and holds five judgement calls no search makes — have I
  reported this before, would their own telemetry show it, is a flag named after the missing
  control, is this a class every model recalls, is a fix already in flight. Each hit takes a
  verdict and each judgement an answer; `--gate` exits non-zero while any is open, and `queue`
  shows the band. It never reports a mechanism as novel: no public match is not no private
  duplicate. **Why:** in six of the eleven duplicates the signal was visible before the work.

- **`verify-anchors` (new), wired into the submission gate.** Opens the file each anchor cites and
  checks the quoted text is in it — objections and answers, escalation amplifiers, `intended`
  odd-one-out reviews, closed `known-hypotheses.md` rows, and the functions `examined.json`
  credits as read. A missing path, a quote that is not there, and a credited function the file
  never names block submission; a drifted line number is reported and does not. Mechanical only:
  it confirms the text is in that file, never that the quote supports the claim.

- **The three paths that dropped a finding with nobody reviewing it are closed.** A closed
  `known-hypotheses.md` row now carries the anchor that closes it, exactly as an objection does,
  and `check` fails without one. SKILL.md no longer tells lenses that burned ground is ground to
  skip, which contradicted `_shared.md` — a known issue and a new mechanism share a function more
  often than not. The `_shared.md` "never report" list became "emit as a `LEAD` tagged
  `likely-excluded`, naming the clause": deciding eligibility is Stage 4's job with the program's
  text in hand, and done at hunt time it is an unanchored refutation nobody can see.

- **`mechanism:` keeps two bugs of one class apart.** Labels are deliberately reused, so two
  different defects in one function merged into a single saturated group and the second
  disappeared. A reading that names `mechanism:` gets its own group; without the field nothing
  changes.

- **Both markdown table parsers skip the header row.** The shipped `known-hypotheses.md` template's
  own header read as a closed row with the status "status", and a kept `coverage.md` header
  counted as a parsed row, which suppressed the "prose over the template" warning.

29 regression tests in `tests/test_tier1.py`; 28 fail on `fd2f48b` and the 29th is the control.
861 tests green on Python 3.9 and 3.15.

**This can newly fail an old run**, on purpose: a closed `known-hypotheses.md` row with no anchor,
and any anchor or `examined.json` entry that cites code the checkout does not have.

## 0.23.0

### Review of 0.22.0: what ran target code, leaked, read exact, or passed when it should not

A six-reader review of `2924bc2` (four on `bounty.py`, one on the other scripts, one comparing
the docs with the CLI) found defects on paths the 773 tests never reached; every code finding was
reproduced before it was fixed. This release fixes the P1 set. Each fix has a regression test in
`tests/test_review_p1.py` that failed on `2924bc2`, and seven negative controls that pass on both.

- **Nothing runs target code before `--deep`.** The toolchain version probes ran in the caller's
  directory, so a committed `.yarnrc` `yarn-path` executed a script from the checkout; they now run
  in an empty directory with `YARN_IGNORE_PATH=1` and `GOTOOLCHAIN=local`. Every helper's git call
  carries the fsmonitor/hooksPath hardening `bounty.py` already had.
- **Nothing bundled or stored leaks.** `--include` bodies and run-context files are redacted and
  counted; raw keys in `accounts: [...]` arrays are redacted; the record secret scan walks nested
  values; `--deep` excerpts are scrubbed of the `--rpc` endpoint.
- **`verify-deployment` never calls a proxy or other code `exact`.** Only a revert means "no getter":
  a rate-limited proxy probe leaves the result `partial`. A `null` RPC result is refused instead of
  read as empty code, an empty slot or a zero balance. A metadata tail is stripped only when it
  parses as exactly one CBOR map of solc's own keys. An empty artifact is a `mismatch`.
- **Gates that passed falsely now fail.** A lens is read only by the Lens column of `coverage.md`;
  `function-coverage` skips only the `.sol` files the graph holds; `converge` keeps the contract
  in the key and `_` in function names; `dup-check` joins by file and function, not substring;
  `dup-harvest` keys triage by repository, reads `total_count`/`incomplete_results`, paginates
  labels and searches only labels the repository has; the runner detects pytest/unittest only as
  the command or the `python -m` module and refuses the inline-code launchers its guard missed; a
  revision other than the run's must be reachable from a remote ref or tag where the checkout has
  any; the backtest credits only sealed findings and hashes every sealed file.
- **Smaller P1 items:** the history ledger survives U+2028 and odd `.git` spellings, and
  `owner/repo` means GitHub; `delta` lists `ignore = all` submodule bumps (14 instead of 3 on
  TON v2025.06..v2026.10) and renamed dependency files; `audit-inventory` is bound to its run and
  commit, lists submodules, and finds `audit-reports/` and firm-named PDFs; import drops upstream
  confidence and keeps same-named contracts in different files apart; a per-address `chain_id`
  binds that address to its chain; cargo `-v`, long forge output and colliding case ids are read
  correctly.

**This can newly fail old runs**, on purpose:
- a record whose `affected_paths` names only the file no longer covers a function group, so its
  singletons reappear in `queue`;
- an `audit-inventory.json` from another run or commit is refused, and each submodule is now an
  entry to triage;
- a deployment file read on a chain other than the one `program.json` gives that address fails;
- a `--label` the repository does not have searches nothing;
- a non-array `dup-map.json`, run outputs cited as a PoC or log, and a PoC revision made locally
  in a checkout with remotes are refused;
- the backtest refuses to seal non-string or repeated ids, or over an existing `matches.json`.

The P2 items and the documentation mismatches from the same review are not in this release.

## 0.22.0

### The ceiling is chosen at target selection, and the reports that decide a finding are published elsewhere

Two fixes, both from measured zero-yield runs rather than from review.

- **`severity_denominator` in `program.json`, scored by `score-target`** (`references/targets.md`,
  `references/misses.md` 32). `payout_max_usd` is what the page advertises; this is what is
  reachable. `kind` is `client-share` / `market-share` / `usage-share` / `window-specific` when the
  rubric multiplies every severity by a fraction the hunter cannot change, or `fixed-usd` /
  `value-at-risk` / `impact-class` when the mechanism sets the band; `measured_fraction` carries the
  share with its `source`, and `ceiling_payout_usd` the highest payout the program's own ladder
  still allows at that share. The scorer **sizes the run** from it — under 5,000 USD
  reachable it says a day rather than a week, under 25,000 USD two or three days — reported as
  `recommended_budget`. Unlike the value ceiling, **`pays_non_fund_impact: true` is no escape** from
  the ceiling, because a share denominator multiplies the non-fund classes too.
  **A low ceiling is a budget question, not a veto:** the band drops one step at most, because
  2,000 USD for a report that lands beats 62,500 USD for one closed as duplicate, and on this
  skill's own record the "better" targets paid zero. The only hard stop is `ceiling_payout_usd: 0`,
  a ladder that pays nothing at the measured share, where no severity is left to claim.
  An absent field is an unknown
  with the instruction to measure the share *before* reading code.
  This came out of three consecutive runs on one client family: the mechanisms were real, two were
  reproduced on a live binary, and a 1.41% network share capped every one of them at Low (about
  2,000 USD) before a line was read. Honest correction, after the first cut of this release: the cap
  did not actually kill those three runs — they died on triage, on public prior art and on
  reachability — so this field is a budget signal, not a post-mortem of them. It reports
  `severity_denominator_ceiling`, `severity_denominator_pays_nothing` and `recommended_budget`, and
  is exercised across the field's shapes including the one that matters: real share numbers on a
  program that does pay non-fund impact.

- **Fetch every published report in Stage 1** (`references/intake.md`, `references/misses.md` 33).
  `audit-inventory` only sees what the repository ships, while the reports that decide a finding sit
  on firm sites, CDNs and contest platforms. The section carries the curl/pdftotext recipe and the
  lesson that cost a week: a competition report recorded as login-gated because its Download button
  had no `href` and one guessed endpoint answered `401` was on a public CDN all along, named in a
  `reportPdfLink` field of the page's own `/api/v0/reports/<id>` response. That file stated the
  load-bearing primitive of a finding already verified on a mainnet fork, in one sentence of an
  acknowledged Low-risk entry. A button handled in JavaScript says nothing about authorization, and
  a 401 on one endpoint says nothing about the others: record a report as unavailable only with the
  list of endpoints tried.

## 0.21.0

### Selection and duplicates, after five consecutive zero-yield targets

No new command. Five targets in a row produced real defects and nothing payable, and the post-mortem
put the cause in Stage 0 and Stage 1 rather than in the hunt. Four corrections, each from a specific
run.

- **Churn is not risk** (`references/targets.md`). `score-target`'s post-audit churn share was being
  read as a bleeding edge. One lending protocol showed **283 commits to the in-scope tree since its
  newest audit** — and every commit subject was `feat: harden…` / `fix: …edge cases`, each with its
  reasoning in the message and a matching regression test. A hardening campaign yields the same
  number as a bleeding edge and is the opposite target. Read the commit subjects; rank on **signs of
  haste** (a product shipped with no audit of its own, deployed bytecode that does not match the
  repository, an absent invariant suite) rather than on commit volume.

- **The target's own adversarial tests are a duplicate source, and a selection signal**
  (`references/dup-map.md` source 2, `targets.md`). One `find | grep -iE "poc|exploit|attack|regression"`
  returned **29 files** covering by name the exact surfaces a day of hunting had probed, and one
  header was a finished verdict in this skill's own format — fixed fork block, live address, graded
  `Low`, with the reasoning. Run it beside `pdftotext` at Stage 1; a `*PoC*` or `P_T<n>*` filename
  is evidence of a previously reported issue even when no audit mentions it.

- **Absence claims about documents need the same standard as absence claims about code**
  (`references/intake.md`). Two runs were steered badly: "no audit in the repository" when the
  `## Audits` table was in `README.md` with an **Acknowledged** finding on the very lane under
  investigation, and "no bounty program" when the program sat at the *sibling* of the page already
  fetched. Exhaust and name `sitemap.xml`, `llms.txt`, the **`.md` twin** (which prints collapsed
  `<details>` blocks a rendered page hides — one hid an entire smart-contract known-issues list),
  sibling security paths, and the vendor's `<project>-audits` repository. **The scope page is usually
  not the rewards page**: one program's bounty page listed no contracts at all while the
  authoritative 21-address list lived elsewhere and contained two contracts absent from every audit,
  every repository and the project's own API.

- **A known issue that asserts a bound is an invitation to test the bound**
  (`references/dup-map.md`). Published text conceding an accounting defect while claiming "no
  principal is lost or frozen, and any voucher can withdraw their full stake at any time" draws the
  eligibility line inside its own sentence. Declare falsification criteria first, then run them. In
  that run the bound held — and the harness instead measured a different actor's loss the sentence
  never mentions, at **4.76% of stake per subsequent participant**.

- **New `references/blind-spots.md` §11 — the delta is where every tool already looks.** Hunting the
  post-audit delta is diff-driven, like every scanner; the surviving bugs are usually in audited code
  that did not change. Also records the three axes that went unused across the whole run — profit
  arithmetic before reading code, state prepared now for somebody else's later call, and protocol
  math under load using the target's own shipped fuzz harness (one protocol's 667 KB corpus was never
  run, and measuring its coverage gave a second gap map in which the in-scope zappers had **zero**
  invariant coverage while an out-of-scope optimizer had 116 references) — plus the mechanical way to
  verify in-body access checks, since a modifier scan reported six unguarded emergency functions that
  each call `_checkOwner()` as their first statement.

- **Practical:** Sourcify v2 (`/server/v2/contract/<chainId>/<address>?fields=sources,compilation`)
  answers keyless where an explorer API is blocked, and **normalise line endings before diffing
  deployed source against an audit snapshot** — without `tr -d '\r'` on both sides `diff` reports one
  whole-file hunk and the real delta is invisible. That one step turned an unreadable 2,341-line diff
  into 5 hunks, +63/−14.

- **Release fixes.** The `tr -d` above and in `references/intake.md` held a literal carriage return
  between the quotes — invisible when rendered, read as `tr -d ''`, which deletes nothing — and is
  now the escape `'\r'`. `.claude-plugin/plugin.json` was still 0.20.0. The skill `description` now
  names Substrate/FRAME and dApp web frontends and backends, both covered since 0.17–0.18 but absent
  from the text that decides when the skill loads. New `tests/test_release.py` asserts the three
  version numbers agree, the changelog leads with the current one, shipped text carries no control
  bytes and the description fits the frontmatter limit; it fails on the original 0.21.0 tree for both
  defects.

## 0.20.0

### Deployed code with no source: read its functions out of the bytecode

A live run had to park an in-scope finding because a factory implementation's source was never
published — the blind spot `references/blind-spots.md` §7 describes and nothing here could measure.

- **New `selectors` command.** From an address (one read-only `eth_getCode`) or from bytecode you
  already hold, it walks the dispatcher and returns the 4-byte selectors the contract compares
  against: named where a known signature matches, unnamed ones listed first because those are the
  surface nobody published. Takes `--abi` (repeatable), `--signatures`, `--block` and `--run`.
- **`verify-deployment` attaches the same lead** to its result and evidence file, from runtimes it
  has already fetched — no extra RPC call. A `partial` or `mismatch` now arrives with "which
  functions differ?" answered, and a resolved proxy implementation gets its own reading.
- **Accuracy, measured.** Across **766 compiled contracts the extracted selectors equal the
  contract's own ABI in 754 (98.4%)**: OpenZeppelin v5.1.0 (150 concrete contracts × four compiler
  settings, including a 45-function Governor that forces the binary-search dispatcher, UUPS, the
  ERC-1967/Transparent/Beacon proxies and clones), 19 hand-written shapes × seven settings (1, 5, 40
  and 200 functions, overloads, nested struct and array arguments, `fallback`/`receive`, payable,
  leading-zero selectors) and 33 Vyper 0.4.0/0.3.10 contracts. ABI canonicalisation was checked
  against solc's own `hashes` map on every case with no mismatch, and `has_fallback`/`has_receive`
  was decided on 525 of 733 solc cases with none wrong.
- **The twelve that are not equal are both explained, not silent:** a hand-written assembly
  dispatcher (its selectors cannot be in a fallback-only ABI — that gap is the signal the lead
  exists for) and Vyper's `--optimize codesize` dense dispatch, whose table lives in copied data;
  both are named in `notes`.
- **It is a lead and nothing more.** Not reachability, not semantics, not a severity; a name is a
  hypothesis. It never sets `deployment_status`, no gate reads it, and a selector handled inside a
  fallback — as `TransparentUpgradeableProxy` handles `upgradeToAndCall` — is invisible to any
  selector list, which the documentation says plainly.
- The signature table is derived from signatures with the bundled keccak, never pasted hex, with a
  test asserting the derived values equal the published ones.
- The module is `evm_selectors.py`: a file named `selectors.py` there shadows the standard library
  module `subprocess` imports and stops every script in the package from starting. Recorded in
  `AGENTS.md`.

## 0.19.1

Three independent reviews of 0.19.0, each by an agent that had not written the code, rebuilt the
honest path end to end and then tried to break it. Everything they reproduced is fixed here, with a
before-and-after re-run of their own repros.

### Evidence gates

- **Zero-test runs no longer pass.** An unrecognised runner is `unknown-runner` unless the case
  declares `expect_tests_marker`; `env`/`timeout` wrappers are unwrapped, `forge t` and `cargo t`
  recognised, and skipped, ignored, `-list`, `--collect-only`, `--dry-run` and `--no-run` runs count
  as zero. `forge test --json` and `mocha --reporter json` are read correctly instead of refused.
- **Deployment evidence is bound to the program**: addresses and chains from `program.json`
  (`in_scope_addresses`, `chain_ids`), no local dev chains, the artifact inside the target's build
  output, and the bytecode comparison re-run at gate time. The record digest is described as what it
  is — it detects accidental edits and is not a signature.
- **One PoC per finding**: two verified records with the same candidate command or identical PoC or
  log content are refused; candidate and control are compared after resolving their directories;
  placeholders can no longer stand in for the executable or most of a command.
- A `blocked` experiment entry needs a command, exit code and failure output, like any blocker.
- `not-applicable` reads the crate manifest before the path, detects workspace and table forms of
  on-chain dependencies, and refuses `.tact` and `.sw`; off-chain keepers under `programs/` and
  client crates keep it.
- Vyper contracts with immutables can now reach `exact`; a short or upper-case revision is accepted
  consistently by both gates; more secret shapes are caught; the runner writes per-case log files;
  `dup-harvest --empty-reason` works without a tracker.

### Coverage and the odd one out

- Comparisons are per deployed contract, through its own linearisation; inherited functions appear
  at the heir, so `upgradeToAndCall` and friends cannot be skipped while coverage reads 100%.
- Modifier arguments count (`onlyRole(MINTER)` is not `onlyRole(PAUSER)`); a modifier is implied
  only by its own checks; `msg.sender` passed as an argument is not a sender check; `_msgSender()` is.
- New `unguarded-hook` lead for authorisation hooks that check nothing; impact paths cap rows per
  sink, drop constructors and name-matched views, and rank unguarded entries first.
- Overload-aware crediting, ambiguous and unparsed surfaces reported, oversized files skipped instead
  of fatal, `stale` results flagged, and `odd-one-out-review.json` to close leads with an anchor.
- On the reviewer's OpenZeppelin-based benchmark: planted bugs found 7/11 → 11/11 (one only at rank
  67 of the impact queue), odd-one-out precision 4/29 → 8/31. A fixture, not a measurement.

### Search

- Bundles no longer tell agents to return only CANDIDATE and LEAD blocks, which had suppressed the
  `EXAMINED` lines function coverage depends on.
- Credentials in bundled source are redacted, not only in configs. The web bundle leaves out deploy
  and script folders.
- `classic` sees the records already in the run; analysis files reach only the lenses documented;
  converge folds raw solidity-auditor output into its run files, accepts common header variants,
  keeps comma-separated `EXAMINED` lists and full `why:` text, and marks untriaged imported records
  UNTRIAGED; `import-findings` orders passes numerically.
- Messaging detection by word boundary across LayerZero, IBC, CCTP, XCM, Wormhole, Hyperlane, CCIP
  and Axelar; `delta` reports config outside `--scope`.

### Tests

- Two tests that searched JSON text for `'95'` failed at random on timestamps; they now check parsed
  values. Fixture commits disable commit signing, so a developer's global signing setup cannot make
  the suite slow or flaky. Two module-level names defined by two merged branches, one of which
  silently replaced the other's secret pattern, were renamed apart.

## 0.19.0

A review of this package against its own claims found the evidence gates checking the shape of
proof rather than proof, coverage that one directory row could satisfy, and a convergence step that
merged distinct bugs into one "closed" line. This release fixes those, measures coverage per
function, makes the odd one out mechanical, and turns the `solidity-auditor` integration from prose
into a command.

### Evidence that takes more than typing

- **A `verified` record needs an executed paired run.** `check --submission` now reads
  `experiments.json`: a verified record whose experiment is `blocked`, queued or missing fails, and
  so does a run with no `experiments.json` at all. The runner binds each result to its plan's
  `finding_id`; candidate and control must differ; one result file cannot back two findings.
- **Evidence fields are checked, not just present.** Log and PoC are two distinct files outside the
  run's bookkeeping, `exit_code` is 0 and matches the paired run, `command` matches the candidate
  argv, and `revision` is a hex prefix of the recorded commit.
- **Deployment records carry provenance and a digest**, and the gate re-checks the compared artifact.
  A typed `exact` no longer passes, nor does one whose artifact was deleted (0.19.1 adds program
  binding: in 0.19.0 a record written by hand with a recomputed digest still passed).
- **`verify-deployment`** probes `implementation()` getters (a large Compound-style delegator read
  as `exact` before), resolves OpenZeppelin and Solady clones including clones with immutable args
  (patterns derived from their sources, hashes checked against Solady's published constants),
  records linked-library code, and verifies Solana program ids against a `.so` build. Move and Cairo
  `exact` is refused rather than accepted by hand.
- **`not-applicable` deployment status** is refused for every on-chain stack and for a path that
  names no file, after stripping `#L…`, `(fn)` and `:symbol` suffixes that used to slip past.
- **Zero-test detection** was rewritten from the real output of forge, cargo, go, pytest, unittest,
  mocha/Hardhat, anchor and the Move test runners.
- **A blocker whose command succeeded is not a blocker**: `reproduced` needs an integer exit code and
  output that shows failure. **Secrets** in evidence, blockers and experiments fail `check`.
- **Weak submissions:** a `not-applicable` amplifier needs an anchor and the ladder needs a ceiling;
  `history check` no longer creates a missing ledger (`--create-ledger`), and `no-match` against one
  is refused; an empty dup map needs `dup-check --empty-map-reason`; `audit-inventory.json` is
  required.

### Coverage you can measure

- **`function-coverage`** lists every external entry point (from the compiler AST, or lexically for
  Vyper, Rust, Move and Cairo) and the ones no record names, ranked so value-moving and state-writing
  functions come first, with `--gate`.
- **Hunt readings end with `EXAMINED` and `NOT-REACHED` lines**; `converge` collects them into
  `examined.json`, which is what credits a function.
- **`coverage-floor`** no longer counts files credited only by a directory row, and reports on-chain
  source outside `--scope` as `outside_scope_onchain`.

### The odd one out, computed

- `semantic_graph.py` records guards per function — modifiers, `require`/`revert` conditions and
  checks in internal helpers — and new sinks: arbitrary calls with a caller-chosen target,
  `delegatecall`, `selfdestruct`, `permit` and token pulls from a parameter address.
- **`odd-one-out.json`** (written by `impact-plan`): `guard-asymmetry`, `paired-write-omission` and
  `sibling-asymmetry` leads. On a planted-bug project it surfaced all six planted bugs with one noisy
  lead; that is a fixture, not a measurement.
- `impact_paths.py` ranks arbitrary calls highest, higher still when the contract also pulls tokens
  from users' standing approvals.

### Convergence and the solidity-auditor integration

- **`converge` keys on file, function and bug class**, accumulates readings across passes in
  `readings-ledger.json` (`--reset` to start over), keeps generic surfaces such as `Pool<T>::swap`,
  parses numbered headers, and matches records on the full path. `queue` lists
  `unrecorded_singletons`.
- **`import-findings`** reads `solidity-auditor`'s raw agent blocks and its `run-K.md` files, maps
  contracts to files, and writes untriaged `hypothesis` records; upstream confidence is never stored.
  `queue` lists them as `imported_untriaged`.
- **`compare.md`** now says how to run it so it helps: in a disposable copy, with `--loop N`, and
  always with the explicit in-scope file list — its default discovery skips `src/lib/` and any file
  named `*Test*`, and its judging rules treat explicit narrowing casts as safe although Solidity 0.8
  truncates them silently.

### Search

- **`classic` lens**: Part A (EIP-7702 delegated EOAs, transient storage, Permit2, signatures, L2
  differences, v4 hooks, ERC-4337, narrowing casts) on every EVM target; Part B, the classic sweep,
  when `solidity-auditor` did not run. Appended to the `attack` group.
- **`web-frontend` is a registered lens** (`--lens web`) and bundles web sources;
  `high-impact` regains `accounting`, `external-call` and `integration-auth`; any messaging signal
  selects `integration-auth`.
- **Bundles carry the run's analysis** — `impact-paths.json`, `odd-one-out.json`, unexamined entry
  points — to the lenses that use them, with explicit truncation.
- **`delta`** reports submodule bumps and config changes, and says when it truncated.
- **`score-target`** takes `approval_exposure_usd`: a router holding dust but spending users'
  approvals is no longer forced to `deprioritise` while that exposure is unmeasured.
- `.circom`, `.nr`, `.sw`, `.tact`, `.jsx`, `.mjs` and `.cjs` count as source; `scope-audit --gate`
  no longer fails on stacks a bundle could never include.

### Documentation

- `SKILL.md` is shorter and states the coverage floor as a measurement. Invariant fuzzing is a
  standard Stage 5 step on high-value targets (`verify-tools.md`). `backtest.md` adds a three-arm
  comparison with contamination controls. `integrations.md` lists vetted skills and MCP servers by
  stage, with what to disable, and the ones not to use. Duplicate section numbers and stale counts
  were fixed.

## 0.18.0

One version again. Four sessions had each been told, in their own chat, to "update the pilot";
each read that as *improve it* rather than *reinstall your copy*, none could see the others, and
the installed skill is not a git repository — so a day of good work existed only as files, and one
VERSION bump was already destroyed by a later write that never re-read the file. Everything is
preserved here with attribution, the overlaps are resolved, and the recurrence is addressed.

### Preserved, with attribution

- **Web and dApp frontend lens** (`hunt-agents/web-frontend-agent.md`, `lenses.md`): twenty-one
  hunt agents existed and none covered XSS, DOM sinks or `postMessage`, while `hack-patterns.md`
  says web scope pays and has few competent competitors. Both of this toolkit's confirmed Highs
  came from outside Solidity.
- **`blind-spots.md` 7, 8 and 9**, `verify-tools.md`, `report.md`, `misses.md` 24 to 30 — each
  earned from a live hunt.
- **`score_target`'s `value_at_rest_usd` severity ceiling**: below 100k USD it forces
  `deprioritise` unless `pays_non_fund_impact`. Two of the longest zero-yield runs ended with every
  candidate real and none payable, because the in-scope contracts held dust between transactions.
- **Substrate/FRAME adapter** and its route in `stack_route.py`. Its detection sits outside the
  workspace-root branch on purpose: a Substrate monorepo declares dependencies under
  `[workspace.dependencies]`, which `has_deps` misses, so moving it inside silently drops roots.
- **`coverage_floor` reports `unparsed_coverage_files`**: it credits coverage from table rows and
  returned 0.0 where the templates had been overwritten with prose.

### Duplicate evidence moves before the week

- `history import --from-file` takes a JSON array, JSON Lines, an object holding the list, CSV or
  TSV, is idempotent, and maps common key spellings. The single-record form needed twelve flags, so
  nobody used it — and a report went out duplicating the hunter's own submission from six weeks
  earlier, already in a duplicate cluster on the same account.
- `audit-inventory --repo --run [--gate]` lists the review artifacts a repository ships, attributes
  a firm, and holds each at `unreviewed` until it is marked `read`, `not-applicable` with a note, or
  `unavailable`. It cannot read a PDF and does not pretend to; the point is that each is an
  accounted-for known-issue source. An unreviewed artifact blocks submission; a target shipping none
  never does.
- `score-target --ledger` reports your own prior outcomes on this project. Duplicates at half or
  more of decided reports costs 25 points — the most decisive signal available, still below the
  largest code factor so it cannot carry a band alone.

### Fixed

- **The two audit-count signals were double-counting.** `public_audit_count` from `program.json`
  and the artifacts the repository ships measure the same fact. A target declaring twenty and
  shipping six was penalised twice; one declaring none and shipping none was rewarded twice. They
  are now one signal scored once, off whichever source is larger, naming which one drove it.
- **`deployment_status: exact` was unreachable on Solana.** The evidence filename was validated
  against `0x[0-9a-fA-F]{40}` and lowercased, so a base58 program id could never match its own
  file. Found by a live Squads run that left its gate failing rather than edit the skill to pass.

## 0.16.0

Fifteen hunts, zero payouts. Reading the records, most were not lost at triage — they stopped
before proving anything. Three mechanisms let a run quit while calling itself finished, and each
is now measured instead of asserted.

### A blocker carries its own evidence

- `next_experiment.blocker` was validated as "is a string". In a live hunt a subagent wrote
  "cannot be installed — no root package.json, no workspaces"; the orchestrator carried it
  unverified and three passes went by with no test ever executed against the highest-paying
  contracts in scope. The root manifest existed and declared the workspaces — the subagent had
  copied one subproject out of a monorepo. A blocker is read by every later pass as closed ground,
  so a wrong one silently deletes a surface, and it is the one claim the triage exchange never
  attacks.
- It now also accepts an object: `claim` plus `command`, `exit_code`, `output_excerpt`,
  `recorded_at`, `attempted_alternative`. A bare string still validates, so existing runs are
  unaffected. A blocker counts as **reproduced** only with both a command and an output excerpt.
- `queue` reports `unverified_blockers`. **Behaviour change that can newly fail a run:**
  `check --submission` refuses a `needs-evidence` record whose only obstacle is an unverified
  blocker. Three one-step escapes — run the command, drop the blocker, or re-file as a hypothesis.

### `capability-probe`: know what this run can prove, before hunting

- The same wall recurred hunt after hunt — "needs an archive RPC this run has no access to",
  "public RPCs give no log history" — always found *after* a candidate existed, which was then
  parked. New `capability-probe --repo <checkout> --run <run> [--rpc URL] [--deep] [--timeout N]`
  records which toolchains are present with versions, which build and test files the checkout
  actually has, and with `--rpc` the chain id, head block and **measured archive depth**.
- It reports six evidence kinds as `available`, `unavailable` or `unknown`, each with a reason, and
  reserves `unknown` for "nothing was measured" rather than letting it read as a pass. `--deep`
  runs the build and tests and records exit codes; it is off by default because it executes
  target-controlled code.
- `build_surface` flags a manifest that exists only below the root — the shape of a subproject
  copied out of its monorepo, which is the mistake above, caught in one command.
- The RPC URL is never written or printed: `capabilities.json` records `"endpoint": "not recorded"`
  and the URL and its bare hostname are scrubbed from every error string.
- `queue` flags `contradicted_blockers` — a blocker whose wording claims the opposite of something
  the probe measured as available. Five named patterns, each tied to one capability; `unknown` and
  `unavailable` never accuse anything.

### `coverage-floor`: "exhausted" has to answer to a number

- On one target a hunt was declared exhausted after eight contracts and nothing compared that
  against the in-scope list. New `coverage-floor --repo <checkout> --run <run> [--scope P]
  [--gate] [--min-fraction F]` compares in-scope files against `coverage.md` rows,
  `known-hypotheses.md` surfaces and `affected_paths`, and reports the examined fraction with the
  complete unexamined list. `--gate` fails below 0.8 by default.
- A surface ending in `/` credits the tree under it; a bare name with no separator credits nothing.
  Vendored and test paths are excluded, counted and sampled, because that exclusion list cannot be
  right everywhere.
- Recorded is not audited: a row means somebody wrote a row, never that the file is safe.

### Trimmed

- `SKILL.md` 24.3KB to 23.4KB. The monorepo case moved to `references/blind-spots.md` §8, where
  blockers are handled, leaving the rule in place at the top. Stale counts fixed: `misses.md` has
  twenty-six items, and `lenses.md` now lists all eight blind spots.
- `misses.md` 26 is the LI.FI lesson that reached 0.15.1 outside git — a balance sweep reported
  half a million dollars on an address typed from recall that turned out to be a Uniswap pool.
  It was filed as a second item 24; renumbered here.

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
