# Advanced Vulnerability Research Engine (AVRE)

AVRE is an **opt-in, local research pipeline** for sequence-dependent and cross-component bug
bounty hypotheses. It is integrated into the existing `bounty.py` CLI and reuses Bounty Pilot's
state graph, Ecosystem Intelligence, blind-spot trust review and scenario runner. It does not
replace the ordinary hunt, evidence gates, report checks or independent adjudication.

Every AVRE candidate is unverified. Lexical relationships, score values, model-supplied trust
flows and measured candidate/control differences do not establish runtime reachability, intended
behavior, attacker control, victim loss, eligibility or payout.

## Repository inventory and reuse

| Existing component | AVRE role | Evidence limit |
| --- | --- | --- |
| `state_graph.py` | Source symbols, approximate state reads/writes and lexical edges | Not an AST/call graph; no proof of ordering, storage identity or reachability |
| `ecosystem_intelligence.py` | Scope classification, dependency inventory, local Git history, archive index, patch-variant leads | Passive and local only; no live roles, RPC or remote history |
| `blindspot_engine.py trust_boundary_review` | Checks a supplied cross-component flow inventory for missing provenance/auth/validation/executed-value fields | Checks inventory completeness, not runtime correctness |
| `scenario_runner.py` | Validates an optional local candidate/control plan in dry-run mode | AVRE always passes `allow_exec=False`; no tests are executed |
| `evidence_verifier.py` and `agent_dispatch.py` | Downstream, separately bound review and evidence gates | AVRE does not invoke or simulate an independent reviewer |
| Existing `backtest` | Blind benchmark protocol | AVRE has no held-out labeled corpus or measured comparison yet |

The AVRE-only modules are `avre_sequence.py` (bounded dependency-aware beam planning and a
caller-supplied replay shrinker) and `avre_economics.py` (metamorphic test plans and exact integer
candidate/control delta comparison). `avre.py` orchestrates these with existing modules.

## Safe invocation

Create a scope file using the schema from
[`ecosystem-intelligence.md`](ecosystem-intelligence.md). Include the repository remote URL in
`allowed.repositories`, `local_static` in `allowed.methods`, and `git_history` when selecting
`historical-ecosystem`, `attack-graph`, or importing an archive index. Add `provided_archive` when
using `--archive-index`. Related exclusions take precedence over broad allow rules.

```sh
python3 skills/bounty-pilot/scripts/bounty.py avre \
  --repo /path/to/in-scope/checkout \
  --scope /path/to/private/scope.json \
  --out /path/to/private/avre-run \
  --modules impossible-state,sequence-mutation,economic-differential,failure-recovery,identity-context,attack-graph,hypothesis-ranking \
  --budget 200 --max-sequence-length 5 --beam-width 16
```

The checkout must classify `IN_SCOPE`; AVRE refuses unknown repositories and non-passive methods.
The output directory must be outside the checkout and not a symlink. AVRE reads tracked local files,
local Git metadata and explicitly supplied local artifacts. It makes zero network requests, does not
validate credentials, does not contact `UNKNOWN` or out-of-scope entities and cannot submit
transactions. Execution is sequential, with at most one AVRE process per output directory.

To pass generated leads into an existing Pilot run without promoting them, add `--pilot-run`:

```sh
python3 skills/bounty-pilot/scripts/bounty.py avre \
  --repo /path/to/in-scope/checkout --scope /path/to/private/scope.json \
  --out /path/to/private/avre-run --pilot-run /path/to/private/pilot-run
```

The run must belong to the same checkout. AVRE writes `avre-leads.md` and uses the existing
`import-findings` parser; imported rows remain `hypothesis`, `severity: unassessed`, and
`origin.triage: untriaged`. Import is idempotent. Continue with the normal Pilot queue and reviewer
workflow. This does not create producer/reviewer session receipts or satisfy `evidence_verifier`.

`--modules` selects any nonempty set of:

- `impossible-state`: pairs lexical state writers/readers with invariant prompts.
- `sequence-mutation`: bounded operation sequences, partial prefixes, reversals, repeats, actor
  switch plans and boundary variants. Coverage feedback is lexical. `minimize_sequence()` only
  calls a replay predicate supplied by a caller; AVRE itself does not run it.
- `economic-differential`: metamorphic plan generation. Optional `--measurements` compares exact
  integer before/after balance deltas for candidate and control observations. The JSON must name a
  full source commit, an equivalence basis, unit, tolerance and both sides' snapshots. A difference
  beyond tolerance is still not a vulnerability or a loss attribution.
- `failure-recovery`: test plans for retries, duplicate delivery, migration restart, stale cache and
  partial failures. It does not inject faults or infer that a failure path is exploitable.
- `cross-reality`: optionally reviews a human-authored `--trust-model` through the existing trust
  boundary checker. Without that model it emits no cross-reality candidate.
- `identity-context`: file-level lexical prompts for signature, domain, nonce, account-context and
  delegate-call signals. A missing token in one file is not proof that a guard is absent elsewhere.
- `historical-ecosystem`: translates local history, saved archive and patch-variant leads from
  Ecosystem Intelligence. Live deployment state is not read.
- `attack-graph`: combines state symbols, dependency edges, hypotheses and longer sequence seeds.
  It does not combine unrelated leads into a proven chain.
- `hypothesis-ranking`: assigns separate heuristic dimensions. Scores are queue ordering only.

Other optional local inputs:

- `--known-issues FILE` adds lexical overlap to duplicate/novelty heuristics; it does not query
  public advisories.
- `--archive-index FILE` passes a previously saved, scope-classified archive index to Ecosystem
  Intelligence. Archive contents are not fetched.
- `--runtime-trace FILE` imports a local trace into `attack-graph`. Its JSON must use
  `schema_version: 1`, `environment: "anvil-local"` or `"mock-local"`, the exact full
  `source_revision`, `execution_id`, `seed`, `tool_versions`, and ordered `actions`. Anvil traces
  also require `chain_id` and `block_number`; mock traces must set both to `null`. Each action names
  `caller`, `callee`, `effect`, `outcome`, and exact `caller_anchor` / `callee_anchor` objects with
  repository-relative `path`, `line`, and `quote`. The importer checks the revision and source
  anchors and records the artifact SHA-256. It does not authenticate the producer or prove the
  named command actually ran; edges are labeled `unverified_artifact`. Do not use hand-authored
  traces as proof.
- `--local-plan FILE` validates a candidate/control plan through `scenario_runner` in dry-run mode.
  No command in the plan is launched.
- `--baseline REPORT.json` compares candidate keys, counts and overlap only. It does not calculate
  true positives, false positives, recall or uplift.
- `--resume` resumes only when commit, tracked-file contents, scope, optional input digests, module
  selection and bounds match the checkpoint fingerprint. A changed input requires a new output
  directory. A system file lock is released by the OS when the process exits.

`--budget` caps ranked hypotheses and sequence exploration; it is **not a token budget**. AVRE makes
no model/API calls. JSON records measured local wall time and process CPU time before report
serialization, along with files, symbols, explored paths and candidate counts. Those measurements
are run-specific and are not performance benchmarks.

## Artifacts

The private output directory contains:

- `avre-report.json` and `avre-report.md`: provenance, scope decision, module outputs, candidate and
  control plans, separate score dimensions, disconfirming evidence, and explicit limits.
- `attack-graph.mmd`: Mermaid view of the generated evidence graph; edges remain labeled as lexical
  or investigator-supplied.
- `skeptical-review-queue.json`: hypotheses and questions for an independent reviewer. It is a
  handoff packet, not an independent review or verdict.
- `audit.jsonl`: timestamps, module completion, zero network/target execution claims and resource
  measurements.
- `checkpoint.json`, `state-graph.json`, and optionally `ecosystem/`: resumable research state and
  the reused local inventory.

Hypotheses include root cause lead, scope, assumptions, attacker capability, invariant, possible
impact, unverified reachability, evidence, disconfirming evidence, a candidate/negative-control
reproduction prompt, confidence, duplicate risk and separate heuristic scores. `actual_impact`
remains unset unless later evidence stages establish it.

For a genuinely independent review, pass the candidate through the existing separate dispatch and
`evidence_verifier.py` process. Preserve reviewer session identity, exact source revision, candidate
and negative-control output, source anchors and measured impact. Never copy AVRE's heuristic
classification into a confirmed finding field.

## Current limitations

- The impossible-state, identity and failure modules are heuristic plan generators, not symbolic
  execution or native test generators. Cross-component reachability requires a human-authored flow
  model.
- Runtime trace import can add source-anchored, caller-supplied edges, but cannot attest to their
  producer or execution; deployment identities, role/asset edges and causal composition remain
  incomplete. No chain is treated as a finding.
- Safe POC execution is not implemented in AVRE. Use native, isolated project tests through the
  existing experiment/evidence workflow; public targets and live funds are never used here.
- No broad positive/negative corpus of historical fixed defects was supplied. AVRE has synthetic
  regression fixtures only; precision, recall, false-positive rate, duplicate rate, time-to-finding
  and uplift are unmeasured. Use Bounty Pilot's sealed `backtest` protocol for a future blind
  comparison.
- Git history and archive indexes must already be local. No remote PR, advisory, public archive,
  chain, role or allowance query is performed.
- Independent reviewer verdicts and target-impact proof remain distinct external pipeline stages.
  `--pilot-run` only hands candidates to Pilot as untriaged hypotheses; it does not run a reviewer
  or the evidence verifier.
