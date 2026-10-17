# Candidate records and evidence

`findings.json` is an array of records, one per root cause. Start from `candidate-template.json`
that `init` wrote, and assign stable ids (`BP-001`, …). Deduplicate by root cause and affected path,
never by title similarity; split independent root causes, and keep multiple impacts of one root
cause together.

## Required fields

- `id`, `title`, `status`, `severity`, `bug_class`, `revision`, `root_cause`, `affected_paths`,
  `attacker_capabilities`, `preconditions`, `impact`, `scope_status`, `deployment_status`,
  `novelty`, `evidence`, `objections`, `rejection_reason`. Optional until the gate: `escalation`.
- `status`: `hypothesis` | `needs-evidence` | `verified` | `refuted` | `parked`. `refuted` means
  the mechanism is wrong. `parked` means it is real but cannot be filed now, and requires
  `park: {reason, revive_if, evidence}` with `reason` one of `out-of-scope`, `excluded-impact`,
  `uneconomic-now`, `accepted-risk`, `other`.
- `severity`: `unassessed` | `informational` | `low` | `medium` | `high` | `critical`. Cite the
  program's rubric in `severity_rationale` before assigning a final label.
- `bug_class`: kebab-case, reused across passes and shared with the dup map, so the same mechanism
  keeps the same label (`aggregate-not-decremented`, `unvalidated-compose-sender`).
- `revision`: the exact commit the record was established against — 7 to 64 hex characters that are
  a prefix of the run's recorded commit or of the experiment's revision. A branch name or "last
  week" is refused. Without it a `verified` record cannot be rechecked after the target moves.
- `scope_status`: `unknown` | `in-scope` | `out-of-scope`.
- `deployment_status`: `unknown` | `exact` | `partial` | `mismatch` | `not-applicable`, as
  `verify-deployment` reported it. Never set `exact` by hand: the submission gate accepts it only
  with `deployment_evidence` (below).
- `deployment_evidence`: the file(s) `verify-deployment --run <run>` wrote, as run-relative paths
  such as `deployments/0xabc….json`. One per address the finding depends on (proxy and token
  addresses alike).
- `deployment_rationale`: required with `not-applicable` — why no deployed code is involved (an
  off-chain service, an undeployed library). Affected paths are normalised first (`#L42`,
  ` (withdraw)`, `:symbol` and `()` are stripped), a path that names no file is refused, and
  `not-applicable` is refused for on-chain source: `.sol`, `.vy`, `.yul`, `.huff`, `.fe`, `.move`,
  `.cairo`, `.fc`, `.func`, `.tolk`, Rust under `programs/`, and crates that depend on `anchor-lang`,
  `solana-program`, `pinocchio`, `cosmwasm-std` or `ink`. Off-chain Rust and Go keep it.
- `novelty.status`: `not-checked` | `no-public-match-found` | `matched-public-issue`, with
  `novelty.sources` listing URLs and the comparison you made at each.
- `next_experiment`: required for `hypothesis` and `needs-evidence`; it must name a decisive
  `question`, a reproducible `method`, and the `expected_evidence`. Add `blocker` when the test
  cannot run yet. `queue --run` lists these leads; a queued experiment is not an attempted test.
- `next_experiment.blocker`: a plain string, or an object with `claim` (required, non-empty) and
  any of `command`, `exit_code`, `output_excerpt`, `recorded_at`, `attempted_alternative`. A
  blocker counts as **reproduced** only when it carries a `command`, an integer `exit_code` and an
  `output_excerpt` that shows failure — a non-zero exit, or exit 0 with error output such as an HTTP
  403 or a JSON-RPC error. A command that succeeded is not a blocker. Anything less is
  **unverified**, and `queue --run` lists it under `unverified_blockers` with the reason. Write
  what the shell printed, not your conclusion about it, and put in `attempted_alternative` the
  cheaper route you tried before giving up — another endpoint, another package manager, the
  monorepo root rather than the subdirectory you copied out of it. **A blocker is a claim and
  carries the same burden as a finding**: every later pass reads it as closed ground, so a wrong
  one deletes a surface, and nothing in the triage exchange ever attacks it. Check it against
  `capabilities.json` before you write it (`intake.md`); `blind-spots.md` §8 has the case.
- `escalation`: the amplifier ladder from `escalate.md`, recorded rather than assumed.
  `escalation.attempted` holds one entry per amplifier — `repetition`, `other-parties-funds`,
  `composition`, `become-the-trusted-party`, `timing`, `freeze-instead-of-theft` — each with a
  `result` of `reached`, `blocked` or `not-applicable`, and an `anchor` whenever the result is
  `reached` or `blocked`. An unanchored `blocked` is an assumption, not a result. `ceiling` names
  the highest impact class the evidence actually reached and `ceiling_evidence` anchors it. The
  field is optional on a hypothesis; the submission gate requires every amplifier to carry a
  result, an anchor for `not-applicable` too, and `ceiling` with `ceiling_evidence`. `queue --run`
  lists the missing ones for every open record.
- `history_review`: record the private-ledger comparison before submission. Use
  `no-match` only after `history check` reports none against a ledger that exists — `history check`
  no longer creates a missing ledger (pass `--create-ledger` to start one), and a `no-match` against
  a missing ledger is refused; use `different-root-cause` with prior case IDs
  and a concrete mechanism comparison; use `regression` only with `evidence` citing how the issue
  was reintroduced in the current deployment. `same-mechanism` blocks submission. `unchecked` and
  `unavailable` also block it.
  The submission gate requires a fresh `history-matches.json`; it checks a fingerprint of each
  candidate's id, status, bug class, affected paths and root cause. Rerun `history check` after any
  of those fields changes, and account for every case it detected.

## Evidence fields, required for `verified`

- `command`: the exact reproduction command — it must equal the candidate argv of the record's
  paired run, with `$VAR` or `<REDACTED>` standing in for secrets. A key, a private key or an RPC
  URL with a key anywhere in evidence, blocker or experiment fields fails `check`.
- `exit_code`: the observed integer; it must be 0 (the candidate test passes when the bug is
  demonstrated) and equal the code the paired run observed.
- `log_path`, `poc_path`: two different existing files inside the private run directory, never
  symlinks out of it and never run bookkeeping (`findings.json`, `run.json`, `experiments.json`,
  anything under `deployments/` or `bundles/`).
- A `verified` record also needs an `executed` entry in `experiments.json` whose paired result
  passes the experiment gate. A `blocked` or queued entry, or no `experiments.json` at all, fails
  the submission gate.
- `assertion`: the property that broke, and what the observed result establishes.
- `negative_control`: the contrasting case you actually ran and its result — not a proposed test.
- `source_integrity`: how unmodified production code and realistic dependency behaviour were kept.
- `impact_quantification`: what moved, how much, and at what attacker cost. Required to submit.

For `refuted`, `rejection_reason` cites a concrete protection, specification or test result. For
`needs-evidence`, name the missing experiment. Lack of a toolchain is not a refutation, and neither
is ineligibility: a real mechanism the program will not pay for today is `parked`, not refuted.

Every finding written up in the run — a `findings/*.md` note, a `SUBMISSION-DRAFT-*.md` — cites its
record's `BP-` id, and every open row of `known-hypotheses.md` names its record. `check` fails
otherwise: a finding that lives only in prose is invisible to `queue` and to every gate.

## The objection exchange

`objections` records the two-round triage from `adjudicate.md`. Each entry carries `gate` (one of
`interruption`, `reachability`, `trigger`, `harm`, `eligibility`, `evidence`), the `claim`, and an
`outcome` of `answered`, `sustained` or `withdrawn`.

An `answered` or `sustained` objection carries an `anchor`. An `answered` one also carries `answer`
and `answer_anchor` — the symmetry is the point: an answer defeats an objection only when it is
anchored in code, specification, a test or a live read, exactly as the objection had to be. A
`withdrawn` objection is one with **no** anchor — the absence of one is why it was withdrawn;
record the claim and `withdrawn_because` so the same unanchored objection is not raised again. An
objection that carries an anchor cannot be `withdrawn`: answer it (`answer` + `answer_anchor`) or
it is `sustained`.

`concessions` records triage's `CONCEDED` blocks: each entry has a `gate` and a `reason` saying
what triage tried to anchor and could not.

The submission gate refuses a finding with a `sustained` objection, and refuses one with no triage
exchange: at least one anchored objection or one concession. Withdrawn objections alone do not
count — a finding no agent attacked is a finding nobody has reviewed. The exchange is
also the raw material for the report's "existing protections" section, so recording it properly is
drafting, not bookkeeping.

## The gates

Technical validity, severity, program eligibility and public-known-issue status are four separate
judgments and are never merged. The decision procedure is `adjudicate.md`; the four technical gates
are reachability, causality, material impact and eligibility, and a record can clear the first three
while the fourth is unknown. That is a normal, reportable state: a source-review finding.

Claims about profit include fees, capital, slippage and the liquidity that must exist. Claims about
denial include persistence, blast radius, one-time cost and the recovery path. Fork simulations are
point-in-time evidence about one block, not proof about every deployment state.

## What a passing checker does and does not mean

```sh
python3 <skill-dir>/scripts/bounty.py check --run <run>               # structure and artifacts
python3 <skill-dir>/scripts/bounty.py dup-harvest --run <run>         # issues already judged
python3 <skill-dir>/scripts/bounty.py dup-check --run <run>           # burned surfaces
python3 <skill-dir>/scripts/bounty.py history check --run <run>       # private prior reports
python3 <skill-dir>/scripts/bounty.py queue --run <run>               # every open lead
python3 <skill-dir>/scripts/bounty.py check --run <run> --submission  # readiness gates
```

The structural check verifies record completeness, the shape of the objection exchange, and that
the artifacts exist. The submission gate applies to the `verified` records — the ones that would be
submitted — and fails when there are none; refuted and open records stay in the file and get the
structural check only. For each verified record it additionally refuses what programs actually
reject: scope that is not established, a `deployment_status` other than `exact` (backed by
`deployment_evidence`) or `not-applicable` (with `deployment_rationale`), an unassessed severity, a severity with no rubric citation, fewer than
two checked novelty sources, missing impact quantification, a run with no dup map built (an empty
map needs `dup-check --empty-map-reason`), no `audit-inventory.json`, no triage
exchange, an unchecked personal history review, a missing or stale personal-history result, a
detected personal match that is not accounted for, a same-mechanism history match, open leads without
their next experiment, and any sustained objection.

On `deployment_status`: only `verify-deployment` sets it. Pass `--run <run>` and it saves its full
result to `<run>/deployments/<address-lowercase>.json` (chain id, block, status, proxy kind,
implementation address, artifact path and sha256, reasons). The gate accepts `exact` only when
every file named in `deployment_evidence` sits directly in that folder, names its own address and
reports `exact`, and the compared artifact has not changed since. For a proxy, the
**implementation** must match — a proxy whose own runtime matches the artifact is reported as
`partial`, because the code that executes was never compared. Immutables and linked libraries are
masked only at the ranges the artifact's `immutableReferences`/`linkReferences` declare, and the
on-chain values found there are listed in `masked_ranges`.

**Neither checker establishes that a finding is real.** They cannot run your PoC, judge your
severity, see a private duplicate, or read the program's mind. An empty findings file passes the
structural check. Personal history matching is a recall-oriented aid: it cannot see another
researcher's private queue and does not adjudicate whether two root causes are the same. Treat a
green gate as "nothing is obviously missing", never as "this is valid".
