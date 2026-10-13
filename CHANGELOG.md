# Changelog

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
