# Changelog

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
