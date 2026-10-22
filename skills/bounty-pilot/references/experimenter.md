# Autonomous experiment drafting and evidence verification

The experimenter automates setup and artifact checks. It does not invent a passing exploit test,
edit target source, broadcast transactions, or change a finding's status.

## Draft a minimal experiment

For an open, source-anchored hypothesis, create a private draft outside the target checkout:

```sh
python3 <skill-dir>/scripts/experimenter.py draft --run <run> \
  --finding BP-001 --stack solidity --out-dir <private>/experiments/BP-001
```

The output contains `experiment.json` plus a native test skeleton whose candidate and control
deliberately fail. It carries the finding's revision, affected-source hashes, actor capability,
preconditions, proposed action sequence, next experiment, claimed invariant and impact. Those values
remain claims until the researcher cites actual source and replaces the TODOs. Never change
production source to make the candidate pass.

The `plan` command binds existing tests to the narrow argv builders in `native_fuzz_plan.py`; it
does not run them. For differential tests, set `kind` to `differential`, provide an
`equivalence_basis` that names a protocol specification or documented invariant, and make the
native tests compare the results with valid fee, rounding and time tolerances. A test that only exits
successfully does not establish equivalence.

Review every generated command. `scenario_runner.py` is dry-run unless `--allow-exec` is explicitly
given. Execute only in a disposable, secret-free checkout with the original production source at the
pinned revision. The runner saves candidate and negative-control outputs; repeat both pairs at least
twice for the strict evidence review.

## Independent evidence review

`evidence_verifier.py` consumes an independent review JSON and recomputes the local evidence gate:

```sh
python3 <skill-dir>/scripts/evidence_verifier.py --run <run> --finding BP-001 \
  --review <private>/independent-review.json --out <run>/evidence-review/BP-001.json --gate
```

The reviewer record uses `schema: 1` and includes:

- `producer_id`, a distinct `reviewer_id`, and `independent: true`;
- `source_review` with `decision: confirmed` and exact `{path, line, quote}` source anchors;
- `reachability` with the same kind of source anchors and `ordered_steps`;
- `assertions.candidate` and `assertions.negative-control`, each naming a run-local `poc_path`,
  an exact assertion `quote`, and the same property; the control also names its protected `expected`
  outcome;
- `impact`, with a confirmed positive `economic` loss, unit and attacker cost, or repeated liveness
  failures plus a failed recovery test, and a run-local artifact quote;
- `scope: {"decision":"in-scope"}` plus a source or program-rule `scope_anchor`;
- `deployment` with `decision: matched`, a run-local deployment artifact and an exact quote.

The verifier checks the target HEAD against the finding and paired run revisions, affected source
integrity, exact source and PoC quotes, saved runner logs, two identical passing candidate/control
pairs, and the separate reviewer metadata. It reports three separate levels:
`SOURCE_CONFIRMED`, `POC_REPRODUCED`, and `IMPACT_VERIFIED`. It never edits `findings.json` or turns
the finding into `verified`.

To make the verifier a structural requirement for verified records in a new run, initialize it
with:

```sh
python3 <skill-dir>/scripts/bounty.py init --repo <checkout> --out <run> \
  --strict-evidence-review
```

Then set `evidence.independent_review_path` on the finding to the reviewer JSON inside that run.
`bounty.py check` and `check --submission` rerun the verifier and block `verified` while any stage
is unconfirmed. Existing runs remain compatible unless this option was selected at initialization.

This is a machine-checkable artifact gate, not a semantic proof. A reviewer still has to determine
that the test assertion expresses the protocol invariant, that its setup is reachable, that the
measured loss belongs to a real victim, and that the deployment artifact is authoritative. The
review record is not cryptographically signed; use a human or a distinct reviewer process and keep
the review file private.

## State models and native execution remain separate

`state_graph.py`, `scenario_fuzz.py`, `invariant_check.py`, and the new review queues produce source
or model leads. Only an executed native test against unchanged pinned source can support
`POC_REPRODUCED`; impact and program scope need their own evidence. A model counterexample, mutation
survivor, parser result, or passing command alone never proves a vulnerability.
