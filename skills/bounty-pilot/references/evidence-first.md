# Evidence-First Hunt (experimental workflow gate)

Purpose: stop a hunt from spending several reading passes on the same untested
hypotheses. This changes the order of work, not the burden of proof.

## Alongside the passes, not between them

The experiments below are serial work the orchestrator does itself; the reading passes are
parallel agents on other surfaces. Run them concurrently. This gate is mandatory before the run
is reported, never before the next pass — a gate between passes delays the only step that finds
bugs, and in a live run that cost eight assembled bundles that were never read.

## At the end of the first reading pass

1. Record every candidate/lead in private findings.json. Set the actual pinned
   revision; never fabricate a deployed bytecode match.
2. Rank open records by plausible severity and experimental cost. The gate
   selects up to three records (Critical, High, unassessed, Medium, Low) and
   returns the others in "deferred". Do not silently discard deferred leads.
3. Run the cheapest decisive experiment while the next pass is already reading:
   read-only chain query, native test or pinned fork as appropriate. A read-only
   query does not satisfy the paired native-execution gate by itself.
4. For executable behavior, run a candidate and negative control on unmodified
   target source in a disposable, secret-free checkout. Use scenario_runner.py
   with an investigator-reviewed test plan.
5. Record the outcome in private experiments.json. Run the gate. If blocked,
   record the actual error and the alternative method you actually attempted.
   A blocker permits further reading but never verifies the candidate.

Example:

~~~sh
python3 <skill-dir>/scripts/scenario_runner.py \
  --plan <run>/test-plan.json --repo <disposable-checkout> \
  --allow-exec --out <run>/v6-native-results.json
python3 <skill-dir>/scripts/bounty.py experiment-gate \
  --run <run> --limit 3 --gate
python3 <skill-dir>/scripts/bounty.py queue --run <run>
~~~

The review gate checks execution records from scenario_runner.py. It requires
executed candidate and negative-control commands that differ (in argv or working
directory), no zero-test selectors or timeouts, matching exit codes, the observed
Git checkout SHA matching the pinned revision, and a concrete observed outcome.
The plan names the `finding_id` it tests at its top level (one plan per
finding); a result must belong to the finding that cites it, and one result file cannot back two findings. Zero-test detection reads
the real output of forge, cargo, go, pytest, unittest, mocha/Hardhat, anchor and
the Sui and Aptos Move test runners; an unrecognised command is `unknown-runner`
and counts as nothing unless the case declares an `expect_tests_marker`
(`verify-tools.md`). Candidate and control are compared after resolving their
working directories, and two findings cannot share one command, PoC or log. A dirty worktree remains possible for local
PoC test files; inspect the actual production sources for changes.
It does not inspect correctness of test assertions, source integrity, economic
impact or eligibility. A green gate never means "exploit verified".

## Experiment ledger

~~~json
{
  "version": 1,
  "experiments": [
    {
      "finding_id": "BP-001",
      "status": "executed",
      "revision": "<pinned-commit>",
      "result_path": "v6-native-results.json",
      "observation": "Candidate and negative control executed with observed state."
    },
    {
      "finding_id": "BP-002",
      "status": "blocked",
      "reason": "Actual native build failure with an identifiable missing dependency.",
      "attempted_alternative": "Tried a reduced native harness in a disposable local checkout."
    }
  ]
}
~~~

A `blocked` row carries the same evidence as a reproduced blocker: `command`, an
integer `exit_code` and an `output_excerpt` that shows failure. A bare sentence
is listed under `unverified_blockers` and fails the gate.

Only one current ledger row per finding. Preserve previous attempts separately
inside the private run directory. Never invent success, manipulate production
state or modify source code to make an experiment pass.

## Mixed-stack scope inventory

Every bundle also returns a scope_audit. A repository with Solidity contracts
and Rust relayers may have code outside an example --scope src/ prefix.

~~~sh
python3 <skill-dir>/scripts/bounty.py bundle \
  --repo <checkout> --run <run> --lens recommended
python3 <skill-dir>/scripts/bounty.py scope-audit \
  --repo <checkout> --run <run> --gate
~~~

An omitted stack raises an error. This is a lexical inventory: a stack may
legitimately be out of program scope, and vendor paths are filtered. Document
exclusions in scope.md. Inventory coverage is not security testing coverage.

## Measuring improvement

CI unit tests protect tool behavior, not real-world vulnerability recall.
A separate native CI job runs tiny intentionally flawed Solidity and Rust
fixtures; it does not prove High/Critical discovery. Use references/backtest.md:
pin the same published-audit revisions, seal blind before viewing findings,
and compare rediscovered High/Critical count, time to decisive experiment and
compute cost. Keep held-out cases and do not claim payout uplift without data.


## Evidence-first extensions on the experimental branch

These helpers **extend** the existing evidence gate; they do not replace
scenario_runner, research_loop, existing blind backtest seal/score or AVRE.

| Helper | Purpose | Required evidence |
| --- | --- | --- |
| exploit_loop.py | Bounded native candidate + negative-control replays | Existing research_loop manifest with pinned checkout |
| exploit_oracle.py | Exact-value attacker, victim, and invariant signals | Local-fork measurements, complete assets/liabilities and costs |
| campaign_metrics.py | Paired backtest and disabled-lens comparisons | Fully scored, separately sealed case arrays and arm metadata |
| target_radar.py | Offline differential deployment/configuration leads | Two read-only snapshots at ascending pinned blocks |
| deep_audit.py | Rank 1-3 scoped value flows and choose four lenses | Reviewed input model with a pinned source revision |

### Bounded local exploit loop

Dry run, no target commands:

~~~sh
python3 <skill-dir>/scripts/exploit_loop.py \
  --repo <pinned-disposable-checkout> --manifest <private>/variants.json \
  --out <private>/dry-run.json
~~~

Optional execution requires operator-enforced isolation and *actual network
denial*, not just CLI flags. The flags are declarations, not a sandbox:

~~~sh
python3 <skill-dir>/scripts/exploit_loop.py \
  --repo <pinned-disposable-checkout> --manifest <private>/variants.json \
  --measurements <private>/measured.json --out <private>/native.json \
  --execute --isolation-attested --no-network-attested
~~~

The native manifest follows research_loop.py (explicit reviewed candidate and
negative-control commands). The measurement JSON schema_version=1 requires
source_revision, chain_id, fork_block, initial_state_digest, and 1..64
experiments. Each experiment has an id, candidate, negative_control and
attestations. Each side contains:
- assets and liabilities: arrays of id, decimals, before_raw, after_raw,
  price_usd (price per *whole* token at the pinned block);
- unreflected_costs_usd: gas, protocol_fees, funding_fees, slippage,
  unrecovered_capital (do not count a cost already reflected in token balances);
- victim_loss_usd and invariant {id, violated}.

All attestations are explicitly required to get a signal: native_execution,
paired_same_initial_state, unmodified_target, realistic_capital,
no_balance_cheatcodes, all_positions_enumerated, flash_loans_fully_repaid,
prices_pinned, receipts_preserved. They are *untrusted claims* until separately
verified against logs, fork receipts, test code and actual token portfolio.
A control that also profits, harms a victim or violates the property blocks
promotion. A claimed observation is never the same as a proven exploit.

The wrapper binds the oracle output to selected native experiment IDs, property
IDs and initial-state digests. It does **not** create code, fund attackers,
request RPC calls or broadcast transactions. Only run native tests on the
vetted isolated self-hosted Mac runner.

### Stateful invariant preset

harness_gen.py now supports exactly one *narrow*, non-universal Foundry property
for reviewer-approved ERC4626 vaults with **direct custody**:

~~~sh
python3 <skill-dir>/scripts/harness_gen.py \
  --artifact <checkout>/out/Vault.sol/Vault.json \
  --contract Vault --repo <checkout> --out-dir <private>/harness \
  --property-preset erc4626-direct-custody \
  --confirm-direct-custody \
  --target-address 0x1111111111111111111111111111111111111111 \
  --fork-block 12345678 --rpc-env BP_RPC_URL
~~~

This produces a real check that reported totalAssets does not exceed the
vault's directly held asset balance. It is *invalid* when assets legitimately
reside in strategies, rebasing/fee-on-transfer tokens or external reserves.
No arbitrary generic-DeFi invariant is enabled. Explicitly fund actors,
configure allowances, and record fuzz coverage/revert rates before trusting
a green run. A bare model.md INVARIANT still yields deliberately failing TODO
properties by default. Nothing automatically runs a fork test during generation.

### Blind scorecard and ablations

Backtest the same pinned cases with and without a selected lens using the
existing backtest init -> hunt -> seal -> score workflow; do **not** read answers
before sealing. Collect each arm's independently scored JSON outputs into a
list, and write a private manifest:

~~~json
{
  "schema_version": 1,
  "baseline": "default",
  "holdout_attested": false,
  "arms": {
    "default": {"scored": "default-scored.json", "metadata": "default-meta.json"},
    "without-rounding": {
      "scored": "without-rounding-scored.json",
      "metadata": "without-rounding-meta.json",
      "disabled_lenses": ["rounding-map"]
    }
  }
}
~~~

~~~sh
python3 <skill-dir>/scripts/campaign_metrics.py \
  --manifest <private>/bench/manifest.json --out <private>/bench/scorecard.json
~~~

The scorecard rejects different case sets, revisions and severity ground truth.
Fewer than 5 cases or missing matched model/budget/provider cost is
inconclusive. No real 15-20-case campaign is bundled or claimed completed;
setup and independently blinded hunts are still needed.

### Target radar and deep mode

For a read-only radar, use the existing config_snapshot.py to collect the same
in-scope targets at two pinned blocks, then compare locally:

~~~sh
python3 <skill-dir>/scripts/target_radar.py \
  --before <private>/snapshot-old.json \
  --after <private>/snapshot-new.json --out <private>/radar.json
~~~

Implementation/code hash/scope may also be declared at the top level of each
snapshot target. This is an offline difference, **not** a daily polling daemon;
capturing on a schedule requires target inventory, read-only RPC and a vetted
Mac-only scheduler. A changed address or configuration is not a vulnerability.

deep_audit.py accepts a JSON model with schema_version=1, source_revision and
flows[]. Each flow has id, kind (vault, lending, amm, bridge, wallet, staking,
governance, generic), in_scope, value_at_risk_usd, unprivileged_reachable,
changed_since_audit and known_duplicate. Set unknowns to null, not false.
Use:

~~~sh
python3 <skill-dir>/scripts/deep_audit.py \
  --spec <private>/flow-model.json --out <private>/deep-plan.json
~~~

The result ranks at most three flows, specifies three-four lenses and supplies
stop rules. The ranking uses **supplied values**, does not inspect target
code and does not assert eligibility or finding severity.

**Success criterion:** independently adjudicated, nonduplicate, reproducible
mechanisms per unit of provider cost and investigator time, not raw lead volume.
