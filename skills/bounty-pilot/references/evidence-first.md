# Evidence-First Hunt (experimental workflow gate)

Purpose: stop a hunt from spending several reading passes on the same untested
hypotheses. This changes the order of work, not the burden of proof.

## At the end of the first reading pass

1. Record every candidate/lead in private findings.json. Set the actual pinned
   revision; never fabricate a deployed bytecode match.
2. Rank open records by plausible severity and experimental cost. The gate
   selects up to three records (Critical, High, unassessed, Medium, Low) and
   returns the others in "deferred". Do not silently discard deferred leads.
3. Run the cheapest decisive experiment before another broad hunt pass:
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
executed candidate and negative-control commands, no zero-test selectors or
timeouts, matching exit codes, the observed Git checkout SHA matching the pinned revision,
and a concrete observed outcome. A dirty worktree remains possible for local
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
