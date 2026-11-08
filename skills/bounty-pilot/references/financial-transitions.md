# Financial transitions — Lab 0.54 (offline only)

This is a **research planning and differential-evidence tool**, NOT a web scanner
or an exploit. A domain state machine cannot establish a finding on a live
deployment without an independently reproduced native candidate + negative
control. No network, credential, RPC or trading operations are implemented.

## Select domains and preserve uncovered surfaces

Choose an operator-reviewed shape explicitly:

~~~sh
python3 skills/bounty-pilot/scripts/surface_route.py --list
python3 skills/bounty-pilot/scripts/surface_route.py --shape cex-custody --shape rollup-l2 --out /private/shape-plan.json
~~~

Twenty-two shapes have review surfaces and expected native evidence;
nine have **offline observation checks**, four of these additionally have
disconnected **operation simulators**. The remaining directions are
methodology-only; they are not automatically supported just because they
appear in a menu. Keep unreviewed directions in coverage.md.

## Stage 1: synthesize a reference trace, not a transaction

For **CEX custody**, create a file in a private temporary directory:

~~~json
{
  "schema_version": 1,
  "domain": "cex-custody",
  "initial": {
    "accounts": {
      "alice": {"available": 100, "held": 0},
      "bob": {"available": 0, "held": 0}
    },
    "custody": 100
  },
  "actions": [
    {"op": "withdraw_request", "id": "withdrawal-1",
     "account": "alice", "amount": 10,
     "reviewed_destination": "alice-wallet",
     "authorized_destination": "alice-wallet"},
    {"op": "withdraw_settle", "id": "withdrawal-1"},
    {"op": "withdraw_settle", "id": "withdrawal-1"}
  ]
}
~~~

```sh
python3 skills/bounty-pilot/scripts/local_transition_sim.py --input /private/trace.json --out /private/trace-expected.json
```

Expected: legitimate first settlement succeeds; duplicate is rejected, and
held funds are released only once. A rejected action makes no state change.
This is a simplified accounting model: it excludes trading collateral,
external fees, real chain reorgs, and asynchronous workers.

The local reference engines are:

* **cex-custody:** finality-gated deposits, available/held balances,
  verified withdrawal destination, reserve/request/settle/cancel, internal
  transfers and repeated request IDs.
* **rollup-l2:** origin/domain/payload binding, proof and challenge gates,
  finality, one-time execution, invalidation. A boolean is only an asserted
  proof status; this script does not verify a cryptographic proof.
* **restaking-lst:** staking shares, queued shares, slash-adjusted exit
  payouts, share conservation and one-time settlement. Real beacon state,
  rewards and slashing formulas vary by protocol.
* **perps:** synthetic whole-unit funding transfers, funding conservation,
  informational equity-versus-maintenance check. Not a matching/ADL engine.

## Stage 2: review paired observations

Use financial_transitions.py for nine supported shapes:
cex-custody, rollup-l2, restaking-lst, perps, launchpad,
prediction-market, airdrop, data-availability and lottery-vrf.

Each case in /private/paired.json contains a candidate and negative control
with the same declared pinned revision and initial-state digest:

~~~json
{
  "schema_version": 1,
  "cases": [{
    "id": "local-candidate-001",
    "domain": "launchpad",
    "source_revision": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "initial_state_digest": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "candidate": {
      "source_revision": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "initial_state_digest": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      "actual_tokens_out": 90,
      "minimum_tokens_out": 100,
      "purchase_succeeded": true
    },
    "negative_control": {
      "source_revision": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "initial_state_digest": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      "actual_tokens_out": 100,
      "minimum_tokens_out": 100,
      "purchase_succeeded": true
    }
  }]
}
~~~

```sh
python3 skills/bounty-pilot/scripts/financial_transitions.py --input /private/paired.json --out /private/review.json
```

A differential-lead-needs-native-verification **only means that supplied
data** show a candidate violation and a nonviolating control. The tool does
NOT authenticate receipts, transaction effects, deployment reachability,
prices, oracle integrity, initial state, isolation, capital, scope or impact.
Outputs are bounded private no-overwrite JSON. Never include private tokens
or personal data in public test fixtures.

## Stage 3: obtain real native evidence

1. Reproduce candidate and honest control against unmodified in-scope pinned
   code from the **same initial chain/DB state**, with actual actors.
2. Capture actual balance deltas, chain receipts, off-chain queue/DB writes,
   fees, pending liabilities, restart/retry behaviour and failure boundaries.
3. Verify the genuine signed authorization/execution path, not just a UI
   display, using a local fork or owned disposable test environment.
4. Reconcile costs, capital, liquidity and independent losses with
   exploit_oracle.py; do not substitute invented observations.
5. Investigate scope rules, duplicates and prior reports before submission.

**Web/API:** web_auth_lab.py deliberately remains GET-only. Do not turn
GitHub CI or the existing script into production POST/PATCH/withdrawal/race
testing. Model mutations in isolated local DBs, mocked workers and controlled
two-owned-account environments with an explicit permission check.

**Runners:** GitHub-hosted executes only synthetic unit/native fixtures. The
private Mac is reserved for separately authorized native target fork tests
and manually dispatched coding agents. This release adds no public requests.

## Vyper known-compiler-issue review

```sh
python3 skills/bounty-pilot/scripts/vyper_bugs.py --inventory /private/compilers.json --out /private/vyper-review.json
```

~~~json
{"schema_version":1,"builds":[
  {"id":"example-build","compiler":"vyper","version":"0.3.0",
   "verified_actual_compiler":true}
]}
~~~

Seeded only with the confirmed [named reentrancy lock advisory](https://github.com/vyperlang/vyper/security/advisories/GHSA-5824-cm3x-3c38):
versions 0.2.15, 0.2.16, 0.3.0. **Incomplete catalog.** Additional
reviewed advisories may be supplied via --advisories JSON with explicit
exact_versions or ranges (introduced inclusive, fixed exclusive). Imported
data are unverified; version matching proves neither an affected code path
nor a new payable finding. Known public compiler bugs are normally duplicates.
See the [official Vyper policy](https://github.com/vyperlang/vyper/security/policy).

## Evaluate utility instead of promising discovery improvement

Compare the previous and new releases on identical, held-out pinned vulnerable
commits with independently assessed truth. Record unique native reproductions,
false positives, duplicate rate, capital, economic effect and agent cost.
No improvement in bounty discovery has yet been measured for 0.54.
