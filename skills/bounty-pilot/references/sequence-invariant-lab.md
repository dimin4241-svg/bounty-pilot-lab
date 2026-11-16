# Sequence Invariant Lab (Cantina-derived, offline)

The Lab extends Bounty Pilot's **existing** `scenario_fuzz`, `impact-plan`,
`harness-gen`, `sandbox-run`, and `experimenter` with a small source-reading
queue and data-only **inter-operation invariant review**. It is neither a
Solidity symbolic executor nor an exploit generator. Source-pattern hits are
**unverified lexical leads**; supplied traces are **unverified observations**.
No requests to contracts, RPC, websites, models or external accounts occur.

## Commands

```sh
BP=skills/bounty-pilot/scripts/bounty.py
REV=$(git -C /private/pinned-repo rev-parse HEAD)

# Bounded source cues; supply scope-reviewed, explicitly pinned checkout.
python3 "$BP" sequence-invariants scan \
  --repo /private/pinned-repo --revision "$REV" --max-files 120 \
  --out /private/new-source-leads.json

# Compare saved, human-reviewed candidate data with invariant specifications.
python3 "$BP" sequence-invariants review --input /private/trace.json \
  --out /private/new-review.json

# Prepare independently reviewed candidate/control native tasks; does not run tests.
python3 "$BP" sequence-invariants proof-plan --input /private/trace.json \
  --out /private/new-tasks.json

# Calibration only. Public known-case answers cannot measure blind rediscovery.
python3 "$BP" sequence-invariants caseforge \
  --corpus skills/bounty-pilot/references/cantina-revert-calibration.json \
  --mode inventory
```

Run `python3 skills/bounty-pilot/scripts/sequence_invariant_lab.py --help`
independently if the CLI router has not been loaded. Output files are
create-only, owner-private (0600). Use private directories outside the repo.

## Supported check kinds

| Check kind | Native experiment it motivates | Important limitation |
|---|---|---|
| `transfer_isolation` | Compare who owns an outflow and who receives it | Fund attribution is supplied, not inferred |
| `obligation_coverage` | Track held funds, recoverable claims and obligations across nested callbacks | Only checks a supplied simplified accounting identity |
| `callback_stack` | Reproduce nested A→B→A action sequence with a protected control | Nested calls are normal; a `REVIEW_NEEDED` result is not a bug |
| `trigger_integrity` | Mode combinations, lost thresholds and consumed-but-unrearmed triggers | Expected trigger labels are researcher-reviewed, not sourced automatically |
| `lifecycle_authority` | Check successor NFT/object permissions after remint or migration | A missing capability name alone doesn't prove reachability |
| `temporal_accrual` | Contrast checkpoint time-weighted interest against actual interest | Rates, units, interest policy and rounding must be established independently |
| `asset_identity` | Compare asset aliases along different protocol paths | Never assume `ETH == WETH`; aliases are explicitly supplied |

The `scan` command identifies pairs of lexical signals in bounded `.sol`
files. Its line numbers are approximate, comment stripping is heuristic, and
no source revision is independently authenticated. The input digest and
code should be verified through Bounty Pilot's existing pinned checkout and
source-anchored native run before filing.

## Example review input

```json
{
  "source_revision": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "checks": [
    {"id": "balance-isolation", "kind": "transfer_isolation"},
    {"id": "trigger-state", "kind": "trigger_integrity"},
    {"id": "nested", "kind": "callback_stack", "disallow_cross_actor_nested": true}
  ],
  "steps": [
    {"event": "enter", "actor": "alice", "operation": "autoCollect"},
    {"event": "enter", "actor": "mallory", "operation": "autoExit",
     "transfers": [
       {"fund_owner": "alice", "recipient": "mallory", "amount": "5",
        "authorized_by_owner": false}
     ]},
    {"event": "exit", "actor": "mallory", "operation": "autoExit",
     "trigger": {"active": true, "required": ["exit_lower"], "armed": [],
                 "disabled": [], "must_survive_failure": true}},
    {"event": "exit", "actor": "alice", "operation": "autoCollect"}
  ]
}
```

The example is **synthetic**. Replace it with researcher-collected, redacted,
source-pinned observations before assessing a real target. For `native_pair`,
include `candidate` and `control` with `source_revision`,
`starting_state_digest`, `command`, `log_sha256`, `exit_code` and
`invariant_holds`. Both tests must start from **identical** actual state,
against identical unmodified source, and differ only in a reviewed control
condition. Even well-formed receipts return
`NATIVE_PAIR_RECEIPTS_NEED_INDEPENDENT_VERIFICATION`: the program **cannot
authenticate logs, assertions or on-chain state**.

## From source lead to a payable finding

1. Pin exact source and program terms, exclude known/out-of-scope features;
   inspect the source and the executed transaction path.
2. Form a specific actor/permission/state invariant. Compare candidate and
   a real negative control on the *same starting state*.
3. Generate tasks with `proof-plan`, then build an **actual** local Foundry
   native test through existing `harness-gen`/`sandbox-run`. Record balances,
   state, events, permissions, fallback and failed calls.
4. Use the existing `experimenter` causal review and novelty gate to disprove
   counterclaims. Separate direct loss from lost yield or operational effects.
5. Record any unresolved deployment, asset units, market feasibility or scope
   as UNKNOWN; no auto-submission and no auto-claim of High/Critical.

## Historical cases and evaluation

`cantina-revert-calibration.json` contains 13 manually selected **public**
Revert v4lend cases: 10 confirmed Medium/High, one confirmed Low, a
rejected case, and a known duplicate. Report titles/links/statuses are
public; caseforge's `inventory`, `tasks` and `score` modes **cannot be used
as blind-model benchmarks**. Statuses can change and should be refreshed.
Do not assert a detection improvement from synthetic checks or score matching.

For a valid old/new uplift claim, use `benchmark-protocol.md` with separately
sealed vulnerable/fixed snapshots, withheld ground truth, identical agent
budgets, independently reviewed native PoCs and false-positive accounting.
Use a separate private holdout corpus, not this calibration catalog.

## Test command

```sh
python3 -m unittest discover -s skills/bounty-pilot/tests \
  -p 'test_sequence_invariant_lab.py' -v
```

Tests exercise both violating fixtures and intact negative controls. They
**do not** run a production protocol or revalidate original Cantina PoCs.
