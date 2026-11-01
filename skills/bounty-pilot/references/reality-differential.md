# Reality Differential Engine (Lab 0.45)

An offline checker for **investigator-supplied** native candidate/negative-control
observations. These are three *differential predicates*, not autonomous exploit
discovery and not a network scanner. The engine never launches project code,
checks chain state, or independently authenticates an observation artifact.

| Operation | Question | Conservative condition |
| --- | --- | --- |
| `settlement` | Did finalized obligations exceed assets available to back them? | Candidate starts backed and finishes insolvent; finalized control does not |
| `outcome` | Was a failed nested operation recorded as a finalized success? | Failure under stated required-success policy, but recorded success; finalized control conforms |
| `context` | Did authorization/verification/execution disagree or verification cache collide? | Bound field mismatch or same cache key for distinct verification contexts; complete control does not |

**The observation model assumes one `asset` and one unit of account for each
settlement pair**. Do not compare differently denominated assets, approximate
token prices, loans, LP share conversion or exchange rates using this command.
Pending/unfinalized deliveries are inconclusive. A pre-existing deficit is not
reported as a newly introduced deficit. Outcomes require an explicit
`success_policy`: `all_required` or `any_required`; a business process
permitting partial completion may need a different model. The tool does not
guess its semantics.

## How to run

Prepare an exact target checkout and a private test observation file. Candidate
and control should be executed by the *target's native* tests in an isolated,
secret-free environment. The observation file is a compact extraction from
those logs; SHA-256 IDs are **researcher-supplied**, not verified by the engine.

```sh
python3 skills/bounty-pilot/scripts/bounty.py reality-diff settlement \
  --input /private/pairs-settlement.json --out /private/settlement-leads.json

python3 skills/bounty-pilot/scripts/bounty.py reality-diff outcome \
  --input /private/pairs-outcome.json

python3 skills/bounty-pilot/scripts/bounty.py reality-diff context \
  --input /private/pairs-context.json
```

The `--out` path must be new, and is created with owner-only permissions on
POSIX hosts. No file is overwritten. Without `--out`, results print as JSON.
Input may contain sensitive data; keep the source file private. Output
suppresses raw authorized/executed payload values, but includes IDs, SHA-256
digests and accounting differences. The engine never automatically changes a
Bounty Pilot finding status.

## 1. Settlement truth

This example contains a finalized synthetic violation: a liability increases
without a corresponding increase in assets. Replace the example with *actual
native* balance observations for a real bounty hunt.

```json
{
  "schema_version": 1,
  "source_revision": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "environment": "mock-local",
  "cases": [{
    "id": "BP-501",
    "invariant": "Finalized liabilities do not exceed held backing",
    "equivalence_basis": "Same checked-out code with refund failure vs successful refund",
    "asset": "USDC:atomic",
    "candidate": {
      "before": {"held_atomic": "100", "owed_atomic": "100"},
      "after": {"held_atomic": "100", "owed_atomic": "115"},
      "finality": "finalized",
      "trace_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    },
    "negative_control": {
      "before": {"held_atomic": "100", "owed_atomic": "100"},
      "after": {"held_atomic": "115", "owed_atomic": "115"},
      "finality": "finalized",
      "trace_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    }
  }]
}
```

All atomic amounts are non-negative base-10 **strings** (up to 78 digits).
Floating-point and exponent forms fail closed. The checker flags a **newly
introduced** shortfall, not an accounting exploit verdict.

## 2. Outcome propagation

Each observation has:
- `outer_status`: `success`, `failed`, `pending`, or `unknown`;
- `recorded_status`: the withdrawal/accounting result;
- `item_statuses`: the *actual* results of nested items;
- `success_policy`: `all_required` or `any_required`;
- `finality`: `finalized`, `pending` or `unknown`;
- `trace_sha256`: digest label supplied by the investigator.

Example candidate:
```json
{
  "outer_status": "success",
  "recorded_status": "success",
  "item_statuses": ["failed", "success"],
  "success_policy": "all_required",
  "finality": "finalized",
  "trace_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
}
```

Place it under a case's `candidate`; pair it with a `negative_control`
where both inner items succeeded and all other parameters are comparable.
For batch semantics, verify failure events, dispatch/acknowledgement, and
the actual *destination* state; an EVM/FRAME extrinsic `Ok` is not
automatically full application success.

## 3. Context binding

Cases must include `bound_fields`, a nonempty subset of:
`operation_digest`, `recipient`, `amount_atomic`, `asset`,
`chain_id`, `domain`, `nonce`, `policy_epoch`, `account`,
`delegate`, `spender`, `signer_set`, `proof_context`,
`authorization_id`.

Each candidate and negative-control side supplies `authorized`, `verified`
and `executed` objects with values for each nominated field, a
`trace_sha256`, and optional `cache_entries` records:
`{"key":"...","verified_context_digest":"..."}`.

If a required binding is absent, the pair is **inconclusive**; if both paths
show the discrepancy, it is **CONTROL_ALSO_VIOLATES** and is not promoted.
A collision in supplied cache identities also needs native proof that two
different verification statements were actually accepted and could
share an unsafe result.

## Output guarantees and explicit limitations

Every run returns `classification: INVESTIGATOR_SUPPLIED_OBSERVATIONS` and
`confirmed_vulnerabilities: 0`. Each case receives one of
`DIFFERENTIAL_LEAD`, `NO_DIFFERENTIAL`, `CONTROL_ALSO_VIOLATES`, or
`INCONCLUSIVE`. A lead includes a concrete follow-up native experiment.

The tool checks structure and differential arithmetic; it does **not**
bind revision to the actual checkout, verify log digests, prove attacker
permissions, establish loss, check scope, reproduce exploit behavior, or
prevent researcher fabrication. Keep the original native PoC logs, bind
them through `scenario_runner` and the separate evidence gates, then have an
independent reviewer confirm original source, control assertions, and
third-party impact.

Benchmarks: the local unit tests use intentionally synthetic cases.
They prove the **differential predicates** and error handling, not
measured rediscovery or increased real bug bounty payouts. Do not add
the cases to a future blind evaluation after tuning on them.
