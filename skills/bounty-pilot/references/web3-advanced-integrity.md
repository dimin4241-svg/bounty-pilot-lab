# Advanced Web3 Integrity Research — Lab 0.47

Three new **offline**, bounded and conservative assistants for Web3 bug-bounty
research. They use either investigator-provided candidate/negative-control
native observations or a locally pinned Git source tree. They never send
HTTP/RPC requests, sign transactions, run target application code,
prove exploit reachability, or authenticate real-world provenance.

## Commands

```sh
python3 skills/bounty-pilot/scripts/bounty.py web3-advanced business-invariants \
  --input /private/business.json

python3 skills/bounty-pilot/scripts/bounty.py web3-advanced signed-intent-mirror \
  --input /private/intent.json

python3 skills/bounty-pilot/scripts/bounty.py web3-advanced runtime-provenance \
  --repo /path/to/pinned-checkout --policy /private/web-policy.json \
  --input /private/artifacts.json --out /private/provenance-results.json
```

Use the existing web policy from references/web3-security.md. All commands
are offline; output is JSON. The output file must not yet exist; it is
created with owner-only permissions on POSIX and is never overwritten.

## Business invariants

The envelope needs schema_version=1, source_revision (40 hex characters),
environment (mock-local, native-local or anvil-local), and cases (1..100).
Every case has an ID, invariant, equivalence_basis, scenario, candidate,
negative_control. A native test must establish each observation first.

### trade-asset: Coinbase-style asset identity

```json
{
  "schema_version": 1,
  "source_revision": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "environment": "mock-local",
  "cases": [{
    "id": "BP-501",
    "invariant": "A completed BTC order debits BTC rather than an unrelated asset",
    "equivalence_basis": "Same local order ID, actor and order asset",
    "scenario": "trade-asset",
    "candidate": {
      "order_id": "order-17", "actor": "alice",
      "order_asset": "BTC", "debit_asset": "SHIB",
      "status": "completed",
      "trace_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    },
    "negative_control": {
      "order_id": "order-17", "actor": "alice",
      "order_asset": "BTC", "debit_asset": "BTC",
      "status": "completed",
      "trace_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    }
  }]
}
```

A completed asset mismatch **could** be a security lead, but only if
the target's documented trade semantics actually require that equality.
This helper does not fetch or check the target's business rules.

### fee-sign: signed fee accepted while negative

Each side supplies order_id, actor, fee_atomic (exact signed base-10
integer string), status (accepted, rejected or unknown) and trace_sha256.
The same order/actor is required across the candidate and control.
A negative fee *accepted* on the candidate versus a nonnegative
accepted control produces a lead. Intentionally signed rebates are
not automatically bugs.

### deposit-finality: finalized credit versus backing

Each side supplies order_id, actor, deposit_status (finalized, pending,
failed, unknown), credit_status (finalized, pending, none, unknown),
received_atomic, credited_atomic and trace_sha256.
The atomic amounts are nonnegative base-10 strings, not floats,
quantities of different assets or oracle-valued estimates. A finalized
credit with pending/failed backing or insufficient received amounts
produces a lead only if an equivalent fully finalized/fully backed
control exists. This compares a *declared* single asset and account
domain; legitimate undercollateralized lending is not a bug.

The engine reports one of DIFFERENTIAL_LEAD, NO_DIFFERENTIAL,
CONTROL_ALSO_VIOLATES or INCONCLUSIVE. It never promotes a finding.

## Multi-leg signed-intent mirror

Use the same envelope and case fields, but omit scenario and add
bound_fields, a nonempty subset of:

chain_id, contract, recipient, spender, asset, amount_atomic, nonce,
domain, function_selector, operator, account, calldata_sha256,
authorization_id.

Each candidate/control has:
- displayed_legs: a complete array of normalized fields the user
  approved, in operation order;
- decoded_signed_legs: the operation *locally decoded with a real native
  or independent decoder*, one object per operation leg;
- executed_legs: operation fields observed in the native local trace;
- display_coverage: complete, partial or unknown;
- decoder: native-abi, native-eip712 or independent-local;
- approval_status: approved, rejected or unknown;
- execution_status: success, rejected or unknown;
- trace_sha256: a hexadecimal digest, supplied by the investigator.

All nominated fields must exist in every leg of all three arrays, on
both sides. Candidate and negative control should use equivalent native
fixtures, allowing one controlled difference. A lead requires a
complete/approved/successful candidate with mismatch between stages
or extra hidden batch legs, while the complete/approved/successful
control must be consistent.

Important: this engine does **not** decode Ethereum transactions,
EIP-712 signatures or ABI on its own. It **compares normalized values
provided by an external decoder** and does not authenticate that
decoder or the native execution evidence. A call with changed calldata
is not necessarily an exploit; prove what the user actually authorized.

## Local runtime provenance

This is a tracked-Git-file byte-integrity comparison, not a CDN or
live browser test. Prepare an independent baseline of reviewed hashes,
then a manifest:

```json
{
  "schema_version": 1,
  "baseline_id": "reviewed-build-artifacts-2026-11",
  "baseline_revision": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "artifacts": [
    {
      "path": "app/dist/bundle.js",
      "expected_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "origin": "first-party",
      "role": "script"
    }
  ]
}
```

The named file must be tracked, under a policy-allowed source prefix,
not symlinked (including parent dirs), and at most 2 MB. Hashing uses
actual bytes with SHA-256. Expected hashes and origin classifications
are investigator-supplied; the tool does not obtain trusted baselines
itself and cannot establish that an inspected file is actually served
to a user. A mismatch yields ARTIFACT_DRIFT (not a vulnerability).
It then highlights bounded *lexical* cues for wallet requests,
dynamic script execution and address-mutation operations in changed
JavaScript. Such cues are not taint analysis or proof of malicious code.

It refuses non-source paths, traversal, files outside declared scope,
untracked files, duplicate artifacts and symlinks. It does not inspect
remote DNS/CDNs, fetch npm packages, install dependencies, compare
browser responses or run a service worker.

## Hunt integration and proof standard

The web-integrity lens is included in bundle --lens web alongside
web-frontend and web-api-boundary. Backend-aware route suggestions
include it when server framework evidence exists. It traces
entry→check→sink with exact file:line anchors and uses the three
commands only when investigator-owned local tests provide both
candidate and negative control.

To report, independently verify actual source revision and deployed
code, native trace provenance, attacker reachability, risk to a third
party, actual program scope and duplicate status. No deployed exploit
or historical blind rediscovery benchmark was run by this release.
