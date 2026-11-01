# Web3 Security Research Engine — Lab 0.46

This is a conservative, **offline** starter for scoped Web3 web-app
research, with four commands: scope, api-map, authz and wallet-intent.
No module initiates HTTP requests, follows remote links, signs transactions,
executes target application code, connects to production RPC endpoints,
brute-forces logins, or reads other users' objects. The tool does not
claim to replace Burp, an application-specific integration harness, or
an independent security review.

An investigator-supplied scope file is **not proof of real program
authorization**. Check the actual program rules and asset eligibility
separately, before any live testing outside this tool.

## Policy file

Save privately as policy.json:

```json
{
  "schema_version": 1,
  "network_mode": "offline",
  "production_requests": false,
  "scope_evidence": "Reference to published program scope and review date",
  "in_scope_origins": ["https://app.example.org", "http://127.0.0.1:8080"],
  "excluded_origins": ["https://admin.example.org"],
  "allowed_source_prefixes": ["app", "api"]
}
```

Exact origins only: a listed host does not include subdomains. Exclusions
win. No wildcard origins, embedded credentials, path-scoped origin rules,
remote cleartext HTTP, traversal, or implicit source root. Loopback
HTTP can be declared for local tests. The scope command classifies
strings, not URLs on the network:

```sh
python3 skills/bounty-pilot/scripts/bounty.py web3 scope \
  --policy /private/policy.json \
  --url 'https://app.example.org/withdraw'
```

## Map a locally cloned web project

```sh
python3 skills/bounty-pilot/scripts/bounty.py web3 api-map \
  --repo /path/to/exact-git-checkout \
  --policy /private/policy.json \
  --scope api --out /private/web-api-map.json
```

Only tracked files in explicitly allowed relative directories are
considered. Scanning is size/count-bounded, symlinks are refused,
and no project code is executed. Source anchors include path, line,
HTTP method and declared path for a limited set of common route
declarations; separate lexical signals identify wallet, authentication,
tenancy, financial APIs, GraphQL, WebSocket and queues.

The map is **not an AST, accurate call graph, endpoint enumerator,
middleware audit, permission verdict, or completeness guarantee**.
Next.js filesystem routes, framework plugins, dynamically declared
routes, API gateways, GraphQL resolver semantics and generated code may
not be recognized. A missing guard or route in this map proves nothing.
Inspect the actual source and deployment manually.

## Paired API authorization observations

Create local test accounts that you own. Candidate and control must
target the **same** resource, owner and operation in the **same** pinned
checkout. All identities and result values are supplied by the
researcher and are NOT verified by this tool.

```json
{
  "schema_version": 1,
  "source_revision": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "environment": "mock-local",
  "cases": [{
    "id": "BP-501",
    "invariant": "Only an account owner can update its payout settings",
    "equivalence_basis": "Two fixture accounts, same operation and resource",
    "candidate": {
      "actor": "bob", "owner": "alice", "resource_id": "payout-1",
      "operation": "update", "result": "allowed",
      "trace_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    },
    "negative_control": {
      "actor": "alice", "owner": "alice", "resource_id": "payout-1",
      "operation": "update", "result": "allowed",
      "trace_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    }
  }]
}
```

```sh
python3 skills/bounty-pilot/scripts/bounty.py web3 authz --input /private/authorization.json
```

This only surfaces a differential when the nonowner is *reported* allowed
and the owner control is *reported* allowed. An unknown, mismatched or
failed control is not promoted. It does not independently confirm
actual server-side authorization or explain an intentional shared role.

## Paired wallet intent and session observations

Use the same document envelope and case fields as authz, but set
`bound_fields` (nonempty) and give both sides five keys:

- `displayed`, `signed`, `executed`: objects recording the declared
  invariant fields.
- `session_permission`: `valid`, `revoked`, or `unknown`.
- `execution_status`: `success`, `rejected`, or `unknown`.
- `trace_sha256`: researcher-supplied 64-digit hex digest.

Supported bound fields include `account`, `address`, `amount_atomic`,
`asset`, `chain_id`, `contract`, `deadline`, `delegate`, `domain`,
`nonce`, `operation_digest`, `recipient`, `session_id`, `signer`
and `spender`. All nominated fields must be present at all stages,
on candidate and control. The negative control must have consistent
values, a valid session and successful execution.

```sh
python3 skills/bounty-pilot/scripts/bounty.py web3 wallet-intent \
  --input /private/wallet-intent.json
```

Reported successful execution with different bound fields, or with an
already revoked session, produces an unverified lead. An unsuccessfully
executed transaction does **not** prove unauthorized wallet execution.
Whether a particular field is supposed to remain unchanged requires
checking the native application's real specification. Formatting
changes, normalized addresses, approvals, intentional conversions and
batch summary views must not be mislabeled.

## Agent discovery and evidence review

The `web-api-boundary` lens is part of the `web` bundle group alongside
`web-frontend`, and is recommended by stack routing only when source
or manifests indicate a backend:

```sh
python3 skills/bounty-pilot/scripts/bounty.py bundle \
  --repo /path/to/checkout --run /private/hunt \
  --lens web
```

The agent traces file:line route→middleware→tenant/owner check→sink,
signing intent and real money movement, then proposes an investigator-run
native candidate/control. Reuse `reality-diff settlement|outcome|context`
for suitable observed backend/worker accounting errors, not guessed
HTTP statuses.

Output never automatically upgrades to a verified finding:
`DIFFERENTIAL_LEAD`, `NO_DIFFERENTIAL`,
`CONTROL_ALSO_VIOLATES`, or `INCONCLUSIVE`.
Trace SHA-256 and source revisions are metadata only and are not
authenticated. Check the native logs, deployment, program scope, actual
attacker permissions, financial impact, and possible duplicates before
reporting. A staged fixture can expose a logic hypothesis but does not
prove a target deployment is vulnerable.

## Scope and result limitations

Only the first four components of the planned Web3 Security Research
Engine are provided in 0.46. Specialized automatic payment-flow,
CDN/service-worker provenance and cross-version regression engines are
*not* implemented here. There is no benchmark of real vulnerability
rediscovery or increase in payout likelihood. Tests use synthetic local
fixtures and assess only schema, routing, comparisons and safety gates.
