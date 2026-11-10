# Web Invariant Research (0.57 preview)

This is an **offline-first, evidence-gated Web/API lab**, extending the existing
Bounty Pilot Target Intelligence and two-account GET authorization helper.
It does not certify findings, discover targets, authenticate third-party data,
run web scans, or prove that a deployed service is vulnerable.

## Implemented components

| Command | Input | Output | Execution |
|---|---|---|---|
| web-invariants graph | saved OpenAPI 3 JSON, optional x-bp-handler/x-bp-operation/x-bp-roles hints | cross-route/method authorization review leads | offline |
| web-route-ast | local Python source directory | FastAPI/Flask-style decorator routes and apparent guard cues | offline Python AST only |
| web-ts-ast | local JS/TS source + pinned TypeScript compiler | Express/Next.js routes and middleware-name discrepancies | offline TypeScript AST; vetted parser executed |
| web-invariants matrix | graph JSON + private owned fixtures | owner/outsider/revoked authorization test-plan descriptions | offline |
| web-invariants state | saved event observations | revocation, private resource, payment binding and idempotency contradictions | offline |
| web-invariants parser | curated URL cases | multi-decoding and normalization review leads | offline |
| web-identity-flow sessions | saved abstract session events | revoke/subject/tenant lifecycle leads | offline |
| web-identity-flow intent | saved displayed/signed/executed fields | signed-intent field mismatches when local execution was asserted | offline |
| web-identity-flow tenant | saved owned tenant events | RAG/tool/cache/document isolation review leads | offline |
| web-nday-review | two pinned web-route-ast snapshots | guard-cue additions and related unreviewed route candidates | offline |
| web-local-replay | researcher-controlled loopback fixture plan | repeated GET candidate/control observations, no bodies | **127.0.0.1 only** |

All of these are independent commands exposed through the main CLI:

```sh
python3 skills/bounty-pilot/scripts/bounty.py web-invariants --help
python3 skills/bounty-pilot/scripts/bounty.py web-local-replay --help
```

## 1. Operation graph and matrix

Store a local OpenAPI 3 document. The importer uses documented security metadata
and **untrusted investigator-supplied** extensions:

- x-bp-handler: stable handler identifier across route aliases
- x-bp-operation: stable business operation identifier
- x-bp-roles: explicit roles in the spec snapshot

Do not assume these accurately describe runtime authorization.

    BP=skills/bounty-pilot/scripts/bounty.py
    python3 "$BP" web-invariants graph \
      --input /private/openapi.json --out /private/web-operations.json

Example of a deliberately simplified owned fixture manifest for the matrix:

    {
      "schema_version": 1,
      "resources": [{
        "id": "invoice-101",
        "operation_id": "REPLACE_WITH_GRAPH_OPERATION_ID",
        "private_resource_confirmed": true,
        "owner": "alice",
        "outsider": "bob",
        "owner_fixture": "alice-invoice",
        "outsider_fixture": "bob-invoice"
      }]
    }

    python3 "$BP" web-invariants matrix \
      --input /private/web-operations.json \
      --fixtures /private/owned-fixtures.json \
      --out /private/web-auth-matrix.json

The matrix has **descriptive checks**, not replayable HTTP requests. Actual
private resources must be created only in researcher-owned environments.
A path or operation ID from OpenAPI alone is not sufficient to test.

## 2. Python AST source graph and N-day review

    python3 "$BP" web-route-ast --repo /isolated/pinned-source-old \
      --out /private/old-route-ast.json
    python3 "$BP" web-route-ast --repo /isolated/pinned-source-new \
      --out /private/new-route-ast.json
    python3 "$BP" web-nday-review \
      --before /private/old-route-ast.json \
      --after /private/new-route-ast.json \
      --out /private/auth-patch-review.json

The AST scanner **does not execute** project modules. It recognizes a subset of
decorator routes in Python. Inherited router policy, dependencies installed
elsewhere, dynamic routing and JS/TS are not parsed. Any added "auth"-named
decorator cue may simply be a refactor, not a security fix. Pin the before and
after Git revisions separately and review the actual patch.

Use the existing js_change_intel for saved JS assets; it currently provides
URL/keyword cues, not a TypeScript call graph. No claim of JavaScript AST
authorization analysis is made here.

### JavaScript/TypeScript source AST (experimental)

The script `web-ts-ast` uses an operator-vetted, explicitly SHA-256 pinned
TypeScript compiler library. It parses saved JavaScript/TypeScript source
without evaluating or importing the target. It recognizes a subset of
Express/router methods and Next.js App Router exports.

Install TypeScript in an isolated parser-toolchain directory, not within
the target checkout, with lifecycle scripts disabled. Example pinned version:

    npm install --prefix /isolated/bp-ts-parser \
      --ignore-scripts --no-audit --no-fund --save-exact typescript@5.9.3
    TS_LIB=/isolated/bp-ts-parser/node_modules/typescript/lib/typescript.js
    TS_SHA=$(shasum -a 256 "$TS_LIB" | awk '{print $1}')
    python3 "$BP" web-ts-ast --repo /isolated/pinned-js-source \
      --typescript-parser "$TS_LIB" --parser-sha256 "$TS_SHA" \
      --out /private/web-ts-routes.json

Security note: TypeScript parser code is executable third-party tooling;
**use a disposable, secret-free, network-isolated environment**, independently
vet the installed parser and pin its exact digest. A source-level
middleware-name cue is not proof of effective authorization. No cross-file
JS/TS whole-program taint or framework middleware inheritance is implemented.

## 3. Stateful observation traces

For local event-sourcing or application integration tests, capture synthetic
events such as:

    {
      "schema_version": 1,
      "events": [
        {"kind":"revoke","actor":"bob","resource":"invoice-1"},
        {"kind":"access","actor":"bob","resource":"invoice-1",
         "owner":"alice","confirmed_private":true,
         "authorized_delegate":false,"allowed":true}
      ]
    }

    python3 "$BP" web-invariants state \
      --input /private/owned-event-trace.json --out /private/state-leads.json

Payment observations accept explicit boolean fields signature_valid,
order_bound, amount_bound, currency_bound, settled and additional_credit.
Missing booleans yield unknowns, not fabricated exploit claims. Supply a
separate positive control and inspect the actual source/test runner.

For identity/session tests use abstract session_ref aliases, not actual JWTs:

    python3 "$BP" web-identity-flow sessions \
      --input /private/session-events.json --out /private/session-leads.json

Other modes: web-identity-flow intent / tenant, web-invariants parser.

## 4. Local HTTP differential replay

This is deliberately separate from web_auth_lab.py. The existing helper
supports bounded, explicitly approved production **GET** checks. This new tool
**never** reaches any production, staging or DNS hostname: only literal
http://127.0.0.1:PORT is accepted. Proxies and redirects are disabled.

Minimal plan (do NOT commit real fixture IDs, tokens, private markers, or plans):

    {
      "schema_version": 1,
      "base_url": "http://127.0.0.1:8765",
      "local_fixture_confirmed": true,
      "test_actors": {
        "alice": {"bearer_env": "BP_WEB_REPLAY_OWNER_TOKEN"},
        "bob": {"bearer_env": "BP_WEB_REPLAY_OUTSIDER_TOKEN"}
      },
      "cases": [{
        "id": "owned-document",
        "private_resource_confirmed": true,
        "owner_marker_env": "BP_WEB_OWNER_MARKER",
        "outsider_marker_env": "BP_WEB_OUTSIDER_MARKER",
        "owner": {"actor": "alice", "method": "GET", "path": "/api/doc/alice"},
        "cross": {"actor": "bob", "method": "GET", "path": "/api/doc/alice"},
        "outsider_control": {"actor": "bob", "method": "GET", "path": "/api/doc/bob"}
      }]
    }

Export separate, fake-fund fixture credentials/markers using the env variable
names shown, then validate the plan **without network access**:

    python3 "$BP" web-local-replay \
      --plan /private/loopback-plan.json --out /private/replay-dry.json

If you own and have started this server locally, execute in a secret-free,
isolated environment:

    python3 "$BP" web-local-replay --plan /private/loopback-plan.json \
      --out /private/replay-run.json --execute

GET cases are retried in two rounds; mutation methods run once because a
repeat without reset may alter state. Owner and outsider independent controls
must succeed before a cross-owner success becomes a local lead. The response
bodies, tokens and private markers are not persisted. Evidence SHA-256 binds
only the saved non-secret observation booleans/statuses.

Statuses: VALIDATED_PLAN_NOT_EXECUTED, LOCAL_REPRODUCED,
LOCAL_CANDIDATE_SINGLE_ROUND, NO_BYPASS_OBSERVED_IN_LOCAL_FIXTURE, INCONCLUSIVE.
None claims a production issue or bounty severity.

**IMPORTANT**: local fixture behavior does not prove a live target is using
the same routes, configuration or guards. The replay tool itself is not an
OS-level sandbox. Run only trusted, owned fixture code in a disposable machine.

## 5. Review, novelty and model routing

- Route leads to existing independent agent_dispatch; do NOT charge three
  expensive models to review every lexical cue.
- First check exact program scope, target branch and deployed revision.
- Apply existing dup-map to source mechanism and affected implementation.
- Prioritize candidates with a concrete caller-controlled input, actual
  entry-to-sink trace, relevant private resource and local negative control.
- Reconstruct impact from local evidence, not model-estimated profit.
- Keep any secrets and payloads outside the public repository.
- Label outputs UNVERIFIED until an independent reviewer inspects runtime
  evidence and matches it to the in-scope deployed artifact.

## 6. Testing and limitations

```sh
python3 -m unittest discover -s tests -p 'test_web_invariant_engine.py' -v
python3 -m unittest discover -s tests -p 'test_web_route_ast.py' -v
python3 -m unittest discover -s tests -p 'test_web_identity_nday.py' -v
python3 -m unittest discover -s tests -p 'test_web_ts_ast.py' -v
```

Tests use synthetic OpenAPI/AST/trace fixtures and an in-process loopback
server. No external target is tested. These prove local implementation
contracts only, **not** an improved bug bounty detection or payout rate.

Known gaps (do not silently call these complete): complete framework-aware TypeScript AST and inherited guards,
cross-file JS dataflow, independently authenticated native traces, actual
JWT/PKCE cryptographic verification, distributed cache semantics, and
multi-hop HTTP request parsing. Those require native language-aware analyzers
and larger controlled benchmark datasets rather than extra keyword heuristics.
