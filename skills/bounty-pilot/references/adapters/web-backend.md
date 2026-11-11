# Python / TypeScript / web backend adapter

Start from app routes, auth/session middleware, permission sources, background workers, DB schema/migrations, RPC clients and external services.

For high-impact Web3 API surfaces, also run web-integrity for paired
asset-identity, signed-fee and deposit-finality hypotheses, and
multi-leg wallet intent/provenance review. See
references/web3-advanced-integrity.md. Changed local scripts and
supplied native observations alone never establish an exploit.

For Web3 website or API scopes, use the offline web-api-boundary hunt lens
and the bounded `bounty.py web3 api-map` inventory. Before every local
native candidate/control, identify the same resource, tenant/owner and
operation; wallet-intent requires actual local success or rejection
observations. Check the published program scope independently; an
investigator-authored scope policy is not authorization to test a
production target. See references/web3-security.md. Follow full input-to-output lifecycle including async queues and webhooks. Prioritize IDOR, authorization scope mismatch, stale cache permissions, nonce/signature intent binding, JS Number safe-integer loss, Decimal/bigint/canonicalization, duplicate payments/claims and time-of-check/time-of-use. Trace retry/idempotency and what remains durable on partial failure. Use pytest/hypothesis or Jest/Vitest/fast-check native harnesses with transaction fixtures and authenticated cross-user negative controls. Do not use a live external service as a load-test target. Separate reported REST success from confirmed chain/DB effects.

## Web invariant and evidence extensions

Before broad model passes, review saved OpenAPI through `bounty.py web-invariants
graph`, and source routes through `bounty.py web-route-ast` or the
explicitly pinned `bounty.py web-ts-ast` parser. Trace claimed discrepancies
to actual guards and object lifecycle. For local owned-account traces, apply
`web-invariants state`, `web-identity-flow` and `web-local-replay` with
positive and outsider controls. The replay helper is literal-loopback-only;
none of these offline leads or local observations establish a real deployed
vulnerability. See `references/web-invariant-engine.md` for limits.

## Phase 2 Web research queue

Apply `web-ts-flow` to pinned, source-authorized JS/TS for cross-file
argument-to-sensitive-call reading leads. For conflicting frontend/backend
HTTP parsing, `web-http-boundary` consumes **saved, local fixture**
observations and a separate negative control, without generating traffic.
For comparisons use the `web-bench-ab` evaluator-separated protocol,
not self-scored model claims. These are unverified investigation aids.
See `references/web-semantic-phase2.md`.

## Phase 3 lab evidence contracts

Use `web-program-policy` to check a specific current scope/action
plan before any authorized external test. Static source routes from
`web-ts-flow` are not taint proof. Event-based
`web-actor-state-graph` and pre/post `web-effect-oracle` are
the allowed offline interchange format for owned test-account
observations; preserve unknowns. Do not join distinct root causes
from matching route names alone; use `web-root-cause-dedup`.
For URL/cookie parser questions, compare synthetic controlled inputs
first and never automate production desync probes from this lens.
See `references/web-invariants-phase3.md`.

## Verified local native adapters

Use the Phase 4 `web-native-toolchain` for vetted native
CodeQL queries (no JS/TS build), a bounded locally owned
Schemathesis OpenAPI service, isolated Playwright local
browser contexts or a manually acquired/pinned HTTP Garden
observation import. A dry-run is always the default.
External OS network isolation remains a separate requirement.
Summaries are review leads; never count them as confirmed
security findings. See `references/web-native-phase4.md`.
