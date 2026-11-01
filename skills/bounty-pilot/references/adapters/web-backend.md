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
