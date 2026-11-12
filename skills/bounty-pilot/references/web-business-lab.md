# Web/API Account & Payment Business Integrity Lab (0.57.0)

This release adds 13 executable invariant rules, native *synthetic* SQLite
vulnerable/fixed fixtures and an evidence-gated, offline review CLI. It does
not fetch target pages, log into services, perform payment transactions, send
HTTP requests, run models, prove an externally deployed bug or certify payout.

## Run

Python 3.9+ and standard library only:

~~~sh
BP=skills/bounty-pilot/scripts/bounty.py

# Disposable in-memory SQLite demo: no websites, payments or credentials.
python3 "$BP" web-business-lab demo --out /private/business-demo.json

# Describe a source-pinned local testing campaign, with no execution.
python3 "$BP" web-business-lab plan \
  --input /private/business-plan.json --out /private/business-jobs.json

# Review already executed, independently captured local candidate/control traces.
python3 "$BP" web-business-lab analyze \
  --input /private/business-observations.json \
  --out /private/business-review.json
~~~

All outputs are create-only mode 0600. Store source and trace evidence outside
the repository; do not upload credentials, actual HARs, personal information,
payment tokens, bank details or unpublished bug reports.

## Plan JSON

~~~json
{
  "schema_version": 1,
  "environment": "researcher_owned_lab",
  "source_revision": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "rules": ["account-owner", "mfa-gate", "session-revocation",
            "reset-one-use", "oauth-binding", "email-verification",
            "unpaid-credit", "event-replay", "webhook-binding",
            "refund-replay", "subscription-entitlement",
            "cancellation-stale", "cross-tenant-credit"]
}
~~~

The plan returns descriptions, not runnable target requests. Before native
target execution independently obtain the official current program scope,
permitted operations, explicitly approved isolated test app with controlled
identities, pinned source and exact product-specific policy facts.

## Supported rule families

| Rule | Explicit violation being reviewed |
|---|---|
| account-owner | unauthorized other-account credential change |
| mfa-gate | protected credential change with required MFA absent |
| session-revocation | revoked session modifies credentials |
| reset-one-use | already-used reset token modifies credentials |
| oauth-binding | invalid issuer/audience/nonce/subject creates session |
| email-verification | email changes despite required but missing verification |
| unpaid-credit | balance increases without PSP confirmation or allowed credit |
| event-replay | repeated payment event increments balance again |
| webhook-binding | invalid signature/order/amount/currency/merchant binding credits |
| refund-replay | repeated refund event pays again |
| subscription-entitlement | paid entitlement activated without payment or grant |
| cancellation-stale | immediate cancellation leaves entitlement when grace disallowed |
| cross-tenant-credit | unauthorized cross-tenant actor credits another balance |

Rule outcomes require explicit observed before/after state. Unknown or missing
authorization facts are NOT interpreted as false. Monetary fields use
nonnegative integer smallest units. Promotion/bonus credit, legitimate
delegation, allowed grace periods and non-PSP settlements are falsifiers.
Invariants are labeled documented versus reviewer-inferred, and assumptions
require product-policy confirmation.

## Observation contract

Input schema_version=1, environment=researcher_owned_lab, source_revision
as 40 hex characters, and cases (1 to 60). Each case has:

- id: bounded non-secret pseudonym
- rule: one supported rule above
- invariant_basis: documented or reviewer-inferred
- candidate_runs: 2 to 5 executions
- control_runs: 2 to 5 negative controls, same number

Each run has a 64-hex initial_state_digest, unique 64-hex evidence_sha256,
and 1..120 JSON events. Events contain kind, actor, subject, before and after
state objects, facts booleans, and optional payment_event_ref or refund_event_ref.
For every candidate/control pair, initial_state_digest must match.
The analyzer only reads saved observations. It never authenticates evidence
hashes, reads a real PSP, verifies native source or performs HTTP traffic.
Only a *repeatable, controlled local trace discrepancy* becomes a LEAD.

Example event from an owned fake-money fixture:

~~~json
{
  "kind": "credit",
  "actor": "alice",
  "subject": "alice",
  "before": {"available_cents": 10000},
  "after": {"available_cents": 10500},
  "facts": {"psp_confirmed": false, "non_payment_credit_allowed": false},
  "payment_event_ref": "local-test-1"
}
~~~

The corresponding honest control must use the same initial state and record
a valid provider confirmation. At least two independent rounds, unique
receipts and negative controls are mandatory. HTTP 200 alone is not enough.

## Native research and agent handoff

1. Check current scope, allowed methods and exact pinned in-scope source.
2. Trace full login/reset/MFA/OAuth, payment/PSP/order/ledger and async-worker
   paths in local source. Use existing web-route-ast, web-ts-ast, web-ts-flow
   and web-invariants graph to prioritize precise source anchors.
3. In a disposable, network-isolated app create two owned test identities,
   a fake PSP and known database state. Execute the same pinned native
   source for candidate and honest negative control, twice each.
4. Record DB, ledger, session and worker facts before and after, signature
   verification where applicable, eventual settlement and compensation.
5. Import redacted observations with analyze; check actual native assertions.
   Require independent review of the source policy, live reachability, exact
   mechanism and plausible alternative explanations.
6. Only reviewed anchored leads reach existing web-root-cause-dedup and
   agent_dispatch. Existing web-evidence-packet is not auto-submittable.
7. Test against real, independently source-pinned historical vulnerable/fixed
   cases before measuring unique findings, spending or duplicate rate.

## Synthetic regression

~~~sh
python3 -m unittest discover -s tests -p 'test_web_business_lab.py' -v
~~~

The 13 cases execute actual SQLite writes in a deliberately defective
in-memory app and run the same 13 against a corrected app. They are paired
synthetic bug/fix patterns, NOT 13 discovered or independently proven
production vulnerabilities.

## Known limitations

No full live ATO browser runner, real JWT/OAuth cryptography, PSP adapter
or signed webhook verification, real async/race execution, third-party
payment interaction, production mutations, external account access, or
native proof authentication is implemented here. The tool does not know
a target's actual documented business semantics without independent
source/policy review. More native adapters and unseen historical holdouts
are necessary before claiming a bug-discovery quality improvement.
