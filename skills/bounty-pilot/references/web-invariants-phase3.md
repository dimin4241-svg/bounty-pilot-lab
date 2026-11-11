# Web Invariant Lab Phase 3 — scope, state, effect, browser and parser controls

This is a **deterministic, offline-first research aid**, not a vulnerability
scanner or evidence that any Standoff 365 / BI.ZONE participant is vulnerable.
Its checks work on operator-supplied, authorized, local observations. A passed
scope preflight is **not** permission to test a production system. Actual
testing must separately comply with the latest official program scope.

Phase 3 is designed to minimize duplicate findings and unnecessary LLM
calls while strengthening the evidence standard for IDOR/BOLA, session and
organization authorization, payment/approval state, browser trust paths and
parser discrepancies. Existing Phase 1/2 commands remain available.

## 1. Program-specific fail-closed preflight

Command: `bounty.py web-program-policy`

Create private JSON with these required keys:

```json
{
  "schema_version": 1,
  "platform": "bizone",
  "program_id": "example-offline",
  "status": "active",
  "source_url": "https://example.test/program-rules",
  "rules_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "reviewed_at": "2026-11-11T00:00:00Z",
  "expires_at": "2026-11-20T00:00:00Z",
  "include": [
    {
      "origin": "https://api.example.test",
      "path_prefix": "/sandbox",
      "actions": ["read-only", "account-test"]
    }
  ],
  "exclude": [
    {
      "origin": "https://api.example.test",
      "path_prefix": "/sandbox/admin",
      "actions": ["read-only", "account-test"]
    }
  ],
  "required_headers": ["X-Research-Id"],
  "operator_reviewed": true
}
```

**This example is fictional. Never use it as an assertion of real program
permission.** `rules_sha256` must come from the rules actually inspected
and reviewed by the researcher. The CLI does not download, verify signatures
or authenticate the rules. Snapshot validity is capped at 30 days; earlier
program changes can revoke permission immediately.

A separate request plan contains an array of objects:

```json
[
  {
    "id": "offline-1",
    "url": "https://api.example.test/sandbox/items",
    "action": "read-only",
    "provided_header_names": ["X-Research-Id"]
  }
]
```

```sh
BP=skills/bounty-pilot/scripts/bounty.py
python3 "$BP" web-program-policy \
  --policy /private/program-policy.json \
  --requests /private/request-plan.json \
  --out /private/scope-decision.json
```

Supported actions: `source-review`, `read-only`, `account-test`,
`state-change`, `browser-test`, `automation`, `upload`, and
`payment-sandbox`. Paths and origins must match **exactly**, including
case and path-segment boundaries; wildcards, all percent-encoded paths,
nested URL-decoding, ambiguous traversal, username/password, query and fragment
are rejected. Rules can explicitly exclude otherwise included actions.
The output contains request IDs and reason codes only, not tokens or URL
values. Header names are recorded, never secret values.

No active production request can be launched by this preflight tool.
Offline snapshots are NOT legal or platform authorization.

## 2. Actor/resource/state graph

Command: `bounty.py web-actor-state-graph`

Private input describes:

- `environment="researcher_owned_lab"`, `schema_version=1`.
- `actors`: `{"id":"user-a","tenant":"org-1"}`.
- `resources`: `{"id":"invoice-1","owner":"user-a","tenant":"org-1","visibility":"private"}`.
- `initial_grants`: optional `{"actor":"user-b","resource":"invoice-1","action":"read"}` facts.
- `events`: monotonically increasing `seq` objects of type `grant`,
  `revoke`, `transfer` or `action`.

Every event has the exact keys `id`, `seq`, `type`, `actor`, `resource`,
`action`, `subject`, `new_owner`, `observed_effect`, and
`evidence_sha256`; non-applicable fields are JSON `null`.
`observed_effect` represents an explicitly supplied protected state
change, not HTTP status. An unknown effect is `null` and does not count
as a violation.

The engine applies the declared grants and revocations across sequence
positions, rejects undisclosed actors and malformed histories, and emits
review leads for effects that conflict with the lab's declared
tenant/owner/grant rules. Public visibility grants `read` only. The
effective authorization model is synthetic and deliberately incomplete:
global admins, delegated owners, group inheritance, actual IAM configuration
and asynchronous consistency require independent review. No live exploit
can be inferred from these leads.

```sh
python3 "$BP" web-actor-state-graph \
  --input /private/actor-events.json --out /private/actor-leads.json
```

## 3. Two-repeat business-effect oracle

Command: `bounty.py web-effect-oracle`

Use a private research fixture document:

```json
{
  "schema_version": 1,
  "environment": "researcher_owned_lab",
  "cases": [{
    "id": "subscription-sandbox",
    "resource_kind": "subscription",
    "business_effect": "plan_activated",
    "predicate": {"field": "plan_level", "relation": "increased", "value": null},
    "candidate_repetitions": [
      {"before": {"plan_level": 1}, "after": {"plan_level": 2},
       "evidence_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
       "effect_observed_at_step": 2},
      {"before": {"plan_level": 1}, "after": {"plan_level": 2},
       "evidence_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
       "effect_observed_at_step": 2}
    ],
    "negative_control": [
      {"before": {"plan_level": 1}, "after": {"plan_level": 1},
       "evidence_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
       "effect_observed_at_step": 2},
      {"before": {"plan_level": 1}, "after": {"plan_level": 1},
       "evidence_sha256": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
       "effect_observed_at_step": 2}
    ]
  }]
}
```

The example shows a controlled **effect**, not proof of unauthorized
subscription activation: an authorization rule and approved fixture still
need to establish that the actor lacked that right. The module requires
2–5 independent candidate/control paired repetitions, explicit pre/post
state fields, a matching starting state and unique observation digests.

```sh
python3 "$BP" web-effect-oracle \
  --input /private/effect-observations.json \
  --out /private/effect-review.json
```

Accepted resource kinds include subscriptions, exports, approvals, jobs,
objects, and explicitly **sandbox** payments/refunds. Only saved scalar
state is read. No purchases, money transfers, web calls or wallet signatures
are produced.

### Optional real loopback effect capture

Run `web-effect-fixture-replay` only against a **researcher-owned local
fixture**, never against a Standoff/BI.ZONE site or an arbitrary forwarded
proxy. The command rejects DNS names, redirects, arbitrary headers,
non-loopback addresses, shared test routes and external URLs. Its normal
mode is a plan validation dry run; `--execute` is required to make any
local GET/empty-POST/GET requests.

An example fixture plan, assuming a local service you control already
implements isolated `/r0` and `/r1` candidate and negative-control routes:

```json
{
  "schema_version": 1,
  "ownership_attestation": "I_CONTROL_THIS_LOCAL_FIXTURE",
  "origin": "http://127.0.0.1:8080",
  "case_id": "subscription-owned",
  "resource_kind": "subscription",
  "business_effect": "plan_activated",
  "predicate": {"field": "plan_level", "relation": "increased", "value": null},
  "rounds": [
    {"candidate": {"state_path": "/r0/c/state", "action_path": "/r0/c/action"},
     "negative_control": {"state_path": "/r0/n/state", "action_path": "/r0/n/action"}},
    {"candidate": {"state_path": "/r1/c/state", "action_path": "/r1/c/action"},
     "negative_control": {"state_path": "/r1/n/state", "action_path": "/r1/n/action"}}
  ]
}
```

```sh
python3 "$BP" web-effect-fixture-replay \
  --plan /private/owned-fixture-plan.json --out /private/local-effects.json
python3 "$BP" web-effect-fixture-replay \
  --plan /private/owned-fixture-plan.json --out /private/local-effects.json --execute
```

The fixture server must return a JSON object containing the one declared
scalar field at each `state_path`. Each `action_path` receives an empty
JSON object via POST. No credentials or cookies are sent or saved. The
output includes the actual pre/post fixture observations and the same
offline oracle review as `web-effect-oracle`. Unique route paths and
evidence digests permit independent rounds, but do not prove provider
authentication, customer authorizations or real deployment behavior.
## 4. Browser/third-party trust graph

Command: `bounty.py web-browser-trust`

Create a bounded `{"schema_version":1,
"environment":"offline_owned_source_or_fixture","nodes":[],"edges":[]}`
file. Nodes have `id`, `kind`, `trust` (`trusted`, `untrusted`,
`unknown`), `sensitive` (boolean) and `user_controlled`
(boolean). Edges have `from`, `to`, `kind`,
`observed_in_source` and `evidence_sha256`.

The engine looks for user-controlled data crossing an explicitly labeled
trusted/untrusted boundary and encountering an explicit privileged-context
edge such as `sends-auth`, `sends-cookie`, `uses-auth` or
`executes-script` before reaching a sensitive sink. It never infers
that a cookie or authorization header was sent merely from the existence
of an image request, redirect or script URL.

```sh
python3 "$BP" web-browser-trust \
  --input /private/browser-trust.json \
  --out /private/browser-paths.json
```

This is an offline **declared graph**, not an instrumented browser.
It does not prove SameSite bypass, XSS, session exposure or production
access. Use Playwright on researcher-owned test applications for
independent browser verification; do not fetch third-party user data.

## 5. Real local URL parser lab

Command: `bounty.py web-parser-lab`

Compares Python `urllib.parse.urlsplit` with Node's WHATWG `URL`
constructor, **not** two imaginary parser observations. Requires Node.js
on the operator's machine. The fixed Node script does not evaluate source
from the target.

```json
{
  "schema_version": 1,
  "environment": "synthetic_offline_fixtures",
  "pairs": [{
    "id": "default-port",
    "candidate_url": "https://fixture.invalid:443/path",
    "negative_control_url": "https://fixture.invalid/path"
  }]
}
```

```sh
python3 "$BP" web-parser-lab \
  --input /private/urls.json --out /private/parser-result.json
```

Only `*.invalid`, `*.test`, and `*.example` are allowed. The
report contains only difference categories and test IDs; URLs and query
values are omitted. No sockets, HTTP requests or DNS resolution occur.
This tests **URL normalization only**. It is not a request smuggling,
cache poisoning or production reverse-proxy test. Existing
`web-http-boundary` continues to compare saved HTTP observations.
A native Docker-backed HTTP Garden comparison is **not** included.

## 6. Conservative root-cause review queue

Command: `bounty.py web-root-cause-dedup`

Input contains a project ID, pinned 40-hex revision and a bounded array
of candidates with concrete `source_file`, `code_anchor`,
`invariant_id`, `trust_boundary_id`, `claimed_effect_id`,
optional `reviewed_root_cause_id`, optional `evidence_digest`,
`disposition`, and `evidence` scores. Five scores from 0 to 2
(`reachability`, `trust_boundary`, `business_effect`, `novelty`,
`testability`) give a review order, **not a payout probability**.

A candidate is grouped automatically only when project, pinned commit,
source file, code anchor, invariant and boundary all match, or when an
operator explicitly supplies a root-cause ID. That asserted review is
not authenticated or independently attested by the tool. Leads sharing
an anchor but differing in invariant/boundary remain separate and are
merely linked for manual review. `refuted` findings rank at zero;
`parked` findings stay in the queue at reduced priority.

```sh
python3 "$BP" web-root-cause-dedup \
  --input /private/research-candidates.json \
  --out /private/root-cause-queue.json
```

Use the queue before expensive model dispatch so one known hypothesis is
not re-audited repeatedly under different endpoint names.

## 7. How to integrate with Codex / Claude and historical benchmarks

Recommended agent order:

1. Review **current official program rules**, obtain permitted source,
   and run the **offline scope preflight**. Never auto-authorize from a
   green indicator.
2. Run existing `web-invariants graph`, `web-ts-flow` and
   `web-route-ast` on local, pinned, in-scope input.
3. Build actor-state and browser-trust hypotheses from verified code facts,
   preserving unknown fields as unknown.
4. Prioritize with root-cause grouping. Use one cheap agent first for
   alternative causes, runtime guards and existing fixes.
5. In an **owned or explicitly authorized test environment**, collect
   paired candidate/control effects; validate with
   `web-effect-oracle`.
6. Only send evidence-supported, still-novel issues to the stronger model
   for review. No auto-reporting from static leads.
7. Compare the old and new workflow using existing
   `web-bench-ab` separately sealed evaluator roles.

The bundled three publicly known historical cases do NOT establish
new-issue rediscovery or an uplift number. A diverse, independently
curated 30–50 case benchmark and truly unseen holdout remain future
evaluation work. Do not call the test suite a discovery benchmark.

## 8. Local tests and limits

```sh
python3 -m unittest discover -s tests -p 'test_web_phase3.py' -v
python3 -m unittest discover -s tests -p 'test_web_effect_fixture_replay.py' -v
```

No synthetic unit result can establish real exploitability, program
eligibility or bounty payout. All seven helpers use Python 3.9+ and mostly
stdlib; the parser lab also requires Node.js. All output files are
create-only and permissioned for private local analysis.
