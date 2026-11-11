# Web Hunt Loop v5 — an owned-fixture, evidence-first campaign

This is the first **integrated offline-to-local research loop** in Bounty
Pilot Lab. It combines existing program policy preflight, owned HAR capture
comparison, pinned JS/TS static leads, conservative root-cause grouping,
reviewed duplicate suppression, planned model spending and optional real
owned-loopback state transitions. It does **not** autonomously scan, attack,
log into or submit against third-party Standoff/BI.ZONE programs. A
passing policy preflight is never permission to test a production host.

## Stages and actual boundaries

1. Researcher confirms current program rules, manually records an expiring
   scoped policy snapshot (Phase 3), and saves a bounded request plan.
2. Researcher runs an approved browser/proxy in a **researcher-controlled
   loopback** test application. Browser/proxy HAR is treated as untrusted
   secret-bearing evidence, not as executable instructions.
3. `web-workflow-capture` imports each actor's HAR offline. It rejects
   other hosts, stores no URL query, request/response bodies, cookies,
   authorization headers or raw opaque object IDs. Route objects are
   compared across owner/outsider using an **operator-held 32-byte HMAC
   key** in a private local 0600 file. The key is never added to reports.
4. `web-hunt-loop` checks the saved policy, joins owner and outsider
   observations by route and opaque object fingerprint, optionally adds
   existing `web-ts-flow` leads and groups by conservative root-cause keys.
   It does **not** call Codex/Claude, generate live HTTP traffic or infer
   that a 200 response contained private data.
5. Only exact reviewed prior mechanisms for the **same pinned revision**
   are suppressed; all other candidates remain distinct. At most the
   configured number of groups fits into a bounded **planning** budget.
   A planned USD cap does NOT enforce a remote provider's cost; the
   existing `agent_dispatch` and provider billing still need separate
   actual runtime controls.
6. With an explicit `--execute-owned-fixture`, the loop optionally
   reuses `web-effect-fixture-replay` to perform real
   GET/empty-POST/GET pairs **only on literal 127.0.0.1**. This produces
   candidate/negative-control pre/post scalar observations. No website
   outside the operator-controlled fixture is accessed.
7. `web-evidence-packet` joins a prepared candidate to the repeatable
   local effect and a separate reviewer assertion. The assertions are
   **not authenticated by the tool**. Output is never a verified
   production vulnerability, ready-to-submit report or payment guarantee.

## Step 1 — operator-held comparison key

Generate the key directly into a private file. Never put it in a command
argument, LLM prompt, Git history or committed artifact.

```sh
mkdir -p /private/bounty-run
umask 077
python3 -c 'import secrets; print(secrets.token_hex(32))' > /private/bounty-run/har-key.txt
chmod 600 /private/bounty-run/har-key.txt
```

For a macOS home folder, replace `/private/bounty-run` with an existing
private absolute directory you control. Reuse the **same** key for the
owner and outsider HAR; otherwise object tokens cannot be matched.
Store original HARs with mode 0600 and never upload them to CI.

## Step 2 — import owner and outsider HARs safely

The input HARs must contain `log.entries` for a literal owned local
service. HTTP methods are GET/POST/PUT/PATCH/DELETE. Every request URL
must use the **same** canonical `http://127.0.0.1:PORT` origin. If
a captured browser fetched external resources, strip them from a
separate copy, then review why they were present before importing.
The import never makes a request.

```sh
BP=skills/bounty-pilot/scripts/bounty.py
python3 "$BP" web-workflow-capture \
  --har /private/bounty-run/owner.har.json \
  --origin http://127.0.0.1:8423 \
  --actor owner \
  --comparison-key-file /private/bounty-run/har-key.txt \
  --out /private/bounty-run/owner-capture.json

python3 "$BP" web-workflow-capture \
  --har /private/bounty-run/outsider.har.json \
  --origin http://127.0.0.1:8423 \
  --actor outsider \
  --comparison-key-file /private/bounty-run/har-key.txt \
  --out /private/bounty-run/outsider-capture.json
```

A route `GET /api/v1/orders/<opaque>` becomes a salted route
fingerprint plus `GET /api/v1/orders/:opaque`, HTTP status and a
matching **HMAC-derived** opaque object fingerprint. An HTTP 200 is
only a review lead. HMAC fingerprints are pseudonyms, not an
authorization policy or cryptographic proof of a browser session.

## Step 3 — create one self-contained campaign manifest

All required fields are shown below. The policy is the exact Phase 3
`web-program-policy` JSON object; `request_plan` is the array of
planned program requests. The owner and outsider captures are the
parsed JSON **contents** from Step 2, not file paths. Replace the
placeholders locally or use a short local script to assemble the
manifest offline. The policy example below is deliberately fictional
and is **not** an approved real-program scope.

```json
{
  "schema_version": 1,
  "environment": "researcher_owned_lab",
  "project": "my-owned-local-web-app",
  "source_revision": "ffffffffffffffffffffffffffffffffffffffff",
  "program_policy": {
    "schema_version": 1,
    "platform": "other",
    "program_id": "synthetic-owned",
    "status": "active",
    "source_url": "https://example.test/fictional-policy",
    "rules_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "reviewed_at": "2026-11-11T00:00:00Z",
    "expires_at": "2026-11-20T00:00:00Z",
    "include": [{
      "origin": "https://api.example.test",
      "path_prefix": "/sandbox",
      "actions": ["read-only"]
    }],
    "exclude": [],
    "required_headers": [],
    "operator_reviewed": true
  },
  "request_plan": [{
    "id": "plan-item-1",
    "url": "https://api.example.test/sandbox/orders",
    "action": "read-only",
    "provided_header_names": []
  }],
  "owner_capture": {"REPLACE": "full sanitized owner capture object"},
  "outsider_capture": {"REPLACE": "full sanitized outsider capture object"},
  "owner_only_route_keys": [],
  "static_analysis": null,
  "known_mechanisms": [],
  "budget": {
    "max_review_jobs": 5,
    "max_usd_per_job": 0.15,
    "max_usd_total": 0.6
  },
  "local_effect_fixture": null
}
```

`owner_only_route_keys` are explicit, operator-reviewed route
fingerprints whose underlying resources should be private. Without
them the engine does **not** label cross-actor 200s as an
authorization hypothesis.

For source-available JS/TS targets, `static_analysis` can be an
existing `web-ts-flow` JSON object, using a separately vetted
SHA-256-pinned parser. Its syntax leads remain unverified.

`known_mechanisms` can contain reviewed previous findings with
`project`, `revision`, `source_file`, `code_anchor`,
`invariant_id`, `trust_boundary_id`, `reviewed_by`,
`evidence_sha256` and `disposition` (only `known-duplicate` or
`refuted`). Matching is **strict and per revision**.

## Step 4 — deterministic review queue, no model calls

```sh
python3 "$BP" web-hunt-loop \
  --input /private/bounty-run/campaign.json \
  --out /private/bounty-run/campaign-dry.json
```

Output has the policy decision, sanitized cross-actor observations,
static flow counts, distinct review groups, reviewed suppression
reasons and cost-limited model/manual work orders. It is an explicit
review plan, not an actual provider invocation. A blocked policy
produces a `BLOCKED_POLICY_PLAN` report with no work orders and
a nonzero CLI exit status.

Use existing `agent_dispatch` to launch any desired isolated jobs;
review which model is selected, its provider-specific cost caps,
their source files and whether any secret-bearing artifacts enter
the agent context. The hunt loop does **not** dispatch models.

## Optional bridge to the existing Codex/Claude agent dispatcher

This bridge is the missing handoff from a Web candidate review queue to
the existing Bounty Pilot `agent_dispatch` machinery. First create
a **new private Bounty Pilot run** outside your local source checkout,
pinned to the same Git commit as the Web campaign:

```sh
python3 "$BP" init --repo /absolute/local/owned-source \
  --out /private/bounty-run/dispatch-run
```

Use the existing **unexecuted** campaign output from Step 4, with at
least one candidate and an explicit budget covering **two replicas**
per candidate. The bridge prepares immutable Markdown bundles and
calls `agent_dispatch.plan(..., mode="independent-blind")`. It does
not launch or authenticate a model:

```sh
python3 "$BP" web-dispatch-prepare \
  --campaign /private/bounty-run/campaign-dry.json \
  --run /private/bounty-run/dispatch-run \
  --replicas 2 \
  --include-source-excerpts
```

The local run's current HEAD must exactly match the campaign revision.
A Bounty run with an existing bundle manifest or dispatch plan is
rejected, instead of overwritten. Each candidate bundle contains its
source file, code anchor or pseudonymous route key, invariant and
required proof controls. No raw HAR/token/cookie/PII enters the bundle.
At most 24 independent jobs are prepared, with two or three separate
readings of each candidate. The optional `--include-source-excerpts`
flag permits the bridge to read at most 13 nearby source lines at each
pinned code anchor from a regular local file. It masks entire lines
that resemble credentials, passwords, tokens or keys and limits their
length. The default omits source code; **without excerpts an agent
can only assess the hypothesis metadata, not actual source code**.
A heuristic source redactor is not guaranteed to catch all sensitive
information. Inspect every generated bundle before executing any
agent job. The existing agent prompt forbids reading files outside
the supplied bundle.

Run actual model jobs only by independently choosing and explicitly
calling the existing `agent-dispatch run-job` command for each queued
job. Verify the available provider, model, cost controls and token
permissions first. For Claude, specify its native
`--max-budget-usd` per job. That limit is **not supported equally
by every provider**, so an offline planning ceiling is NOT a hard
billing cap. No actual model invocations, verification or payouts
are performed by `web-dispatch-prepare`.

## Step 5 — optional actual local proof

Only if the operator controls a disposable local fixture with
distinct candidate/negative-control routes, reuse the Phase 3
`web-effect-fixture-replay` plan as the
`local_effect_fixture` object. Then run:

```sh
python3 "$BP" web-hunt-loop \
  --input /private/bounty-run/campaign-with-owned-fixture.json \
  --out /private/bounty-run/campaign-with-local-effect.json \
  --execute-owned-fixture
```

The scope preflight must first pass. Execution is restricted to
literal `127.0.0.1` without redirects, proxies or credentials.
A demonstrated local scalar effect alone is **not** a live authorization
bypass. Ensure each test uses fresh independent fixture state.

## Step 6 — build a non-submittable evidence packet

The separate review statement must contain these exact keys:

```json
{
  "schema_version": 1,
  "project": "my-owned-local-web-app",
  "source_revision": "ffffffffffffffffffffffffffffffffffffffff",
  "candidate_id": "lead-from-the-campaign",
  "effect_case_id": "owned-effect-case",
  "reviewer_id": "reviewer-pseudonym",
  "reviewer_independent_asserted": false,
  "authorization_policy_evidence_sha256": "1111111111111111111111111111111111111111111111111111111111111111",
  "source_reachability_evidence_sha256": "2222222222222222222222222222222222222222222222222222222222222222",
  "effect_observation_evidence_sha256": "3333333333333333333333333333333333333333333333333333333333333333",
  "negative_control_evidence_sha256": "4444444444444444444444444444444444444444444444444444444444444444",
  "novelty_review_evidence_sha256": "5555555555555555555555555555555555555555555555555555555555555555",
  "deployed_state_reviewed": false,
  "independent_replay_asserted": false
}
```

These digest values are **examples**, not proof. Keep flags false
until real independent evidence exists. Review hashes are only
checked for shape and uniqueness; the tool cannot check whether
their underlying evidence really supports the assertion.

```sh
python3 "$BP" web-evidence-packet \
  --campaign /private/bounty-run/campaign-with-local-effect.json \
  --review /private/bounty-run/review-statement.json \
  --out /private/bounty-run/evidence-packet.json
```

The packet is clearly marked `ready_to_submit: false` and
`verified_production_vulnerability: false`. To submit an actual
bounty finding, independently examine program rules, live deployment,
victim impact, controls and duplicate status.

## Validation and remaining work

```sh
python3 -m unittest discover -s tests -p 'test_web_hunt_loop.py' -v
```

The tests include actual GET/empty POST/GET request sequences on a
researcher-owned ephemeral loopback server, HAR privacy checks,
cross-actor object matching, stale-policy gating, strict duplicate
suppression, spending ceilings, source-lead import and evidence review.

**Still not a 10/10 autonomous production hunter:** no live-program
workflow recorder with third-party permission negotiation, no
authenticated model executions in this integrated loop, no actual
hard USD caps across all providers, no instrumented independent
production exploit oracle and no 30–50-case paid-model unseen
A/B demonstration. The Mac native workflow must run on the user's
self-hosted runner before claiming native local verification.
