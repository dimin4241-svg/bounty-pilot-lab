# Autonomous Fast Hunt — adaptive two-account local proof

This is a **bounded, experimental owned-lab feature**. It runs a real sequence
of HTTP requests with two operator-controlled identities, uses an optional
OpenAI-compatible LLM (including DeepSeek via an operator-provided endpoint)
to choose which **pre-approved case ID** to try next, and automatically
repeats a potential owner-only read with negative controls. It does not log in
to a real website by itself, generate unreviewed URLs, bypass a production
scope, discover arbitrary paths, make writes, or produce a bounty report.

## What actually runs

1. Validate an exact operator-owned `127.0.0.1` origin, two distinct
   environment-held test credentials, a small list of **explicit owned**
   resource paths and a hard request/model budget.
2. For each case, read each actor's own synthetic private marker. Markers are
   hashed immediately and never saved or sent to a model.
3. Choose the next reviewed case ID using a deterministic heuristic or the
   operator's OpenAI-compatible model. The model sees only case IDs, status
   codes and Boolean comparison flags, not raw paths, bodies, cookies or keys.
4. Read the owner resource as the other controlled account. If the result
   matches the owner's private marker, repeat the cross-account request.
5. Also verify that an anonymous request and a missing synthetic object
   are denied; re-read the owner baseline. Only a repeatable, controlled
   candidate/control difference becomes `OWNED_FIXTURE_CROSS_ACTOR_READ_REPRODUCED`.
6. Record status codes, SHA-256 witness hashes, counts and limitations.
   `confirmed_production_vulnerabilities` remains **0** in every outcome.

## Minimal manifest

First deploy your own disposable web fixture on `127.0.0.1:18766` with
two **distinct, owned accounts** and two **distinct, owned objects**:

```json
{
  "schema_version": 1,
  "environment": "researcher_owned_loopback",
  "ownership_attestation": "I_CONTROL_BOTH_TEST_IDENTITIES_AND_FIXTURE",
  "origin": "http://127.0.0.1:18766",
  "actors": {
    "owner": "BP_LAB_OWNER_TOKEN",
    "outsider": "BP_LAB_OTHER_TOKEN"
  },
  "cases": [
    {
      "id": "owned_invoice",
      "owner_path": "/api/test/invoices/owned-a",
      "outsider_path": "/api/test/invoices/owned-b",
      "missing_path": "/api/test/invoices/unknown",
      "marker_field": "canary",
      "expected_policy": "owner-only"
    }
  ],
  "limits": {
    "max_http_requests": 8,
    "max_llm_calls": 0,
    "max_cases_checked": 1,
    "timeout_seconds": 2,
    "max_response_bytes": 4096
  },
  "decision_engine": {"kind": "heuristic"}
}
```

Each fixture response must be a JSON object containing an intentionally
synthetic, stable string `canary` field. Real personally identifying
data, API secrets or payment tokens must never be used as markers.
Paths are **operator-reviewed**; no route scanning is performed.
For bearer auth, define two environment variables before starting:
`BP_LAB_OWNER_TOKEN` and `BP_LAB_OTHER_TOKEN`, each containing
the appropriate fixture's private session token. They are never stored
in the plan or output file. Do not embed credentials in the manifest.

For fixture apps that use a single cookie, add:

```json
"auth": {"mode": "cookie", "cookie_name": "pilot_session"}
```

The cookie value still comes from the two environment variables. This
does not enable browser interaction, redirects or CSRF operations.

## Execute only after reviewing the exact local plan

```sh
S=skills/bounty-pilot/scripts/bounty.py
python3 "$S" fast-hunt-agent --manifest /private/owned-plan.json \
  --out /private/dry.json

python3 "$S" fast-hunt-agent --manifest /private/owned-plan.json \
  --execute-owned --out /private/owned-replay.json
```

Output is create-only and mode `0600`. Dry run makes zero requests.
Each JSON evidence file is unverified, not submission-ready. Tests intentionally
include a vulnerable local fixture and a corrected variant to catch false positives.

## Optional DeepSeek / Model Gate adapter

To enable adaptive scheduling, set the decision engine to:

```json
"decision_engine": {
  "kind": "openai-compatible",
  "endpoint": "https://YOUR-APPROVED-PROVIDER.example/v1/chat/completions",
  "model": "deepseek-v4.1-flash",
  "api_key_env": "BP_LLM_API_KEY"
}
```

Set `BP_LLM_API_KEY` in the operator's **process environment**, not in
manifest, GitHub or shell logs. The endpoint must be the actual
OpenAI-compatible `/v1/chat/completions` endpoint. A local test provider may
use `http://127.0.0.1:PORT/v1/chat/completions`; a non-loopback provider must
use HTTPS. The two actor secrets are never included in model messages.
No model tools/functions are enabled. The model's JSON is validated strictly
against the remaining case IDs, so it **cannot choose target URLs, methods,
headers, cookies or arbitrary shell commands**. Total LLM calls are capped.

**Model limits:** the client requests only a small completion. A configured
call-count cap is not a provider-side spend guarantee. Use provider limits
to enforce spend and avoid sharing any real user data with a model.

## Relationship to Fast Hunt and real bug bounty targets

Use `fast-hunt plan` to rank pinned source cues, `fast-hunt merge` to
carry independent observations, and `fast-hunt-agent` to run the
owned-fixture candidate/control experiment. For a public program, continue
using the separate `fast-hunt probe` with a manually reviewed current
scope, public pinned IP and pre-approved **unauthenticated** GET/HEAD requests.
The two-actor autonomous runner **deliberately does not target public hosts**.

Treat an owned synthetic reproduction as a local mechanism test, not proof
that an external deployment is affected. Real on-site IDOR/BOLA verification
requires explicit program permission, two operator-owned accounts and objects,
live scope enforcement, isolated execution, separate human review, and evidence
from the actual relevant production or sanctioned sandbox deployment.
