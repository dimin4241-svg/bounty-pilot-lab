# Web Native Research — Phase 4 (owned fixtures + honest benchmarks)

This phase provides a bounded local integration bridge for installed
**CodeQL**, **Schemathesis**, **Playwright** and **HTTP Garden observation
imports**, plus a 40-pair synthetic detector regression and a strict
30–50 case historical-benchmark readiness check.

None of these tools certifies a finding or authorizes tests against the
public Internet. **Production Standoff 365 and BI.ZONE programs are not
exercised by these commands.** An operator-approved current program policy,
isolated owned fixture and independent effect/authorization evidence are
still required.

## 1. Shared launcher and execution gate

The unified CLI is:

```sh
BP=skills/bounty-pilot/scripts/bounty.py
python3 "$BP" web-native-toolchain --plan /private/plan.json \
  --out /private/native-dry.json
```

Dry-run is the default; it validates the full, bounded plan and writes a
private create-only artifact with status `PLAN_VALIDATED_NOT_EXECUTED`.
It does **not** contact a toolchain or API. To run a reviewed native
command against an **owned local fixture**, use `--execute` and a fresh
output path:

```sh
python3 "$BP" web-native-toolchain --plan /private/plan.json \
  --out /private/native-executed.json --execute
```

Every plan requires these fields:

```json
{
  "schema_version": 1,
  "mode": "schemathesis",
  "attestation": "I_CONTROL_THIS_LOCAL_FIXTURE",
  "max_seconds": 60
}
```

Add the mode-specific fields below. The owner attestation is a local
operator assertion, **not independently verified** by ChatGPT or GitHub.
The module drops inherited API keys and GitHub tokens, runs without a
shell and never persists raw native command logs. It does not create a
kernel-level network sandbox. Run every third-party executable in a
disposable, externally egress-restricted machine/container without
wallets, account tokens, private bug reports or secrets.

## 2. CodeQL JavaScript/TypeScript dataflow

Use installed `codeql` with a **trusted locally vetted** `.ql` or
`.qls` query outside the target checkout:

```json
{
  "schema_version": 1,
  "mode": "codeql",
  "attestation": "I_CONTROL_THIS_LOCAL_FIXTURE",
  "max_seconds": 180,
  "repo": "/absolute/path/to/owned/pinned-repository",
  "source_commit": "1111111111111111111111111111111111111111",
  "local_query": "/absolute/path/to/trusted/query.ql"
}
```

The bridge checks the exact Git HEAD and creates a temporary CodeQL
database using `--language=javascript-typescript --build-mode=none`,
then analyzes it using the supplied local query with SARIF v2.1.0
output. It retains bounded **rule ID + source path + line** information
only. CodeQL results are `STATIC_CODEQL_SIGNAL_UNVERIFIED`, not
confirmed taint, authorization bypass or exploitability. CodeQL might
normally resolve packs over the Internet; **prepare its query dependencies
offline** and independently restrict egress.

Official CLI references:
- <https://docs.github.com/en/code-security/reference/code-scanning/codeql/codeql-cli-manual/database-create>
- <https://docs.github.com/en/code-security/reference/code-scanning/codeql/codeql-cli-manual/database-analyze>

## 3. Schemathesis stateful Web/API testing

Only a JSON OpenAPI **3.x file within the owned fixture directory** is
accepted. No remote schema URLs, remote `$ref`, external servers,
webhooks or callbacks are supported. The bridge forcibly overrides the
base URL with literal `127.0.0.1`, caps generated examples at ten,
runs one worker and disables redirects/retries.

```json
{
  "schema_version": 1,
  "mode": "schemathesis",
  "attestation": "I_CONTROL_THIS_LOCAL_FIXTURE",
  "max_seconds": 60,
  "origin": "http://127.0.0.1:8080",
  "fixture_dir": "/absolute/owned/lab",
  "openapi_file": "/absolute/owned/lab/openapi.json",
  "seed": 17,
  "max_examples": 4,
  "phases": "stateful"
}
```

The installed CLI is invoked as `st run <local-file> --url
http://127.0.0.1:PORT --phases stateful --max-examples 4` plus
deterministic, sanitized and bounded options. It emits a private local
JSON report; the bridge deliberately stores only its SHA-256 digest,
tool return status and size, not potentially sensitive raw responses.
A failing Schemathesis assertion is a lead, not a bounty report.
**Use a disposable fixture with isolated account state**, not a
staging/production endpoint.

Current documentation:
<https://schemathesis.readthedocs.io/en/latest/reference/cli/>.

## 4. Playwright browser isolation and visible effect signals

Install Playwright into a separate, trusted `node_modules` directory,
**outside source under review**. Install Chromium in that isolated tool
environment. The launcher only accepts one literal `127.0.0.1` origin,
two distinct local fixture pages, and a simple CSS `#id` selector:

```json
{
  "schema_version": 1,
  "mode": "playwright",
  "attestation": "I_CONTROL_THIS_LOCAL_FIXTURE",
  "max_seconds": 60,
  "origin": "http://127.0.0.1:8080",
  "owner_path": "/owner/state",
  "outsider_path": "/outsider/state",
  "scalar_selector": "#entitlement",
  "browser_module": "/absolute/isolated/node_modules"
}
```

Each owned page may expose a single scalar, e.g.:

```html
<span id="entitlement" data-bp-scalar="2"></span>
```

The fixed trusted script launches headless Chromium, opens separate
browser contexts with service workers blocked and downloads disabled,
and **aborts every browser request outside the exact loopback origin**.
It records only numeric scalar values, presence, HTTP status and the
count of blocked external requests. It does not execute JavaScript
specified in the plan, persist cookies, save DOM/response bodies,
claim that two pages represent authenticated roles, or prove XSS.
Actual role authorization still requires separately verified fixture
identity and an independent authorization policy.

## 5. HTTP Garden

HTTP Garden relies on Docker/Linux and exposes an interactive REPL;
automatic container builds and arbitrary probe execution are
**not enabled** by this bridge. Use its own isolated local installation
to collect paired **owned-lab** parser observations with a distinct
negative control. Save those observations in the existing
`web-http-boundary` format; then import them with:

```json
{
  "schema_version": 1,
  "mode": "http-garden-import",
  "attestation": "I_CONTROL_THIS_LOCAL_FIXTURE",
  "max_seconds": 30,
  "garden_checkout": "/absolute/pinned/http-garden",
  "garden_commit": "2222222222222222222222222222222222222222",
  "observation_file": "/private/owned-parser-observations.json"
}
```

The exact Garden Git HEAD is checked. The import calls the existing
parser-boundary comparator, preserving its candidate/control distinction.
It does **not** independently prove that the observations came from
the pinned Garden implementation. It performs **zero** HTTP/Docker
requests and never generates request-smuggling payloads.

Upstream installation reference:
<https://github.com/narfindustries/http-garden>.

## 6. 40 paired synthetic detector regressions

```sh
python3 "$BP" web-benchmark-regression \
  --out /private/web-regression-40.json
```

This executes the real local deterministic engines from Phase 3:
ten actor authorization cases, ten business-effect cases, ten browser
trust cases and ten URL parser cases. Each has a positive and a
negative-control snapshot: **40 related case pairs / 80 observations**.

This is regression coverage only. The cases are parameterized synthetic
variants of four families, **not 40 independent historical bugs**;
zero agents are launched and no measured improvement in bug bounty
payouts can be inferred. The result reports missed fixture leads and
false-positive controls. Native Node is required for the URL cases.

The regression also runs in CI against fixed synthetic fixtures, but
real research/tool runs belong on the operator-controlled Mac runner.
The optional `web-native-mac.yml` workflow is manual-only and uses
`[self-hosted, macOS]`; it never runs production target scans.

## 7. Real historical A/B benchmark readiness

The existing public Web history catalog contains **three** source
pinned historical cases. A meaningful public historical study would
need many more case families, independent pre-fix/post-fix revision
replays, a separate evaluator, controls and fixed cost/time settings.
Do not substitute synthetic cases into the historical catalog.

```sh
python3 "$BP" web-benchmark-readiness \
  --catalog skills/bounty-pilot/references/web-historical-seeds.json \
  --evaluator-reviews /private/independent-review-evidence.json \
  --out /private/historical-readiness.json
```

The evaluator-only evidence input has:

```json
{
  "schema_version": 1,
  "reviewer_role": "external_independent_reviewer",
  "cases": [
    {
      "id": "EXACT-CATALOG-ID",
      "reproduced_vulnerable_sha256": null,
      "reproduced_patched_sha256": null,
      "revision_chain_checked": false,
      "distinct_negative_control": false,
      "reviewer_id": "reviewer-opaque-id",
      "independent_review_asserted": false
    }
  ]
}
```

Replace `null` and `false` only after independent local testing.
The gate requires **30–50** cases, at least **5 distinct repositories**,
at least **5 mechanism families**, and separately supplied evidence for
both affected and corrected versions of every case. Even when those
requirements are met, attestations remain operator-supplied, not
cryptographically verified. The gate never claims a truly unseen
holdout or a public uplift result.

Use the existing `web-bench-ab` for preparing paired opaque tasks,
sealed predictions, independent reviews and matched model spending.
Do **not** run an AI cost benchmark without actual model access,
independent historical truth and isolated agent/evaluator workspaces.

## 8. Practical next steps on the Mac runner

1. Pull `main`; inspect the installed CodeQL, Schemathesis,
   Playwright, Node, Git and Docker versions. Do not blindly upgrade
   or run unvetted installs in the target checkout.
2. Run `web-benchmark-regression`; retain a private result fingerprint.
3. Install/verify each native tool into its own disposable, pinned
   environment; prepare a self-owned browser/API test service.
4. Run `web-native-toolchain` first without `--execute`; inspect
   the exact plan and local source/URL restrictions.
5. Only after external network isolation is configured, perform
   local `--execute` runs, compare observations against independent
   controls and use `web-root-cause-dedup`.
6. Add independently checked public cases over time; use historical
   readiness before starting an expensive model A/B study.

Limits: no background work, no current active program enumeration,
no independently verified 30–50 source-pinned real historical cases,
no deployed Web exploit proof, no validated payout improvement.
