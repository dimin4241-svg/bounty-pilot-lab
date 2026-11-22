# Fast Hunt: small source queue, shared anomalies, controlled HTTP observations

This opt-in helper deliberately avoids the full multi-lens cycle for an initial
reading. It is **not a standalone autonomous AI hacker**, and the source cues
are neither semantic proofs nor vulnerabilities. The operator remains responsible
for reviewing scope, accounts, side effects and any report.

## 1. Rapid, offline source triage (no model, no network)

```sh
BP=skills/bounty-pilot/scripts/bounty.py
REV=$(git -C /absolute/pinned-target rev-parse HEAD)
python3 "$BP" fast-hunt plan \
  --repo /absolute/pinned-target --scope src \
  --max-files 80 --max-leads 24 \
  --out /absolute/private/fast-queue.json
```

The output ranks syntactic risk cues with real file/line anchors, SHA-256 of
each source line, guard/entry cues and an explicit count of uninspected files.
No source lines, secrets, target response bodies or credentials enter the queue.
A missing nearby guard **does not imply** a missing authorization check.
Prioritize leads for human review and send *only selected* ones through the
existing pinned bundle, independent agent review, native PoC and negative
control workflow. Do not mark records verified just because a cue fired.

## 2. Lightweight, shared cross-lens anomaly memory

Create an operator-reviewed JSON array of observations (never paste live
tokens or sensitive responses). Each observation must have exactly these keys:

```json
[
  {
    "path": "src/Token.sol",
    "line": 57,
    "kind": "ACCOUNTING",
    "note": "Fee accounting may diverge after nested callback",
    "evidence_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "observed_by": "accounting"
  }
]
```

Valid kinds: AUTHZ, ACCOUNTING, TRUST, STATE, OTHER. The hash should come
from the exact evidence captured independently by the operator, not from
an LLM assertion.

```sh
python3 "$BP" fast-hunt merge \
  --revision "$REV" --observations /absolute/private/observations.json \
  --out /absolute/private/anomalies-v1.json

# After a composition lens adds more observations:
python3 "$BP" fast-hunt merge \
  --revision "$REV" --previous /absolute/private/anomalies-v1.json \
  --observations /absolute/private/composition.json \
  --out /absolute/private/anomalies-v2.json

python3 "$BP" fast-hunt plan --repo /absolute/pinned-target --scope src \
  --anomalies /absolute/private/anomalies-v2.json \
  --out /absolute/private/fast-with-shared-context.json
```

The merge is create-only, deterministic, carries weak observations forward,
and marks nearby observations from different lenses for **review**, not exploit
confirmation. It refuses different source revisions.

## 3. Bounded, reviewed GET/HEAD execution

`fast-hunt probe` can automatically execute **1–8 explicitly listed GET/HEAD
requests**, serially, on an operator-owned loopback server or on a
program-approved, exact public HTTPS origin. The dry run is the default.
It **never** follows redirects or reads additional paths, performs logins,
submits reports or asserts that HTTP 200 is an IDOR.

For an owned local service listening on `127.0.0.1:8765`, save this manifest
as `/absolute/private/local-probe.json`:

```json
{
  "schema_version": 1,
  "environment": "owned-loopback",
  "acknowledgement": "I_CONTROL_THIS_LOCAL_FIXTURE",
  "origin": "http://127.0.0.1:8765",
  "pinned_ip": "127.0.0.1",
  "program_policy": null,
  "requests": [
    {
      "id": "baseline",
      "method": "GET",
      "url": "http://127.0.0.1:8765/health",
      "headers": {}
    }
  ],
  "timeout_seconds": 3,
  "max_response_bytes": 32768
}
```

```sh
python3 "$BP" fast-hunt probe --manifest /absolute/private/local-probe.json \
  --out /absolute/private/dry.json

# Only after operator review:
python3 "$BP" fast-hunt probe --manifest /absolute/private/local-probe.json \
  --execute --out /absolute/private/observations.json
```

For a real public bug bounty: change `environment` to `approved-public`,
set `acknowledgement` to
`I_HAVE_REVIEWED_CURRENT_RULES_AND_TARGET_IP`, specify an exact HTTPS origin
without port or wildcard, supply the **operator-reviewed public IPv4 address**
in `pinned_ip`, and supply a fresh `web-program-policy` snapshot with
`operator_reviewed:true`, exact included paths, actions `read-only`,
exclusions and required header names. Do not use the values in this document
as authorization for a real target. `X-Bug-Bounty` header value can be passed
for programs that require it. No authorization/cookie header is accepted:
this version does not perform authenticated cross-account tests.

Safety properties: HTTPS connects to the **pinned IP** with SNI/certificate
verification for the approved hostname (no DNS rebinding and no implicit
proxy settings); exact origin/path and saved policy are rechecked before a
socket is opened; methods are GET/HEAD only; timeouts, response sizes and
request count are bounded; only SHA-256, lengths and statuses are stored.
Redirects are observed as 3xx but are **never followed**. Query strings,
userinfo, encoded ambiguous paths, arbitrary headers, local/private targets
in public mode, and mixed-case duplicate headers are blocked. No response
bodies are retained or forwarded to a model.

**Important limits:** GET can cause side effects on a poorly designed server.
An approved origin and an offline policy snapshot are not permission: manually
review every exact path before `--execute`. This module is not an
OS-level network firewall, does not execute arbitrary shell/LLM-generated
requests, and cannot by itself prove account boundary violations. For
authenticated multi-actor PoCs, use operator-owned fixtures and existing
`web-effect-fixture-replay`/native candidate-control flows; any live
authorization test needs a separately approved and enforced tool boundary.

## Evidence tiers and next stage

- `UNVERIFIED_SOURCE_READING_LEAD` — regex cue only
- `UNVERIFIED_HTTP_OBSERVATION` — one exact, permission-reviewed live response
- `locally reproduced` — paired positive/negative native PoC on owned fixture
- `production-equivalent` — independently pinned deployment/runtime assumptions
- `verified` — evidence and program-specific eligibility adjudicated independently

No automatic status promotions. A response digest or local PoC is not a
guarantee of impact or bounty eligibility.

For comparative evaluation, use the existing sealed `backtest` and
`benchmark-protocol.md` with held-out historical findings, equal model
and request budgets, and a separately scored judge. This helper's own
synthetic tests are not evidence of finding real High/Critical vulnerabilities.
