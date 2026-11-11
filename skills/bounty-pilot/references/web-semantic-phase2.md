# Web Semantic Research — Phase 2 (experimental)

This phase extends Web Invariant Research with **cross-file JavaScript/TypeScript
syntax-flow leads**, **offline HTTP parser boundary comparison** and **sealed,
paired Web benchmark accounting**.

None of the three is a production scanner or an exploit engine. No published
research, payout uplift, or novel vulnerability detection is claimed.

## 1. Cross-file JS/TS route-to-sink argument traces

The previous `web-ts-ast` tool inventoried routes in individual files. The
new `web-ts-flow` loads a bounded set of source files into a pinned TypeScript
AST parser. It recognizes selected Express/Fastify and Next.js App Router
routes, exported functions, simple ESM relative named imports, function call
arguments, and basic local variable aliases.

It follows potential request arguments through a limited chain of imported
functions to operations such as database writes, transfers, refunds and
queries. Outputs are **static syntactic leads**, not precise executable
dataflow, verified guards, taint proof, SQL injection, IDOR or loss.

Example local, explicit source checkout and independently vetted compiler:

```sh
BP=skills/bounty-pilot/scripts/bounty.py
npm install --prefix /isolated/bp-ts-parser --ignore-scripts --no-audit --no-fund --save-exact typescript@5.9.3
TS_LIB=/isolated/bp-ts-parser/node_modules/typescript/lib/typescript.js
TS_SHA=$(shasum -a 256 "$TS_LIB" | awk '{print $1}')

python3 "$BP" web-ts-flow \
  --repo /isolated/pinned-target-source \
  --scope src --typescript-parser "$TS_LIB" --parser-sha256 "$TS_SHA" \
  --out /private/web-ts-flow.json
```

Treat the TypeScript compiler as executable third-party tooling: vet its
package and digest. Use a disposable, externally network-isolated host with
no secrets. All target source stays on local stdin; it is parsed, not
imported/evaluated, and is never written into output JSON.

At most 120 JS/TS source files and 4 MB of content are inspected per run,
with file and parser time limits. Excluded and oversized files are reported.
Source budgets fail closed rather than silently capping the result set.
The output includes actual route-to-call-chain file/line anchors, apparent
middleware and guard-name cues, source SHA fingerprints and unresolved routes.

Known gaps: class or object dispatch, namespace/CommonJS imports, server
framework inherited guards, request-to-return taint, spread/destructuring,
sanitizer proof, actual DB side effects, full type-checker program
analysis and runtime reachability. **A missing guard-name cue is not evidence
of broken authorization.**

## 2. HTTP frontend/backend parser observation comparison

`web-http-boundary` consumes two parser observations of the **same saved
synthetic input** and a separate negative-control input from a privately
owned, isolated laboratory. It does not send raw HTTP traffic.

It compares request counts and byte boundaries, canonical route and
authority, explicit authorization context, cache key and body digest. All
fields are investigator supplied. The tool rejects different input hashes,
unmatched parser builds, malformed captures and candidate/control
disagreements that invalidate promotion.

Private paired-observation format:

```json
{
  "schema_version": 1,
  "environment": "researcher_owned_isolated_lab",
  "pairs": [{
    "pair_id": "local-case-1",
    "candidate": {
      "front": {
        "parser_id": "front", "parser_build": "owned-front-v1",
        "input_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "request_count": 1, "consumed_bytes": 42,
        "requests": [{
          "start_offset": 0, "end_offset": 42,
          "method": "GET", "canonical_route": "/fixture",
          "authority": "fixture.invalid", "auth_context": "owned-a",
          "cache_key": "owned-a-fixture", "body_sha256": null
        }]
      },
      "back": {
        "parser_id": "back", "parser_build": "owned-back-v1",
        "input_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "request_count": 1, "consumed_bytes": 43,
        "requests": [{
          "start_offset": 0, "end_offset": 43,
          "method": "GET", "canonical_route": "/fixture",
          "authority": "fixture.invalid", "auth_context": "owned-a",
          "cache_key": "owned-a-fixture", "body_sha256": null
        }]
      }
    },
    "negative_control": {
      "front": {
        "parser_id": "front", "parser_build": "owned-front-v1",
        "input_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "request_count": 0, "consumed_bytes": 0, "requests": []
      },
      "back": {
        "parser_id": "back", "parser_build": "owned-back-v1",
        "input_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "request_count": 0, "consumed_bytes": 0, "requests": []
      }
    }
  }]
}
```

```sh
python3 "$BP" web-http-boundary \
  --input /private/paired-parser-observations.json \
  --out /private/http-boundary-review.json
```

The output intentionally omits raw request payloads, auth identifiers, path
values and response bodies. It contains only disagreement categories, status
and capture digests. Its strongest status is
`CONTROLLED_PARSER_DIFFERENCE_IN_SUPPLIED_TRACES`, **not** a confirmed HTTP
smuggling exploit. Any production test needs program-specific written
permission; this tool does not implement such testing.

## 3. Paired, evaluator-separated historical benchmark

The existing `web-history-bench` supports opaque task preparation,
sealed predictions, and independently supplied judgments. New
`web-bench-ab` coordinates two arms against the **same** opaque source
snapshots and adds fixed per-task time/spend bounds and recorded token costs.

Create a private config:

```json
{
  "schema_version": 1,
  "model_id": "MODEL_ID_USED_FOR_BOTH_ARMS",
  "baseline_skill_revision": "1111111111111111111111111111111111111111",
  "candidate_skill_revision": "2222222222222222222222222222222222222222",
  "max_usd_per_task": 1.0,
  "max_seconds_per_task": 3600
}
```

Replace placeholder SHAs and model ID with actual immutable revisions,
then prepare **only on an isolated evaluator machine**:

```sh
python3 "$BP" web-bench-ab prepare \
  --config /private/experiment.json \
  --catalog skills/bounty-pilot/references/web-historical-seeds.json \
  --out-dir /private/web-ab-20261110
```

Deliver only the corresponding `baseline/hunter/blind-queue.json`
or `candidate/hunter/blind-queue.json` task packets to separate agents.
**Do not give an agent access to evaluator folders, the seed catalog, the
other arm's output, or any answer key.** The benchmark program does not
enforce filesystem or process isolation; configure it externally.

For each arm, follow existing `web-history-bench seal` on that arm's
evaluator folder. Supply independently reviewed `judgments.json` files.
Prepare separate spend logs covering every opaque task ID, including
failed tasks:

```json
{
  "schema_version": 1,
  "model_id": "MODEL_ID_USED_FOR_BOTH_ARMS",
  "tasks": [{
    "task_id": "WB-0000000000000000",
    "spent_usd": 0.15, "elapsed_seconds": 600,
    "input_tokens": 12000, "output_tokens": 3000
  }]
}
```

```sh
python3 "$BP" web-bench-ab compare \
  --study /private/web-ab-20261110 \
  --baseline-judgments /private/baseline-review.json \
  --candidate-judgments /private/candidate-review.json \
  --baseline-spend /private/baseline-spend.json \
  --candidate-spend /private/candidate-spend.json \
  --out /private/web-ab-evaluation.json
```

The comparison validates identical task queues, intact sealed
predictions, complete independent adjudication documents, identical model ID,
and per-task spending/time limits. The report includes TP, FN, false claims,
patched-control results, budget, time and USD per true positive, with zero
rediscovery reported truthfully as zero.

**No benchmark or model has been run by this release.** The built-in
historical corpus currently has only three public cases from two repositories.
That is too small and too contamination-prone to demonstrate Web bug-bounty
uplift. The comparison always sets `public_uplift_claim_allowed=false` until
independent holdout provenance, evaluator isolation, real model execution
and a larger, varied corpus can actually be verified.

## 4. Testing

```sh
python3 -m unittest discover -s tests -p 'test_web_ts_flow.py' -v
python3 -m unittest discover -s tests -p 'test_web_http_boundary.py' -v
python3 -m unittest discover -s tests -p 'test_web_bench_ab.py' -v
```

The TypeScript native AST integration test additionally requires
`BP_TYPESCRIPT_PARSER` pointing to the locally pinned compiler file.
The other tests use only synthetic local fixtures and saved JSON observations.
