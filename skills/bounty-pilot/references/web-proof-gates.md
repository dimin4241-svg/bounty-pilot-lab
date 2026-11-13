# Web proof gates — offline argument binding and specification mapping

Two deterministic, **non-attesting** preflights for Android/Web/API research:
`web-evidence-gates argument-binding` and `web-evidence-gates spec-implementation`.
Neither sends requests, executes target code or claims a vulnerability.

## 1. Argument-binding

Before ranking a Retrofit/HTTP candidate, read the *declaration annotation per
parameter*, the exact call argument order, the source of the URL and headers
and the possible forms of the dynamic URL. Do not infer that changing a
`baseUrl` changes the recipient of a request with an absolute `@Url`.

Example offline manifest, stored privately (replace hashes, lines and revision
with values from the exact local checkout):

```json
{
  "schema_version": 1,
  "source_revision": "PUT_ACTUAL_40_HEX_GIT_HEAD_HERE",
  "cases": [{
    "id": "fixture-1",
    "method": {
      "name": "a", "syntax": "java",
      "declaration": {
        "path": "src/Api.java", "line": 2, "span": 1,
        "text": "@GET", "sha256": "PUT_ACTUAL_SHA256_OF_ENTIRE_FILE_HERE"
      }
    },
    "invocation": {
      "path": "src/Caller.java", "line": 8, "span": 1,
      "text": "api.a(", "sha256": "PUT_ACTUAL_SHA256_OF_ENTIRE_FILE_HERE"
    },
    "claim": {"header": "Cookie"},
    "url_examples": [
      {"label": "absolute", "value": "https://server.example/result"},
      {"label": "relative", "value": "/rs/api"},
      {"label": "empty", "value": ""}
    ]
  }]
}
```

```sh
BP=skills/bounty-pilot/scripts/bounty.py
python3 "$BP" web-evidence-gates argument-binding \
  --repo /isolated/pinned-source --input /private/binding.json \
  --out /private/binding-result.json --gate
```

The parser covers simple Java Retrofit annotations and limited Smali
`.method` with ordered `.param p1` / `.end param` annotations. A Smali call
must use explicit `invoke-interface` or `invoke-virtual` registers. Unresolved
overloads, Kotlin compiler transformations, Smali ranges, indirection,
interceptors and redirects require manual review; do not silently fill gaps.

The gate pins full-file SHA-256 and exact line excerpts, checks the annotated
method position and reads call argument expressions/registers. It models URL
*forms*, not production URL values:

- `dynamic`: absolute HTTP(S) or protocol-relative `//host/path`; URL
  determines host independently of the base.
- `base`: root-relative `/path`, relative `path` and empty string; host
  inherited from base.
- `unknown`: unsupported or ambiguous URL.

A native OkHttp check is still required for edge cases. The status is
`DESTINATION_CLAIM_CONTRADICTED` for all modeled dynamic values,
`CONDITIONAL_ROUTING_ONLY` for mixed/unknown examples,
`STATIC_ROUTING_ONLY` when all examples inherit the base, or
`BLOCKED_UNRESOLVED_BINDING` for invalid source mapping.

These are **routing leads**, not proof of runtime reachability, header value,
simultaneous session state, actual request, sensitivity or impact. Even when
`--gate` exits zero for `STATIC_ROUTING_ONLY`, production remains unverified.

## 2. Specification-to-implementation

Before writing a business invariant, classify its origin:
`SPEC_CONFIRMED`, `DESIGN_INFERRED` or `RESEARCH_HYPOTHESIS`. A historical
document can be precisely quoted without proving that current production
still obeys that specification.

Input example:

```json
{
  "schema_version": 1,
  "source_revision": "PUT_ACTUAL_40_HEX_GIT_HEAD_HERE",
  "cases": [{
    "id": "fixture-1",
    "requirement": {
      "type": "SPEC_CONFIRMED", "version": "1.5",
      "anchor": {
        "path": "requirements.txt", "line": 12,
        "text": "Only an authorized",
        "sha256": "PUT_ACTUAL_SHA256_OF_ENTIRE_DOCUMENT_HERE"
      }
    },
    "implementation": {
      "anchor": {
        "path": "src/Decision.java", "line": 37,
        "text": "finalizeDecision",
        "sha256": "PUT_ACTUAL_SHA256_OF_ENTIRE_SOURCE_FILE_HERE"
      }
    }
  }]
}
```

```sh
python3 "$BP" web-evidence-gates spec-implementation \
  --repo /isolated/pinned-source \
  --documents /private/pinned-documents \
  --input /private/spec-mapping.json \
  --out /private/spec-result.json
```

Keep page number, document origin and publication date in separate private
review notes. The tool verifies the transcribed text anchor, not the
authenticity of the underlying original PDF/website.

A case optionally contains an `experiment` with `source_revision` matching
the checkout and `candidate` / `control` objects. Each receipt references
a **different local file** relative to `--evidence /private/receipts`, with
`file`, `sha256`, `executed: true` and `exit_code: 0`. These are
**investigator-supplied** flags and bytes: the tool does *not* authenticate
execution, control quality or assertion semantics.

Statuses:
- `SPEC_SOURCE_LINK_ONLY`: anchored specification and code; no pair.
- `REVIEW_PACKET_UNAUTHENTICATED`: distinct hashed candidate/control receipts
  attached; human semantic review still required.
- `HYPOTHESIS_NOT_SPEC` / `HYPOTHESIS_WITH_RECEIPTS`: unconfirmed requirements
  remain hypotheses regardless of receipts.
- `BLOCKED_MISSING_EVIDENCE`: missing/stale anchors, identical receipts, etc.

The `--gate` flag succeeds only for every case in
`REVIEW_PACKET_UNAUTHENTICATED`, but **never** marks a vulnerability
confirmed or submission-ready.

## Cross-cutting constraints

- All inputs local; read-only pinned Git HEAD, normal UTF-8 files, full-file
  digests and exact line excerpts; no symlink traversal or target traffic.
- Outputs are new, private files outside the checkout/documents/receipts;
  never commit private target material, real tokens, HARs or reports.
- Tool output includes only IDs, syntax argument labels and evidence status.
- Independent native candidate and negative control, exact deployed-version
  correspondence, authorized scope, source integrity, and adversarial review
  are still required for actual severity or report readiness.
- Neither a green `--gate` nor a model confidence score establishes a flaw.

Run synthetic regression tests with:

```sh
python3 -m unittest discover -s tests -p 'test_web_evidence_gates.py' -v
```
