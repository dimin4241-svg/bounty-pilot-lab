# Native Web3 Evidence Capture + Historical Web Benchmark (Lab 0.48)

Two new tools are available. Neither claims a vulnerability has been independently proven.

## 1. Automated local native evidence collection

`web-native-capture` reuses the existing `scenario_runner` rather than inventing
a new subprocess executor. It runs one candidate and one negative-control
native test **twice**, checks that each recognized runner actually executed
and succeeded, extracts one structured JSON observation from each case,
computes SHA-256 over captured scrubbed command output, and checks that the
local Git HEAD and tracked source remain unchanged.

Native test code is untrusted code: **the collector does not sandbox network
or filesystem access**. Run only in an isolated disposable, secret-free
environment with networking blocked externally. The confirmation flags are
operator attestations, not isolation technology.

Example `/private/capture.json`, for a locally implemented fee-signing fixture:

```json
{
  "schema_version": 1,
  "source_revision": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "finding_id": "BP-501",
  "operation": "business-invariants",
  "environment": "native-local",
  "scenario": "fee-sign",
  "invariant": "Fee may not be negative under the protocol specification",
  "equivalence_basis": "Same local order, one controlled fee mutation",
  "runner_plan": {
    "finding_id": "BP-501",
    "cases": [
      {
        "id": "fee-candidate", "pair_id": "BP-501", "role": "candidate",
        "cwd": ".", "argv": ["python3", "-m", "unittest", "-v", "test_fee.NativeFee.test_negative"]
      },
      {
        "id": "fee-control", "pair_id": "BP-501", "role": "negative-control",
        "cwd": ".", "argv": ["python3", "-m", "unittest", "-v", "test_fee.NativeFee.test_positive"]
      }
    ]
  }
}
```

The tests must exist inside the pinned repository and print **exactly one**
line with the marker, with genuine assertions tied to their application:

```text
BP_NATIVE_OBSERVATION_V1 {"schema_version":1,"pair_id":"BP-501","role":"candidate","observation":{"order_id":"order-17","actor":"alice","fee_atomic":"-1","status":"accepted"}}
```

The control uses role `negative-control` and fee `1`. Do not include
`trace_sha256`; it is computed by the collector. A test may print fabricated
claims, so **native stdout is not a cryptographic attestation**, and the actual
test assertions and native source need an independent reviewer.

Supported checker operations: `business-invariants`, `signed-intent-mirror`,
`authz` and `wallet-intent`. Use bound_fields for signing operations and
scenario only for business. The output is compatible with existing Web3
differential engines.

Dry-run / validation without execution:

```sh
python3 skills/bounty-pilot/scripts/bounty.py web-native-capture \
  --config /private/capture.json --repo /isolated/disposable-checkout
```

Execute only inside an actual **externally network-isolated** disposable host
or container, with private evidence outside the checkout:

```sh
python3 skills/bounty-pilot/scripts/bounty.py web-native-capture \
  --config /private/capture.json --repo /isolated/disposable-checkout \
  --out /private/new-native-capture \
  --allow-exec --isolated-workspace-confirmed --network-isolated-confirmed
```

Outputs are create-only and private: `native-round-1.json`,
`native-round-2.json`, `native-observations.json`,
`differential.json` and `capture-manifest.json`. Failed, skipped, truncated,
wrong-revision, duplicate or inconsistent native observations are blocked.

## 2. Independent historical Web benchmark harness

The **evaluator-only published seed catalog** is at
`references/web-historical-seeds.json`. It contains three published findings
over two unrelated codebases, each pinned at immutable *affected* and *fixed*
Git commits. The full commit SHAs were resolved through GitHub official
release tag references:

| Case | Affected / fixed tag | Public advisory |
| --- | --- | --- |
| Next.js CVE-2025-29927 authorization middleware | 15.2.2 / 15.2.3 | GHSA-f82v-jwr5-mffw |
| CryptoJS CVE-2026-71851 weak random generation | 3.3.0 / 4.0.0 | GHSA-rg76-677x-56q9 |
| CryptoJS CVE-2023-46233 weak PBKDF2 defaults | 4.1.1 / 4.2.0 | GHSA-xwcq-pm8m-c4vf |

**Three public findings in two repositories are insufficient to prove
real-world discovery improvement.** A model may have seen them in training.
A reliable blind assessment requires a different evaluator, strict access
separation and genuinely unseen target issues. No independent model run has
been executed as part of this release.

### A. Prepare opaque assignments with separated answers

```sh
python3 skills/bounty-pilot/scripts/bounty.py web-history-bench prepare \
  --hunter-out /private/NEW-hunter-directory \
  --evaluator-out /separate-private/NEW-evaluator-directory
```

Only pass `NEW-hunter-directory/blind-queue.json` to the hunting model.
**Never pass the public seed file, evaluator answer map, this case table,
patched pairs, or advisory URLs** to a supposedly blinded agent.
The queue gives opaque IDs, pinned commits, repo URLs and equal time
budgets, with no vulnerability labels.

The tool does not download source. Clone source separately in a permitted
environment, verify its origin and then check each pinned local checkout:

```sh
python3 skills/bounty-pilot/scripts/bounty.py web-history-bench verify \
  --queue /private/NEW-hunter-directory/blind-queue.json \
  --task WB-<opaque-task-id> --repo /local/pinned-checkout
```

`verify` checks exact local Git HEAD, **not remote provenance**.

### B. Seal all search findings before showing any truth

Write `predictions.json` with one record for every task including those
with no findings:

```json
{
  "schema_version": 1,
  "tasks": [{
    "task_id": "WB-0123456789abcdef",
    "source_revision": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "findings": [{
      "id": "BP-501",
      "source_path": "exact/file.ts",
      "mechanism": "Precise source-grounded mechanism"
    }]
  }]
}
```

```sh
python3 skills/bounty-pilot/scripts/bounty.py web-history-bench seal \
  --queue /private/NEW-hunter-directory/blind-queue.json \
  --predictions /private/predictions.json \
  --evaluator /separate-private/NEW-evaluator-directory
```

The seal is create-only, cryptographically fingerprints all predictions
and refuses edits or missing tasks.

### C. Independently judge every claim, then score

An independent reviewer examines claims against the published root cause
and native evidence **only after sealing**, using a local `judgments.json`:

```json
{
  "schema_version": 1,
  "reviewer": "reviewer identifier",
  "judgments": [{
    "task_id": "WB-0123456789abcdef",
    "finding_id": "BP-501",
    "valid_match": true,
    "basis": "Primary advisory, exact source path and observed native assertion agree"
  }]
}
```

All claims require one review judgment. No already-fixed snapshot can
receive positive rediscovery credit for its known issue.

```sh
python3 skills/bounty-pilot/scripts/bounty.py web-history-bench score \
  --evaluator /separate-private/NEW-evaluator-directory \
  --judgments /separate-private/judgments.json
```

The report includes true-positive cases, misses, false positive claims,
duplicate claims, patched-control cleanliness and precision/recall.
Its label explicitly says the independent model run is **NOT attested**.
A/B comparisons require identical code budgets, model resource budgets,
sealed source snapshots and genuinely withheld final labels; source
locality and reviewer identity must be independently checked.

### Distinguish what was delivered from what was proven

- Implemented: two-round native transcript capture, pinned local source
  binding, SHA-256 evidence, strict observation parsing and offline
  case preparation / seal / independently supplied scoring.
- Not implemented: automatic EIP-712/ABI decoding, browser-based evidence
  extraction, cryptographic verification of target test assertions,
  independent remote source attestation or a paid model-based historical run.
- Future honest benchmark work requires real isolated target builds,
  pinned native regression tests and evaluation on previously unseen issues.
