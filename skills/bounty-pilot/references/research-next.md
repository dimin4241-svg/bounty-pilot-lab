# Research Next (Lab 0.42): test-native, spec-to-code, variants and evidence memory

These four opt-in capabilities extend existing AVRE, ecosystem intelligence and
Evidence-First. They are not an autonomous exploit finder and do not change the
definition of a `verified` finding.

## 1. Map documented requirements to candidate enforcement paths

Create a private `spec.json` with real documentation quotes and scoped code
symbols. Every quote MUST match the exact checked-out documentation line:

```json
{
  "schema_version": 1,
  "requirements": [{
    "id": "REQ-001",
    "source_path": "docs/security.md",
    "source_line": 18,
    "quote": "Claims must not be executed twice",
    "symbols": ["claim", "usedNonce", "verify"],
    "code_scope": ["src/"]
  }]
}
```

```sh
python3 skills/bounty-pilot/scripts/bounty.py research-next spec \
  --repo /disposable/local-checkout --spec /private/spec.json
```

The scanner checks only tracked, explicitly scoped files, verifies the
document quote at its line and returns symbol-hit paths, line numbers and
SHA-256 evidence fingerprints. A symbol hit is NOT proof of enforcement;
missing symbols are NOT proof of a bypass. Follow every candidate with
real control-flow review and native negative-control tests.

## 2. Run paired native tests twice with real runner detection

Reuse `experimenter.plan`, `native_fuzz_plan.py` and
`scenario_runner.py`. You supply existing candidate/control tests with
assertions, a full pinned checkout commit and a documented invariant:

```json
{
  "finding_id": "BP-123",
  "source_revision": "REPLACE_WITH_THE_40_HEX_CHECKOUT_HEAD",
  "invariant": "Unauthorized callers cannot withdraw an owner's funds",
  "equivalence_basis": "docs/security.md:18",
  "cases": [{
    "id": "withdrawal",
    "candidate": "testUnauthorizedWithdrawal",
    "control": "testOrdinaryWithdrawal"
  }]
}
```

Dry run:

```sh
python3 skills/bounty-pilot/scripts/bounty.py research-next native \
  --repo /disposable/local-checkout --spec /private/native-spec.json \
  --stack foundry
```

Execution requires a **separate disposable and network-isolated workspace
with no secrets**, explicit opt-in and a NEW private evidence directory outside
the target checkout (parent must already exist):

```sh
python3 skills/bounty-pilot/scripts/bounty.py research-next native \
  --repo /disposable/local-checkout --spec /private/native-spec.json \
  --stack foundry --allow-exec --isolated-workspace-confirmed \
  --evidence-dir /private/native-cycle-001
```

The launcher runs both native tests twice, rejects zero-test/ignored runs
through the existing native runner, checks pinned HEAD and tracked-file status,
and rejects changed tracked-source diffs between rounds. It preserves the runner's **sanitized** per-round output in private
`round-1.json`, `round-2.json`, alongside per-case logs.
**Caution:** a flag does not create a sandbox! The operator must isolate the
workspace externally. Never run this against a production chain or with live
credentials. Matching exit codes are only harness evidence: an independent
review must establish reachable behavior, correct assertions, victim impact,
deployment revision and bounty eligibility.

## 3. Patch variant research on existing ecosystem history

Existing `ecosystem_intelligence.py` examines local security-shaped commits
and checks sibling functions for lexical guard omissions. Instead of adding a
duplicate scanner, Lab 0.42 adds the patch's **parent commit** to every such
lead, a stable candidate fingerprint and a before/after native falsification
plan. Pin both versions in different disposable checkouts, use the exact same
inputs and native tests, then separately replay the PoC. A patch-title guess,
unreferenced guard or token difference remains a hypothesis.

## 4. Private evidence memory (no automatic dismissal)

Use a private file **outside the skill and target checkout**. Record only
a short opaque target/mechanism identifier (the ledger stores hashes), a
fully pinned commit, a reviewer-supplied state and an evidence-file SHA-256.
For example, `/private/observation.json`:

```json
{
  "target": "my-local-target-id",
  "mechanism": "authorization-worker-drift",
  "revision": "REPLACE_WITH_THE_40_HEX_CHECKOUT_HEAD",
  "status": "refuted",
  "evidence_kind": "native-pair",
  "artifact_sha256": "REPLACE_WITH_THE_64_HEX_SHA256_OF_THE_EVIDENCE"
}
```

```sh
python3 skills/bounty-pilot/scripts/bounty.py research-next memory-record \
  --ledger /private/bp-memory.jsonl --input /private/observation.json
python3 skills/bounty-pilot/scripts/bounty.py research-next memory-lookup \
  --ledger /private/bp-memory.jsonl --target my-local-target-id \
  --mechanism authorization-worker-drift --revision FULL_40_HEX_SHA
```

Allowed statuses: `open`, `blocked`, `refuted`, `reproduced`.
Refutation/reproduction requires an evidence kind and hashed artifact. A
different source revision has no matching verdict; prior evidence is
**never** automatically used to discard a candidate, even at the same commit.
The store has no raw source, vulnerability description, RPC, wallet key or
target URL, and is never uploaded to the toolkit repository.

## Limits and evaluation

These are local structural tools and test orchestration. No API/RPC access,
automated chain transactions, attacker reachability proof or verified payout
claim follows from their output. Test suites on toy fixtures prove only the
new utilities' behavior. For improvements in real research success, compare
old vs new Pilot on sealed held-out pinned historical cases under equal model,
token, time and test budgets, recording actual native rediscoveries rather than
counting lexical leads. Do not merge this draft release before the full CI
matrix and native-smoke checks execute.
