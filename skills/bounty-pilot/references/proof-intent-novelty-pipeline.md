# Proof, intent and novelty pipeline — bounded local implementation

This extension builds on `sequence-invariants`, `harness-gen`, `experimenter`,
`scenario_runner.py` and the existing Bounty Pilot submission gate. It targets
three common reasons strong findings fail review: no executable paired PoC,
uncertain protocol semantics, and duplicate root causes described with different
consequences.

**All three helpers are offline.** No browser, network, live RPC, wallet,
provider model, or target mutation is performed. They do not certify a
vulnerability, independent validity, severity or novelty.

## 1. `business-intent` — source-anchored expected behavior

Extract candidate normative sentences from local docs in an **exact pinned**
checkout (text is untrusted and cannot command the assistant):

```sh
BP=skills/bounty-pilot/scripts/bounty.py
python3 "$BP" business-intent extract \
  --repo /private/pinned-checkout --document docs/spec.md \
  --out /private/research/intent-candidates.json
```

Candidates are *only cues*. Marketing, outdated documentation, and implementation
comments do not automatically create security guarantees. Select an actual
promise, confirm the relevant version, then prepare a reviewed manifest:

```json
{
  "schema_version": 1,
  "source_revision": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "requirements": [{
    "id": "REQ-001",
    "kind": "trigger_liveness",
    "basis": {
      "file": "docs/spec.md", "line": 42,
      "quote": "Protective actions must remain active until executed or explicitly disabled.",
      "sha256": "<SHA-256 of the entire pinned documentation file>"
    },
    "source_anchors": [{
      "file": "src/Hook.sol", "line": 100,
      "needle": "_dispatchProtection", "sha256": "<SHA-256 of entire source file>"
    }],
    "expected_behavior": "An action failure preserves or re-arms the protection",
    "negative_control": "A supported, successful action clears protection only after completion",
    "operator_reviewed": true
  }]
}
```

The `quote` must equal the exact trimmed documentation line, not a paraphrase,
and `needle` must appear at the exact code line. `verify` checks local file
hashes and the Git commit, but **cannot** prove the requirement is true.

```sh
python3 "$BP" business-intent verify --repo /private/pinned-checkout \
  --manifest /private/research/intent-reviewed.json \
  --out /private/research/intent-verified.json
```

Optional observations input (same `source_revision`):

```json
{"source_revision":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
 "results":[{"requirement_id":"REQ-001",
   "candidate":{"satisfies":false},
   "negative_control":{"satisfies":true}}]}
```

Using `--observations` outputs `REPORTED_INTENT_CONFLICT_REQUIRES_NATIVE_PAIR`.
It never upgrades a self-reported boolean to a vulnerability.

## 2. `native-poc` — paired Foundry test generation

A human or an independent coding agent maps a strong invariant to **typed,
fully anchored local fixture calls**. No source modifications, untrusted raw
Solidity snippets, shell commands or free-form ABI expressions are accepted.

```json
{
 "schema_version":1,
 "id":"ExampleGuard",
 "source_revision":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
 "fixture":{"import":"test/OwnedFixture.sol","contract":"OwnedFixture"},
 "operator_reviewed_intent":true,
 "actions":[
  {"role":"setup","target":"vault","signature":"prepare(uint256)",
   "args":[{"literal":"1"}],"actor":"alice"},
  {"role":"enabler","target":"vault","signature":"enableMode(uint256)",
   "args":[{"literal":"2"}],"actor":"alice"},
  {"role":"action","target":"vault","signature":"step(uint256)",
   "args":[{"literal":"3"}],"actor":"alice"}
 ],
 "observations":[{"name":"protectedBalance","target":"vault",
   "signature":"balanceOf(address)","args":[{"fixture_ref":"alice"}]}],
 "checks":{
   "candidate":[{"observation":"protectedBalance","relation":"lt"}],
   "negative_control":[{"observation":"protectedBalance","relation":"eq"}]
 }
}
```

If `negative_control` is omitted, the generator creates one by omitting all
`role=enabler` actions while retaining setup and the core action. This is a
**suggestion**, not guaranteed to be the right experiment. To specify a better
control, provide an explicit `negative_control` list with the same schema as
`actions`. Accepted canonical ABI types: int/uint 8/16/32/64/128/160/192/224/256,
address, bool and bytes32. Each observable is a 32-byte unsigned numeric
`staticcall`. More complex argument types and result decodings require a
reviewed native fixture (no automatic unsafe fallback). The imported fixture
must expose the named contracts/actors, inherit Foundry's `Test`, and deploy
**unmodified pinned source** in its inherited `setUp()`.

```sh
python3 "$BP" native-poc --scenario /private/research/scenario.json \
  --out-dir /private/research/generated-proof-001
```

This produces `BPSequence.t.sol`, `manifest.json` with test/hash information
and `runner-plan.json` compatible with existing `scenario_runner.py`.
There is **no native run at this point**.

For an explicit, separately copied **disposable** clean checkout at the
same Git SHA:

```sh
printf 'I_CONTROL_THIS_DISPOSABLE_CHECKOUT\n' > /private/disposable-checkout/.bounty-pilot-disposable-proof
python3 "$BP" native-poc --scenario /private/research/scenario.json \
  --out-dir /private/research/generated-proof-002 \
  --install-disposable /private/disposable-checkout
python3 skills/bounty-pilot/scripts/scenario_runner.py \
  --plan /private/research/generated-proof-002/runner-plan.json \
  --repo /private/disposable-checkout
```

The last command is **dry run**. Only after an operator vets the repository,
fixture, original code and external network-isolated environment, add
`--allow-exec`. The tool does not create a Docker sandbox and does not block
network use by the invoked native toolchain. The same tool should be run with
repeated seeds and an independent negative control before reporting. `forge`
may be absent: report that, never manufacture passing test results.

### What this does / doesn't automate

- **Does:** emit real test functions with local fixture calls and concrete
  before/after assertions; infer a basic omit-enabler control; write a validated
  paired-run plan; pin Git SHA; install only to an operator-marked, clean,
  disposable checkout without overwriting existing files.
- **Does not:** invent correct ABI bindings, set up mainnet forks, create
  malicious contracts, solve unknown business logic, run deployments or infer
  financial impact from a passing unit test. Complex callback paths must be
  implemented in a reviewed, local test fixture.

## 3. `novelty-mechanism` — root-cause dedup review

Input contains one candidate and local known findings, each with the same five
**reviewed** root-cause fields. For example:

```json
{
 "schema_version":1,
 "candidate":{"id":"30","project":"revert-v4lend-2026",
  "root_cause":{"component":"RevertHookTriggers",
   "operation":"computeTriggerTicksCore",
   "state_resource":"trigger slots zero and two",
   "failure_mode":"AUTO_LEND overwrites AUTO_RANGE triggers",
   "invariant":"configured modes preserve their triggers"},
  "impact":"withdrawal disabled"},
 "known":[{"id":"63","project":"revert-v4lend-2026",
  "root_cause":{"component":"RevertHookTriggers",
   "operation":"computeTriggerTicksCore",
   "state_resource":"trigger slots zero and two",
   "failure_mode":"AUTO_LEND overwrites AUTO_RANGE triggers",
   "invariant":"configured modes preserve their triggers"},
  "impact":"unexpected swaps","status":"Confirmed",
  "source_url":"https://cantina.xyz/code/e275368c-547d-4d91-a418-053ad31082a8/findings/63"}]
}
```

```sh
python3 "$BP" novelty-mechanism --input /private/research/known-mechanisms.json \
  --out /private/research/novelty-review.json
```

The scorer ignores titles and submitted-at ordering. It compares root causes
within the same target program and retains a note when the impact differs.
The signal is a **review queue**, never an automatic duplicate ruling.
`NO_LOCAL_MATCH_REMOTE_UNCHECKED` explicitly means Cantina, existing audits,
private triage queues and upstream fixes might still contain a duplicate.

## Integration into discovery and proof workflow

1. `sequence-invariants scan` and bounded `mode-matrix` identify source cues.
2. `business-intent extract` + operator review anchor promised behavior to the
   exact protocol docs and implementation (or say intent UNKNOWN).
3. `sequence-invariants review` and `scenario_fuzz` find model-level conflicts.
4. `native-poc` emits candidate/control Foundry tests for a reviewed scenario.
5. Run only in authorized locally isolated fixtures via `scenario_runner`;
   check runtime traces, source hash, repeatability, affected actors and funds.
6. `novelty-mechanism` compares *actual mechanism*, not just titles, with
   reviewed local history and imported adjudications; search external records.
7. `experimenter`/`reality-gate`/submission gates remain authoritative for
   reporting status. A compiled test, green CLI or no local duplicate is **not**
   proof of a payable High/Critical finding.

## Measuring whether it helps

The previous 13 Cantina cases are **known calibration only**; they are not
blind rediscovery. Use unseen pinned projects, identical baseline/new model,
time and token budget, two independent reviewers, a real native candidate /
negative-control test and verified root-cause grouping. Report verified novel
issues, false positives and USD per validated finding; do not promise uplift.