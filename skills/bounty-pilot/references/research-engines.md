# CaseForge and differential research (Lab 0.41)

These are **opt-in, offline research aids**, not vulnerability scanners that prove
reachability. They complement AVRE, the existing backtest system and the Evidence-First
submission gate; they do not replace them or change any finding's status.

## A. CaseForge: research precedents with provenance

```sh
python3 <skill-dir>/scripts/bounty.py caseforge validate
python3 <skill-dir>/scripts/bounty.py caseforge index --family semantic-identity
python3 <skill-dir>/scripts/bounty.py caseforge blind-queue
```

The seed corpus is `references/caseforge-catalog.json`, presently **ten**
sourced, retrospective cases: Polygon Plasma, Liquid/Elements, Monad, Wormhole,
Balancer V2, Euler V1 and KelpDAO/LayerZero. Each has an HTTPS publication,
the mechanism, a safety invariant and a source type. A publication can be an
official incident post-mortem, a paid-disclosure review or a judged audit;
the categories must not be conflated.

Six are `documented`; four separate Monad findings (H-01 through H-04)
share the same `revision-pinned` source snapshot at
`category-labs/monad-bft@6aaccc2ec51eac66a2cf18ec64ab0df2c1448990`.
The Code4rena report identifies this audit snapshot, and the affected
source paths for all four findings were independently confirmed in that
revision. CaseForge groups all four truths into **one opaque benchmark task**;
there is no executed blind rediscovery or evidence of improved bug discovery.
Never infer a vulnerable revision from a publish date, fix commit, repository
HEAD, tag or project name.

All findings sharing one repository and pinned commit become a single opaque
blind benchmark task; the hunter must not learn how many findings it contains.

To enroll additional historical benchmark cases, a maintainer must independently
prove the vulnerable commit, affected source paths and revision citation; set
`status: revision-pinned`, `repository_url`, `vulnerable_commit`,
`revision_source_url` and `scope_paths`, then isolate the hunting agent from
this catalog and the published write-up. `caseforge blind-queue` includes only an
opaque task ID, repository and pinned SHA; it intentionally withholds source URLs,
titles and mechanisms. It is only a preparation aid and **not** a benchmark run.
Use the existing sealed procedure:

```sh
python3 <skill-dir>/scripts/bounty.py backtest init \
  --name <opaque-case> --repo <pinned-checkout> --out <new-private-case-dir>
# Hunt without reading the answer, then seal the output.
python3 <skill-dir>/scripts/bounty.py backtest seal \
  --case <case-dir> --run <private-run>
# Only after the seal: read authoritative truth, record it and score.
python3 <skill-dir>/scripts/bounty.py backtest score --case <case-dir>
```

A case's appearance in CaseForge is not a new vulnerability, a payout prediction,
proof that the source is currently vulnerable, or a rediscovery count.

## B. Semantic Identity Engine

Detect discrepancies between the identity used for **replay protection, proof
context or cache keys** and the semantics of the associated operations.

First collect bounded **passive leads from in-scope tracked source**:

```sh
python3 <skill-dir>/scripts/bounty.py research-diff scan \
  --repo <target-checkout> --scope src --scope contracts \
  > <private-run>/identity-and-phase-leads.json
```

The scan only matches lexical cues such as packed ABI encoding, cache-key
terms, quorum counting, or phase boundaries. It does not parse full data flow,
claim a bug, run target code, read network state or scan directories outside the
explicit relative `--scope` prefixes. No hit is a finding; no hit is an
assurance of safety either.

For a directly executable **synthetic raw-byte framing experiment**,
compare two different byte-field tuples. This computes an actual unframed
byte collision and a framed negative control, without importing target code:

```json
{
  "schema_version": 1,
  "pairs": [{"id": "byte-boundary",
             "left_fields": ["0x61", "0x6263"],
             "right_fields": ["0x6162", "0x63"]}]
}
```

Run `bounty.py research-diff byte-tuple --input <private-pairs.json>`.
The output is `SYNTHETIC_COUNTEREXAMPLE`, not a target vulnerability:
the native target's actual typed codec, authorization and use of the key
still must be confirmed. This is **not a Solidity ABI encoder**.

For a native parser/proof test, supply an **investigator-created JSON observation**
file rather than executing an untrusted checkout inside the scanner:

```json
{
  "schema_version": 1,
  "pairs": [
    {
      "id": "exit-encoding-pair",
      "expected_semantic_relation": "same",
      "equivalence_basis": "native decoder maps both representations to the same withdrawal",
      "left": {"identity_key": "exit-key-A"},
      "right": {"identity_key": "exit-key-B"}
    },
    {
      "id": "distinct-proof-negative-control",
      "expected_semantic_relation": "different",
      "equivalence_basis": "native verifier sees different asset commitments",
      "left": {"identity_key": "proof-1"},
      "right": {"identity_key": "proof-2"}
    }
  ]
}
```

Run `bounty.py research-diff identity --input <private-observations.json>`.
`SAME_ACTION_DISTINCT_KEY` indicates possible replay identity splitting;
`DISTINCT_CONTEXT_SHARED_KEY` indicates possible cache/verification context
collision. The tool cannot independently establish the supplied semantic relation:
**native decoder equivalence, actual cache/replay usage, a reachable caller and a
control test remain mandatory**. Optional `verified_message_fingerprint` and
`executed_operation_fingerprint` fields compare the operation the verifier accepted
with the operation a later stage executes. `encoded_payload_hex` records byte equality
separately from semantic equality. Domain, chain ID, epoch, nonce, state and attacker
permission labels are fingerprinted for context. These values come from a researcher-run
native test; the scanner does not execute a target decoder or verifier. Keys and context
are SHA-256 digested in the report to avoid echoing input values; this is not Ethereum
Keccak-256 hashing.

For example, native adapters may record both sides after running the target's own
decoder, signature recovery and operation builder:

```json
{
  "id": "message-versus-execution",
  "expected_semantic_relation": "same",
  "equivalence_basis": "native decoder returns the same signed operation",
  "left": {
    "identity_key": "replay-key-A",
    "verified_message_fingerprint": "canonical-message-digest",
    "executed_operation_fingerprint": "execution-payload-digest",
    "encoded_payload_hex": "0x0102",
    "domain": "bridge:chain-1",
    "chain_id": "1",
    "epoch": "4",
    "nonce": "9",
    "attacker_permissions": "public-relayer"
  },
  "right": {
    "identity_key": "replay-key-B",
    "verified_message_fingerprint": "canonical-message-digest",
    "executed_operation_fingerprint": "canonical-message-digest",
    "encoded_payload_hex": "0x010203",
    "domain": "bridge:chain-1",
    "chain_id": "1",
    "epoch": "4",
    "nonce": "9",
    "attacker_permissions": "public-relayer"
  }
}
```

All fingerprint and equivalence fields are supplied observations, not independently
validated facts. A mismatch remains a lead until an owned native candidate/control test
establishes the path and the intended invariant.

### Unique signer quorum observations

`research-diff quorum` compares authenticated signer identities produced by a local native
verifier. Each candidate needs a valid negative control using the same threshold and allowed
signer set. Optional chain, epoch, nonce, state, attacker-permission and policy context
fingerprints must match across the pair:

```json
{
  "schema_version": 1,
  "cases": [
    {"id": "duplicate-candidate", "pair_id": "q1", "role": "candidate",
     "threshold": 2, "authorized_signers": ["A", "B"],
     "authenticated_signers": ["A", "A"]},
    {"id": "unique-control", "pair_id": "q1", "role": "negative-control",
     "threshold": 2, "authorized_signers": ["A", "B"],
     "authenticated_signers": ["A", "B"]}
  ]
}
```

The report fingerprints signer IDs and flags when the candidate has enough signature
records but too few distinct authorized signers. It does not verify signatures, signer
authorization or whether the target counts duplicates. Run the candidate and control
against the actual local verifier through Foundry, Cargo or the project's existing test
runner before making a source or impact claim.

## C. Cross-Phase Differential Engine

Compare *the same recorded request and policy* at two or more independently
implemented stages, e.g. transaction admission, block construction/validation,
API authorization and worker execution, transaction admission and block validation,
signer approval and signed payload, bridge verification and settlement, cached and full
validation, or old/new policy configuration.

```json
{
  "schema_version": 1,
  "cases": [
    {
      "id": "request-001",
      "same_policy_expected": true,
      "equivalence_basis": "same canonical request, chain and policy epoch",
      "required_context_fields": ["chain_id", "epoch", "nonce", "attacker_permissions"],
      "stages": [
        {"name": "api", "decision": "allow", "payload_digest": "hash-a", "policy_id": "v2"},
        {"name": "worker", "decision": "deny", "payload_digest": "hash-b", "policy_id": "v2"}
      ]
    }
  ]
}
```

Run `bounty.py research-diff phases --input <private-observations.json>`.
It reports separate leads for `DECISION_DIVERGENCE`, `PAYLOAD_DRIFT`,
`POLICY_VERSION_DRIFT`, and changes in the supplied domain, chain ID, epoch, nonce,
state and attacker-permission context. Stage array order is preserved in the report.
`required_context_fields` makes absent context observations block comparison; partial
or missing policy identity and any observed stable-context drift also block it. Set
`state_transition_expected: true` only when a local scenario intentionally mutates state
between phases; the observed transition is recorded and the case remains non-comparable
across that state boundary. Supplied payload, policy and context values are fingerprinted
before inclusion. Different admission requirements may be **intentional** even under the
same policy, so native candidate/negative-control runs and documented guarantees are
necessary.

### Evidence and routing discipline

Pass JSON outputs with `bundle --include <private-run>/identity-and-phase-leads.json`
to the relevant independent hunt lens only when the run's scope permits it.
Do not copy in source text outside scope; do not feed the retrospective CaseForge
answer catalog into a blind hunting bundle. Imported candidates remain
untriaged; `SOURCE_CONFIRMED`, `POC_REPRODUCED` and `IMPACT_VERIFIED`
remain distinct.

No real wallet keys, mainnet writes, production API calls, network probing,
third-party accounts, arbitrary target code execution, or presumption of
compromised privileged infrastructure. Review program exclusions first.

### Current limits and next work

- Passively scanned cues are not AST or a semantic call graph.
- A generic byte-join and framed negative control are executable, but do **not**
  model a real target's typed encoder or prove a vulnerability.
- Native encoders and verifiers are **not** automatically executed. Pair JSON
  compares outputs that an investigator obtains through separately authorized
  local, paired tests.
- `tests/fixtures/native` contains synthetic Foundry byte-framing and Rust signer-quorum
  candidate/control tests wired into the existing native smoke workflow. They test the
  harness and generic mechanism only; they are not target vulnerabilities or historical
  rediscoveries.
- The corpus is curated, not comprehensive; ten retrospective cases prove
  only that citations and structure were captured. There is no measured
  rediscovery or uplift.
- Sequence generation, economic metamorphic plans, exact integer measurements and replay
  minimization remain in AVRE (`avre_sequence.py`, `avre_economics.py`). This engine does
  not add another sequence/economic generator. Reproduce locally through the existing
  `scenario_runner.py` candidate/control path and provide exact measurements to AVRE when useful.
