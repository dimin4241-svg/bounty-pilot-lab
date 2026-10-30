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

The seed corpus is `references/caseforge-catalog.json`, presently **seven**
sourced, retrospective cases: Polygon Plasma, Liquid/Elements, Monad, Wormhole,
Balancer V2, Euler V1 and KelpDAO/LayerZero. Each has an HTTPS publication,
the mechanism, a safety invariant and a source type. A publication can be an
official incident post-mortem, a paid-disclosure review or a judged audit;
the categories must not be conflated.

Six are `documented`; the Monad H-02 case is `revision-pinned` at
`category-labs/monad-bft@6aaccc2ec51eac66a2cf18ec64ab0df2c1448990`.
The Code4rena report identifies this audit snapshot, and the two affected
source paths were independently confirmed in that revision. There is **one
prepared pinned benchmark task but no executed blind rediscovery**.
Never infer a vulnerable revision from a publish date, fix commit, repository
HEAD, tag or project name.

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
control test remain mandatory**. Keys are SHA-256 digested in the report to avoid
echoing input values; this is not Ethereum Keccak-256 hashing.

## C. Cross-Phase Differential Engine

Compare *the same recorded request and policy* at two or more independently
implemented stages, e.g. transaction admission, block construction/validation,
API approval, signer and queued worker execution.

```json
{
  "schema_version": 1,
  "cases": [
    {
      "id": "request-001",
      "same_policy_expected": true,
      "equivalence_basis": "same canonical request, chain and policy epoch",
      "stages": [
        {"name": "api", "decision": "allow", "payload_digest": "hash-a", "policy_id": "v2"},
        {"name": "worker", "decision": "deny", "payload_digest": "hash-b", "policy_id": "v2"}
      ]
    }
  ]
}
```

Run `bounty.py research-diff phases --input <private-observations.json>`.
It reports separate leads for `DECISION_DIVERGENCE`, `PAYLOAD_DRIFT`, and
`POLICY_VERSION_DRIFT`. If the policies differ, or no equivalence basis is
given, `comparable=false` and the reason is recorded. Supplied payload and
policy identifiers are hashed before being included in the emitted report. Different admission
requirements may be **intentional** even under the same policy, so native
candidate/negative-control runs and documented guarantees are necessary.

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
- The corpus is curated, not comprehensive; seven retrospective cases prove
  only that citations and structure were captured. There is no measured
  rediscovery or uplift.
- Economic sequence search remains part of AVRE. A future extension should
  integrate native value-invariant execution rather than duplicate AVRE's
  heuristic sequence generator.
