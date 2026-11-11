# Phase 6: independent invariant authoring and blinded model mutations

This is a deterministic **state-model** mutation evaluation, not native Solidity mutation or a new exploit engine. The existing harness generator still creates intentionally FAILING Solidity property stubs until a researcher implements the actual checks.

## Correct ordering and independent roles

1. The operator prepares reviewed external intent documents, accounting identities or independent tests, plus observable state field names. No source-code implementation or historical patches are given to the property author.
2. A separate bank worker generates mutants from a JSON state model containing only state, actors and actions, **before** authoring properties. The bank uses fixed operators unrelated to any LLM output. Seal the bank privately, chmod 0600, outside the checkout. Do not mount it into the property author's environment.
3. A property author uses an external-intent-only brief and returns data-only rules with provenance. This author must not have access to the mutant bank or source patches.
4. The evaluator receives both the sealed bank and independent rule specification. It evaluates reached original state sequences, replays mutants and records control validity and the first observed behavioral divergence.
5. Human reviewers check actual deployed specification, original Solidity reachability, native tests, independent negative controls and novelty. A high mutation score is not proof of a bug or coverage of an entire protocol.

Independent sessions and isolation are **operator assertions**, not something these scripts can cryptographically prove.

## 1. Prepare a model WITHOUT invariants

The accepted state model has exactly state, actors and actions, using the existing scenario_fuzz data-only grammar. For example:

~~~json
{"state":{"assets":"10","liabilities":"10"},"actors":["alice"],"actions":[{"name":"accrue","actor":"alice","guards":[{"path":"assets","op":"ge","value":"0"}],"effects":[{"path":"assets","op":"add","value":2},{"path":"liabilities","op":"add","value":2}]}]}
~~~

Create the sealed bank in a private non-shared directory:

~~~sh
BP=skills/bounty-pilot/scripts/bounty.py
python3 "$BP" mutation-lab bank --model /private/bpl/model-no-rules.json --out /private/bpl/sealed-bank.json --max-mutants 40
~~~

The fixed mutation operators are skip-write (self-assignment), reverse-arithmetic, off-by-one, remove-guard and boundary-shift. **Only the JSON state transition model is mutated; not Solidity source code.** The bank includes a seal and exact original model digest. No property is accepted during generation.

## 2. Prepare the independent model author's brief

Save a reviewed external-intent file, for example:

~~~json
{
  "schema_version":1,
  "target_label":"owned_vault",
  "observable_state_fields":["assets","liabilities"],
  "independent_sources":[{
    "source_ref":"spec_balanced",
    "source_kind":"protocol_specification",
    "text":"At the end of every accrual, assets and liabilities change by the same amount.",
    "reviewer_confirmed":true
  }]
}
~~~

Create the prompt:

~~~sh
python3 "$BP" mutation-lab author-brief --sources /private/bpl/external-intent.json --out /private/bpl/author-brief.json
~~~

Give that prompt only to a **separate LLM/session** with access to the intent brief and no mutation bank or target code. This tool DOES NOT call any model.

The author returns a JSON with exactly schema_version=1, author_role=separate_property_author, bank_visible_to_author=false, rules=[{id,invariant,provenance}].

A candidate example:

~~~json
{
  "schema_version":1,
  "author_role":"separate_property_author",
  "bank_visible_to_author":false,
  "rules":[{
    "id":"assets_match_liabilities",
    "invariant":{"id":"assets_match_liabilities","kind":"compare","left":{"path":"assets"},"op":"eq","right":{"path":"liabilities"}},
    "provenance":{
      "tier":"confirmed_requirement",
      "source_kind":"protocol_specification",
      "source_ref":"spec_balanced",
      "source_sha256":"<real SHA-256 of the exact independent source text>",
      "supporting_excerpt":"At the end of every accrual, assets and liabilities change by the same amount.",
      "reviewer_confirmed":true
    }
  }]
}
~~~

Source provenance tiers: confirmed_requirement, industry_assumption and hypothesis. These are *reported claims*; the script checks format and operator assertion, not whether the underlying source really supports the rule. The evaluator accepts only data-only compare, conservation and unique rule kinds defined by invariant_check.

## 3. Score reached changes, not the number of generated mutants

~~~sh
python3 "$BP" mutation-lab score --bank /private/bpl/sealed-bank.json --property-spec /private/bpl/proposed-rules.json --out /private/bpl/mutation-score.json --depth 4 --max-states 300
~~~

Each original reachable state must satisfy the supplied property. Otherwise the campaign is INVALID_BASELINE_PROPERTY_OR_MODEL, and no valid score exists. A sealed bank edit is rejected.

Results:
- NOT_REACHED: affected action not attempted in bounded model execution — **excluded**.
- OBSERVATIONALLY_EQUIVALENT_WITHIN_BOUNDS: action attempted, but no observable behavioral difference in tested paths — **excluded**; true equivalence is NOT proven.
- KILLED_BY_PROPERTY: reached difference violates the property — **included**.
- REACHED_DIFFERENT_BEHAVIOR_NOT_CAUGHT: reached difference is not detected — **included**, but the operator must confirm it is relevant to that property.

When the bounded search is truncated, kill_rate is null. A missing counterexample does not certify safety.

## 4. Existing sandbox integration

The existing sandbox-run command has an opt-in mode for the data-only scorer:

~~~sh
python3 "$BP" sandbox-run --repo /absolute/disposable-checkout --mutation-bank /private/bpl/sealed-bank.json --property-spec /private/bpl/proposed-rules.json --out /private/bpl/docker-score.json --image trusted/python@sha256:REPLACE_WITH_REAL_64_HEX_DIGEST
~~~

The Docker image must be trusted, actually installed and pinned to a REAL immutable digest. It uses --network=none, read-only filesystem, non-root execution, no capabilities, and deliberately **does not mount the target checkout**. It cannot run Solidity or hit production RPC. Docker must be available separately on the host.

## 5. Transfer rules into the existing native harness

~~~sh
python3 "$BP" harness-gen --artifact /checkout/out/Vault.sol/Vault.json --repo /checkout --property-spec /private/bpl/proposed-rules.json --out-dir /private/bpl/native-harness
~~~

The harness plan records source-backed provenance. Solidity property functions remain deliberately failing TODO stubs. A researcher must author exact executable assertions, set up native dependencies and ghost state, execute controlled native tests, and record per-selector calls/reverts; a campaign dominated by revert calls is NOT useful coverage.

## 6. Optional native Foundry campaign with per-handler revert diagnostics

The existing sandbox wrapper can now run an operator-vetted Foundry
*Invariants harness in offline, pinned, non-root Docker. This is distinct
from the data-only mutation scorer:

~~~sh
python3 "$BP" sandbox-run \
  --repo /absolute/disposable-checkout \
  --plan /private/bpl/native-harness/harness-plan.json \
  --forge-harness VaultInvariants \
  --out /private/bpl/native-harness-receipt.json \
  --image trusted/forge-toolchain@sha256:REPLACE_WITH_REAL_64_HEX_DIGEST
~~~

The source checkout is **read-only inside Docker**, all Foundry
build/output/cache writes go to disposable /tmp, and the sandbox blocks
networking, drops Linux capabilities and uses a non-root account.
The fixed runner invokes forge test with a literal contract selection
(no shell, no user-defined commands). The image must be already
installed and pinned to a *real trusted* digest.

The receipt never persists raw test logs. It keeps only a SHA-256 of
stdout, exit status and parsed per-handler calls/reverts/accepted
counts, when the existing harness emitted a recognizable signature
summary. A handler with zero calls or ≥80% revert fraction is marked
unexplored/low-acceptance. Missing/ambiguous console summaries are
**HANDLER_COVERAGE_NOT_OBSERVED**, not proof of adequate fuzzing.

These arguments construct a native execution path that needs a
fully configured repository, Foundry dependencies, local deployment
and correctly written properties. The CI tests ONLY the command
builder and synthetic log parser; they do NOT actually run untrusted
target code or validate that an arbitrary protocol harness compiles.
If your native Foundry version formats logs differently, coverage
must remain unknown until reviewed evidence is supplied.

## 6. Honest A/B research

Use existing blind_campaign, bench_compare, backtest and benchmark-protocol. Seal pre-fix sources and hide patched commits, bug descriptions, reports and mutation banks from authors. Different isolated author and evaluator workspaces must be enforced by the operator. Both arms need identical model versions, context, tool access, fixed spend/time and independent reviewers. Public bugs may have been in training; prioritize independently verified post-training cases. Measure *unique confirmed* root causes and actual cost, not only mutant kills.

**Not yet implemented by this phase:** a genuine LLM automatically called to produce properties, Solidity AST/native mutations, fully automated Echidna/Foundry mutant compilation, or a paid-model historical holdout comparison. The automated regression tests show only the deterministic state-model evaluator and Docker command safety contracts.
