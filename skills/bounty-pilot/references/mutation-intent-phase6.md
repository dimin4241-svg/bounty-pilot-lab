# Phase 6: Blind deterministic mutants and intent-sourced invariants

Phase 6 extends existing harness_gen.py, scenario_fuzz.py,
experimenter.py and sandbox_run.py rather than creating a competing
scanner. It does not scan production targets, issue blockchain
transactions or prove that a deployed contract is vulnerable.

## Mandatory blind sequence

1. Check out a clean, pinned Git commit in a disposable source tree.
2. Prepare deterministic mutations from a FIXED operator table BEFORE
   an agent writes a property.
3. Store the complete mutant catalog in a private 0600 directory;
   do NOT give it to the property-writing model.
4. Create a separate documentation-only intent task. Include only
   citations, source hashes, line numbers and approved quotations.
5. Generate candidate rules in a fresh independent agent context.
   Classify each rule as confirmed_requirement, industry_assumption,
   or hypothesis and list exceptions and assumptions.
6. A different reviewer approves only independently supported rules.
7. Emit typed Solidity getters/assertions only for approved rules
   whose ABI can be checked. All other rules stay unverified.
8. Compile and fuzz the ORIGINAL project before trying isolated
   single-mutation copies. Require nonzero executed native tests.
9. Record per-handler calls/reverts and source-line LCOV reachability.
10. Measure observable state infection and negative controls separately.
11. Minimize any model/native witness and replay the same exact trace
    against a proposed fix in a separate disposable checkout.
12. Run a genuinely blind historical A/B study before claiming uplift.

## Commands

Use the existing Bounty Pilot CLI, never a new parallel framework:

Step A: deterministic sealed mutations (source files must be tracked and clean):

    BP=skills/bounty-pilot/scripts/bounty.py
    python3 "$BP" harness-gen prepare-mutants \
      --repo /absolute/local/pinned-source \
      --source src/Vault.sol \
      --limit 12 \
      --out /private/bp-phase6/sealed/mutants.json

Mutation operators are deterministic, limited one-line Solidity changes:
skip-state-update, reverse-accounting-sign, tighten-time-boundary,
flip-sender-auth, skip-require-guard and reverse-rounding. Mutants are
not guaranteed to compile, reach meaningful states, or be non-equivalent.

Step B: separate mutant-BLIND agent task from an external intent document:

    python3 "$BP" harness-gen prepare-intent \
      --repo /absolute/local/pinned-source \
      --sealed-mutants /private/bp-phase6/sealed/mutants.json \
      --intent-source docs/accounting.md \
      --out /private/bp-phase6/agent/intent-task.json

The property agent sees ONLY this task, never the catalog, patches,
mutant IDs or evaluation metrics. An independent reviewer may use
protocol docs, requirements and accounting identities. Do not
derive a security requirement solely from implementation code;
it may already be wrong. Review the task for remaining secrets.

The agent writes structured JSON of the form:

    {
      "schema_version": 1,
      "source_revision": "<40-hex Git SHA>",
      "properties": [{
        "name": "assetsCoverLiabilities",
        "text": "Available assets cover all recorded liabilities",
        "kind": "getter_compare",
        "left_getter": "totalAssets",
        "right_getter": "liabilities",
        "op": "ge",
        "evidence_id": "ref-0001",
        "tier": "confirmed_requirement",
        "reviewer_approved": false,
        "assumptions": ["Pending withdrawals and external assets are accounted for"]
      }]
    }

Start with reviewer_approved=false; only an independent reviewer
may change this after checking the cited requirement and all
relevant exceptions. Industry assumptions and hypotheses cannot
auto-promote.

Step C: validate the proposals against cited intent:

    python3 "$BP" harness-gen validate-properties \
      --intent-task /private/bp-phase6/agent/intent-task.json \
      --proposals /private/bp-phase6/agent/proposals.json \
      --out /private/bp-phase6/review/approved-properties.json

The currently auto-compilable subset is deliberately narrow:
getter_compare over two zero-argument uint256 view/pure ABI getters
with eq/le/ge. It generates real assertEq/assertLe/assertGe calls
through staticcalls; unsupported properties remain review tasks.

Step D: prepare the existing Foundry harness with approved properties:

    python3 "$BP" harness-gen \
      --repo /absolute/local/pinned-source \
      --artifact /private/owned/Vault.json \
      --contract Vault \
      --reviewed-properties /private/bp-phase6/review/approved-properties.json \
      --out-dir /private/bp-phase6/generated

SetUp still requires a real owned deployment or permitted pinned fork.
The generated handler is not automatically integrated into your
Foundry test project; inspect it and prepare a disposable copy
with a passing baseline suite. A successful callSummary alone does
not imply substantive invariant coverage.

Step E: run on Mac in already installed immutable Docker image with Forge:

    python3 "$BP" sandbox-run mutation-campaign \
      --repo /absolute/local/disposable/foundry-project \
      --catalog /private/bp-phase6/sealed/mutants.json \
      --out /private/bp-phase6/results/native-receipts.json \
      --image trusted/foundry@sha256:<operator-pinned-digest> \
      --test-contract VaultInvariants \
      --max-mutants 8

Docker uses network=none, read-only mounts for source/catalog/helpers,
a non-root account, caps/memory/CPU/pids limits, a fresh tmpfs and
fixed forge build/test/coverage --offline commands. Every mutant
is applied in a separate container-local copy, never to the host's
checkout. The environment is not installed by this script.

The runner records actual build/test exit status, nonzero baseline
test count, command output hashes and best-effort LCOV reachability.
It does NOT classify a failing test as a killed mutant, because a
failure could be an unrelated revert or an environmental problem.
The state-diverged/property-failed/control fields are null until
independently validated by the operator.

Step F: assess only independently supported mutations:

    python3 "$BP" experimenter mutation-score \
      --catalog /private/bp-phase6/sealed/mutants.json \
      --receipts /private/bp-phase6/review/independently-reviewed-receipts.json \
      --out /private/bp-phase6/results/mutation-assessment.json

Possible classifications: NONVIABLE_COMPILE, UNREACHED_BY_CAMPAIGN,
REACHABILITY_UNKNOWN, INFECTION_UNKNOWN,
POSSIBLY_EQUIVALENT_OR_WEAK_STATE_ORACLE,
NEGATIVE_CONTROL_NOT_VERIFIED, OPERATOR_REPORTED_KILLED,
OPERATOR_REPORTED_REACHED_INFECTED_SURVIVOR and NOT_RUN.

Only reached, observably divergent, controlled cases are eligible
for an operator-reported detection fraction. If none qualifies,
the fraction is null, NOT 0. Equivalent mutants cannot generally
be proven equivalent automatically; avoid penalizing a property
for unreachable or uninfected mutants. All evaluation booleans
are operator-supplied unless independently authenticated elsewhere.

Step G: model-only causal localization and independent native replay:

    python3 "$BP" experimenter counterfactual \
      --original /private/bp-phase6/model/original.json \
      --proposed-fix /private/bp-phase6/model/proposed-fix.json \
      --trace /private/bp-phase6/model/minimal-trace.json \
      --out /private/bp-phase6/results/counterfactual.json

scenario_fuzz.py now stores changed state fields and the FIRST
violating step in its minimal BFS witness. When given --control,
it replays the same trace in the control model, rather than
relying only on a separate exhaustive search. These observations
are model-only and do not prove a safe Solidity patch.

## Revert and reachability diagnostics

Inspect per-selector handler call/revert counts from actual Forge
stdout. A high-revert handler (>=80% with at least 10 calls) means
the fuzzer may not explore important reachable states. A missing
counter is UNKNOWN, never good coverage. Where local coverage data
is not available, the mutation assessment cannot score reachability.

## Historical A/B: genuinely blind evaluation

Compare baseline versus Phase 6 on 20–30 diverse, real and independently
verified post-audit bugs. Model context may contain the vulnerable
PRE-fix source revision and legitimate protocol documentation, but NOT
the patch, bug description, advisory, target line, severity label,
or sealed mutant set. Keep the ground truth evaluator-only. Hold
model, time, tool access and token/dollar budget constant per case;
score independently reproduced unique causes, false claims, model
cost and confirmed cause per dollar. Public bugs may already have
contaminated model training. Prefer later discovered cases if a
model's training cutoff is actually known.

No such paid model benchmark is executed by this code change.
Green synthetic tests are maintenance checks, not demonstrated
improved bug discovery or payouts.
