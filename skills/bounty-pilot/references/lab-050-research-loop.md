# Experimental Lab 0.50 — evidence-guided research loop

This is a collection of **opt-in, bounded research helpers**, not an
automatic exploit generator, verified dynamic call graph, or evidence of improved
payout rate. Its core goal is hypothesis → controlled experiment → observable
result → new research priority.

## 1. Retaining all ranked leads

AVRE evaluates and scores all deduplicated candidates before enforcing the
global hypothesis budget. It reserves one candidate from each producing module
when possible and writes excluded candidates into a private
deferred-hypotheses.json. Deferred means not selected, not refuted. Earlier
per-module input caps still exist and must be reviewed separately.

## 2. Compiler-resolved static state/effect bridge for Solidity

impact-plan already emits a compiler-derived semantic-graph.json from pinned
solc build-info. It does not attach checkout provenance. Explicitly bind that
artifact to the reviewed checkout HEAD and hash its source files:

    python3 skills/bounty-pilot/scripts/semantic_state_bridge.py \
      --graph "$PRIVATE_DIR/impact/semantic-graph.json" \
      --repo "$TARGET_CHECKOUT" \
      --out "$PRIVATE_DIR/bound-semantic-graph.json"

Binding **does not authenticate** which exact sources went into solc. Check
build-info, source commit and original file hashes separately. Only then use
the compiler AST static call/write graph for a new passive AVRE run:

    python3 skills/bounty-pilot/scripts/bounty.py avre \
      --repo "$TARGET_CHECKOUT" --scope "$PRIVATE_DIR/scope.json" \
      --out "$PRIVATE_DIR/avre-ast" \
      --semantic-graph "$PRIVATE_DIR/bound-semantic-graph.json"

Unresolved dynamic calls, compiler paths with missing source spans, external
dependencies and authorization semantics still require manual review.

## 3. Cross-file security slices

Run the planner against a pinned, scope-permitted local checkout:

    python3 skills/bounty-pilot/scripts/security_slices.py \
      --repo "$TARGET_CHECKOUT" --max-source-bytes 160000 \
      --out "$PRIVATE_DIR/security-slices.json"

Each primary source file appears exactly once as core context, while direct
import and unique-filename cues can introduce duplicated context or separate
two-file bridge shards. The resulting JSON supplies scope_args for a *fresh*
private Bounty Pilot run per shard. Inspect unrepresented_cross_shard_edges;
large dependencies and non-import runtime links are not solved by this planner.

## 4. Local native feedback campaign (isolated Mac runner only)

research_loop.py accepts up to 32 *explicitly authored* native test variants
with exactly one candidate and one negative-control test each. It executes
nothing by default. It repeats each selected pair two or three times and
records structured observations. It does not manufacture assertions or tests.

Example private campaign.json (replace the placeholder SHA and selectors with
your own pinned local test harness):

~~~json
{
  "schema_version": 1,
  "source_revision": "0123456789012345678901234567890123456789",
  "variants": [
    {
      "id": "actor-switch-01",
      "family": "actor-isolation",
      "priority": 5,
      "hypothesis_id": "AVRE-candidate-id",
      "cases": [
        {"id": "candidate", "pair_id": "actor-switch-01",
         "role": "candidate",
         "argv": ["forge", "test", "--match-test", "testActorSwitch", "-vvv"],
         "cwd": ".", "timeout_sec": 120},
        {"id": "control", "pair_id": "actor-switch-01",
         "role": "negative-control",
         "argv": ["forge", "test", "--match-test", "testProtectedControl", "-vvv"],
         "cwd": ".", "timeout_sec": 120}
      ]
    }
  ]
}
~~~

Each real native test should emit exactly one line of the following shape with
its matching role and variant. The negative control must set violated:false and
use the same property_id. Both roles and repeated rounds must share the same initial_state_digest.
A marker alone does not prove that the test asserted
the corresponding state property.

    BP_LAB_OBSERVATION={"variant":"actor-switch-01","role":"candidate","property_id":"cross-user-rights","violated":true,"victim_loss":"1","attacker_delta":"0","initial_state_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","state_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}

Dry-run first:

    python3 skills/bounty-pilot/scripts/research_loop.py \
      --repo "$TARGET_CHECKOUT" \
      --manifest "$PRIVATE_DIR/campaign.json" \
      --out "$PRIVATE_DIR/dry-run.json"

Only after external, enforced filesystem isolation, an offline network
boundary, a secret-free test workspace, trusted tooling and project permission,
run on the private **Mac self-hosted runner**, not cloud-hosted CI:

    python3 skills/bounty-pilot/scripts/research_loop.py \
      --repo "$TARGET_CHECKOUT" \
      --manifest "$PRIVATE_DIR/campaign.json" \
      --out "$PRIVATE_DIR/replay.json" \
      --execute --isolation-attested --no-network-attested --rounds 2

These two attestation switches **do not create a sandbox**. They only record
operator assertions. The tool delegates bounded commands to scenario_runner.py;
target tests themselves are untrusted and require a separate source review.
Dirty source checkouts require explicit --allow-dirty-poc and manual inspection.

Use a **new** AVRE run to take feedback into account:

    python3 skills/bounty-pilot/scripts/bounty.py avre \
      --repo "$TARGET_CHECKOUT" --scope "$PRIVATE_DIR/scope.json" \
      --out "$PRIVATE_DIR/avre-feedback" \
      --feedback "$PRIVATE_DIR/replay.json"

Feedback must match source_revision. Matching local witnesses shift queue
priority slightly but remain unverified. Independent reproduction,
evidence_verifier.py, deployment/permission checks and attacker economics
are still required.

## 5. Measured-point economics

economic_frontier.py reads explicitly supplied local scenario measurements;
it never fetches live liquidity or invents flash loans:

    python3 skills/bounty-pilot/scripts/economic_frontier.py \
      --measurements "$PRIVATE_DIR/measured-points.json" \
      --available-capital "100000" \
      --out "$PRIVATE_DIR/economic-frontier.json"

Each point provides id and exact decimal capital_required, gross_extraction,
victim_loss, accessible_liquidity, manipulation_cost, protocol_fees,
slippage_cost, gas_cost, funding_cost and unrecovered_capital. Evidence and
explicit booleans are required to support native_test_executed,
paired_control_passed, capital_restored, position_closed,
unprivileged_reachability_verified and real_chain_state_verified. The tool
checks the supplied assumptions and chooses the *minimum positive tested*
capital, not an untested global optimum. Values are unauthenticated until an
independent reviewer checks the fork receipts and assertions.

## 6. Cross-layer outcomes

    python3 skills/bounty-pilot/scripts/outcome_consistency.py \
      --observations "$PRIVATE_DIR/outcomes.json" \
      --out "$PRIVATE_DIR/outcome-review.json"

The JSON input uses schema_version:1 and observations. Each observation names:
id, ack_semantics (final-settlement/submitted-only/unknown),
ack_success (boolean), nested_results (success/failure/unknown), and optional
exact expected_asset_delta, observed_asset_delta, asset_tolerance,
entitlement_owner, effective_receiver, delegation_or_transfer_authorized.

A successful *submission* beside later nested item failure is not a finality
violation. Explicit final-settlement with failed nested operations, a measured
asset difference, or unauthorized cross-user outcome becomes a review cue,
never an automatic bug report.

## 7. Blind measurements and limitations

Compare Lab 0.49.5 and Lab 0.50 on genuinely held-out pinned source revisions,
with identical models, budgets and runtimes, before seeing their published
findings. Measure native-reproduced root causes and cost per verified finding,
not synthetic fixture counts or number of unverified hypotheses.

The experiment still lacks fully automatic native exploit synthesis, complete
cross-contract semantics, trustworthy runtime provenance, arbitrary multi-step
capital optimization and any demonstrated bounty improvement. Keep all code,
logs, outcomes, traces and private reports outside the audited repository.
