# Historical Web A/B — executed, fixed-budget, source-only diagnostic (Lab 0.49)

## Exact scope of this experiment

This is a genuine **offline source-scanning A/B** on six real, pinned public
Git source snapshots. It is **not** a blind LLM/agent experiment, native
historical exploit reproduction, independent human source audit, or a
measured improvement in real bug bounty detection.

The two pre-existing Bounty Pilot analysis strategies are:

- **Baseline**: generic web API and source lexical cues from Lab 0.46
  (`web3_research.SIGNALS`).
- **Extended**: the same cues plus generic JavaScript runtime cues from
  Lab 0.47 (`web3_advanced.SOURCE_CUES`).

Lab 0.48 primarily improved evidence capture and benchmarking, not
vulnerability search logic. Both strategies produce only lexical
reading leads, not source-validated vulnerability reports or PoCs.
Therefore neither arm is credited with rediscovering a historical
finding merely because it mentions a risky API.

## Data and fixed budget

The evaluator uses the existing `web-historical-seeds.json` catalog
(three publicly disclosed bugs, each with an affected and fixed Git SHA,
six total snapshots from Next.js and CryptoJS). Each source snapshot is
fetched by exact 40-byte Git commit from an allowlisted public GitHub
repository. Source provenance is limited to local Git SHA and HTTPS:
the script does not verify git tag cryptographic signatures.

The same source window is passed to both arms:

| Constraint | Fixed cap per snapshot and per arm |
| --- | --- |
| Source files | 120 |
| Lines | 6,000 |
| Total source bytes | 1,000,000 |
| Single file | 100,000 bytes |
| Per-arm wall time | 60 seconds |

A source-content hash is calculated from actual selected paths and bytes.
Targets are not installed, executed, probed, fuzzed or connected to.
A repository-specific *general* source scope is selected before any
finding review: Next.js `packages/next/src/server/web`; CryptoJS root.
Those choices narrow the search and may miss findings elsewhere.
No advisory details or vulnerable/fixed labels are passed to either
source analyzer. The snippets and prompts for these published cases
are nevertheless not genuinely blind to a model trained on public
disclosures.

## Automatic execution

The GitHub Actions workflow
`.github/workflows/web-ab-diagnostic.yml` performs the replay,
prints both arms' sealed scoring summaries, and uploads the complete
`diagnostic-report.json` as a workflow artifact.

Manual invocation (requires network only to retrieve six *public*
immutable Git source snapshots; source auditing itself is offline):

```sh
python3 skills/bounty-pilot/scripts/web_ab_diagnostic.py \
  --out /private/NEW-diagnostic-directory
```

The source runner calls the existing `web_historical_bench.prepare`,
`verify_checkout`, `seal` and `score`. It seals a complete empty
finding list for each task because raw lexical cues do **not**
constitute a reproducible root cause. No claims means no individual
judgments to request, and each arm truthfully scores 0 rediscoveries
and 3 known misses. A source cue may still justify manual investigation.
If the historical sources cannot be retrieved or the source budget
cannot be met, execution fails; it cannot silently simulate missing data.

Interpretation:
- `lexical_cues`: rough review workload indicator, not an exploit metric.
- `verified_root_causes`: always zero unless later changed by an
  independent source-specific/native validation stage.
- `measured_verified_rediscoveries`: zero in this diagnostic, not
  evidence that a human or LLM could not find the bug.
- `recall`: zero among the three seeded historical cases **for these
  lexical-only strategies with no independently validated claims**.
- `not_a_model_trial: true` and `independent_human_review: false`
  explicitly prevent claiming genuine blinded LLM performance.

## How to run a genuine blind *model* A/B next

The existing `web-history-bench` prepare/verify/seal/score protocol
provides queue separation and immutable prediction logs. For a real
model comparison, supply **two separately executed, independently
configured researchers** with the same source snapshots, task time
and token budgets, and no evaluator answers or historical advisory
access. Log every search step, model/API version, cost and elapsed
time; store native candidate/control assertions and new evidence
artifacts for each claimed bug. Seal predictions from both arms.
Then have a different reviewer score causal root cause, reachability,
native PoC and false positive claims *without knowing the arm*.

The ChatGPT conversation itself has already discussed several seed
CVEs, and the public catalog is in the repository, so **this chat
cannot be a truly blinded hunter for the present public seed set**.
No external paid model has been authorized or executed in this version.

To establish an actual improved bug-bounty success rate, use a larger
private, independently sourced, previously unseen holdout set and
compare both arms under the same money/time/compute and evidence gates.
