
# Paired local benchmark quality scorecard

This is a reporting layer, not a second hunt engine. Use existing
`web_bench_ab.py`, `blind_campaign.py` and native benchmark protocols for
preparation, isolation, sealed predictions and independent review. For
self-grading local training fixtures and reviewed negative controls, export
only aggregate task receipts to this new scorecard. No target names, URLs,
payloads, reports, credentials or model transcripts are accepted.

Use the same pinned model build, fixtures, tool access and budgets for both
arms. Keep evaluator labels outside model contexts, preserve every failed
run, and use fresh independent sessions. The reviewer, not the model, fills
confirmed/rejected/unresolved counts; deduplicate mechanisms within a task.
An oracle solve needs completed execution and at least one reviewed claim.
A negative control is clean only when completed without rejected or
unresolved claims. A timeout does not count as a clean negative.

```sh
python3 skills/bounty-pilot/scripts/quality_scorecard.py \
  --input /private/paired-receipts.json --out /private/quality.json
python3 -m unittest discover -s tests -p test_quality_scorecard.py -v
```

Schema example (synthetic only; not actual benchmark data):

```json
{
  "schema_version": 1,
  "model": "pinned-model-build",
  "baseline_revision": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "candidate_revision": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "budget": {"usd": 1, "seconds": 120, "input_tokens": 10000, "output_tokens": 2000},
  "tasks": [{"id": "opaque1", "kind": "positive"}],
  "receipts": [
    {"arm": "baseline", "task_id": "opaque1", "status": "completed",
     "oracle_solved": false, "confirmed": 0, "rejected": 0, "unresolved": 0,
     "usage": null},
    {"arm": "candidate", "task_id": "opaque1", "status": "completed",
     "oracle_solved": true, "confirmed": 1, "rejected": 0, "unresolved": 0,
     "usage": {"usd": 0.12, "seconds": 30, "input_tokens": 3000,
               "output_tokens": 500, "context_tokens": 1000}}
  ]
}
```

For negative cases set `oracle_solved` to null and `confirmed` to 0.
For error/timeout positive cases set `oracle_solved` false. Usage must be
provider/operator measured; do not estimate actual usage from text length.
Context tokens are the measured subset of input attributable to loaded
skill/reference context. If unavailable, leave usage null rather than invent
a number. Any missing usage suppresses that arm's aggregate cost ratios.
Budget breaches are recorded rather than excluding inconvenient cases.

The report is exploratory, not a proof of real-world discovery, independent
blinding, global novelty, bounty eligibility or payout. It never launches
models, sends requests or verifies provider bills. Do not publish private
receipts. Inspired by the evaluation-first idea in
[Claude-BugHunter](https://github.com/elementalsouls/Claude-BugHunter)
by Sachin Sharma; this implementation is original.
