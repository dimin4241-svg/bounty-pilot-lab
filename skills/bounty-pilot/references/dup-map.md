# The duplicate map — built before the first pass

A bounty pays for a bug nobody has reported. Most of what a competent sweep finds on a mature
protocol is already public: in the program's own known-issues list, in its audit reports, in a
contest's published findings, in a closed GitHub issue, in the docs as acknowledged behaviour.
Discovering those again costs a pass and, filed, costs reputation with the program.

So the map is built **first**, and it burns surfaces before anyone reads code for bugs.

## Sources, in order of authority

1. **The program's own known-issues or out-of-scope list.** Highest authority: the team is telling
   you what it will reject. Read every line and record it, including the ones that sound like real
   bugs — especially those, because they are the tempting ones.
2. **Published audit reports** for this protocol, with their exact reviewed revision. A finding
   fixed at a later revision is still a dup signal for the mechanism; check whether the fix landed.
3. **Public contest results** (Sherlock, Code4rena, Cantina and similar), which publish every valid
   finding and often the invalid ones.
4. **The upstream's public issues** when the target is a fork: upstream's known bugs are not novel
   here either.
5. **Closed issues, PRs and release notes** in the target repository: a PR titled "fix rounding in
   redeem" names a class the team already handled.
6. **Post-mortems** of protocols running the same fork.

Record retrieval dates. A known-issues list is edited, and the version you read is the one you were
judged against.

## Harvest the closed issues first

Source 5 is the one that is skipped, and it is the one that kills reports. A team that has already
judged a mechanism says so on a closed issue, under a label: `wontfix`, `known issue`, `by design`,
or the name of the firm whose report it imported. `liquity/bold` issue #506 carried `ChainSecurity`
and `wontfix`, and the competition page linked the `label:wontfix` query as out of scope.

```sh
python3 <skill-dir>/scripts/bounty.py dup-harvest --run <run>
# inside a network-free environment, or for a non-GitHub host:
python3 <skill-dir>/scripts/bounty.py dup-harvest --run <run> --from-file <saved-search.json>
```

It reads the repository's own label list, keeps the labels that mean *already judged*, searches
closed issues and PRs for them, and writes `dup-harvest.json`. It never writes `dup-map.json`:
mapping an issue to a surface and a bug class is judgement, and an entry invented from an issue
title burns a surface that was never burned.

Then triage **every** candidate in `dup-harvest.json` under `triage`, keyed by its `ref`:

```json
"triage": {
  "#506": {"disposition": "in-map", "entry_id": "KI-004"},
  "#771": {"disposition": "irrelevant", "note": "frontend build flake, no contract surface"}
}
```

`in-map` names the `dup-map.json` entry the issue became, and the gate checks that id exists.
`irrelevant` needs a reason. The submission gate blocks while any candidate is untriaged, and
while the harvest stopped at `--limit`. Labels are a filter, not a guarantee: a judged issue
carrying no label is not in the harvest, so read the closed-issue list for your surfaces too.

Unauthenticated GitHub search allows only a few queries a minute. Export a read-only token and
name its variable with `--token-env`; the value is never printed or written to the run.

## Format — `dup-map.json` in the run directory

`id` is required and unique: it is the name a finding's `dup_review.entry_ids` cites, and the
gate uses it to check that every collision was actually reviewed.

```json
[
  {
    "id": "KI-001",
    "kind": "program-known-issue",
    "source": "https://github.com/<org>/bug-bounty#known-issues (read 2026-10-08)",
    "surfaces": ["src/oracle/PriceOracle.sol:latestAnswer", "src/oracle/DualFallbackOracle.sol"],
    "bug_classes": ["oracle-staleness"],
    "note": "team states staleness is accepted for this feed; deprecated market"
  }
]
```

`kind` is one of `program-known-issue`, `past-audit`, `contest-finding`, `docs-acknowledged`,
`public-disclosure`. `surfaces` uses the same `path:Contract.function` spelling the hunt agents
emit, because the join is mechanical:

```sh
python3 <skill-dir>/scripts/bounty.py dup-check --run <run-directory>
```

That reports every finding whose surface and bug class were already burned, as `class-match`
(same surface and same class) or `surface-only` (same surface, different or unlabelled class).

## What a collision means

A collision is **not** an automatic drop. It means: before this goes anywhere, state in the record
how your mechanism differs from the published one. Three outcomes, and all three are legitimate.
Each one is a `dup_review.status` on the finding, with the `entry_ids` it was compared against and
a `rationale`:

- **Same mechanism** (`same-mechanism`) → mark the finding `refuted` for submission purposes with
  the dup source as `rejection_reason`, and keep it in the file. It is coverage, not waste. The
  gate refuses to submit it.
- **Same surface, different mechanism** (`different-mechanism`) → keep it, and write the difference
  into the report. This is common and valuable: teams burn a surface with one sentence and leave a
  second bug sitting there.
- **Same mechanism, different consequence** (`different-consequence`) → keep it only when the new
  consequence changes severity materially, and lead the report with the consequence rather than the
  mechanism.

`no-match` is for a finding the join did not hit at all, and it carries no `entry_ids`. Claiming it
over a collision fails the gate.

## The gate

`check --submission` blocks unless, for every submitted record:

- `dup-harvest.json` exists, was not truncated, and every candidate is triaged;
- `dup-matches.json` exists and is **fresh** — same `run_id`, same candidate mechanisms, same map.
  A map that grows after the join invalidates it, because the new entry was never compared;
- the record carries a `dup_review` that is not `unchecked` and not `same-mechanism`, and whose
  `entry_ids` cover every collision `dup-check` reported for it.

A join against a map that does not validate is never written, so a broken map cannot be certified
by running the command.

## The limit of this map

No public search proves there is no private duplicate. Another hunter may have filed yours an hour
ago, and self-hosted programs rarely publish their queue. `no-public-match-found` is the strongest
claim the evidence supports; never upgrade it to "original" in a report.
