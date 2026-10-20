# Target selection

The largest factor in whether a hunt finds a payable bug is chosen before any code is read. A
well-run sweep of a thoroughly audited vanilla fork returns nothing; a careless look at fresh glue
code returns something. Spend an hour here.

## What makes a target worth a week

- **Unreviewed code exists.** Code committed after the last audit, or never audited at all. This is
  measurable: `bounty.py score-target` reports the share of in-scope lines churned since the audited
  revision. A protocol whose scope is identical to its audited revision is a poor target no matter
  how large the bounty.
  **But churn measures activity, not risk, and on a well-run team it inverts.** Read the commit
  *subjects* over that delta before believing the number. In a live run a lending protocol showed
  **283 commits to the in-scope tree since its newest audit** — the thesis that selected it — and
  every one read `feat: harden…`, `fix: …edge cases`, `Feat: Removing pruning logic for greater
  position scrutiny`, each with its reasoning in the message and a matching regression test. Every
  guard the passes went looking for was already there. A hardening campaign produces exactly the
  same churn figure as a bleeding edge and is the opposite target. What actually predicts risk is
  **signs of haste**: a product shipped with no audit of its own while the repository ships many for
  other products, deployed bytecode that does not match the repository, an absent invariant suite,
  a deployment whose source was never published.
- **The custom part is the scope.** A fork's own deviation, the chain-specific adapters, the glue
  between two systems. Vanilla upstream code is audited, public and in every known-issues list.
- **The rubric prices paths, not just severities.** Read the payout table for per-path structure
  before allocating a single hour. Programs routinely split their scope into reward tiers — "Group 1"
  for the core and long-lived contracts, "Group 2" for everything else — and the same severity can be
  worth several times more in one tier than the other. In a live run the brief paid a critical a
  **$50,000 minimum** in the tier covering the older AMM and farming contracts, against a **$100,000
  cap** for the whole of the shiny new flagship system; the flagship also carried a second $1M bounty
  on another platform with 248 findings already submitted, so it had both the lower ceiling and the
  most competition. Map each tier to concrete repository paths in `scope.md`, and note that a minimum
  which applies even when value-at-risk is near zero can make an undeployed-but-in-scope defect worth
  more than a deployed one in the other tier.
- **Few eyes per dollar.** A new chain, an unfashionable language, an off-hours program, a protocol
  whose contest ended before half its code was written.
- **First-to-report.** Platforms that split or reject duplicates make your work contingent on
  strangers' timing; first-to-report programs do not.
- **No deposit, and a published rubric.** A program that states severities and payouts in writing is
  a program you can argue with.
- **A published known-issues list.** Counter-intuitive, but a long list is good news: it is a free
  dup map, and it tells you exactly where the team has already looked.
- **Live state you can read.** A deployed protocol lets you check constants, configuration and
  aggregates against the chain — evidence nobody reviewing source alone can produce.
- **A payout history that is actually measured, not a published ceiling.** Low audit coverage per
  line is a reason the *bugs* are there; it says nothing about whether the program *pays*. Both
  numbers are needed, and the second one is cheap: where the program (or a mirror of the same
  codebase on a platform) publishes lifetime totals, divide paid-out by submissions. A target with
  almost no public audits and a $25,000 advertised Critical, whose platform mirror shows **$18,500
  paid across 325 submissions** — about $57 a report — is not the target its rubric advertises.
  Read that ratio before the first pass, not after a week of work. Where no history is published at
  all, record it as unknown and price the run accordingly.

## What makes a target a waste

- Scope is a faithful fork of a heavily audited upstream, unchanged. Diff it, confirm identity,
  record that, and leave.
- Formally verified core with the verification published, and the scope is that core.
- A contest that just closed on the same revision: hundreds of hunters have read it this month.
- Known-issues list that pre-empts the entire custom surface.
- Rules that exclude the only impact class the code can plausibly suffer.
- **Two clauses to find and quote into `program.json` before the first pass**, because they decide
  findings rather than colour them: a *special-or-unrealistic-conditions* clause, and a
  *no-practical-impact* clause. Both are near-universal in first-party programs, and together they
  reject two whole categories a code-only sweep produces happily: a defect whose precondition the
  attacker cannot create, and a defect that is latent because the triggering state does not exist
  on chain. They convert into two cheap habits applied **before** any PoC. First, trace every
  storage item in the precondition to its *writers*: if the only writers are genesis and a
  root-gated call, the exploit needs specific pre-existing keys and is out of scope — in a live run
  this killed a fully verified free-extrinsic finding whose 84 reachable accounts all turned out to
  be 2017 token-sale participants. Second, separate the *arming* condition from the *loss*
  condition and measure both on chain: one pool carrying a non-zero slash armed a code path, but
  with no sub-pool actually diluted the realisable loss was zero across all 207 live pools, which
  moves the finding from live to latent and under the second clause.
- **A clause excluding every issue, closed PR, prior contest and audit.** Quote this one into
  `program.json` verbatim when present, because it is near-fatal and it is easy to read past. It
  removes the *deployed-versus-main divergence* — normally the best gap on a mature target — since
  any fix that landed on main arrives through a PR, and a `fix:` PR documents its own bug. In a live
  run a perps protocol carried exactly that clause plus "keepers are a trusted role" plus no
  rounding errors and no design choices; the measured gap was real and every single thing in it was
  excluded by one of those four. Rank a modest Critical behind a narrow exclusion list above a $1M
  Critical behind a wall of carve-outs.
- **The team runs its own red team, and ships the evidence.** Before anything else, list the
  target's own adversarial tests (see `dup-map.md`). A suite of `*PoC*` files whose names map onto
  the surfaces you were about to probe means you are not racing a six-month-old audit but a
  continuous internal programme using your method, and the easy surface is gone.
- Unverifiable payment history, or a program with no public rules at all — hunt it only knowingly.
- **In-scope contracts that hold nothing at a block boundary, in a program that pays only for
  loss of funds.** Measure this first; see `value_at_rest_usd` below. In this skill's own history
  two of the longest zero-yield runs — a bridge aggregator and a DEX router — both ended with
  every candidate confirmed as a real defect and every one unpayable, because the diamond, the
  executor, the token proxy and the aggregator each held zero or dust between transactions. The
  measurement that closed both weeks takes about a minute.
- Your own last reports on it all closed as duplicate or known; see *Duplicate risk is decided here*
  below, because the pattern repeats more reliably than it breaks.

## The facts file

Write `program.json` in the run directory from the program's own pages, and record where each fact
came from. Never infer a fact to make the score better.

```json
{
  "program": "Example",
  "url": "https://example.com/bug-bounty",
  "rules_read_at": "2026-10-08",
  "platform": "self-hosted",
  "deposit_required": false,
  "duplicate_policy": "first-to-report",
  "payout_max_usd": 100000,
  "payout_groups": [
    {"name": "Group 1", "paths": ["projects/v3-core/", "projects/masterchef-v3/"], "critical_min_usd": 50000, "critical_cap_usd": 1000000},
    {"name": "Group 2", "paths": ["src/"], "critical_min_usd": 20000, "critical_cap_usd": 100000}
  ],
  "severity_rubric_url": "https://example.com/bug-bounty#severity",
  "in_scope_paths": ["src/"],
  "excluded_impacts": ["DDoS on UI/API/RPC", "economic attacks requiring a large price move"],
  "audited_revision": "<exact commit the last audit covered>",
  "audit_reports": ["https://..."],
  "known_issues_count": 12,
  "public_audit_count": 109,
  "value_at_rest_usd": 0,
  "pays_non_fund_impact": false,
  "severity_denominator": {"kind": "client-share", "measured_fraction": 0.0141,
                           "source": "clientdiversity.org, read 2026-10-20",
                           "ceiling_payout_usd": 2000},
  "upstream_fork": "aave-v3",
  "deployment_addresses_url": "https://docs.example.com/contract-addresses",
  "in_scope_addresses": ["0x…", {"address": "0x…", "chain_id": 8453}],
  "chain_ids": [1, 8453]
}
```

`in_scope_addresses` and `chain_ids` bind deployment evidence to the program: once they are filled
in, `check --submission` refuses a `deployments/` record for an address or chain the program does not
list, and it always refuses a local development chain (31337, 1337) as evidence of what is deployed.

Two of those fields decide more than all the others, and both are measured, not read off a page:

- **`value_at_rest_usd` — the severity ceiling, and it is checked before you commit.** Sum what
  the in-scope addresses actually hold at a block boundary (`bounty.py value` over every one of
  them; it returns token units, so apply a spot price and record where it came from — stablecoins
  need no lookup and the threshold is coarse). Every loss-of-funds severity you can claim is bounded by this number, so a flawless
  mechanism over an empty contract pays nothing. Below 100k USD the scorer records a
  `severity_ceiling` and forces `deprioritise` unless the rubric evidences payment for non-fund
  impact classes, which is what `pays_non_fund_impact` records. Routers, aggregators, proxies and
  executors are the common trap: they move very large volume and hold nothing between
  transactions, so a TVL figure from a dashboard is the wrong number — read the balances.
- **`public_audit_count` — eyes already on the code.** Count the published reports. Twenty or more
  costs the target 20 points: every mechanism in the custom surface has been read by paid
  auditors, so expect duplicate or intended-behaviour verdicts and hunt only the post-audit delta
  and the live configuration. Keep the report *text*, not just the count — it becomes the dup
  corpus, and a corpus has caught a candidate as an acknowledged duplicate before a fee was spent.
  Note this pulls against `known_issues_count`, which scores positively: a short known-issues list
  is a free dup map, a large audit corpus is a crowded room, and a target can be both.

Then:

```sh
python3 <skill-dir>/scripts/bounty.py score-target --repo <checkout> --program <run>/program.json
```

The score is a reading order over targets, not a prediction. It reports its own unknowns, and an
unknown is a question to answer, not a reason to round up. `band: deprioritise` on a program you
have a specific reason to hunt is fine — write the reason down, so the next scan can check whether
it held.

## What the payout is proportional to — measure it before reading code

`payout_max_usd` is what the page advertises. `severity_denominator` is what you can actually
reach, and on some programs the two are far apart because the rubric multiplies every severity by a
fraction you cannot change. Record it as an object:

- `kind`: `client-share`, `market-share`, `usage-share` or `window-specific` when the ceiling is a
  share of something; `fixed-usd`, `value-at-risk` or `impact-class` when the mechanism you find
  sets the band.
- `measured_fraction`: the share, measured and dated, not estimated.
- `source`: where you read it.
- `ceiling_payout_usd`: the highest payout actually reachable at that share, from the program's own
  ladder. This is the number that does the work; the fraction is its evidence.

`score-target` forces `deprioritise` when a shared denominator leaves under 10,000 USD reachable,
and **`pays_non_fund_impact: true` is no escape from it** — a share denominator multiplies the
non-fund classes too. That is the difference from the value ceiling, and it is the whole point: a
rubric graded on a client's share of the network caps a chain-split finding exactly as hard as a
griefing one.

This came out of three consecutive zero-yield runs on one client family. The mechanisms were real,
two were reproduced on a live binary, and the ladder capped all of them at Low because the client
held 1.41% of the network — about 2,000 USD, decided before a line of code was read. **On a
share-denominated ladder the band is chosen by target selection, so measure the share first and
prefer the spec, or a dependency every implementation shares, over any single implementation.**

## Duplicate risk is decided here, not at submission

The dominant cause of loss across recorded hunts is not a wrong finding, it is a correct one
somebody had already filed. Morpheus closed all six reports as *reported multiple times / known* —
one of them a verified High that had passed the full submission gate. Ledger returned DUPLICATE on
four findings demonstrated end to end in a real build. Chainflip paid nothing on three. In every
case the evidence that would have predicted it was available before the week was spent, and in
every case it was gathered after.

So `score-target` reports two facts beside the code ones:

- **Your own prior outcomes on this project**, read from the private ledger: counts by outcome and
  the most recent few. A program whose last reports from you all closed as duplicate is a worse
  target than its payout suggests, and the next one is likelier to join them than to be the
  exception. An **empty ledger is reported as an unknown** — it means you have no record here, not
  that the ground is clear, and it is never scored as a good sign.
- **The count of review artifacts the repository ships.** A target carrying ten published audits is
  more farmed than one carrying none: every issue in them is a surface already read, by someone
  paid to read it, before you opened the repository. Squads v4 ships ten, and the rule that came
  out of that hunt is one line — **select by audit coverage, not by prize.**

Neither number vetoes a target, and neither is a prediction. Both change what a payout is worth: a
high cap on a heavily reviewed program with a duplicate-only history behind it buys a worse hour
than a modest cap on unreviewed glue. Both are then acted on at Stage 1 — the artifacts are
enumerated and accounted for by `audit-inventory` (`intake.md`), what they already burned becomes
`dup-map.json`, and what you already sent this program is bulk-imported into the ledger
(`dup-map.md`).

## Keep the outcome

For each submitted report, record its disposition in the private history after submission and again
when the program decides it:

```sh
python3 <skill-dir>/scripts/bounty.py history record --run <run> --finding BP-001 \
    --outcome submitted --program "Cantina / Example" --hours 4
python3 <skill-dir>/scripts/bounty.py history record --run <run> --finding BP-001 \
    --outcome paid --case-id <id-printed-by-first-command>
python3 <skill-dir>/scripts/bounty.py history summary
```

Use `history import` to seed previous reports from concise, verified metadata — and
`history import --from-file` to load a whole platform export at once before a hunt starts
(`dup-map.md`). Keep target-level
effort for hunts with no submissions in a separate private note. Compare counts by target shape,
bug class, lens and disposition; they describe your recorded sample and do not forecast future
acceptance or payment.
