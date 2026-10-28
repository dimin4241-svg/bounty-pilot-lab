# Where hunts stop short

Run this against **your own output** before you report anything, including before reporting that you
found nothing. Each item is a failure that has a cheap fix, and most of them are the difference
between a finding and a near-miss rather than between effort and no effort.

Answer every question in writing. "Probably fine" is not an answer to any of them.

## 1. Did you conclude anything from a name?

This is the single most measured weakness of automated reviewers: **they reason from identifiers
instead of from behaviour.** It cuts both ways — a false finding because a variable is called
`totalDebt`, and a missed finding because a modifier is called `onlyOwner` and was never read.

For every conclusion you reached, in a finding *or* in a "this is safe", name the lines you actually
read. Specifically re-check: anything called `safe*` that may not check a return value; `onlyX` that
may compare the wrong variable; `total*` that may not be the total; `is*`/`has*` flags that some
public function writes; `_internal` functions reachable externally; a `validate*` that returns a
bool nobody checks.

## 2. Did you stop at the first consequence?

For each finding, write the chain: broken thing → the value it corrupts → the decision made from
that value → who loses what. If your impact sentence ends at the broken thing, you are filing at a
lower class than the code earns. Then check `impact-classes.md` and place it deliberately.

## 3. Did you put numbers on it?

If the mechanism involves price, liquidity, rounding, caps or profit, the report needs: capital
required, cost of the manipulation, gross extraction, net result, and the live values behind each.
Read them — `eth-call` and `value` take seconds. "The attacker profits" is a placeholder, and triage
reads it as one.

## 4. Did you skip the privileged path because a checklist told you to?

"Do not report admin can rug" means *the admin behaving badly*. It does not mean skipping how an
**unprivileged** actor reaches privileged power. Access control and initialization are the two
categories automated reviewers miss most, and the most expensive incidents live there. Did you check
initializers, the implementation behind the proxy, role-granting paths, and what every guard
actually compares against — live?

## 5. Did you read the dependency, or trust it?

The bug is often in the integration's assumption about a framework, and provable only from the
framework's own source. Did you open the messaging layer, the token, the router, the oracle, the
base contract — or did you stop at the interface? `lib/` being out of scope makes it unreportable,
not safe.

## 6. Did you check what is actually live?

Constants against real feeds. Hardcoded addresses against what is deployed there. Caps and fees
against current values. Owner and implementation slots against the docs. Whitelists against whether
they are populated. Pause flags. A guard that is correct in source and disabled in production is a
finding; a guard you assumed is disabled and is not is a wasted report.

## 7. Did you check the compiler?

`solc-bugs --repo <checkout>`. Two nine-figure-adjacent incidents came from compiler versions, not
contracts: a malfunctioning reentrancy guard in specific Vyper versions, and an old contract
compiled without overflow checks. Takes one command.

## 8. Is the revision you reviewed the revision that is deployed?

Not HEAD — the revision at the **in-scope addresses**. Programs pin scope to deployed contracts, and
a repository's main branch is frequently ahead of or behind them. Run `verify-deployment`, and for a
proxy compare the implementation. Reporting against code that is not deployed is the most common
single reason a technically correct report is rejected.

## 9. Did you look for the siblings?

The same mistake is nearly always copied: the paired function, the second market, the other
collateral, four adapters with one hook, and **the same contract on another chain with one value
configured differently**. One instance is a bug; five is the same bug with five times the exposure,
and exposure is how severity gets argued.

## 10. For anything that reverts or blocks — did you establish persistence?

Trigger, who is affected, one-time cost, and whether it clears by itself, by a keeper, by an admin
function you **read**, or never. A revert with no persistence analysis is not a finding and will be
closed as one.

## 11. Did you check it is not already known?

Program known-issues list, past audits, contest findings, closed issues and PRs. `dup-harvest`
retrieves the closed issues the team already judged and `dup-check` does the join. If the surface
collides, is your *mechanism* different, and did you write the difference down in `dup_review`?

## 12. Did you write prose where one command would have settled it?

For every `needs-evidence` record, name the cheapest decisive experiment and ask why you did not run
it. Order of preference: a live read, then a fork test at a pinned block, then a local deployment,
then analysis. Agents routinely reason for pages about a question that one `eth-call` answers.

## 13. Did a toolchain failure become a narrative?

If the build or test runner failed, say so plainly and switch to a cheaper decisive experiment. Do
not describe what a test would have shown. Do not claim an exit code you did not observe. Write the
failure as a `blocker` object with the `command` and the `output_excerpt` that produced it, not as a
sentence — see item 24.

## 14. Did you drop anything silently?

Every lead you opened should end as a candidate, a refuted record with an anchor, or an
`open-needs-experiment` entry in `known-hypotheses.md` with the next step. A trail that exists only
in your reasoning is lost work, and the next pass will pay to rediscover it.

## 15. Is your claimed coverage real?

List what you did **not** read: files, branches, dependencies, configurations. An audit that reports
honest partial coverage is more useful than one that implies completeness; and the unread list is
where the next pass aims. Which lenses did you actually dispatch, and how many readings each?

Do not answer this from memory. `coverage-floor --repo <checkout> --run <run>` writes
`coverage-floor.json`: the in-scope files against the ones your `coverage.md`, `known-hypotheses.md`
and `findings.json` actually name, with the examined fraction and the unexamined list. A run may not
call itself exhausted over an unread majority — on one target a hunt was closed after eight
contracts and nothing compared that against the file list. The unexamined list is the answer to this
item; paste it.

Then go one level down: `function-coverage --run <run>` lists every external entry point and the
ones no record or coverage row names. A file counted as read can still hide thirty entry points
nobody looked at, and the unexamined list is ranked so that the functions that write state or move
value come first. A directory row (`src/`) credits nothing toward either floor. Inherited functions
count at the contract that deploys them, so an upgrade or ownership entry point inherited from a
library is on the list until someone names it; read-only inherited functions are left out. A
surface with an argument list credits one overload; `ambiguous_surfaces` and `unparsed_surfaces` list
what credited nothing, and a `stale` result must be rerun.

## 16. Did you let an unanchored objection kill a finding?

Re-read every record you refuted. Does `rejection_reason` quote code, a specification, a test or a
live read? If it says "probably intended", "the deployer would set it correctly" or "no attacker
would bother", the refutation is invalid — reopen it. A wrongly refuted finding is invisible, which
is exactly why it needs a deliberate second look.

## 17. Did you read the tests?

Not for coverage percentages — for intent. A mock that cannot distinguish two inputs, a test that
asserts only "did not revert", a hardcoded expected value with no derivation, a skipped test, a TODO
on a validation path. These are the authors telling you what they did not check.

## 18. Did you read the program's whole scope?

Many programs include websites, APIs, infrastructure and off-chain components, often at real
severity and with far fewer competent competitors than the contract scope. Did you check, or did you
assume it was a Solidity-only hunt?

## 19. If you found nothing — is that a result or a gap?

A zero-finding run is legitimate and useful **if** it says which surfaces were closed and on what
evidence. "I reviewed it and it looks fine" is not that. Which lenses ran, which surfaces are closed
with reasons, which leads are open with next steps, and what you could not reach.

## 20. Would you pay for this report?

Read it as the triage engineer: first three sentences, then the reproduction. Does it say who can do
what, to whom, for how much, and how to see it happen? If the first thing it does is explain the
code, rewrite it.

## 21. Did you read the controls that have no source file?

Peers and trusted remotes, the verifier set and thresholds, oracle feed registries, role holders,
timelock delays, caps and rate limits, pause flags, the implementation behind each proxy. None of
these appear in a diff, so no reviewer before you has read them. Enumerate **every** destination,
market and chain and compare the configurations against each other — the bug is almost never a
missing control, it is one corridor configured differently from its five siblings.
`references/blind-spots.md` has the enumeration and how to record a clean result.

## 22. Did you recompute the derived constants?

Every literal that is the output of a formula — ERC-7201 namespace slots, domain separators and
type hashes, selector constants, precomputed CREATE2 addresses, merkle roots — gets read as a name
and never as a value. One `cast keccak` per constant settles it, including the trailing characters
of the namespace string. Colliding namespaces alias two structs onto one storage slot.

## 23. Did you look for the odd one out, or only for what is wrong?

In a mature, heavily audited codebase the bug is the inconsistency, not the mistake. Tabulate the
handlers in a dispatch, the implementations of an interface, the call sites of a helper, the same
contract on each chain — then read the one that differs. See `references/blind-spots.md`.
For Solidity the first table is already built: did you read every entry of `odd-one-out.json` and
record in `odd-one-out-review.json` why each asymmetry is intended — with a quoted anchor — or not?

## 24. Did you verify the blocker, or inherit it?

Every "cannot build", "no archive access", "tool unavailable" in the run record is load-bearing:
later passes read it as closed ground and stop trying, and it is the one claim nobody adversarially
reviews. So check them as claims. Does each `blocker` carry a `command` and an `output_excerpt`, or
only a `claim`? Run `queue --run <run>` and treat everything under `unverified_blockers` as an open
surface rather than a closed one: reproduce it, or drop it and read the code. Then read it against
`capabilities.json` — a probe that found the toolchain, the root manifest and its workspaces, or an
archive deeper than the blocker assumed, settles the question in one command. When a blocker is
lifted, record which pass wrote it and what the real cause was. `references/blind-spots.md` §8 has
the case that cost three passes over the highest-paying contracts in a scope, and `evidence.md` has
the field shapes.

## 25. Did you calibrate the number before you concluded from it?

Any derived quantity — a price, a decimal-adjusted ratio, a threshold, a share — gets one
known-answer check before it is allowed to support a conclusion. Price fields in particular come in
reciprocal pairs (`token0Price` / `token1Price`), and nothing in the value says which direction you
have. In a live run an inverted pair produced a clean-looking table naming three live pools as
vulnerable; the error surfaced only when a reference pair whose true value is public was run through
the same formula and came out as its own reciprocal. Pick the pair you already know the answer to,
push it through the identical code path, and only then read the table. The same applies to units: wei
versus whole tokens, and a `10**(dec1-dec0)` factor, are where a plausible figure becomes an
impossible one.

## 26. Did you confirm the address *is* the contract before believing what it holds?

Severity is argued from balances, so a wrong address invents or deletes impact. In one run a
balance sweep reported **120,381 USDC and 62 WETH** on what it had labelled `ERC20Proxy` — a
contract whose own balance should always be zero. That read as a half-million-dollar finding. The
address was a **Uniswap V3 pool**, typed from recall rather than read from
`deployments/mainnet.json`. The tell cost ten seconds: `cast code` returned 23KB where a 60-line
proxy should return 2.5KB, and the selectors decoded to `fee()` and `ticks()`.

Rules that follow:
- Every in-scope address comes from the project's own deployment artifacts or the program's scope
  page. Never from memory, and never from an earlier message in the same session.
- Before quoting a balance or an allowance as impact, prove identity on the same chain you read the
  value on: a function only that contract has (`owner()`, `authorizedCallers(address)`), or code
  size plus two decoded selectors. A revert on the identity call means the label is wrong, not that
  the node is flaky.
- A balance that contradicts the contract's design — a pass-through proxy holding funds, a vault
  holding nothing — is first evidence of a misidentified address, and only second evidence of a bug.

## 27. What actually produced a confirmed finding, counted honestly

Keep this ledger, because technique improves faster than target selection and the ledger is the
only thing that says so. Across roughly fourteen targets run with this skill, two produced a
confirmed High. Neither came from the dominant activity, which was reading mature, heavily audited
Solidity for a logic bug.

- **An operational secret in a live configuration.** Publicly reachable message-broker credentials
  granted a wildcard subscription across every private user channel. No contract involved; the
  defect was in what was deployed, not in what was committed. Lens 1 in `blind-spots.md`.
- **A resource cliff above any tested scale.** Vote records sized by member count made proposals
  unwritable past roughly 106 members, permanently freezing an autonomous multisig. Rust, and the
  number exists only in the account layout. Lens 9.

What the mature-EVM attempts produced instead, each confirmed as a *real* defect and still
unpayable: duplicates of acknowledged audit findings; behaviour the project documents as intended;
and — twice, on a bridge aggregator and a DEX router — mechanisms with no severity left to claim
because the in-scope contracts hold nothing at a block boundary.

The conclusions worth carrying into target selection:

- **Measure the severity ceiling before the week, not after it.** `value_at_rest_usd` in
  `targets.md`. Volume is not balance; a router can settle billions and hold dust.
- **Count the published audits before reading code.** Twenty or more means the custom surface has
  been read by paid auditors repeatedly, and your edge is only the post-audit delta and the live
  configuration.
- **Prefer surfaces that auditors structurally cannot cover**: what is deployed rather than
  committed, what only appears at scale, and what is wired per chain. Both wins were there.
- **Being right is not the same as being paid.** Most of these runs ended with a correct technical
  claim and no eligible impact. When a finding is real but unpayable, record it `parked` with its
  `revive_if`, and do not let the correctness of the analysis argue you into a submission fee.

## 28. For a spec with several implementations — did you read what the *other* ones fixed?

When the target is one client of a shared specification, every `fix:` commit in a sibling client is a
bug report its team wrote for you, for free. The question is always the same: **does my target still
have it?** Run it as a sweep, not a hunch — list every post-release, post-fork `fix:` commit touching
the feature across all implementations, then check each sibling.

Two properties make this the highest-yield lens on such a target:

- **A fix that landed in two clients independently, within days, is a live divergence.** Two teams do
  not converge on the same patch by coincidence; they both hit it on a testnet.
- **The official test vectors frequently do not cover it.** In a live run on the Gloas upgrade, a
  Lodestar fix's own commit message said so outright: "The `should_apply_proposer_boost_withheld` spec
  vector never imports a payload for the parent so it does not reach the tiebreak, hence the unit
  test." A client can implement from the spec, pass the whole vector suite, and still carry the bug —
  which is precisely why two clients carried that one.

Worked example, start to finish in minutes: Lodestar #10339 "keep proposer boost root for the payload
tiebreak when boost is withheld" and Nimbus #9248 "don't skip payload tiebreak when boost is
suppressed" landed the same day, three days after a testnet fork. The mechanism: `should_extend_payload`
reads `store.proposer_boost_root` unconditionally, but both clients derived that root from the *applied
boost weight*, so withholding the weight zeroed the root and the head stopped at the parent's FULL
variant. Checking the siblings refuted it for both remaining implementations in one read each —
Lighthouse keeps the root in `fc_store` and reads it directly, Grandine the same — so the sweep cost
little and closed a Critical-class hypothesis with evidence instead of with a guess.

The refutation is the normal outcome and still worth the hour: it is the one lens that produces
*precise*, immediately checkable hypotheses on a mature target, instead of a reading order.

## 29. Did you compare against the spec revision the implementation pins, or only against HEAD?

An implementation of a moving specification carries its own idea of which revision it targets, often as
a permalink per function. A difference from HEAD is then two different things, and only one of them is
reportable: a divergence from the revision the client claims to implement, or an un-merged lag behind a
later spec change. For an unactivated fork the second is ordinary work-in-progress, and filing it as a
bug burns credibility.

Diff the function at the pinned revision against the function at HEAD *before* reading the
implementation. In a live run this inverted the conclusion twice over: the pinned permalink said
`v1.7.0-alpha.11` while the latest tag was `alpha.14`, so a lag looked likely — and the diff showed the
spec had changed three ways that the client had *already* implemented. The comment was stale, the code
was current, and the "it is just behind" explanation was closed before any time went into it.

## 30. Did the tool measure anything, before you believed its verdict?

`score-target` and `coverage-floor` count source files. Point either at a scope that is not source —
Markdown specifications, a multi-repository client scope, generated code that is not committed — and
they return a confident-looking verdict computed over nothing: `in_scope_lines: 0` with
`band: deprioritise`, or `examined_fraction: 0.0` with `state: below-floor`.

Before quoting a band or a floor, read the counts it is derived from. `in_scope_files`,
`files_in_scope` and `examined_by_source` are the tell: zero, or a file list that is obviously the
wrong corpus (the repository's build tooling rather than its specs), means the number describes a
format mismatch and not the target. Say which it was. The verdict may still be right for other
reasons — in that same run the dup map independently confirmed `deprioritise` for the spec surface —
but it has to be argued from the evidence that actually exists, and `unparsed_coverage_files` in the
output means the run's own notes were never credited either.

## 31. Did you gather the duplicate evidence before the work, or after it?

Item 11 asks whether the finding is already known. This one asks **when** you found out. Before the
first reading pass, did you read your own prior submissions to this program, the audit reports the
repository ships, and the team's own closed issues and PRs — or did you estimate duplicate risk by
guesswork and learn the answer at submission? That guess is the largest recorded source of loss
here: six Morpheus reports closed as known, one of them a verified High; four Ledger findings
demonstrated end to end and returned DUPLICATE; a marginfi PoC the team had already discussed in
its own PR #623; and a finding whose root cause was the hunter's **own** report from six weeks
earlier, already in a duplicate cluster on the same account.

Four commands answer it, and all four belong before the hunt, not after it: `score-target` reports
your prior outcomes on this project and how many review artifacts the repository ships
(`targets.md`); `audit-inventory` turns each of those artifacts into an accounted-for known-issue
source (`intake.md`); `history import --from-file` loads what you already sent this program into
the ledger, and `dup-harvest` retrieves the closed issues the team already judged (both in
`dup-map.md`). If any of them ran only after the reading passes, write that here — it is the gap,
not a clean answer.

## 32. Did you measure what the payout is proportional to, before you read the code?

Three consecutive runs on one client family produced real, reproduced mechanisms and nothing
payable, because the rubric graded every severity by the client's share of the network: 1.41%, about
2,000 USD, fixed before a line was read. A share denominator multiplies the non-fund classes too, so
"the program pays DoS" is no escape from it.

The fix is one field and one minute: `severity_denominator` in `program.json`
(`references/targets.md`), with the share measured and dated and the reachable payout taken from the
program's own ladder. `score-target` then sizes the run from it — under 5,000 USD reachable is a day,
not a week.

Note what this is **not**: a reason to skip a cheap target. 2,000 USD for a report that lands beats
62,500 USD for one closed as duplicate, and the "better" targets on this skill's own record paid
zero. The field answers "how long is this worth?", and only a ladder paying nothing at all at the
measured share stops a run. On a share-denominated ladder, prefer the spec or a dependency every
implementation shares over any single implementation — that is the only way to move the ceiling
itself.

## 33. Did you fetch the published reports, or only the ones the repository ships?

A finding verified on a mainnet fork, hardened through a hostile triage round and past the
submission gate, died on one sentence in an acknowledged Low-risk entry of a competition report —
a report recorded as "behind a login" because its Download button had no `href` and one guessed API
endpoint answered `401`. The file was on a public CDN the whole time, named in a field of the page's
own `/api/v0/reports/<id>` response.

A button handled in JavaScript says nothing about authorization, and a 401 on one endpoint says
nothing about the others. Pull every published report in Stage 1 and grep it
(`references/intake.md`); record a source as unavailable only with the list of endpoints tried.

## 34. Did you read the commits that promised only a cosmetic change — and could you?

Two questions, and the second one first, because it is the one that fails silently.

**Could you?** Run `git rev-list --count HEAD` and `git rev-parse --is-shallow-repository` on the
checkout you reviewed. A depth-1 or shallow clone has no history to read, so every lens that reads
commits — the predecessor-base comparison, the cosmetic-regression sweep, item 28's sibling sweep,
"read the merge request, not the changelog" — returns the same empty answer it would return from a
clean codebase, and the run writes that silence down as coverage. This is item 24 one level up: not
a harness that never fired, but a checkout that made firing impossible, and nothing was checking.
`capability-probe` now measures it as the `commit-history` evidence kind; a history lens may not
record a clean result while that kind is `unavailable`. Full history costs almost nothing —
`git clone --filter=blob:none --bare` carried 19,288 commits of trezor-firmware in 23 MB.

A live pass closed a target with "0 submittable" over a depth-1 checkout. The defect it was closing
over was live in the branch it never fetched, in a file that pass had open and quoted by line
number, and the commit that introduced it was not in the clone at all.

**Did you?** A security guard is rarely attacked; it is refactored away by someone fixing a
complaint that a value appears twice on screen, and the commit message says it changes nothing.
`cosmetic_regression.py` is the sweep: a semantic predicate (a declared path, a type check, an enum
comparison, a formatter probe) disappearing from the removed lines while a comparison against
rendered text appears in the added ones. `blind-spots.md` §4 has the worked case, the calibration
numbers and the caution about what may be written up where. The commit vocabulary alone is not the
signal — it passed 46% of commits on the calibration target — so do not ship the grep without the
diff test.
