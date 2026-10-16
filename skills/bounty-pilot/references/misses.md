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
not describe what a test would have shown. Do not claim an exit code you did not observe.

## 14. Did you drop anything silently?

Every lead you opened should end as a candidate, a refuted record with an anchor, or an
`open-needs-experiment` entry in `known-hypotheses.md` with the next step. A trail that exists only
in your reasoning is lost work, and the next pass will pay to rediscover it.

## 15. Is your claimed coverage real?

List what you did **not** read: files, branches, dependencies, configurations. An audit that reports
honest partial coverage is more useful than one that implies completeness; and the unread list is
where the next pass aims. Which lenses did you actually dispatch, and how many readings each?

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

## 24. Did you verify the blocker, or inherit it?

Every "cannot build", "no archive access", "tool unavailable" in the run record is load-bearing: later
passes read it as closed ground and stop trying. So a wrong blocker deletes a surface silently, and it
is the one claim nobody adversarially reviews. Reproduce each one yourself, paste the command and the
output, and spend one minute on the hypothesis that the cause is your own setup — a package manager
reaching the public registry for a sibling that only exists locally means you copied one subproject
out of a monorepo, not that the project cannot be installed. When a blocker is lifted, record which
pass wrote it and what the real cause was. A blocker survived three passes in one live run and cost
every test against the highest-paying contracts in scope.

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
