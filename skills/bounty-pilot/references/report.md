# English report template

Title: [Impact] through [root cause] in [component]

Status: technical validity / scope / deployment / public-known-issue check.
Severity: provisional or final, with the program's rubric clause and the rationale.
Target: repository, full commit, affected file and function; chain, address and block when verified.

## Summary
Who can do what, under which realistic conditions, and who is harmed. Lead with the consequence,
not the mechanism — a triage engineer decides in the first three sentences whether to keep reading.

## Root cause
The violated property and the exact implementation behaviour, with source locations. One root cause
per report.

## Preconditions and attack path
Attacker capabilities, the reachable setup, the calls in order, and the resulting state. Name every
capability the attacker must already hold and nothing it does not need.

## Impact
Quantify what was demonstrated, separately from the theoretical maximum: what moves, how much, at
what attacker cost, to which victim. Include persistence and recovery for a denial claim, and fees,
capital and liquidity for a profit claim. State the limitations in the same section rather than
hiding them at the end.

## Reproduction
Environment and tool versions, build prerequisites, the exact command, the PoC location, the
observed log and the assertions. Explain the negative control and how unmodified production source
was preserved. No secrets, and nothing that requires attacking a live deployment.

## Deployment evidence
Chain id, address, block, and the result of the bytecode comparison against the audited artifact. If
the finding is against code that is not deployed, say so here in one sentence and label the report a
source-review finding — do not let the reader discover it later.

## Existing protections and known issues
Why the relevant guards do not stop this mechanism. If the surface appears in the program's
known-issues list, in a past audit or in a contest, link it and state exactly how this mechanism
differs. Never claim certainty about private duplicates.

## Suggested remediation
A minimal mitigation, and the invariant or regression test that should preserve it. Keep any patch
separate from the reproduction, so the reproduction still runs against the original code.

## Limitations
Unsupported assumptions, missing deployment evidence, checks not run, and what would change the
severity in either direction.

Draft only. Do not submit automatically, do not open a public issue, and do not publish the PoC.

## When every piece is individually excluded

A composition can be real while each of its parts is on the program's exclusion list. Say so, and file
it as a hardening note rather than inflating it into a claim.

The case that taught this: a dApp frontend had a link guard that compared only the last two hostname
labels, ignored the URL scheme and failed open on exception; five of the project's own config and API
origins fed unvalidated URLs into navigation sinks, one of them from the always-loaded bundle with
`cache:"no-store"`; and no route served a CSP. Individually: missing headers are excluded, out-of-scope
subdomains are excluded, and a guard with no attacker-controlled source is "theoretical without
demonstration" — also excluded. Together they mean a single compromise of any one config origin becomes
script execution on the main origin with wallet access.

So write it as what it is: the composition, each component with the exclusion that covers it, and an
explicit line saying this is **not** a bounty claim. Two things follow. The project gets something
actionable it would not otherwise receive, and your submittable records are not contaminated by a claim
triage would reject — which is what makes the rest of the report readable. Never let a hardening note
drift into the findings list to raise a count.
