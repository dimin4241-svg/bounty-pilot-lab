# Writing the report

Write it in English, as one hunter writing to one engineer who will decide in about ninety seconds
whether to keep reading.

## Why the voice matters now

Programs are drowning in machine-written reports. One first-party program says so on its own front
page — delays in triage, caused by LLM-generated submissions — and practitioners report the same
thing from the other side: AI is pushing duplicate rates up and triage queues out. A report that
*reads* as generated gets skimmed, batch-closed, or parked behind the ones that do not, whatever is
actually in it.

So this is not a style preference. The report has to read like a person who did the work, because
that is the signal a triage engineer uses to decide what to read first. **Everything below is about
removing the tells, not about adding personality.** No jokes, no voice, no padding either.

## The tells, and what to write instead

| Tell | Write instead |
|---|---|
| "I hope this message finds you well." | Nothing. Start with the bug. |
| "## Executive Summary" over three sentences | No heading. Just the three sentences. |
| "This report details a critical vulnerability which could potentially allow…" | "An unprivileged caller can drain the fee pool. Here is how." |
| "It is important to note that…", "It should be emphasized…" | Delete the phrase; keep the fact. |
| "This could potentially lead to possible loss of funds." | "The attacker keeps the 4.2 ETH. I ran it." |
| "Comprehensive analysis", "robust solution", "leverage", "utilize", "delve into" | "I read", "a fix", "use", "use", "look at". |
| Bold on half the sentences, emoji section markers, `🔴 CRITICAL` | Plain text. One bold phrase per section at most. |
| A table with one row, or a table for two facts | A sentence. |
| The same impact restated in Summary, Impact and Conclusion | Say it once, in the first paragraph. |
| "In conclusion," / a Conclusion section | End at the last fact. |
| Every section filled because the template has it | Drop a section you have nothing to put in. |
| Nine findings bundled into one report | One root cause per report. |

Two more that matter more than the rest:

**Hedging.** "may", "could potentially", "appears to" in the impact sentence reads as a model
covering itself. If you ran it, say what happened. If you did not, say that plainly — "I did not
test this against the deployed contract" is credible; "this could potentially affect deployed
instances" is not.

**Confidence you have not earned.** The opposite failure. Do not write Critical because the
mechanism is interesting; write the severity the program's own rubric gives for the impact you
demonstrated, quote the clause, and let them upgrade it.

## What it looks like

Short sentences. Active voice. First person for what you did: "I forked mainnet at block 21402111
and ran the test below." Past tense for the work, present tense for how the code behaves. Numbers
instead of adjectives. The file and the line, every time you say something about the code.

Keep the whole thing under about two pages of prose. Length is not thoroughness; the PoC carries
the proof, and it is on the gist.

## Structure

Use these as needed, in this order. Drop what does not apply; do not pad.

**Title.** `[Impact] via [root cause] in [component]` — the impact first, because that is what gets
read.

**One opening paragraph, no heading.** Who can do what, under what conditions, and who loses. Three
or four sentences. This is the whole report for most readers.

**The bug.** The violated property and the code that breaks it, with file and line. One root cause.
Quote the three or four lines that matter, not the whole function.

**Attack path.** The capability the attacker starts with and nothing more, then the calls in order,
then the resulting state. If a precondition has to be created, say who creates it and how.

**Impact.** What you demonstrated, with numbers, separated from the theoretical maximum. Attacker
cost, victim, whether it persists, whether anyone can undo it. Put the limitations here, not in a
footnote at the end.

**Reproduction.** The link to the unlisted gist, the exact command, the tool versions, the commit
it ran against, and what the output shows. Say that the PoC runs against unmodified source, and
what the negative control does.

**Deployment.** Chain, address, block, and the result of comparing the deployed bytecode with the
artifact. If the code is not deployed, say so in the opening paragraph instead — not here, where it
reads as something you hoped they would miss.

**Why the existing guards do not stop it.** Name them and say why. If the surface is in a known
issues list, a past audit or a contest, link it and state exactly how this mechanism differs. Never
claim anything about private duplicates.

**Fix.** The minimal change, and the regression test that would keep it fixed. Keep the patch out
of the PoC so the PoC still reproduces.

## Attach the proof, do not paste it

Before the report goes out, run `poc-bundle --run <run> --finding <id> --publish`. It packs the
test, the log it printed and the paired-runner result, refuses outright if any of them carries a
credential shape, and creates an **unlisted** gist. The report links it.

Three things about that gist, all of which have cost somebody something:

- **Unlisted is not private.** Anybody with the URL reads it. The link goes in the private report
  and nowhere else — not in an issue, a forum post, a screenshot or a tweet.
- **Delete it when the finding is triaged or closed.** `poc-gists.json` holds the exact command.
  An unfixed vulnerability with a live PoC URL is a disclosure with extra steps.
- **A gist has no directories.** Paths are flattened and the generated README carries the original
  layout, so the reader can map a file back to the run.

Never paste a long PoC into the report body. A triage engineer wants to run it, not read it.

## Before you send

- The opening paragraph names the impact and the actor, with no hedging.
- Every claim about the code cites a file and a line, and `verify-anchors` passes.
- Severity quotes the program's rubric clause.
- Every number in the report was re-derived from the artifact, not copied from your notes.
- Limitations and what you did not test are in the report, not omitted.
- The gist is published, unlisted, verified file-for-file, and linked.
- Nothing in the report or the gist contains a credential, an endpoint with a key, or a private
  address.
- You have read it once as the engineer receiving it, and cut the sentences that said nothing.

Draft only. Do not submit, do not open a public issue, and do not contact the project unless the
user says to.

## When every piece is individually excluded

A composition can be real while each of its parts is on the program's exclusion list. Say so, and
file it as a hardening note rather than inflating it into a claim.

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
