# Relationship to pashov/skills `solidity-auditor`

Read this before deciding whether to run Bounty Pilot's own hunt passes, `solidity-auditor`, or
both. The honest answer is usually both, in a particular order. Observations below are from
`solidity-auditor` v4.1; check the version you have installed before relying on them.

## What `solidity-auditor` does

One invocation dispatches twelve specialist agents in parallel, each given the whole in-scope
Solidity source plus a senior-auditor reasoning file, its own specialty file, shared output rules and
report-language rules. Nine agents are single-lens (math and precision, access control, economic
security, execution trace, invariants, periphery, first principles, asymmetry, boundaries) and three
hunt the seams between lenses (flow, numerical, trust). Loop mode runs N such passes — three by
default — and feeds each later pass the bug classes earlier passes already found, deduplicating on a
`Contract | function | bug_class` key and persisting across scans in a ledger. Findings are then
judged against four gates, scored for confidence against a 75 threshold, and assembled into one
report, with explicit lists of safe patterns and things not to report.

**It is very good at generating candidates.** The breadth of lenses, the parallel independent
contexts, the three seam agents, the "deepen the attack, never refute your own finding" stance and
the cross-contract weaponization rule are the right machinery for recall, and Bounty Pilot's own
lens set does not replace it on Solidity.

## What it is not built to do

It audits a repository. A bounty submission is a claim about a **deployed** system inside a
**program's rules**, and that is a different object:

| Needed for a payable report | `solidity-auditor` | Bounty Pilot |
| --- | --- | --- |
| Program rules, scope and exclusions | not modelled | `intake.md`, `targets.md`, gate 5 |
| Deployed code is the code you audited | not checked | `verify-deployment`, EIP-1967 resolution |
| Known issues and public findings burned first | not checked | `dup-map.md`, `dup-harvest`, `dup-check` |
| Priority on code the last audit never saw | all code equally | `delta`, `delta-agent` |
| Constants and config checked against the chain | source only | `live-reality-agent`, `eth-call` |
| A runnable PoC with a negative control | reasoning trace | `evidence.md`, `templates/` |
| Novelty search with cited sources | not performed | stage 6 |
| Non-EVM targets | Solidity only | Rust/Solana route, `anchor-account-agent` |

Two more differences matter in practice. Its confidence number is self-assessed by the model that
produced the finding, so a 90 means the agent was convinced, not that anything executed — Bounty
Pilot's `verified` requires a command, an exit code, a log and a negative control. And its
generation stance deliberately suppresses self-refutation, which is right for recall and must be
paid for by a real adjudication pass afterwards, or the report arrives at the program full of
confident candidates that a triage engineer kills in one reading.

## When it is not installed

Bounty Pilot's own `attack` group does not replace twelve specialists. Its `classic` lens carries the
classic sweep as one reading (Part B of `hunt-agents/classic-agent.md`) so a run without
`solidity-auditor` still asks the standard questions, but expect lower recall on those classes and
say so in `coverage.md`. On a Solidity target worth a week, installing it is the cheaper fix.

## Recommended combination

1. **Bounty Pilot stages 0–2.** Choose the target, read the program rules, build the dup map, verify
   what is deployed, run `delta` and `impact-plan`. Nothing is read for bugs yet.
2. **Run `solidity-auditor` in a disposable copy of the checkout**, at the revision you recorded. It
   scans the working directory and writes `.solidity-auditor/` into it, and the target checkout must
   stay clean. Pass `--loop 3` (or another number): without a pass count it stops at an interactive
   question, which an orchestrated run cannot answer.
3. **Aim it with file names, not prose.** It has no input channel for a ranked list or a dup map:
   its agents receive bundles assembled by shell from fixed files. What it does accept is a list of
   files — `$filename ...` mode scans exactly those. Name the top of `delta.json` and the files that
   `impact-paths.json` and `odd-one-out.json` point at. A default scan of everything is fine on a
   small codebase.
4. **Run Bounty Pilot's own lenses that it does not have** — `delta`, `upstream-diff`,
   `coverage-gap`, `live-reality`, `accounting` (as writer enumeration), `integration-auth`,
   `liveness`, `classic` Part A (post-2023 EVM semantics it does not cover: EIP-7702, L2 sequencer
   checks, Permit2), and `anchor-account` for non-EVM. These are aimed at axes outside its lens set:
   time, lineage, observability, live truth, and the authorization of parameters rather than callers.
5. **Import its output as hypotheses, not findings:**

   ```sh
   python3 $S import-findings --run <run> --from <copy>/.solidity-auditor/runs/<stamp> --repo <checkout>
   ```

   It reads both the raw agent blocks (`FINDING | contract: … | function: … | bug_class: …`) and
   the persisted run and report files (`<!--F key=contract|function|bug-class … kind=FINDING-->`),
   maps each contract to the file that declares it, and writes `status: hypothesis` records with an
   `origin` and empty evidence. Its confidence score is not evidence and is not copied. Imported
   records show in `queue` as `imported_untriaged` until a hunter or triage pass has worked them.
   `converge` reads the same formats, so its readings can count toward convergence too.
6. **Adjudicate everything together** with `adjudicate.md`, then verify survivors with a real paired
   PoC, then `dup-harvest`, `dup-check` and `check --submission`.

Do not nest the two orchestrators — do not ask `solidity-auditor` to run Bounty Pilot's passes or
the reverse. Both are multi-pass loops; nesting multiplies cost and makes coverage unreadable.

## Note on its artifacts

`solidity-auditor` writes `.solidity-auditor/` — run files, a report and, with memory on, a findings
ledger — into the directory it scans. That is why it runs in a copy. That path is already in this
repository's `.gitignore`; never commit a findings ledger to a public target repo.

## Also in the same family

`x-ray` (pre-audit readiness: threat model, invariants, git history) is a reasonable substitute for
parts of Bounty Pilot stage 2 on Solidity targets. `fizz` (Echidna/Medusa invariant suites) is the
quickest route to the invariant campaign Stage 5 makes standard on high-value targets: a broken
invariant with a shrunk call sequence is strong evidence, and replaying that sequence as a
deterministic test with a negative control turns it into a submittable PoC. Record the exact commit
you ran either at, and normalise whatever they produce through this workflow's gates.
