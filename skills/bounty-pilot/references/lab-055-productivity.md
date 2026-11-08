# Lab 0.55 — PoC authoring, genuine benchmarking and research diagnosis

These tools **plan** and examine evidence. They do not run an agent, compile
a target, verify a cryptographic proof, broadcast transactions or contact a
production API. All examples use independently owned, local files. Never
send source credentials, live tokens or user data to a model.

## 1. Source-anchored PoC task for Codex/Claude on the authorized Mac

Hypothesis JSON (here \`source_anchors\` has the SHA-256 of a real local
file; do not copy the sample hash verbatim):

```json
{
  "id": "review-001",
  "stack": "solidity",
  "source_revision": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "invariant": "A failed withdrawal must not spend reserved collateral",
  "entry_point": "withdraw(uint256)",
  "attacker_capabilities": ["ordinary user of a locally simulated account"],
  "steps": ["create owned accounts", "replay candidate",
            "replay honest negative control"],
  "source_anchors": [
    {"path": "src/Vault.sol", "line": 120,
     "sha256": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}
  ]
}
```

```
python3 skills/bounty-pilot/scripts/poc_builder.py plan \
  --finding /private/hypothesis.json \
  --repo /private/pinned-target-checkout \
  --out-dir /private/poc-task-001
```

The planner rejects source-file hash drift, absent files, symlink traversal
and unsupported stacks. It creates a **deliberately failing** native test
skeleton, metadata, and \`authoring-task.md\` for manual submission to an
approved local Codex/Claude run on the Mac. It does not invoke the model.

Use a disposable, pinned copy of the actual in-scope target; the model's
generated candidate and control should use the same starting state and
must assert *observable* effects. Do not alter protected production code
just to make a PoC pass.

After running your real local tests, provide a receipt JSON with
\`case_id\`, \`source_revision\`, \`schema_version:1\`, plus
\`candidate\` and \`negative_control\` objects. Each must contain
\`status:"passed"\`, \`exit_code:0\`, the **modified test file** SHA-256 as
\`test_file_sha256\`, and a \`log_sha256\` of the native test log.

```
python3 skills/bounty-pilot/scripts/poc_builder.py check \
  --bundle /private/poc-task-001 \
  --receipt /private/test-receipt.json
```

\`check\` does NOT execute or authenticate the tests. Its highest status is
\`reported-local-pair-passed-independent-review-needed\`. An unchanged
scaffold, deliberate failure placeholders, mismatched file digest or failed
control blocks promotion. A self-reported passing log never proves a bug.
Use the existing evidence-verifier, independent reviewer and economic
oracle to evaluate real native receipts and attacker/victim delta.

Supported scaffold languages mirror existing \`poc_scaffold.py\`:
Solidity, Rust, Python and Go. Move/Anchor-specific scaffolding still
requires a native project adapter; do not label them implemented.

## 2. Blind A/B campaigns: old versus new skill

Use the *existing* \`bench_compare.py\`, \`bounty.py backtest\` and
\`evmbench_pair.py\` for actual scoring/official evaluation. The added
\`blind_campaign.py\` is an offline planner that strictly separates
two agent task directories and a private judging ledger.

Prepare a campaign manifest with exact, independently pinned vulnerable
commits, equal model/budgets and scope. It must contain **NO truth labels**:

```json
{
  "schema_version": 1,
  "baseline_skill_sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "candidate_skill_sha": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "model": "same-pinned-provider-and-model",
  "budget_usd": 10,
  "minutes_per_case": 30,
  "cases": [
    {"case": "opaque-internal-one",
     "repo_url": "https://github.com/example/project",
     "pinned_commit": "cccccccccccccccccccccccccccccccccccccccc",
     "scope_paths": ["src"]}
  ]
}
```

```
python3 skills/bounty-pilot/scripts/blind_campaign.py prepare \
  --campaign /private/bench-input.json \
  --out-dir /private/blind-campaign
```

**Do not mount the campaign directory wholesale into a hunter!** Give
each independent isolated agent ONLY its individual
\`jobs/baseline/<opaque>/TASK.json\` or
\`jobs/candidate/<opaque>/TASK.json\`, matching pinned source checkout
and skill revision; never provide \`private-judge-ledger.json\`, rival
arm output, CaseForge truth, published write-ups or PR history exposing
the answer. PREPARE does not launch a model.

Score only sealed, separately adjudicated backtest reports for the
exact same pinned cases:

```
python3 skills/bounty-pilot/scripts/blind_campaign.py compare \
  --campaign /private/bench-input.json \
  --baseline-scored /private/baseline-scores.json \
  --candidate-scored /private/candidate-scores.json \
  --out /private/benchmark-private-result.json
```

Output remains **unverified private comparison** regardless of observed
rates. At least five *independent* held-out cases, model/session/budget
receipts, proof of true blinded isolation, and outside adjudication are
needed before making any public performance claim. No measured 0.54→0.55
accuracy gain has been produced here.

## 3. Partial Rust MIR and Move/Rust normalized IR

Rust compiler's documented \`rustc --emit=mir\` can output a text MIR
artifact. **Run that compiler only in a separately approved sandbox** on
the actual pinned target. Do not compile untrusted dependency code in
GitHub-hosted CI. Given an already exported MIR file:

```
python3 skills/bounty-pilot/scripts/native_ir_flow.py \
  --rust-mir /private/target.mir \
  --source-revision aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --out /private/rust-mir-leads.json
```

The extractor conservatively traces simple MIR register assignments from
function arguments into selected sensitive call hints. The output is
\`rust-mir-partial-lexical-defuse\`, NOT full native Rust analysis:
MIR blocks, internal entrypoint vs external signer, aliases, ownership,
real access checks, persistent state, call graphs and exploitability
are not fully modeled. This distinction is especially important for
Solana/Anchor.

Move and other Rust IR can be fed as researcher/compiler-extracted
normalized directed graphs:

```json
{
  "schema_version": 1, "language": "move",
  "source_revision": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "nodes": [
    {"id": "user", "kind": "signer", "file": "sources/asset.move", "line": 10},
    {"id": "amount", "kind": "value", "inputs": ["user"],
     "file": "sources/asset.move", "line": 20},
    {"id": "transfer", "kind": "asset-transfer", "inputs": ["amount"],
     "file": "sources/asset.move", "line": 30}
  ]
}
```

```
python3 skills/bounty-pilot/scripts/native_ir_flow.py \
  --normalized-ir /private/normalized-move.json \
  --out /private/move-leads.json
```

The normalized graph is **operator-supplied** and not independently checked
against a native Move compiler. Source-to-sink paths are candidates for a
native harness, not authorization bypass findings. There is no automated
Move bytecode-to-graph importer in this release.

## 4. Why a bug did not become payable

Existing \`discovery_doctor.py\` diagnoses missing model output and parser
failures. The new \`failure_taxonomy.py\` consumes structured per-case
milestones, for example:

```json
{"schema_version":1,"cases":[{
  "id":"local-case-1","reading":"completed","candidate":"hypothesis",
  "poc":"candidate-failed","impact":"not-assessed",
  "eligibility":"not-checked","disposition":"not-submitted"
}]}
```

```
python3 skills/bounty-pilot/scripts/failure_taxonomy.py \
  --ledger /private/case-ledger.json \
  --doctor-report /private/discovery-doctor.json \
  --out /private/bottlenecks.json
```

The taxonomy separates missing reading, no candidate, failed candidate,
invalid control, unmeasured loss, unrealistic capital, out-of-scope and
duplicate. An empty hunt cannot prove a model missed a real bug without
independently identified ground truth. Paid/accepted outcomes remain
operator-ledger assertions, never verified transactions.

## 5. Offline setup wizard and environment

```
python3 skills/bounty-pilot/scripts/setup_wizard.py \
  --interactive --out /private/project-preflight.json
```

It asks for a **local** checkout, runtime and scope paths, an optional
official bounty-program URL and an optional *environment variable name*
(for example BP_FORK_RPC), NEVER the actual key, token, RPC URL or secret.

For scripted setup on owned fixtures use:

```
python3 skills/bounty-pilot/scripts/setup_wizard.py \
  --answers /private/wizard-answers.json \
  --out /private/project-preflight.json
```

The wizard checks local existence of scope files and presence of runtime
CLI binaries. It neither installs packages nor considers a project
authorized merely because a URL exists. Native tools (Foundry/Cargo/etc.)
must be separately pinned, installed and checked by the operator.

The optional \`.devcontainer/devcontainer.json\` is a **Python-only**
convenience environment, not a hermetic/frozen full audit toolchain:
its image tag can move and it does not supply Foundry, Solana or Move
VMs. Existing \`sandbox_run.py\` insists on an explicitly trusted
local Docker image pinned by immutable digest for real isolated tests.

## What 0.55 does not do

* No automatic autonomous exploit-generation or self-healing proof loop:
  the PoC authoring bundle is passed to the locally configured agent
  only by deliberate operator action.
* No real public blind result or validated improvement over 0.54.
* No full rustc MIR CFG, Solana Anchor account analysis, or Move bytecode
  extraction; generated flows are intentionally unverified reading leads.
* No production state-changing HTTP requests, wallet signing or public RPC
  traffic.
* No implied vulnerability severity or reward eligibility.

The correct next experimental step is a Mac-only, budget-limited,
independently adjudicated native run on held-out pinned targets, followed
by an honest comparison with 0.54.
