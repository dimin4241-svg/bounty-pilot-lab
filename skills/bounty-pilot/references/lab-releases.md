# Lab tools by release

The release-by-release guidance for the optional lab tools, moved out of `SKILL.md` so the core
workflow reads first. `SKILL.md` keeps an index; read the section for a tool before running it.
Every rule here still applies: nothing below is weaker for living in a reference file.

### Experimental Lab 0.52 — the taint queue aims at the scope

`taint-paths.json` is still a reading queue and still proves nothing, but it is now worth reading
top-down: every sink gets its best lead before any sink gets a second, `--scope` marks and orders
both ends of a lead, control-takeover sinks outrank a generic external call, line numbers resolve on
hardhat and foundry build-info, and the same build-info gives the same queue twice.
`sinks_represented`, `leads_dropped_by_scope` and `leads_suppressed_by_sink_cap` state what the caps
left out. Test and mock sinks sort after production ones here and in `odd-one-out.json`, and so does
a sink every one of whose public entries sits behind an access modifier — `entries_all_gated` and
`entry_auth_modifiers` say which, and nothing is dropped to achieve it. Read `entry_auth_modifiers`
beside `entries_without_access_check`, never alone: the names are listed even when the sink is not
gated, and that count is how many public entries reach it carrying none of them. Treat that flag as a cue and
not a verdict: a modifier can be a no-op, an owner can be a single key, and the gate disappears the
moment one ungated entry is added, so check authorization at the source span either way.

### Experimental Lab 0.51 — compiler-AST taint-path leads

`impact-plan` now also writes `taint-paths.json`: bounded compiler-AST paths from public
parameters, entry-scoped EVM environment values and external-call return values to sensitive
call targets/calldata, native ETH recipients/amounts, token transfer/pull, permit and other
operation operands, including paths across internal calls and persistent state. Read these as source
navigation leads; this analysis does not model control flow, modifiers, complete aliases, runtime
reachability or exploitability. Confirm every hop, authorization check, transaction sequence and
protected control in the target source before treating a path as a hypothesis. See
`references/impact-first.md` for how the impact-first and high-impact passes consume the report.

### Experimental Lab 0.50 — native feedback and no-drop discovery

See references/lab-050-research-loop.md for the new optional tools.
AVRE now ranks all discovered candidates before capping and preserves deferred
ones in a private artifact. semantic_state_bridge.py can bind compiler-AST references for an explicitly
pinned checkout; this is not deployed-state proof. security_slices.py plans
cross-file context bridges.
research_loop.py selects explicitly supplied candidate/control native tests and
records repeated observations **only** after external network-disconnected,
secret-free isolation and explicit opt-in; it never generates exploit code.
economic_frontier.py compares exact measured capital/profit assumptions, while
outcome_consistency.py compares layered completion semantics and asset effects.
A new passive AVRE run may use --feedback as unverified prioritization input.
Do not equate local test observations with independent proof, novelty or payout.
For target native execution use the operator's isolated Mac runner only.

### Three-model hypothesis integrity — Lab 0.49.5

For Claude Code, Codex and DeepSeek use the independent three-worker plan
described in `references/agent-dispatch.md`. The DeepSeek provider is routed
through a locally installed OpenCode CLI with an explicit `deepseek/<model-id>`,
not a custom direct-API client. Keep all provider API keys local and set
provider-side spend limits (only Claude Code exposes a generic per-job cap here).
For oversized repositories create non-dropping source scope groups with
`scripts/source_shards.py --repo <checkout> --out <private-plan.json>`.
Use a separate private run directory per shard and review cross-shard call paths.
Run `scripts/discovery_doctor.py --run <private-run>` on apparent zero-yield
runs; it distinguishes no output, unparsed candidate blocks, unimported leads,
failed jobs and oversized bundle contexts without claiming bug validity.
Import raw hypotheses only as unverified LEADs. The pinned Charon Opus trial
writes `readings/*.md` alongside its private JSON on complete text responses;
use `bounty.py import-findings` and native PoC review for those hypotheses.

The scoped `web-api-boundary` and `web-integrity` lenses now receive both
frontend source and other in-scope backend code (including Go/Python/Rust),
rather than only browser/frontend source. If a bundle is over 400 KB, split
the project into explicit, smaller `--scope` groups in separate private runs.
The warning is not a coverage claim and no source is silently declared read.

### Historic source diagnostic — Lab 0.49

Use `scripts/web_ab_diagnostic.py` to run the bounded, reproducible
**lexical-only** baseline versus extended pass on six published,
pinned historical Git snapshots. Source data is identical for both arms,
and the report uses the existing sealed benchmark scorer. The GitHub
Actions workflow uploads the complete report. Do not call source cues
security findings: no model calls, native PoCs or independent human
reviews are supplied by this procedure. For a truly blind model run,
use the evaluator-separated workflow with new holdout cases and
a separately engaged agent/reviewer. See `references/web-ab-diagnostic.md`.

### Native evidence and historical replay — Lab 0.48

When an in-scope web bug hypothesis is testable in a local native framework,
use `bounty.py web-native-capture` with an explicit pinned source revision
and a real candidate/negative-control plan. The runner performs two rounds,
collects structured test observations and hashes transcripts. Native
execution **requires a genuine externally network-isolated, disposable,
secret-free environment**; opt-in flags do not create isolation. Collected
test claims are not independently verified bug evidence.

For historical web evaluation use `bounty.py web-history-bench`. Only
give the hunter the opaque queue, never the published source catalog,
answer map, fixed/vulnerable labels or reviewer judgments. Freeze all
findings before separate human adjudication; present missing benchmarks
as unmeasured, never as zero or successful rediscovery. The small public
seed corpus cannot estimate bug-bounty yield. Read
`references/web-native-history.md`.

### Advanced Web3 web integrity — Lab 0.47

For explicitly scoped websites, client SDKs or financial API backends,
the `web-integrity` lens now joins `bundle --lens web`. Trace source
anchors and authorized native test paths for three advanced hypotheses:
asset/fee/deposit business consistency, complete displayed/signed/executed
multi-leg intent, and local JavaScript artifact provenance. Use
`bounty.py web3-advanced business-invariants|signed-intent-mirror|
runtime-provenance` with investigator-controlled local evidence.
Read `references/web3-advanced-integrity.md` for exact JSON schemas
and fail-closed controls. This engine never authenticates deployed bytes,
signature decoders, native traces, scope permission or a bug bounty verdict.

### Web3 web applications — Lab 0.46

Use the optional offline Web3 Security Research Engine when an explicitly
in-scope website or backend is part of the program. The source-grounded
`web-api-boundary` lens is included in `bundle --lens web`, alongside
`web-frontend`. First document the actual program's scope and exclusions,
then create a private offline policy file and use `bounty.py web3 scope`
to classify origin strings or `bounty.py web3 api-map` to inspect only
tracked local source. Use `bounty.py web3 authz` and `wallet-intent`
on investigator-run, synthetic candidate/negative-control observations.
See `references/web3-security.md`. The source map does not prove
absence of authorization, the policy is not independently verified,
and the engine must never send live network requests, execute code, promote
a finding, or attest a native trace by itself.

### Optional Lab 0.42 — executable research and memory

When a bounty hypothesis cites a published protocol requirement, read
`references/research-next.md` and use `bounty.py research-next spec`
only on explicitly in-scope source. Treat mapped or missing symbols as
research leads, never verified compliance or violations. For an existing
paired native test, use `research-next native` to pin the source revision
and repeat candidate/control twice. Actual execution requires a disposable,
externally network-isolated, secret-free checkout and a fresh private
evidence directory; the launcher does NOT provide a sandbox. The separate
Evidence-First submission gate must still independently verify reachability,
assertions, impact and deployed revision.

Use `research-next memory-record` and `memory-lookup` only with an
external private ledger. Previous refutations inform next experiments but
do NOT automatically suppress new or repeated hypotheses. Existing
`ecosystem_intelligence` patch variants now cite parent/patch commits
and explicit falsifiers. No new lexical engine replaces AVRE.
