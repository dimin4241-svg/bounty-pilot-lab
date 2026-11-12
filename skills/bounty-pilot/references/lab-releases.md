# Lab tools by release

The release-by-release guidance for the optional lab tools, moved out of `SKILL.md` so the core
workflow reads first. `SKILL.md` keeps an index; read the section for a tool before running it.
Every rule here still applies: nothing below is weaker for living in a reference file.

### Experimental Lab 0.59.0 — route anchors and conservation sequences

`business-route-bind` joins `web-route-ast`'s route/handler/call-name graph
with `business-schema-bind`'s lexical leads, by handler function: a lead now
names the route and its own guard cues, not just a bare line match. Neither
input tool is duplicated; `web-route-ast` gained one additive `end_line`
field so the join can tell whether a hit actually falls inside a given
handler's body. Read `references/economic-conservation-sequences.md`: a
paired, test-locked `scenario_fuzz` model combines the engine's bounded BFS
with `invariant_check.py`'s existing `conservation` rule kind for the first
time, finding a two-subaccount retry-credit sequence (the Balancer/Cetus/
Arcus shape) that no single action or static snapshot check shows alone.
Also fixed: `business-schema-bind`'s cross-import of `web_business_lab.RULES`
silently fell back to a stale, family-less dict whenever loaded by path from
a cwd other than scripts/ — true of every real caller, including bounty.py's
own dispatcher — so every report's `family` field was quietly `None`.

### Experimental Lab 0.58.0 — access/money blind spots

Read `references/web-business-lab.md`: a 14th rule, `cross-actor-disclosure`,
covers pure-read IDOR/BOLA (another actor's private fields) that the prior 13
missed because each required a mutation to compare. Read
`references/web-sequence-models.md` for two paired, test-locked `scenario_fuzz`
models showing a two-step Web ATO/payment violation that no single action
shows alone; `web-business-lab` only reviews an operator-captured trace, it
does not search for the violating order itself. `sibling-finder` leads a
structurally near-duplicate function pair where only one side carries an
access-check cue (misses.md #9). `business-schema-bind` leads a
`web-business-lab` rule's `source_anchor` lexically against the real target
checkout; it is never auto-accepted and `bridge()` still requires a reviewed
anchor.

### Experimental Lab 0.57.0 — Web account and payment integrity

Read references/web-business-lab.md for the offline CLI and synthetic SQLite
benchmarks. web-business-lab plan/analyze/demo covers thirteen session/ATO,
payment, refund, subscription and cross-tenant state invariants. It requires
two-to-five paired candidate/control runs on matching declared initial state
and records unknown facts as unknown. The synthetic demo executes only
researcher-owned SQLite and never handles real funds or users. Observations
and digests supplied by the researcher remain unverified. No live website
probes, model execution, independent historical holdouts or payout improvement
are provided.

### Experimental Lab 0.56.1 — conservative reality-gate evidence

Read `references/reality-gate.md` before aiming a run at a programme whose published components
may not be deployed. `reality_gate.py` sorts supplied page, API, auth, chain and bundle probes into
`LIVE`, `AUTH_ONLY`, `BACKEND_BROKEN`, `MARKETING_ONLY`, `NOT_DEPLOYED` or `UNKNOWN`, and emits the
next experiment for each gated or broken surface. API `LIVE` needs a structured, non-error-looking
2xx payload; plain text, health envelopes and HTML fallbacks stay inconclusive;
`AUTH_ONLY` needs every saved API/auth probe to be gated; chain `LIVE` needs a successful chain
probe and verified addresses. `NOT_DEPLOYED` needs `address_search_complete: true` plus zero found
addresses, and `MARKETING_ONLY` needs `client_search_complete: true`; both completeness flags are
the investigator's assertions, not something the offline tool can verify. Partial searches and
ambiguous probes stay `UNKNOWN`. It sends no request, executes
nothing and reads no target code. The output is a reading order, never a scope decision or a finding.

### Experimental Lab 0.55 — reproducible research productivity

Read `references/lab-055-productivity.md` before any local PoC
authoring or blind comparison. `poc_builder.py` checks bounded source
hashes and writes a deliberately failing scaffold and a human-reviewed
local coding-agent task; it does not invoke an LLM or execute PoCs.
`blind_campaign.py` prepares separate workspaces for two skill
revisions and compares independently sealed scores without claiming
the benchmark truly stayed blinded. `native_ir_flow.py` is partial
textual Rust MIR / researcher-supplied Rust/Move normalized IR analysis.
`failure_taxonomy.py` distinguishes model/PoC/impact/scope issues;
`setup_wizard.py` preflights only local files and tool presence.
No utility output independently proves loss, exploitability, bug
novelty, payout, or enhanced rediscovery.

### Experimental Lab 0.54 — offline financial state transitions

Read `references/financial-transitions.md` for exact input schemas,
coverage, provenance, limitations and safe CLI use. Disconnected simulators
model how operation order should work, not how a real target works. The
paired observation checker does not authenticate inputs, receipts, source
revision or loss. The Vyper advisory checker is limited to one bundled
verified public historical advisory plus optional unverified exports.
The 22-shape router explicitly labels missing native adapters.
Do not infer new payable findings or run production state-changing tests.

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
