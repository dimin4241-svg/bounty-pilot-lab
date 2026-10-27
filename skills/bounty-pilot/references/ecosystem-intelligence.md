# Ecosystem Intelligence (MVP)

This optional module complements source-focused passes with a passive inventory of external
dependencies, local history, and candidate trust boundaries. It is deliberately separate from the
existing `delta`, `bundle`, `impact-plan`, `state_graph`, `dup-harvest`, and deployment commands.
It does not change their inputs, statuses, or gates.

For mixed-stack targets, pair this inventory with
[`ecosystem-attack-chains.md`](ecosystem-attack-chains.md). That playbook turns ecosystem boundaries
into twelve scoped research tasks; copy `templates/attack-chain-review.md` into the private run and
record evidence and gaps. It is an analyst checklist, not an extra scanner or a claim that each
pattern exists in the target.

## Run

Create an explicit scope file outside the target checkout and keep generated artifacts in a
private run directory, also outside that checkout:

~~~sh
python3 skills/bounty-pilot/scripts/bounty.py ecosystem-intel \
  --repo /path/to/checkout \
  --scope /path/to/private/scope.json \
  --out /path/to/private/run/ecosystem
~~~

The scope file must authorize the passive methods the run will use. Example:

~~~json
{
  "schema_version": 1,
  "project": "Example protocol",
  "allowed": {
    "domains": ["app.example.org", "api.example.org"],
    "urls": ["https://docs.example.org/security/"],
    "repositories": ["https://github.com/example/protocol"],
    "contracts": [
      {"address": "0x1111111111111111111111111111111111111111", "chain_id": 1}
    ],
    "networks": [{"name": "Ethereum", "chain_id": 1}],
    "methods": ["local_static", "git_history", "provided_archive"]
  },
  "related_out_of_scope": {
    "domains": ["status.example.org"],
    "urls": [],
    "repositories": [],
    "contracts": [],
    "networks": [],
    "methods": []
  },
  "limits": {"note": "No network collection is enabled in this MVP."}
}
~~~

An allowed domain includes its subdomains. A URL rule includes its exact path and child paths.
Contract rules may be bound to a network or chain ID; an unbound network context remains `UNKNOWN`.
No omitted entity inherits permission. Active method names are rejected even if included in a scope
file. The current CLI only performs `local_static` and `git_history`; `provided_archive` accepts
only a local index of already downloaded documents.

To import local public archive snapshots, add a capture index:

~~~json
{
  "captures": [
    {"url": "https://docs.example.org/security/", "captured_at": "2026-01-10",
     "kind": "documentation", "path": "snapshots/security.html"}
  ]
}
~~~

Then pass `--archive-index /path/to/private/archive-index.json`. Each URL must classify as
`IN_SCOPE`; the file path must stay beneath the index directory. The tool never fetches the URL.

## Outputs

- `ecosystem-intelligence.json`: scope decisions, commit and file provenance, dependency graph,
  historical leads, patch-variant candidates, trust-boundary observations, ranked hypotheses,
  state-transition and agent/CI leads, runtime-verification handoffs, unexecuted safe-verification
  plans, and skeptical-review checklists.
- `ecosystem-report.md`: a concise human-readable view of the same run.
- `dependency-graph.mmd`: Mermaid graph of endpoint references and low-confidence component flows.
- `audit.jsonl`: timestamped operation and scope-decision records. It records no source excerpts or
  credential values.

Every dependency edge has an observation timestamp, source path and line, source commit timestamp
when available, a role, confidence label, scope classification, and trust boundary. Component
edges inferred from path names are explicitly low confidence.

## State-transition and trust-handoff research

`ecosystem-intel` also runs the standard-library-only `scripts/transition_research.py` helper over
the same bounded, Git-tracked source set. Its results appear under
`state_transition_research` in the JSON and as short lead counts in the Markdown report:

- `alternative_path_discovery` compares same-file primary and alternate operations such as
  create/restore, register/import, or issue/reconnect when both lexically write the same symbol
  and their detected guard families differ.
- `revocation_resurrection` pairs revoke/disable paths with restore/refresh/reconnect paths when
  both lexically mutate the same symbol and the latter lacks a recognized revocation-state marker.
- `deleted_object_lifecycle` links delete/remove operations to same-file asynchronous/queue/worker
  operations that mutate the same symbol.
- `security_policy_drift` compares same-named functions across files when both mention policy or
  authorization state but their local guard markers differ.
- `ci_release_provenance` records workflow evidence for untrusted events, write permissions,
  caches/artifacts, and release steps. `agentic_trust` raises a separate lead when agent/tool
  configuration appears in the same local file as untrusted input and elevated capabilities.
- `architecture_divergence` looks for explicit 32-bit and 64-bit branches plus integer/codec
  markers. `lower_layer_surfaces` only inventories kernel, hypervisor, storage, container, and
  sandbox-related paths; every item requires a separate in-scope decision.

These are deliberately conservative lexical comparisons. The helper does not build ASTs, infer
function equivalence, resolve call graphs, follow state across services, calculate effective
GitHub permissions, or establish that a listed service is deployed. Each candidate carries local
source anchors and disconfirming evidence. No match is not a safety conclusion; a match is not a
finding. Candidate and negative-control tests are plans only and are never executed by this
command.

For contract addresses referenced by deployment-like files, and every explicit contract listed in
the scope file even when it has no repository source, `runtime_reality_handoffs` records the local
anchor/scope declaration. Contract and network scope must both match when network rules are
present; an address alone does not authorize a different chain. This does not enumerate chain
deployments or inspect runtime code. Only an explicitly `IN_SCOPE` address with a known chain ID
gets a pending handoff to the existing
`bounty.py verify-deployment` and `bounty.py selectors` commands. Run those separately only when
the program permits read-only RPC, at a pinned chain and block, using an investigator-approved
read-only endpoint. Unknown and excluded references are blocked from that handoff. Record roles,
allowances, proxy authority, and events as separate pinned reads; bytecode equality alone does not
prove the current policy. No RPC URL is written by `ecosystem-intel`.

## Evaluating the new leads

The repository already provides the blind `bounty.py backtest` protocol. To evaluate these methods,
use a private, curated set of 20 historically fixed issues with pinned pre-fix commits and their
corresponding fixed commits. A case curator must not participate in the blind hunt. Seal each
pre-fix hunt before loading its published root cause into `truth.json`; use the same model, scope,
prompt, and budget for the baseline (0.32.0) and candidate (0.33.0) arms. Keep fixed-commit runs
separate and have reviewers compare only the exact historical mechanism against its patch, after
sealing. Do not call unmatched leads false positives: the existing benchmark explicitly does not
support that conclusion. Report raw rediscoveries and individually adjudicated patch-suppression
results, with all misses, rather than an unvalidated recall or bounty-success percentage.

No 20-case corpus has been curated or run for this release. The new signals remain unmeasured until
that experiment is completed; no improvement in recall, precision, payout odds, or runtime coverage
is claimed.

## Interpretation and limits

The collector reads Git-tracked regular files only. It skips sensitive/generated path names,
symlinks, oversized files, and files outside fixed size/count limits. It scrubs credential-shaped
values and query strings from endpoint references. It never validates a credential or connects to
an endpoint, chain, archive, API, or provider. Git history and tags are local objects and refs;
PR bodies, security advisories, and remote archives are not fetched.

`IN_SCOPE`, `RELATED_OUT_OF_SCOPE`, and `UNKNOWN` are scope decisions, not safety labels for an
exploit. The module makes no active request at all. An unknown or excluded endpoint is represented
as an inventory lead only.

Dependency and invariant extraction is lexical. It does not establish that a service is deployed,
a path is reachable, an attacker controls a field, or an invariant is absent from generated code or
third-party libraries. Historical patch comparison checks whether invariants tokenized from a
security-shaped diff also appear in current lexical functions; candidate matches are low-confidence
leads, not proof of an incomplete fix or an equivalent defect. Ranking scores are explicit
heuristics, and novelty is unmeasured without a supplied local known-issues corpus. There is no
benchmark claim.

The report proposes a local-only verification procedure for each hypothesis, including a negative
control and evidence to preserve. These plans are `NOT_EXECUTED`: the module does not launch
Foundry/Anvil, run target code, contact a mock or live API, or verify a balance delta. Any target
side effect requires a separately confirmed authorization and is outside this command. The review
checklist is also a handoff, not a second agent: it cannot attest reviewer identity or issue an
independent verdict. Generated records remain `hypothesis` and
`NOT_INDEPENDENTLY_REVIEWED`; no output is a confirmed vulnerability or a payout estimate.
