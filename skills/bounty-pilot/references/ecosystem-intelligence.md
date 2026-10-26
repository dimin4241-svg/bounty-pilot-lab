# Ecosystem Intelligence (MVP)

This optional module complements source-focused passes with a passive inventory of external
dependencies, local history, and candidate trust boundaries. It is deliberately separate from the
existing `delta`, `bundle`, `impact-plan`, `state_graph`, `dup-harvest`, and deployment commands.
It does not change their inputs, statuses, or gates.

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
  unexecuted safe-verification plans, and skeptical-review checklists.
- `ecosystem-report.md`: a concise human-readable view of the same run.
- `dependency-graph.mmd`: Mermaid graph of endpoint references and low-confidence component flows.
- `audit.jsonl`: timestamped operation and scope-decision records. It records no source excerpts or
  credential values.

Every dependency edge has an observation timestamp, source path and line, source commit timestamp
when available, a role, confidence label, scope classification, and trust boundary. Component
edges inferred from path names are explicitly low confidence.

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
