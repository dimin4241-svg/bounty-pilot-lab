# Reality gate: what the programme advertises vs what is deployed

A published bounty page can name six components and ship one working host. A hunt pass aimed at
an unbuilt wallet, an undeployed contract set or a deleted database burns the whole budget and
produces "no finding" reports that look like review coverage. This gate sorts every advertised
component into one of six states **from observations you already saved**, before any hunt pass is
aimed at it.

It is offline. It sends no request, executes nothing and reads no target code. It is not a scope
tool: a component can be in scope and still unbuilt, and the program may still pay for a bug in
something it never mentions.

## When

Stage 0/1, once the public pages and client bundles have been captured:

- a programme with a marketing site and several "Launching Soon" products;
- a Web3 programme with no repository, no address and no RPC in the published scope;
- a mixed target where only one host answers and the rest are aliases or dead subdomains;
- before writing `scope.md`, to separate `deployed`, `gated`, `broken` and `advertised only`.

Do not run it on guesses. Feed it the probe statuses, bodies and bundle scans you actually
recorded. An absent probe is `UNKNOWN`, never `NOT_DEPLOYED`.

## Command

```bash
python3 scripts/bounty.py reality-gate --probes <run>/reality-probes.json \
    --out <run>/reality-gate.json
# or the script directly
python3 scripts/reality_gate.py --probes <run>/reality-probes.json --out <run>/reality-gate.json
```

`--out` refuses an existing path. Without `--out` the report goes to stdout.

## Input

```json
{
  "schema_version": 1,
  "program": "EXAMPLE",
  "components": [
    {
      "id": "drc-contracts",
      "kind": "onchain",
      "claims": ["seeding", "referrals", "liquidity"],
      "signals": {
        "assets_scanned": 89,
        "address_search_complete": true,
        "client_search_complete": false,
        "addresses_found": 0,
        "addresses_verified": 0,
        "client_api_calls": 0,
        "client_crypto_libs": [],
        "download_links": {"total": 0, "resolving": 0},
        "source_repository": false
      },
      "probes": [
        {"kind": "dns", "target": "explorer.example", "status": 200},
        {"kind": "page", "target": "https://example/", "status": 200}
      ]
    }
  ]
}
```

`kind` is one of `onchain`, `client-app`, `api-backend`, `marketplace`, `game`, `infra`. It is a
structured claim category, not a name guess.

`signals` are aggregate scan results. `assets_scanned` counts fetched pages and bundles;
`address_search_complete` is the investigator's explicit assertion that every supplied claim asset
relevant to this component was searched for addresses. `client_search_complete` is the matching
assertion that every relevant client bundle and release control was inspected. Leave either `false`
when coverage is partial or uncertain; the tool cannot verify completeness. `addresses_found` counts
addresses seen anywhere; `addresses_verified` counts those whose code you actually read (bytecode,
explorer source or a verified build) — never promote one to the other without that read.
`download_links.total` counts published download controls, `resolving` counts those that returned
an artifact. `client_crypto_libs` lists libraries found in the bundles (`ethers`, `viem`, `web3`,
`@solana/web3.js`, `bip39`, ...), not libraries you expected.

`probes` are individual observations: `kind` is `page`, `api`, `auth`, `chain`, `bundle`, `dns`,
`repo` or `asset`; `status` is the HTTP status or `null` for a non-HTTP observation;
`body_excerpt` is a short saved excerpt (≤2000 chars). Optional `redirect_to` records the observed
destination of an HTTP redirect; a 30x status without its destination is not enough to call a path
gated. Excerpts are checked for auth challenges, common API error envelopes and backend
initialisation failures; they are not copied into the report. This is heuristic payload inspection,
not schema validation for the target API.

## States

| State | Meaning | Typical basis |
|---|---|---|
| `LIVE` | A supplied probe shows a working surface | API 2xx with valid structured, non-error-looking data; successful 2xx chain probe plus verified addresses; client crypto code plus API calls; a resolving release |
| `AUTH_ONLY` | Every saved API/auth path is gated | every API/auth probe is 401/403 or redirects to a recorded login destination |
| `BACKEND_BROKEN` | API probes show backend failure and no other supplied signal proves a working surface | 5xx, `PrismaClientInitializationError`, `ENOTFOUND`, connection refused |
| `MARKETING_ONLY` | A page renders, the relevant client search is marked complete, and no client runtime cues or functional surface were observed | page plus `client_search_complete: true`, no crypto/API-call cues, API data or resolving release |
| `NOT_DEPLOYED` | The complete supplied on-chain claim-asset search found no addresses | `address_search_complete: true` and `addresses_found: 0` |
| `UNKNOWN` | The supplied observations do not establish a state | missing/incomplete search, mixed auth responses, ambiguous API payload, failed chain probe, or an address without verified code |

Precedence is deliberate: a positive live surface wins over a failing sibling API route, and the
failure is retained as `partial-backend-failure`; without a positive surface, a backend error
outranks a page-only response. `AUTH_ONLY` requires every supplied API/auth probe to be gated, and
a mixed result stays `UNKNOWN`. A verified address alone is not enough for chain `LIVE`: at least
one chain probe must have a successful 2xx status. A client page alone is not enough for
`MARKETING_ONLY`: the investigator must mark the client search complete. An on-chain zero-address
result is `NOT_DEPLOYED` only when the investigator marked the supplied search complete. The full decision
order is in `classify()` and is covered by `tests/test_reality_gate.py`.

## Output

`reality-gate.json` carries `status_counts`, `live_components`, `blocked_components` (with the
next experiment), `dead_claims`, `unverified_components`, component-scoped `warnings` and each
component's `basis` and `next_action`.

Warnings are prompts to collect evidence, not verdicts:

- `api-claim-unprobed`, `api-claim-inconclusive`, `chain-claim-unsearched`,
  `client-bundles-unprobed`, `client-search-incomplete`, `client-runtime-unverified` — the claim
  was not tested or the evidence is mixed, so it stays `UNKNOWN`;
- `partial-backend-failure`, `chain-probe-inconclusive` — a sibling API path or the chain probe
  failed even though another saved signal may establish a live surface;
- `inert-download-controls` — published download buttons have no resolving target;
- `no-client-crypto-or-api` — the completed client search found neither crypto libraries nor API
  calls, which is what a wallet mockup can look like;
- `addresses-without-bytecode` — an address exists but its code was not verified;
- `page-only-surface` — a rendered page did not establish the component's functional surface;
- `unprobed-component`, `inconclusive-probes` — nothing to classify.

## How it feeds the run

- `LIVE` → aim the hunt passes here first.
- `AUTH_ONLY` → write the authorization experiment (role check, object ownership, IDOR) into
  `queue`; do not call the API safe because it returned 401.
- `BACKEND_BROKEN` → record the exact probe in `unverified_blockers`; re-test when it responds. A
  dead backend is not a finding.
- `MARKETING_ONLY` / `NOT_DEPLOYED` → do not spend a pass. Keep the claim in `scope.md` as
  advertised-but-not-deployed, with the evidence that established it.
- `UNKNOWN` → name the missing probe before any conclusion.

A `NOT_DEPLOYED` state can still hide a live legacy deployment the marketing site no longer links;
`legacy-sweep` answers that different question. A `BACKEND_BROKEN` state is frequently followed by
`AUTH_ONLY` once the database returns, which is where the payable IDOR lives.

## What it does not establish

- That a surface can never exist, that an unlisted component is out of scope, or that a gated API
  is correctly authorized.
- That a probe is exhaustive. Absence of an address is only as good as the asset set that was
  scanned; the report repeats the counts so a later pass can extend them.
- Any severity, originality or payout. It is a reading order, never a finding.
