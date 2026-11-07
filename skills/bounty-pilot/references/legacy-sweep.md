# Legacy sweep: deployed, deprecated, still funded

Every current review starts from HEAD. Contracts a protocol stopped mentioning are outside it, and
some of them still hold value or permissions. Recent losses of this shape (figures approximate; a
report cites the protocol's own post-mortem, see `hack-patterns.md`):

| Incident | Shape |
|---|---|
| Truebit, Jan 2026, ~$26.4M | 2021 Solidity 0.6 bonding curve, never re-audited; an overflow minted TRU for ~0 ETH |
| Aztec Connect, Jun 2026, ~$4.3M | deprecated rollup bridge with live verification keys and escape hatch |
| Yearn yETH, Nov 2025, ~$9M | legacy custom stableswap |
| Troves, Oct 2026 | old rebalancer kept vault permissions after it was replaced |
| Scallop | legacy reward contract |

Users' standing approvals to a deprecated router are the same shape: the contract is retired, the
allowance is not.

## When

Stage 0/1, for any protocol older than about a year or with V1/V2 (or vN) migrations. It is cheap:
one pass over `git log -p`, plus read-only RPC if you pass `--rpc`.

## Commands

```bash
# History only: which addresses did the repository record and later drop?
python3 scripts/bounty.py legacy-sweep --repo <checkout> --program <run>/program.json \
    --out <run>/legacy-sweep.json

# Plus on-chain facts for the removed ones: code present, native balance, ERC-20 balances
python3 scripts/bounty.py legacy-sweep --repo <checkout> --program <run>/program.json \
    --rpc "$RPC_URL" --token <USDC> --token <WETH> --out <run>/legacy-sweep.json
```

`--max-commits` (default 5000) bounds the scan to the newest commits; when it bites, the report
says `truncated: true` and `first_seen` is a lower bound.

What it reads: every EVM address (`0x` + 40 hex, case-insensitive, normalized to lower case) in
the history of address-bearing paths - `deployments/`, `broadcast/`, `.openzeppelin/`, `deploy*/`,
`docs/`, `config/`, `script/`, `addresses*.{json,ts,md}`, `*.env.example`, `README*` and JSON
files named like an address book. The zero address, the precompiles `0x01`-`0x09` and the
`0xEeee...` native-asset placeholder are dropped; addresses seen only under `test/`, `lib/` or
`node_modules/` are dropped and counted (`excluded_test_or_lib_only`), as are addresses seen only
in other paths (`excluded_outside_address_paths`).

Each address carries `first_seen` / `last_seen` (commit and date), `paths`, a `label` (the JSON key
or deployment file name) and the quoted `line`, `present_at_head`, and `scope` (`in_scope` /
`not_listed`) when program.json is given. `current` addresses are still at HEAD; `removed` ones are
the `legacy_candidates`. With `--rpc`, candidates are ranked: code and value first, then code,
then the rest. Balances are raw units per asset - no price conversion.

Only `eth_chainId`, `eth_blockNumber`, `eth_getCode`, `eth_getBalance` and `eth_call` are sent.
The endpoint is written as `"not recorded"` and scrubbed (URL and host) from every error. A
chain id that program.json does not list is reported as `chain_id_mismatch`. One failing address
records its error and the sweep continues. Git runs hardened: the target's `.git/config` is
untrusted, so fsmonitor, hooks and external diff drivers are overridden.

## Triage

1. **Is it theirs, on this chain?** An address in history may be a third-party dependency, a
   testnet deployment or a typo. Confirm identity with `verify-deployment` against the source at
   the commit that recorded the address.
2. **Read the old source at that commit** (`git show <first_seen.commit>:<path>`), not HEAD. Look
   for drain and mint paths, unchecked arithmetic (pre-0.8), live verifier keys, escape hatches,
   and permissions the old contract still holds in contracts that are current.
3. **Who still points at it?** Current vaults, registries and routers that grant it a role; user
   approvals to it (Approval logs - use `config-snapshot` / `eth-call`, not this sweep).
4. **Scope wording.** Many programs list only current deployments. Read the "previous versions" or
   "deprecated contracts" clause; when it is silent, ask the program before testing. A finding on
   an out-of-scope address is not reportable however much it holds.
5. **Never interact with the live contract.** Reproduce on a fork.

Value at rest in a deprecated contract is reportable only if the program covers it and an
unprivileged path to it exists. Everything this sweep outputs is a lead.

## Limits

- History may be squashed, rewritten or shallow; a shallow clone answers with too little, not
  with "nothing removed". Deploy records often live in another repository (a deployments repo, the
  docs site, the frontend); sweep those too.
- Hardcoded addresses in source files are not harvested (they are mostly external dependencies).
- `--max-commits` truncates to the newest commits.
- EVM addresses only: Solana, Move, Cairo and CosmWasm ids are not covered.
