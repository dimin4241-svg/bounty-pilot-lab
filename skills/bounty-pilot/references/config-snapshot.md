# Config snapshot: the deployed configuration source review never sees

`bounty.py config-snapshot` reads the configuration a protocol actually runs with - Safe thresholds
and modules, timelock delays, owners, AccessControl role members, proxy admins and implementations,
LayerZero receive-side verifier sets, Chainlink feed freshness and protocol risk parameters - at
**one pinned block**, and flags the shapes that lost the most money in 2025-2026. The helper lives
in `scripts/config_snapshot.py`.

**Every flag is a lead, never a finding.** Read the eligibility section before spending an hour on
one.

```bash
python3 $S config-snapshot --rpc "$RPC_URL" --targets targets.json \
    --known known.json --block 21000000 --out run/config-snapshot.json
```

- `--rpc` is an argument only. The output says `"endpoint": "not recorded"` and the URL and its bare
  hostname are scrubbed from every error, as `capability-probe` does. Keep the URL in an
  environment variable, not in a file in the run.
- `--block` defaults to `latest`, which is resolved **once** to a number; every read uses it. Pin a
  number for anything you intend to cite.
- `--known` is optional: a JSON list of addresses that make up the declared architecture (strings or
  `{"address": ...}` objects; a `program.json` object is accepted and its `in_scope_addresses` used).
  Without it, the "not in the declared architecture" flags are skipped and the output says so.
- With `--out`, the full snapshot is written there and a short summary is printed; without it the
  full snapshot is printed.

Only read-only methods are sent: `eth_chainId`, `eth_blockNumber`, `eth_call`, `eth_getCode`,
`eth_getStorageAt`, `eth_getLogs`, `eth_getBalance`, `eth_getBlockByNumber`. Nothing is signed or
sent. Selectors, event topics and storage slots are derived from their signatures with the bundled
keccak.

## Where the address list comes from

1. `program.json` `in_scope_addresses` - the program's own list, and the natural `--known` file.
2. `bounty.py verify-deployment` results for the run - each verified address with its proxy
   implementation; the implementation addresses belong in `--known`.
3. legacy-sweep output, where the run has one - deprecated or superseded deployments that still
   hold permissions or funds are exactly what `access-control` and `ownable` flag.
4. The protocol's docs deployment page, cross-checked against the above. A docs page alone is a
   claim, not evidence of what is deployed.

Then decide the kind of each address by reading its verified source or ABI, not by guessing.

## Targets file

A JSON list (or `{"targets": [...]}`) of `{address, kind, label?, expect?}`. One example per kind:

```json
[
  {"address": "0x...", "kind": "safe", "label": "protocol multisig",
   "expect": {"min_threshold": 3}},
  {"address": "0x...", "kind": "timelock", "label": "governance timelock",
   "expect": {"min_delay": 172800}},
  {"address": "0x...", "kind": "ownable", "label": "fee router"},
  {"address": "0x...", "kind": "access-control", "label": "vault",
   "expect": {"from_block": 19000000, "max_range": 10000, "max_chunks": 400,
              "role_names": ["ALLOCATOR_ROLE"]}},
  {"address": "0x...", "kind": "erc1967-proxy", "label": "pool proxy"},
  {"address": "0x...", "kind": "layerzero-oapp", "label": "bridge adapter",
   "expect": {"endpoint": "0x1a44076050125825900e736c501f859c50fE728c",
              "eids": [30101, 30184], "min_confirmations": 15,
              "receive_library": "0x...", "peers": {"30101": "0x000...peer"}}},
  {"address": "0x...", "kind": "chainlink-feed", "label": "ETH/USD",
   "expect": {"heartbeat": 3600}},
  {"address": "0x...", "kind": "getter", "label": "risk params",
   "expect": {"calls": [
     {"sig": "mintCap()", "returns": "uint256", "flag_if": {"eq": 0}, "why": "no cap"}
   ]}}
]
```

### What each kind reads, and what each flag means

**`safe`** - `getThreshold()`, `getOwners()` (with each owner's code size: an owner with code is a
nested Safe or contract signer, an owner without code is a key), `getModulesPaginated(0x1, 100)`,
the guard at the storage slot `keccak256("guard_manager.guard.address")`, and `nonce()`.

- `SAFE_THRESHOLD_ONE` - one signature executes anything.
- `SAFE_MINORITY_THRESHOLD` - `threshold * 2 <= owners`: a minority controls the Safe. Drift
  (Apr 2026, as reported) ran 2-of-5 with no timelock in front.
- `SAFE_THRESHOLD_BELOW_EXPECTED` - below `expect.min_threshold`.
- `SAFE_MODULE_ENABLED` - a module calls `execTransactionFromModule` without any owner signature.
  Read what the module permits and who may call it; a permissionless path into a module is the
  interesting case.

**`timelock`** - `getMinDelay()` (OpenZeppelin `TimelockController`), falling back to `delay()`
(Compound `Timelock`).

- `TIMELOCK_ZERO_DELAY` - queued operations execute immediately; the timelock is decorative.
- `TIMELOCK_DELAY_BELOW_EXPECTED` - below `expect.min_delay` (seconds), typically the delay the docs
  promise users as an exit window.

**`ownable`** - `owner()`, `pendingOwner()` where present, the target's code size, and its balance
when the owner is a key.

- `OWNER_IS_EOA` - a single key owns a contract (the detail gives its code size).
- `OWNER_NOT_KNOWN`, `PENDING_OWNER_NOT_KNOWN` - the owner, or the address a two-step transfer is
  waiting on, is outside the declared architecture.

**`access-control`** - rebuilds role membership from `RoleGranted` / `RoleRevoked` logs, scanned in
chunks of `expect.max_range` blocks (default 50,000) from `expect.from_block` (default 0), at most
`expect.max_chunks` chunks (default 200). A range the provider refuses is split in halves a few
times before it is recorded under `failed_ranges`. Each member is then cross-checked with
`hasRole` at the pinned block, which wins over the logs. Common role names are labelled by their
derived hash; add your own with `expect.role_names`.

- **Truncation is stated, never hidden.** `log_scan.truncated` is true when chunks ran out or a
  range failed, and `log_scan.truncation` names the blocks that were not scanned. A truncated scan
  can miss a member - set `from_block` to the deployment block before treating a role as clean.
- `ADMIN_ROLE_EOA` - `DEFAULT_ADMIN_ROLE` is held by an address with no code: one key can grant
  every role.
- `ROLE_MEMBER_NOT_KNOWN` - a contract outside the declared architecture holds a role. This is the
  Troves shape (Oct 2026, as reported): a rebalancer was replaced and the old one kept its vault
  permissions. Ask whether the old contract still has a callable path an unprivileged user can
  reach.
- `ROLE_MEMBER_NO_CODE` - a role holder with no code: a key, or a contract that self-destructed or
  was never deployed. A role granted to a CREATE2 address nobody has deployed yet may be claimable
  by whoever can deploy there.
- `ROLE_KNOWN_MEMBER_NO_CODE` - a declared architecture address with no code at this block: wrong
  chain, not yet deployed here, or destroyed.

**`erc1967-proxy`** - the implementation, admin and beacon slots, each derived as
`bytes32(uint256(keccak256('eip1967.proxy.<name>')) - 1)`, plus the beacon's `implementation()`.

- `PROXY_ADMIN_EOA` - one key can upgrade the proxy.
- `PROXY_ADMIN_NOT_KNOWN`, `PROXY_IMPLEMENTATION_NOT_KNOWN` - the upgrade authority, or the code
  actually running, is outside the declared architecture. An unknown implementation also means
  source review read the wrong code: run `verify-deployment` on it.
- `PROXY_IMPLEMENTATION_NO_CODE` - the proxy points at nothing, so every call succeeds silently or
  reverts, depending on the proxy.

**`layerzero-oapp`** - for each `expect.eids` entry: `peers(eid)` on the OApp,
`endpoint.getReceiveLibrary(oapp, eid)` (which also says whether the library is the default), and
`endpoint.getConfig(oapp, lib, eid, 2)` - config type 2 is the ULN config - decoded as `UlnConfig`
(`confirmations`, `requiredDVNCount`, `optionalDVNCount`, `optionalDVNThreshold`, `requiredDVNs`,
`optionalDVNs`). A `requiredDVNCount` of 255 is LayerZero's explicit "none" and reads as zero.

- `LZ_SINGLE_VERIFIER` - `requiredDVNCount + optionalDVNThreshold <= 1`: one verifier can attest a
  message. This is the KelpDAO shape (Apr 2026, ~$292M as reported): a 1-of-1 required DVN, so one
  poisoned verifier forged an inbound message.
- `LZ_LOW_CONFIRMATIONS` - fewer source-chain confirmations than `expect.min_confirmations`.
- `LZ_RECEIVE_LIBRARY_UNEXPECTED` - the receive library is not `expect.receive_library`.
- `LZ_PEER_ZERO`, `LZ_PEER_UNEXPECTED`, `LZ_PEER_NOT_KNOWN` - no peer, a peer other than
  `expect.peers[eid]`, or (without `expect.peers`) a peer outside `--known`. Remote peers live on
  other chains, so `--known` for one chain usually will not list them; give `expect.peers`.

**LayerZero v2 defaults.** When an OApp sets no config of its own, the endpoint applies the
LayerZero default config for that pathway, and `getConfig` returns the effective (merged) values.
`uln_config_source` reports `default` when the library's `getAppUlnConfig(oapp, eid)` shows no
custom fields, `custom` when it shows some (unset fields still fall back to the default), and
`undetermined` when that read is unavailable. A default config can change without the OApp doing
anything, so a clean default today is not a property of the protocol. This kind reads the receive
side only; read the send side by hand if the impact is on outbound messages.

**`chainlink-feed`** - `latestRoundData()`, `decimals()`, `description()`, and the pinned block's
timestamp from `eth_getBlockByNumber`.

- `FEED_STALE` - `block.timestamp - updatedAt > expect.heartbeat`. Without a heartbeat the age is
  reported and not judged; take the heartbeat from the feed's page, not a guess.
- `FEED_NONPOSITIVE_ANSWER` - the answer is zero or negative.

A stale or bad feed is a lead only if the consuming contract fails to check it: read the consumer.

**`getter`** - a generic list of calls for protocol-specific risk parameters. Each call is
`{sig, args?, returns, pick?, flag_if, label?, to?, why?}`: `returns` is a static type or a list of
them (`uint256`, `int256`, `address`, `bool`, `bytes32`), `pick` selects which returned value is
tested, `flag_if` is any of `eq`, `ne`, `lt`, `gt`, `lte`, `gte` (`"max"` means uint256 max), and an
argument of `"$block"` or `"$block-1"` becomes the pinned block number. `to` reads a different
contract than the target. A hit is `GETTER_CONDITION`.

```json
{"address": "0xPOOL_DATA_PROVIDER", "kind": "getter", "label": "Aave reserve", "expect": {"calls": [
  {"sig": "getReserveConfigurationData(address)", "args": ["0xASSET"],
   "returns": ["uint256", "uint256", "uint256", "uint256", "uint256",
               "bool", "bool", "bool", "bool", "bool"],
   "pick": 2, "flag_if": {"gt": 8000}, "label": "liquidation threshold (bps)",
   "why": "high threshold on an illiquid asset"}]}}
```

```json
{"address": "0xCOMPTROLLER", "kind": "getter", "label": "Compound market", "expect": {"calls": [
  {"sig": "markets(address)", "args": ["0xCTOKEN"], "returns": ["bool", "uint256", "bool"],
   "pick": 1, "flag_if": {"gt": "750000000000000000"}, "label": "collateralFactorMantissa"}]}}
```

```json
{"address": "0xGOVERNOR", "kind": "getter", "label": "quorum vs supply", "expect": {"calls": [
  {"sig": "quorum(uint256)", "args": ["$block-1"], "label": "quorum"},
  {"sig": "totalSupply()", "to": "0xVOTES_TOKEN", "label": "voting token supply"}]}}
```

```json
{"address": "0xMINTER", "kind": "getter", "label": "mint cap", "expect": {"calls": [
  {"sig": "mintCap()", "flag_if": {"eq": 0}, "why": "zero may mean uncapped"},
  {"sig": "mintCap()", "flag_if": {"eq": "max"}, "why": "uint256 max is uncapped"}]}}
```

The Aave and Compound reads echo Moonwell and Tectonic (Aug 2026, as reported): a high collateral
factor on illiquid collateral. The Governor pair echoes Term Finance (Aug 2026, as reported):
compare the quorum with the supply of the token that actually votes - a quorum denominated in a
wrapped or thinly held supply can be met far more cheaply than it looks. The mint cap echoes Resolv
(Mar 2026, as reported): a privileged mint with no on-chain cap. The same `getter` shape reads a
pull-oracle verifier's signature threshold (Bonzo, Jul 2026: zero signatures accepted) or an
Axelar or Hyperlane receiver's threshold (CrossCurve, Feb 2026: threshold 1); flag `lt` the value
the protocol's docs promise. Check the exact signature against the verified ABI - a wrong
signature returns no data and is recorded as an error, never as a clean read.

## Output

```json
{"schema_version": 1, "chain_id": 1, "block": 21000000, "endpoint": "not recorded",
 "targets": [{"address": "0x...", "kind": "safe", "label": "...", "reads": {},
              "flags": [{"code": "SAFE_MINORITY_THRESHOLD", "detail": "...", "shape": "..."}],
              "errors": []}],
 "errors": [], "notice": "..."}
```

A target that fails records scrubbed `errors` and keeps whatever it read first; it never stops the
other targets. A read that returned no data is an error, not a zero.

## Triage path

1. **Re-read at a pinned block.** Quote the exact `eth_call` / `eth_getStorageAt` with the block
   number and the decoded value; `latest` is not evidence.
2. **Find who gains.** A configuration value is only a vulnerability when it lets someone who is
   *not* the trusted party take value or break an invariant: a module with a permissionless entry,
   a stale role on a contract anyone can call, a single DVN that anyone who compromises one
   third-party verifier can use, a stale feed a liquidation consumes unchecked.
3. **Fork test.** Reproduce on a fork at the pinned block with a candidate (the unprivileged path)
   and a control (the same path where the configuration is sound), and record both runs through
   the experiment gate in `references/evidence-first.md`.
4. **Name the precedent** from the protocol's own post-mortem, never from this file or
   `references/hack-patterns.md`; loss figures and attributions here are approximate.

## Eligibility caveats

- **Many programs exclude admin, centralisation and trusted-role issues outright.** A 1-of-1
  multisig, an EOA owner or a zero timelock is, by itself, a centralisation observation that most
  programs will not pay for. Read `program.json` `excluded_impacts` and the program text first.
- A configuration lead is reportable where an **unprivileged** actor gains, or where the program
  **explicitly** pays for misconfiguration of deployed contracts.
- Some programs scope only listed addresses; a flag on an address outside `in_scope_addresses` is
  out of scope however bad it looks.
- Values change. A config that was unsafe at the pinned block may have been fixed; say which block
  you read.
- **Never act on a flag against a live system.** No transaction, no test against mainnet state
  other than read calls and a local fork.
