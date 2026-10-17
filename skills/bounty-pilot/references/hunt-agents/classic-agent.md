# Classic agent — the shapes every reviewer knows and still misses

Two lists, used differently. **Part A** is EVM semantics that changed after most checklists were
written, plus the classes `solidity-auditor` v4.1 is known to drop; no installed sweep covers all of
it, so it runs on every EVM target. **Part B** is the
classic bug-class sweep. When `solidity-auditor` ran on this revision, Part B is its ground: read
its imported records in `findings.json` and spend this reading on Part A and on what its records
do not name. When it did not run, Part B is yours.

Work each item as a question against **this** code, not as a checklist to paste. An item that does
not apply costs one line in `known-hypotheses.md`; an item skipped silently is the gap a later pass
cannot see.

## Procedure

1. List every external and public function in the bundle. If `function-coverage.json` or
   `odd-one-out.json` is in the bundle, start from their unexamined entry points and flagged
   asymmetries — they are the mechanical half of this lens.
2. For each item below, find the code it applies to by grep, not by memory of what such code usually
   looks like. Quote the line that makes it apply, or write the one-line reason it does not.
3. For each hit, write the property it breaks and the experiment that settles it. A hit with no
   reachable unprivileged path is a LEAD, not a CANDIDATE.

## Part A — semantics newer than the checklists

- **EIP-7702 delegated EOAs.** An externally owned account can now carry code. `tx.origin ==
  msg.sender` no longer means "no contract logic runs around this call": the delegated account can
  batch, re-enter and flash-borrow inside one transaction. `extcodesize == 0` / `isContract()` no
  longer identifies an EOA, in either direction. A plain ETH transfer to a delegated EOA runs code
  and can revert or re-enter. A signer recovered by `ecrecover` may also answer ERC-1271. Grep for
  `tx.origin`, `extcodesize`, `code.length`, `isContract`.
- **EIP-1153 transient storage.** `tstore` values live until the end of the **transaction**, not the
  call. A lock, a callback context or a "current caller" slot that is not cleared leaks into the next
  call of a multicall, a batch or a router hop. `tstore` costs 100 gas, so a receiver can change
  transient state inside the 2300-gas stipend of `transfer`/`send` — the stipend no longer means "the
  receiver cannot change state". Grep for `tstore`, `tload`, `transient`.
- **Permit and Permit2.** A `permit` signature can be submitted by anyone first: a function that
  calls `permit` without `try`/catch-and-check-allowance is a griefable revert. Contracts holding
  standing Permit2 or ERC-20 allowances behind an arbitrary-call path are a drain of every user who
  approved them. Check that a Permit2 witness binds the recipient and the action, not only the amount.
- **Signatures.** `ecrecover` returns `address(0)` on a bad signature — compare against an unset
  signer. Malleable `s` values matter wherever the signature bytes are used as an id or nonce. The
  EIP-712 domain must bind `chainId` and `verifyingContract`, and a cached separator must be
  recomputed after a fork. The typehash must bind the action, so one signature cannot be replayed on
  a sibling function. `abi.encodePacked` with two dynamic arguments collides.
- **L2 and alt-EVM semantics.** A Chainlink feed on an L2 needs the sequencer-uptime feed and a grace
  period. `block.number` on Arbitrum is an approximate L1 number. A cross-domain `msg.sender` from L1
  is aliased on most rollups. zkSync Era derives `CREATE`/`CREATE2` addresses differently from
  Ethereum and routes value transfers through system contracts. `PUSH0` breaks deployment on chains
  without Shanghai. Check
  which chains the program lists and read each one's documented differences.
- **Uniswap v4 hooks.** Hook permissions are bits of the hook address. Any pool can be initialised
  with any hook, so a hook that assumes one pool must check the `PoolKey`. Hook entry points must
  check that `msg.sender` is the `PoolManager`. A hook that returns deltas carries its own accounting:
  reconcile what it takes against what it settles.
- **ERC-4337 accounts and paymasters.** `validateUserOp` touching storage outside the account,
  paymaster `postOp` griefing, signature failure returned as a revert instead of
  `SIG_VALIDATION_FAILED`, counterfactual `initCode` that anyone can front-run with other owners.
- **Batching and value.** `msg.value` read inside a loop or inside a `delegatecall` multicall is spent
  once per iteration and paid once.
- **Receiver callbacks.** `_safeMint`, `safeTransferFrom`, `onERC721Received`,
  `onERC1155Received`/`BatchReceived` and ERC-777 `tokensReceived` hand control to the receiver
  before the caller's state is final.

- **Explicit narrowing casts.** In Solidity 0.8 checked arithmetic does not cover conversions:
  `uint128(x)`, `uint64(x)`, `int128(int256(x))` silently drop the high bits. `solidity-auditor` v4.1
  lists "explicit narrowing casts in 0.8+ (reverts on overflow)" as a safe pattern in its judging
  rules, so its judge can discard a real downcast its own math agent found. Grep every narrowing
  cast without `SafeCast` and ask whether an attacker can make the value exceed the target type.
- **Files a default `solidity-auditor` scan never reads.** Its default `find` excludes every path
  containing `/lib/` — the project's own `src/lib/` too, not only dependencies — and every file whose
  name contains `Test` or `Mock`. If the run delegated to it without an explicit file list, the
  in-scope files matching those patterns had no classic sweep; read them here.

## Part B — the classic sweep

- **Reentrancy:** cross-function, cross-contract, and read-only — a `view` that another protocol
  prices from while this contract is mid-update.
- **Token behaviour the code really accepts:** fee-on-transfer (amount credited vs balance delta),
  rebasing balances held as constants, tokens that return `false` or nothing, approve-to-nonzero
  reverts, blocklists and pauses that freeze a withdrawal path, decimals other than 18, ERC-777 hooks,
  double-entry-point tokens. Read the token list the program supports before claiming one.
- **Share vaults (ERC-4626 and look-alikes):** first-depositor inflation by donation, `totalAssets`
  read from `balanceOf`, rounding direction on each of deposit, mint, withdraw and redeem, `preview*`
  disagreeing with the action, zero-share mints.
- **Oracles:** staleness (`updatedAt`), min/max-answer circuit breakers, decimals, spot prices from
  AMM reserves, TWAP windows short enough to move, an oracle revert that blocks liquidation.
- **Slippage, deadline, ordering:** missing `minOut`, a minimum computed on-chain from a manipulable
  spot, `deadline = block.timestamp`, sandwichable harvest and compound, front-runnable
  initialisation.
- **Arithmetic:** division before multiplication, unsafe downcasts, `unchecked` blocks, fees and
  rewards that round to zero per call and compound across calls, signed/unsigned mixing.
- **Denial of service:** unbounded loops over user-growable arrays, push payments to a recipient that
  can revert, strict equality on a balance anyone can donate to, external calls with caller-chosen
  gas.
- **Upgradeability:** storage layout drift between versions, missing gaps, an implementation left
  initialisable, an initialiser that can be front-run, `selfdestruct` or `delegatecall` reachable in
  the implementation.
- **Low-level calls:** a call to an address with no code succeeds, unbounded returndata, unchecked
  return values.
- **Liquidation:** profitable self-liquidation, liquidation blocked while paused or for dust
  positions, bad debt that is never socialised, incentives larger than the collateral.
- **Governance:** voting power read from the current balance (flash-loanable), quorum against a
  manipulable supply, proposals that can be griefed.

## Proof standard

Quote the line the item applies to and the line whose absence matters, and name the experiment. For
Part A, also name the chain or fork that has the semantics: "post-Pectra mainnet", "Arbitrum One",
"zkSync Era". A semantic difference on a chain the program does not list is not a finding.
