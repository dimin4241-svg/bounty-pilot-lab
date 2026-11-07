# Stateful harness and deployment atomicity

Two offline helpers for the bug classes a reading finds worst: bugs that only show up across a
sequence of transactions, and initialization races in how a contract was deployed. Neither one
runs target code or queries a chain. Both produce leads or skeletons, never evidence. A finding
still needs a native candidate/control pair that passes the `experiments.json` gate
(`evidence-first.md`).

## Why sequences need a campaign

On EVMbench's re-evaluation (arXiv 2603.10795), none of 26 agent configurations found a signature
state machine with nested calls, and multi-step state inconsistency was found about 4% of the
time. GMX v1 (July 2025) was cross-function reentrancy: a refund callback, then `increasePosition`
skewing `globalShortAveragePrices`. Abracadabra (October 2025) was a `cook()` action flag reset
that skipped the solvency check. In both, the bug was the order of the calls. A reader cannot list
every order of calls. A handler-based invariant campaign can, but only once someone has written
the property it checks. (Figures are approximate. Cite the protocol's own post-mortem in a report.)

Kinto (July 2025, about $1.55M) deployed an ERC1967 proxy and initialized it in a separate
transaction, and someone front-ran the initialize call. EVMbench has a proxy initialization race
that all 26 configurations missed. An implementation that can still be initialized is the Parity
2017 shape. Source code rarely shows these gaps. Deploy scripts and broadcast logs do.

## When to use

- `harness_gen.py` runs **after `impact-plan`**, once `model.md` names the state and the
  properties. Reach for it on lending markets, vaults, AMMs, bridges and explicit state machines,
  especially when there is a batch/multicall/`cook`-style dispatcher or a callback surface (hooks,
  flash loans, ERC-777/721/1155 receivers, refunds).
- `init_race.py` runs **whenever a checkout contains a deploy**: `broadcast/`, `deployments/`,
  `.openzeppelin/`, `script/*.s.sol`, `deploy/*.ts`. Run it also for any upgradeable contract in
  scope, and again after a new deployment or upgrade lands.

## Commands

```sh
S=<skill-dir>/scripts
# handler + invariants skeleton (Foundry default; --framework medusa adds property_ functions)
python3 $S harness-gen --artifact out/Vault.sol/Vault.json --model <run>/model.md \
  --repo <checkout> --out-dir <private>/harness
python3 $S harness-gen --semantic-graph <run>/semantic-graph.json --contract Vault \
  --actors 4 --repo <checkout> --out-dir <private>/harness

# deployment atomicity and initializer exposure
python3 $S init-race --repo <checkout> --scope src --out <run>/init-race.json
```

### harness_gen.py

The input is either a Foundry or Hardhat artifact (anything with an `"abi"` list) or the run's
`semantic-graph.json`. From the graph it takes deployable contracts and their external/public
`entry` functions with `abi_parameter_types`. `--contract` filters which contracts are used. Every
model.md line that starts with `INVARIANT:` becomes one property stub, and
`INVARIANT: name: text` sets the stub's name. `--out-dir` is refused if it is inside `--repo` or
inside the skill package, and existing harness files are never overwritten.

It writes:

- `<Contract>Handler.sol`. Each external/public non-view, non-pure function gets one
  `call_<fn>`. The handler selects an actor with `actors[bound(actorSeed, 0, actors.length - 1)]`
  and calls `vm.startPrank`. Each uint is clamped with `bound()` to `MAX_AMOUNT` (TODO: narrow
  it). Addresses are drawn from a pool made of the `makeAddr` actors, the target and the system
  contracts. Arrays and bytes are capped. Each call sits inside try/catch, so
  `calls[selector]` and `reverts[selector]` show what the campaign actually reached. It also has a
  ghost-variable section marked TODO, and it talks to the target through a generated ABI-shaped
  interface.
- `<Contract>Invariants.t.sol`. `setUp` has TODO deploy-or-fork comments and contains no
  addresses. It calls `targetContract(handler)` and `targetSelector`. Each property gets an
  `invariant_<name>()` whose body is `assertTrue(false, "TODO: write the property: ...")`, plus
  `invariant_callSummary()`. **The suite fails until every property is written.** This is a
  deliberately failing skeleton, the same convention as `templates/README.md`.
- `harness-plan.json`. Lists contracts, `functions_included` (signature, derived selector,
  handler), and `functions_skipped` with a reason: `view`, `payable-unhandled`,
  `unsupported type` (tuple/struct, nested arrays, fixed arrays over 16), fallback/receive. It
  also lists the properties and a notice.

The generator never writes call sequences, attack steps or exploit logic. The fuzzer picks the
order of calls. You write the property and fill in setUp, funding/approvals and ghost updates. If
a skipped function holds value, write its handler by hand: a function the handler does not expose
is a place where a bug can hide.

### init_race.py

- **Broadcast logs** (`broadcast/**/run-*.json`). It reads both tracked logs and logs that exist
  only in the working tree, and says which (`tracked`). `run-latest.json` is skipped when
  timestamped runs exist. Transactions are ordered per chain across scripts. The proxy check
  matches a CREATE/CREATE2 whose `contractName` is `ERC1967Proxy`, `TransparentUpgradeableProxy`,
  `BeaconProxy`, `UUPS*` or `*Proxy`, and looks at its last constructor argument:
  - empty init data, then a later CALL to the proxy naming `initialize*` → `split-deploy-init`.
    The lead gives the transaction distance and the block gap taken from `receipts`.
  - empty init data and no such call → `no-init-call-seen`.
  - non-empty init data → `atomic`. This is counted, not reported as a lead.
  - `dry-run/` logs were never broadcast. Their leads are labelled and marked low confidence.
- **hardhat-deploy** `deployments/<network>/*.json`. A proxy record that has no `execute`
  method is `proxy-no-recorded-init`. This is best effort, low confidence. **OpenZeppelin
  manifests** `.openzeppelin/*.json` are only listed, proxies and implementations, because they
  do not record the init call.
- **Solidity source** (tracked, in `--scope`, not test or vendored code), read lexically:
  - `implementation-initializable`: a non-abstract contract with initializer functions whose
    constructor neither calls `_disableInitializers()` nor carries `initializer`.
  - `unguarded-initialize`: an external/public `initialize*` with no
    `initializer`/`reinitializer`/`onlyInitializing` modifier and no visible initialized-flag
    check.
  - `script-empty-init-data`: a deploy script that does `new ...Proxy(impl, "")` or
    `deployProxy(..., {initializer: false})`.
- The output includes `oz_v5_initializable_slot`. It is derived with the bundled keccak as
  `keccak256(abi.encode(uint256(keccak256("openzeppelin.storage.Initializable")) - 1)) &
  ~bytes32(uint256(0xff))`. It is not pasted in.

**Triage of a split lead.** A split deploy is exploitable only if the window was real on the live
chain **and** initialize is still callable or was actually front-run. Read the live proxy's
initialized slot at a pinned block with `bounty.py eth-call` / `verify-deployment`. Use the v5
slot above. In OZ v4, `_initialized` is packed into the first slot of the layout. Then read the
`initialize` transaction itself: who sent it, and in which block. A proxy that is already
initialized is history, not a finding, unless re-initialization is possible (`reinitializer(n)`
with a reachable higher `n`, a reset flag, or an upgrade path that re-runs init).

## Writing properties

Write each property in model.md first, with units and rounding direction, and cite the line that
makes it hold. Prefix a guessed property with `inferred:`. Shapes that pay:

- **Conservation.** Tokens held ≥ the sum of recorded claims; `totalSupply == Σ balances`;
  `totalDebt == Σ userDebt` (±rounding, in the protocol's favour).
- **Monotonic indexes.** Borrow/supply index, share price under no-loss conditions, nonce, epoch
  and cumulative funding never decrease.
- **Solvency.** After any sequence, every account that passed the health check still satisfies
  it, or is liquidatable. Abracadabra's bug was a skipped solvency check.
- **No free mint.** Shares or debt-free assets never increase without the matching asset coming
  in. Track this with ghosts from observed balance deltas, not from arguments.
- **Access lifecycle.** Once initialized, a contract stays initialized. A revoked role stays
  revoked. A cancelled order never executes. Ownership changes only through its two-step path.

Keep the handler honest. Fund and approve the actors. Expose only calls an unprivileged actor can
make, or label privileged ones. Watch `reverts[selector]` in the call summary: a selector that
always reverts was never explored.

## Running and recording

Run the campaign in a disposable copy or worktree of the target, never in the working tree
(`templates/README.md`):

```sh
forge test --match-path test/harness/VaultInvariants.t.sol -vvv   # [invariant] runs/depth in foundry.toml
medusa fuzz --target-contracts VaultInvariants                     # with --framework medusa
```

For a fuller Echidna/Medusa suite, the `fizz` skill generates one. A broken property from either
tool counts as the same quality of evidence. For each campaign, record the tool and its version,
the seed, runs, depth, revision and the call summary in `experiments.json`. Then minimise the
counterexample into a concrete candidate test with a negative control before claiming anything.

## Limits

- The harness is a skeleton. A clean campaign covers only the properties that were written, never
  safety, and it depends on bounds, funding and depth. A broken invariant is a candidate. It still
  needs a concrete PoC on unmodified source.
- Tuples/structs, nested arrays, payable functions and fallbacks are skipped and listed. Handlers
  for them are written by hand.
- `init_race.py` is lexical and reads files only. Broadcast logs record what was submitted, not
  what the chain confirmed. Factory-made proxies (CREATE2 through a deployer contract), init via
  multicall or a Safe batch, inherited initializers, custom guard modifiers and assembly flags are
  invisible to it. Its silence is not evidence that a deploy was atomic.
