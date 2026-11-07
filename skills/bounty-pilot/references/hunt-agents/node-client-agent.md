# Node and client agent — the layer under the contracts

Six of the seven largest public bounties ever paid were not application logic. They were a
precompile that let a caller delegatecall into the chain's own exit path, a client fork that
duplicated ETH on `SELFDESTRUCT`, a system contract with no balance check, a bridge proof whose
branch mask was malleable, and an uninitialised proxy whose impact was a **permanent freeze** of
the bridged funds. About a fifth of one platform's lifetime payout value went to blockchain and
DLT targets. This is that layer: the node, the client, the runtime, the precompile, the prover.

Your question is not "can someone steal". It is: **what can a peer, an RPC caller, or a crafted
block do to a node that keeps running the rest of the network?**

## Procedure

1. **Map the untrusted ingress.** Every byte that arrives from somebody you do not control: p2p
   messages, gossip, RPC and its batch forms, block and transaction bodies, snapshot and
   state-sync chunks, the archive or history protocol, and anything a peer can make the node
   fetch. For each, find the first function that parses it, and read that function.
2. **Follow every length and count that came from the wire.** A length field read before the data
   it describes is an allocation an attacker sizes. Look for `with_capacity`, `reserve`, `vec![0;
   n]`, `make([]T, n)`, a buffer sized from a header, a loop bounded by a peer's number, and a
   decompression ratio nobody caps. The bug is usually not a crash: it is a node that allocates
   gigabytes because a peer said `0xffffffff`.
3. **Find the panics that are reachable from that ingress.** `unwrap`, `expect`, `panic!`,
   `assert`, slicing, integer indexing, division, `unreachable!`, `todo!`, and in Go an
   out-of-range index or a nil map write. Then do the step that decides whether it is a finding:
   **trace the panic to the process.** Is it caught by a task boundary, a recover, a supervisor
   that restarts, a per-peer task that dies alone? A panic in a worker that restarts is noise; a
   panic in the block-processing path that halts the node is a finding.
4. **Separate the three blast radii, and say which one you have.** One peer connection dies; this
   node stops; every node that processes the same block stops. Only the third is a chain halt, and
   it is the one with the severity. A message only the sender's own peer parses is not it.
5. **Ask about determinism wherever consensus reads it.** Map or set iteration order, floating
   point, a time or environment read, `HashMap` ordering, locale, goroutine scheduling, a sort
   that is not total. Two honest nodes that compute different results from the same input is a
   fork, and it is the highest-value shape in this class.
6. **Read the block and epoch hooks.** `BeginBlock`/`EndBlock`, `on_initialize`/`on_finalize`,
   epoch transitions, slashing and reward loops: work that is not metered, iterates a collection
   a user can grow, or panics. The user who grows the collection and the node that dies on it are
   often different people, which is what makes it payable.
7. **Read the state transition for the cheap-work asymmetry.** What costs the attacker one
   message and the node a thousand operations: a verification done before a cheap check that
   would have rejected it, a signature checked before the sender is known to exist, a proof
   verified before its header is validated.
8. **Check the resource ceilings that exist.** Peer limits, rate limits, message size caps,
   timeouts, queue bounds. Then check the path that bypasses them: a second endpoint, an
   unauthenticated variant, a code path taken before the limiter runs.

## Where the money is

- A length or count from the wire that sizes an allocation before anything validates it.
- A decoder reached before authentication, especially a custom one beside a hardened one.
- A panic on the block-processing path, where every node processing that block hits it together.
- Non-determinism anywhere a consensus value is computed.
- An unmetered loop in a block hook over a collection any user can extend.
- A precompile, host function or syscall whose argument handling differs from the VM's own rules,
  particularly anything that forwards a call with the caller's privileges.
- A client's own deviation from the specification its peers implement — this is where a fork of
  an audited client earns its keep, so diff against upstream and read what the fork changed.
- Proof or witness verification that accepts an encoding the honest producer never emits.

## Discipline

- **A panic is not a finding until you have named the process that dies.** Read the caller's
  error arm, the task boundary, and the supervisor. "The node panics" has been wrong more often
  than right, because the restart loop was right there.
- **Say which blast radius you proved,** and do not write the third when you measured the first.
- **A validator attacking the network is usually out of scope**, and so is anything that needs a
  quorum of honest validators to misbehave. Read the program's text before spending the pass.
- **Debug-only and test-only paths pay nothing.** Check the build profile, the feature flags and
  whether the binary ships with that code.
- A crash reachable only with a flag no operator sets, or a config file nobody deploys, is the
  excluded shape. Find who sets it in production before claiming it.
- **Measure the client's share before pricing severity** when the rubric grades by it: a share
  you cannot change caps every severity on that target.

## Verification caches, mempool validation and precompile state bridges

Three places where a node accepts something it never verified: a cache that remembers a verdict,
a mempool that admits what block building cannot handle, and a precompile that moves value between
the EVM and native module state.

1. **Check every verification cache key against every input the verdict depends on.** A cache hit
   must be at least as strict as the miss path. Liquid/Elements, Sep 2026, roughly $320M: on a
   range-proof cache hit, `secp256k1_rangeproof_verify` and the min-value checks were skipped, so
   3,998 unbacked L-BTC were created. Aptos Move VM, Feb 2026 (Hexens): a stale cache led to type
   confusion, and Aptos disputes practical exploitability. For each cache, list the inputs the
   verifier reads and the fields in the key; a missing field is the finding.
2. **Diff mempool admission against block building.** Every rule block building assumes must be
   enforced at admission. Nethermind, Feb 2026, $50k Ethereum Foundation bounty: blob transactions
   with more `blobVersionedHashes` than blobs entered the mempool, block building then produced
   null entries, and every Nethermind proposer missed its slot. It was found by an AI tool and
   validated by a human.
3. **Measure asymmetric CPU on P2P paths.** ETH Rangers, 2026, reported 14 bugs across all five
   execution clients, many of them flooding and work-asymmetry shapes. Price each message by the
   work it causes before the peer is penalised.
4. **Probe state-root edge cases.** Empty accounts, self-destructed and recreated storage, and
   reorg boundaries where two code paths compute the root (Reth, Nov 2026).
5. **Read precompiles that bridge EVM and native module state.** Every balance a precompile reads
   or writes on the native side must stay in sync with the EVM view, including vesting and locked
   balances. Cosmos EVM ASA-2026-002, Aug 2026, concerned the ICS20 precompile. A vesting/locked
   balance sync underflowed `0 - 1` to `MAX_UINT` and was exploited on six chains after a silent
   upstream patch; on any fork, run `bounty.py nday-scan` (see `references/nday-scan.md`) to find
   upstream fixes the fork has not taken.
6. **Check sync liveness.** A peer that can stall block sync is a liveness finding: CometBFT
   blocksync stall, Apr 2026, CVSS 7.1.

For Cosmos SDK chains, read `references/adapters/cosmos-sdk.md` for module, precompile and
`BeginBlock` specifics. Proof is a native test in the client's own harness: the cached input that
skips verification, the admitted transaction that breaks block building, or the precompile call
sequence whose native and EVM balances diverge.
