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
