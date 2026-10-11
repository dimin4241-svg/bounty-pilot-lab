# PoC templates

## Convention (one pass/fail rule everywhere)

Every template and generated skeleton follows a single convention, so the exit code means the same
thing across Solidity, Rust/Anchor, Python and Go:

- **The candidate test PASSES if and only if the vulnerability is demonstrated.** It asserts the
  attacker's gain, the broken invariant, or the wrong resulting state — not that a call reverted.
- **The negative-control test PASSES if and only if the protection holds** on the control path (the
  same sequence with the one attacker capability removed, or against the fixed code).
- **Both tests are expected to exit 0** (both pass). That is what `scenario_runner.py` /
  `native_fuzz_plan.py` encode as `expected_exit: 0` for candidate and control alike.

A freshly generated skeleton deliberately *fails* (a `revert("fill in")` / `panic!` / `raise` /
`t.Fatal`) until you implement it, so an empty skeleton is never mistaken for evidence.

## Where to put the test — a disposable copy, never the working tree

`forge test --match-path` and the runner's cwd confinement both require the test file to live
**inside the checkout**. Do not add it to the user's working tree. Instead:

- make a **disposable copy or a `git worktree`** of the target at the recorded commit, e.g.
  `git worktree add ../poc-<commit> <commit>`, and place the PoC under its `test/` there; or
- copy the target into a throwaway directory pinned to that commit.

Keep the target **source unmodified**; only the added test file differs. Delete the copy/worktree
when done. This is the only reason a template ever sits next to the target code.

## What a template must contain

Every template is built around the four things `evidence.md` requires and a reviewer looks for:

1. **Unmodified production source.** Import or fork the real contracts. If you must change anything
   to make the exploit work, the exploit does not exist yet — record the change as a limitation.
2. **An assertion on the violated property** (candidate) or the maintained property (control), not
   on a revert. `vm.expectRevert` proves a revert happened; it does not prove a vulnerability. State
   the property in the assertion message, and log initial/final state.
3. **A negative control** in the same file, following the convention above. Without it, a reviewer
   cannot tell your harness from your finding.
4. **A pinned environment.** A fork test without a pinned block (`vm.createSelectFork(rpc, block)`)
   is not reproducible. Read the RPC endpoint from an environment variable and name that variable in
   the runner's `pass_env` list; never hardcode a key.

No private keys, no mainnet transactions, no broadcast. Use `vm.prank`, impersonation and local
forks. Read the program's rules before any network interaction.

| Template | Use for |
| --- | --- |
| `ForkPoC.t.sol` | a deployed EVM protocol, exploited against live state at a pinned block |
| `LocalPoC.t.sol` | a source-level finding on code that is not deployed, or needs a built-up state |
| `Invariant.t.sol` | a property that breaks under some sequence you cannot name by hand |
| `anchor_poc.rs` | a Solana program, account substitution and PDA findings |
