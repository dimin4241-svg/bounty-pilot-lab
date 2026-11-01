# Audit lenses

Two kinds of lens, and they are used differently.

**Aimed lenses** live in `hunt-agents/` and are dispatched per pass by `passes.md`. Each is a
procedure over one axis — time, lineage, observability, aggregates, boundary authorization,
persistence, live truth, the Solana account model — and each produces falsifiable candidates.

**Classic bug-class lenses** are the list below: the standard sweep for well-known vulnerability
shapes. Select only the relevant ones; a generic checklist pasted into a report is not a finding.
On Solidity targets this sweep is exactly what `solidity-auditor` does in parallel and in depth, so
prefer delegating it when installed (see `compare.md`) and spend your own passes on the aimed
lenses it has no equivalent for. The `classic` hunt lens (`hunt-agents/classic-agent.md`) is the
dispatched form of this list: its Part A — EVM semantics newer than most checklists, such as
EIP-7702 delegated EOAs, transient storage, Permit2, L2 sequencer checks and v4 hooks — runs on every
EVM target, and its Part B is the fallback sweep when `solidity-auditor` did not run.

**Blind-spot lenses** are in `blind-spots.md`: controls that exist only as live configuration,
derived constants nobody recomputes, the odd one out (computed for Solidity by `impact-plan` into
`odd-one-out.json`), the authoritative value that was available
and unused, safety resting on a dependency detail, state that only exists between versions, code
that is deployed but absent from the repository, the surface your own run closed with a blocker
nobody reproduced, and the cliff at a scale nobody's test fixtures ever reach.
Reach for them on a heavily audited target where the lenses above came back empty.

For every lens, produce: entry point, attacker capability, preconditions, state transition, broken
property, consequence, experiment. Derive the property from the protocol's actual intent, read from
its docs, specs and tests — not from a template.

## Solidity / EVM

- **Access lifecycle:** creation, initialization, ownership and role transfer, revocation, delegated
  permissions, callback authority, upgrade authority.
- **Signed intent:** signer, account, chain, nonce, deadline, action and parameter binding; compare
  the quoted intent against the executed order and recipient.
- **Asset accounting:** per asset, the real balance, the accounted balance, shares, debt, pending
  claims and every writer; reconcile all branches; separate user loss from protocol debt from dust.
- **Arithmetic:** units, decimals, casts, rounding beneficiary, repeated operations, minimum nonzero
  values, the first and last user, exhausted reserves.
- **Time and cohorts:** accrual relative to entry and exit, checkpoints, epoch rollover, expiry,
  cancellation, claim uniqueness.
- **Solvency and liquidation:** economic assumptions, price freshness, collateral and debt
  valuation, bad debt, liquidation reachability, and the capital and liquidity actually required.
- **Integration:** external call boundaries, hooks, read-only and cross-contract reentrancy, the
  token behaviours the project really supports, oracle trust, returndata and gas limits.
- **Liveness:** poisoned queues and batches, retry persistence, restart and recovery, gas growth,
  griefing cost, victim impact and repair paths.
- **Cross-chain:** message identity, domain and source binding, replay state, finality, retries,
  refunds and compensation.

## Rust / Solana

Establish the program boundary and runtime from Cargo and Anchor metadata. Then work the account
model — signer, writable and owner checks, PDA seeds and bumps, account substitution, CPI authority,
account lifecycle, close and reinitialisation, arithmetic, token-program selection — with the
procedure in `hunt-agents/anchor-account-agent.md`. Include Token-2022 extensions only where they are
reachable in a supported configuration. Demonstrate account constraints and runtime behaviour in a
local validator or test harness. An ordinary Rust panic is a failed transaction, not a chain halt.

For off-chain Rust: untrusted parsing, panic and abort boundaries, persistence and retry state,
resource growth, synchronisation, and `unsafe`. Keep chain and runtime semantics explicit.

## Web and dApp frontend

The `web` group bundles the web sources (`.ts`, `.tsx`, `.js`, `.jsx`, `.vue`, `.svelte`, `.html` and
similar) and leaves out deploy, script, task and migration folders and tool configuration.

When the program lists a website or an app next to the contracts, it is usually the only in-scope
surface with no competent competition, and the aimed lens for it is
`hunt-agents/web-frontend-agent.md`. The payable class is narrow — typically only script execution or
a redirect that changes **what the user is asked to sign** — and the exclusion list removes everything
a scanner reports, so read the program's web exclusions before the first grep. The one question that
closes the largest class in a single pass: does any URL parameter, hash fragment or stored value set a
transaction recipient, spender, router, token address or calldata?
Two disciplines carry over to every target: prove the sink and the source **separately** and file
neither alone; and settle a URL guard against `new URL()` rather than by eye, because a hostname check
that ignores the scheme passes `javascript://host/%0a…`.

## Below the contracts, beside them, and in front of the user

Three groups added in 0.25.0, each selected from what the target **is**, not from its language.

**`node` → `hunt-agents/node-client-agent.md`.** The node, client, runtime, precompile or prover.
Six of the seven largest public bounties ever paid were in this layer — a precompile delegatecall,
a client fork duplicating ETH, a system contract missing a balance check, a malleable bridge proof,
an uninitialised proxy whose impact was a permanent freeze — and about a fifth of one platform's
lifetime payout value went to blockchain and DLT targets. The lens walks untrusted ingress to the
first parser, follows wire-supplied lengths into allocations, finds panics on the block-processing
path, and asks about determinism. `stack_route.py` selects it when a Go, native-Rust or Substrate
stack is detected and never otherwise, because on a contracts-only target it reads nothing.
Its discipline is one rule: **trace the panic to the process** before calling it a crash.

**`artifacts` → `hunt-agents/secrets-artifacts-agent.md`.** What the project published without
meaning to: served bundles and source maps, packaged mobile and desktop clients, container and CI
artifacts, and the commit history behind the current checkout. One of the two confirmed Highs in
this skill's own ledger came from this class and was found by accident, outside the pipeline. The
lens never uses a credential it finds; the finding is that the value is published and what the
service's own permission model says it would authorise.

**`signing` → `hunt-agents/signing-control-plane-agent.md`.** Research off-chain
signing and withdrawal authorization across API, queue, worker, HSM/MPC/EOA signer
and EIP-7702 delegated EOA policy. Only a demonstrated low-privilege route
becomes a candidate. The `cross-stack` group includes this lens, while
`recommended` selects it only on passive off-chain signing code/path signals.

**`wallet-app` → `hunt-agents/wallet-agent.md`.** The client that signs: extension, mobile, desktop
or a hardware device's companion app. Every finding in the class is one sentence — the user saw A
and signed B, or an origin that should not have been able to ask, asked. Its bundle carries the web
sources when the target ships them and the ordinary source tree otherwise. The exclusion that
decides the class: **a precondition of a compromised host pays nothing** on every programme in it,
so the entry point has to be remote — a page, a link, a message, a peer.

## Other languages

Route from `adapters.md`. Build the model from primary documentation and the project's own tooling,
and state plainly when this package has no specialised checklist for that stack. Do not carry EVM
assumptions into Move, CosmWasm, TON, Cairo or a native bridge. Use an ecosystem-specific upstream
skill only after checking its compatibility, and record which one ran. For a mixed repository, run
component-specific analysis and a separate cross-boundary pass.
