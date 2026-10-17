# Adapter — Rust / Substrate / FRAME (Polkadot, Kusama, parachains)

Route here, not to `rust-native`, whenever a Cargo manifest pulls `frame-support`, `frame-system`,
`sp-runtime`, `polkadot-sdk`, or any `pallet-*`. FRAME's attack surface is nothing like a generic
Rust binary's: the entry points are *dispatchables* reached through an extrinsic pipeline with its
own fee, weight and validation stages, and most of the exploitable composition lives in the
**runtime configuration**, which is usually in a different repository from the pallets.

## 0. First, find the repo that actually builds the chain

This is the single most expensive mistake available on this stack. The pallet library and the
deployed runtime are frequently separate repos:

| what you read | what runs |
|---|---|
| `paritytech/polkadot-sdk` (pallets, `polkadot/runtime/{westend,rococo}` = **testnets**) | `polkadot-fellows/runtimes` (`relay/polkadot`, `system-parachains/*`) |

Procedure:
1. Read the live `spec_version` from the chain (`state_getRuntimeVersion`).
2. Find the tag in the **runtime** repo whose `spec_version` constant equals it.
3. Read that tag's `Cargo.lock` to get the exact `pallet-*` / `sp-*` crates.io versions, and check
   them against the library checkout you are reading. Matching versions = chain of custody; a
   mismatch means your anchors describe code that is not running.
4. Dup-check **both** repos (see §7). The production relay/parachain runtimes were removed from
   polkadot-sdk by `bf90cb0b73` (#1731), so a finding anchored only in `polkadot/runtime/westend`
   is a testnet finding.

A pallet's `Config` is also set per chain, so "is this even wired in?" is a per-runtime question.
Example: no runtime inside polkadot-sdk installs `PrevalidateAttests`, so Rococo ships `claims` in
the state its own doc calls "Insecure" — while the live Asset Hub runtime does install it.

## 1. The release-profile lens — check this before anything else

In polkadot-sdk's root `Cargo.toml` (~`:1532`):

```toml
[profile.release]
opt-level = 3
panic = "unwind"          # no debug-assertions, no overflow-checks

[profile.testnet]
debug-assertions = true
overflow-checks = true
inherits = "release"
```

Live WASM is built on `release`/`production`. Therefore, in production:
- `debug_assert!` is **compiled out**, and its argument is **not evaluated** — any side effect
  inside it silently never happens.
- `defensive!`, `defensive_assert!`, `defensive_saturating_sub/add`, `defensive_unwrap_or`,
  `log_or_panic!` **log an error and continue with a clamped value** instead of panicking.
- integer arithmetic **wraps** silently.

So: *a guard that is only a `defensive_*` call is not a guard.* Grep `defensive`, `debug_assert`
and `log_or_panic` and ask, for each, "what external actor can reach the violating state, and what
does the clamped value do to the ledger?" The project tests **with** the protections
(`--profile testnet`) and ships **without** them; its own test suite therefore cannot see these.
Always run the decisive PoC under **both** profiles and report both outcomes — "rejected under
testnet, applied under release" is the proof that this lens is load-bearing.

## 2. Fees and weights — where "free" calls hide

- `#[pallet::weight((w, class, Pays::No))]` set **statically** in the attribute means the call is
  free **regardless of whether the dispatch succeeds or fails**:
  `PostDispatchInfo::pays_fee` (`frame/support/src/dispatch.rs:345-355`) short-circuits on the
  **pre-dispatch** info and never consults the result; `compute_fee_raw`
  (`frame/transaction-payment/src/lib.rs:663-688`) then waives **base, length and weight** fees.
- The repo convention is **free on success only**: nearly every production free path returns
  `Ok(Pays::No.into())`, so an `Err` pays (`Pays::default() == Yes`). Enumerate the static form:
  `rg -U '#\[pallet::weight\(\([^)]*Pays::No'`. A static `Pays::No` on a call that can fail is an
  outlier worth reading closely. Parity has itself removed `Pays::No` from this shape twice
  (`498a3e83d0` "do not return Pays::No if call is above weight/size limits", `795a049937`
  "Message delivery transaction is not free!!!"), and the current reviewed idiom puts every
  `ensure!` **before** the `Pays::No` return.
- `#[pallet::feeless_if]` + `SkipCheckIfFeeless` decides freeness pre-dispatch from call args only
  — same structural property, same question.
- **Never claim spam/censorship from a free extrinsic.** `get_priority`
  (`frame/transaction-payment/src/lib.rs`) gives `Normal` class
  `(tip + 1) * min(max_block_length / len, weight cap)`, so a large zero-tip extrinsic scores
  priority ≈ **1** — the lowest possible — while an ordinary 200-byte zero-tip tx scores in the
  thousands. A free spammer occupies only leftover block space and crowds out nothing. Also,
  tipping to regain priority costs the tip, so "free" and "prioritised" are mutually exclusive.
- Extrinsic **length is charged as proof_size**: `frame/system/src/extensions/check_weight.rs`
  (`:57-76`, `:155-165`) does `.saturating_add_proof_size(len as u64)`, and
  `cumulus/pallets/weight-reclaim` does **not** reclaim that term. Get the real per-chain limits
  from live metadata constants (`BlockLength.max[class]`, `BlockWeights.max_block`) rather than
  assuming the 75% Normal ratio — Asset Hub uses 85%.
- Pre-dispatch validation lives in `TransactionExtension`s and `ValidateUnsigned`. A pallet whose
  doc says "insecure unless your chain includes X as a TransactionExtension" is telling you where
  to look: compare the extension's checks against the dispatchable's own checks, and against the
  sibling `validate_unsigned`. **An asymmetry between the two gates is a finding.**

## 3. Storage — two traps that produce false findings

- **Key derivation:** `twox128(pallet_name) ++ twox128(item_name)`, then per-key the map's declared
  hasher: `Twox64Concat` → `twox64(k) ++ k`; `Blake2_128Concat` → `blake2_128(k) ++ k`;
  **`Identity` → `k` with no hash at all**. Polkadot's `claims` maps all use `Identity`
  (`claims/mod.rs:246,261,265`). Using the wrong hasher makes every lookup miss, which looks
  exactly like "every entry is stale" — a clean 100% result is a red flag, not a finding. Verify
  the hasher in the source before trusting any cross-reference.
- **`ValueQuery` with a default:** an absent item does **not** read back as zero; it reads back as
  its declared default. `StorageValue<_, u32, ValueQuery, ConstU32<DEFAULT>>` on an untouched chain
  returns `DEFAULT`. Never infer "unset → 0".
- Unbounded growth: a `Vec<u8>`/`Vec<T>` **call argument** with no `MaxLength` bound, and
  `BoundedVec` bounds applied only to *stored* types, are different things — check both.

## 4. Composition lattices — the most under-audited surface

Auditors audit pallets; the runtime wiring that composes them gets far less scrutiny, and it is
where a declared relation can contradict the filter that implements it.

- **`pallet_proxy`**: a proxied `add_proxy`/`remove_proxy` is authorized on
  `def.proxy_type.is_superset(proxy_type)` **alone** (`frame/proxy/src/lib.rs:1008-1013`). So for
  every declared edge `(A, B) => true` in `is_superset`, check that `filter(A) ⊇ filter(B)` over
  the real `RuntimeCall` variants. A blanket arm like `(ProxyType::NonTransfer, _) => true` is
  false the moment any other type admits a call family `NonTransfer` omits — and an in-source
  comment such as `// Specifically omitting Registrar \`swap\`` is the author stating the intent
  the lattice breaks, which is the strongest possible rebuttal to "working as designed".
- **Dispatchers vs filters**: a call blocked by `BaseCallFilter`/`SafeCallFilter` but reachable
  through `Utility::batch`, `Proxy::proxy`, `Multisig`, `Scheduler` or XCM `Transact`.
- **Referenda tracks**: each track's `origin` vs the `EnsureOrigin` the privileged call requires —
  can a cheap, fast track dispatch an origin a stricter track was meant to gate?
- **XCM config** (distinct from executor internals): `XcmExecuteFilter`, teleport/reserve filters,
  barrier tuples, `Aliasers`, `LocationToAccountId`, `OriginConverter`. Look for a location that
  converts to a privileged account, or an aliaser admitting what the barrier rejected. Note
  `TakeWeightCredit` sits first in most barrier tuples and `pallet_xcm::execute` passes full weight
  credit, which short-circuits the shape checks behind it.
- **Migration seams**: after a state migration (e.g. the Asset Hub Migration), look for pallets
  still wired on the origin chain with emptied storage but live, callable extrinsics, and for
  Config params still shaped for the old chain.

## 5. Proving live reachability

Read-only, aggregate/structural reads only; never enumerate, profile or name an individual account,
and never submit a transaction. Useful calls: `state_getRuntimeVersion`, `state_getKeysPaged`
(count keys under a prefix), `state_queryStorageAt` (batch up to a few hundred keys),
`state_getMetadata` (for constants and the extension stack), and `state_call` for runtime APIs —
e.g. `NominationPoolsApi_pool_pending_slash` with a SCALE-encoded `u32` argument.

Sweep the **whole** id space, not a prefix of it: a sweep of pool ids 1..120 concluded "no pool is
slashed" when id 200 was. And distinguish the *arming* condition from the *loss* condition — one
pool having a non-zero `pending_slash` arms a code path, but if no sub-pool is actually diluted the
realisable loss is zero and the finding is latent, not live.

## 6. What does not pay on this stack

- **Pure DoS / liveness / chain growth.** Parity's terms exclude anything that "requires special or
  unrealistic conditions" and anything where "there's no way they can be used to break our systems
  in practice". Combined with the priority-≈-1 fact in §2, free-blockspace findings are informative
  at best.
- **A precondition the attacker cannot create.** Trace every storage item in the precondition to
  its writers. If the only writers are genesis and a root-gated call, the exploit needs specific
  pre-existing private keys and is out of scope by the "special conditions" clause. Do this *before*
  building a PoC — it is cheap and it is decisive.
- **Latent bugs.** Code-correct but currently unreachable states fall under "no practical impact".
- **A fix merged upstream but not yet released.** The live chain is genuinely vulnerable, which
  matters operationally, but the issue is known → worthless as a bounty.

## 7. Dup-check, specific to this stack

Run all of these before any impact work or PoC:
- `git log --all -S'<exact code>' -- <path>` and `git log --all --grep=<term>` in the **library** repo.
- `git show origin/master:<path>` and `git show origin/stable<NNNN>:<path>` — is the code still
  identical upstream? (Nearby hardening of the *same file* that left your line alone is a useful
  signal that maintainers looked and did not change it — it cuts both ways, so report it.)
- `rg -il '<pallet>|<term>' prdoc/` — every user-visible change carries a prdoc entry, so an absent
  prdoc is real evidence of novelty.
- The **runtime** repo's `main` HEAD and merged PRs, plus
  `git merge-base --is-ancestor <fix-sha> <live-tag>` to tell "fixed and released" from "fixed on
  main, live chain still vulnerable, issue known".
- Partial/blob-filtered clones make `git log -S` fetch blobs and it can time out; fall back to
  path-restricted pickaxes and say so rather than reporting an incomplete sweep as clean.

## 8. Submission channel

Parity runs its own program: terms at `parity.io/bug-bounty`, submissions **only** through the form
at `security-submission.parity.io`. Hosting the report externally and linking to it is explicit
grounds for disqualification — so the usual secret-gist workflow must **not** be used here. Scope
covers both `paritytech/polkadot-sdk` and `polkadot-fellows/runtimes`. Payout is discretionary with
no published table; identity and a DOT address are required. The HackenProof mirror of the same
codebase charges a submission fee and has a reputation gate — check the engagement's constraints
before choosing a channel, and never submit the same finding to both.
