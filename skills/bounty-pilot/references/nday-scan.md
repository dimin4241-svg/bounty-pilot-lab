# N-day scan: upstream fixes the target never took

The `upstream-diff` lens reads what a fork **changed** against its upstream. This is the other
direction: the fixes upstream **shipped after** the revision the target pinned, which the target
never merged. For a fork, a submodule or a vendored library, each one is a candidate N-day in the
target, and it became public the moment upstream pushed it.

Why it earns a step:

- **Cosmos EVM, August 2026.** A fix was pushed to the public repository on 19 August with no
  advisory. From 20 to 25 August six chains running the unpatched module (MANTRA, TAC, KiiChain,
  Nesa and others) were exploited, roughly $14.8M realized. The commit was the disclosure.
- **Cetus, May 2025 (~$223M).** An overflow check in the `integer-mate` math dependency, not in
  the protocol's own code.
- **Liquid / Elements, September 2026.** A bug in mature upstream node software, inherited by
  everything built on it.

Loss figures are approximate; cite the protocol's own post-mortem in a report.

## When to run it

Whenever the target's code is someone else's code at a pinned revision:

- forks of chain frameworks: Cosmos SDK / Cosmos EVM / CometBFT / ibc-go, OP Stack, Arbitrum
  Nitro, geth / reth / erigon forks, Substrate / Polkadot SDK;
- DeFi forks: Uniswap v2/v3/v4, Aave, Compound, Curve, Balancer, Morpho, GMX;
- vendored or pinned libraries: math libraries (`integer-mate`, `FullMath`, `PRBMath`,
  `solady`), OpenZeppelin copies, bridge or light-client verifiers;
- Move / Sui / Aptos packages pinned by `rev` in `Move.toml` (scan with `--map` against the
  package directory), Rust crates pinned by git `rev` in `Cargo.lock`, Go modules in `go.mod`.

Run it in intake, next to the `upstream-diff` lens, and again before writing a report on a fork
(a fix you found may already be upstream - which changes novelty, not just severity).

## Commands

The tool is offline. Clone and fetch the upstream yourself; it never touches the network.

```
git clone https://github.com/cosmos/evm /path/to/cosmos-evm && git -C /path/to/cosmos-evm fetch --all --tags
python3 $S nday-scan --repo <checkout> --upstream cosmos-evm=/path/to/cosmos-evm --out <run>/nday-scan.json
```

Options:

- `--upstream NAME=PATH` (repeatable) - a local clone. NAME is matched against submodule paths
  and URLs, `go.mod` module paths, `Cargo.lock` package names and advisory package names.
- `--map NAME=TARGET_SUBDIR:UPSTREAM_SUBDIR` - where a vendored copy lives
  (`--map integer-mate=sources/math:sources`). Also selects a submodule by path. An empty side
  means the repository root (`vendor/geth:`).
- `--ref NAME=REF` - compare against a branch or tag other than the clone's `HEAD`. Fixes often
  land on `main` and on release branches separately; run once per line you care about.
- `--advisories FILE` - a JSON list you exported (GHSA, OSV, the vendor's security page):
  `[{"id", "package"|"name", "summary", "patched_commit" | "fixed_versions", "url"}]`.
- `--since-days N`, `--limit N` (default 200 per upstream), `--walk-cap N` (default 2000).

How the pin is found, in order: submodule gitlink; vendored copy by blob-hash match (with match
fraction and confidence; a tie resolves to the older commit so more is listed, and a capped walk
says so); shared history for a fork that has upstream commits; `go.mod` tag or pseudo-version;
`Cargo.lock` git `#sha`. Otherwise `unresolved` with the reason - never dropped. A `go.mod`
`replace` is reported, not followed: the target runs the replacement, so scan that.

## Reading the output

Each upstream row has `pinned`, `resolution`, `confidence`, ranked `candidates` and `omitted`.
Each candidate carries `score`, `signals` (message keywords and diff shape: an added
require/assert/revert, a changed comparison operator, checked arithmetic, a bounds check),
`files`, and `fix_status`:

- `fix_absent` - the target's copy still has the pre-fix text (blob equality, or the upstream
  diff applies cleanly with `git apply --check`);
- `fix_present` - the target already has the post-fix text (blob equality, or the diff
  reverse-applies);
- `undetermined` - the copy diverged; read the hunks by hand.

An advisory row is `advisory_unpatched` when no patched commit or fixed-version tag is an ancestor
of the pin, `patched_at_pin` when one is, `undetermined` when nothing resolves in the clone, and
`no_matching_upstream` when no `--upstream` matches its package.

Read the top of the list first, but do not trust the ranking: silent security fixes are titled
"refactor" or "cleanup" on purpose, and the Cosmos EVM fix carried no advisory. Skim the
zero-score rows that touch consensus, accounting, signature or bridge code too.

## Triage of a candidate

Every row is a lead, not a finding.

1. **Confirm the pin.** A `low` or `medium` confidence vendored pin can be wrong; diff the
   target's copy against the reported commit for the touched files.
2. **Confirm the target reaches the changed code.** Is the function called, the module wired in,
   the message type registered, the precompile enabled, the feature flag on in the deployed
   configuration? An unmerged fix to an unused path has no impact.
3. **Understand the bug from the fix.** Read the diff and the upstream tests added with it; state
   the violated invariant in one sentence.
4. **Write a native candidate test and a negative control** in the target's own harness: the
   candidate reaches the bug on the target's revision; the control applies the upstream fix (or
   uses the guarded input) and must not. Follow `evidence.md`; a dry run is not evidence.
5. **Check whether it is already public or known.** An advisory, a CVE, an upstream issue, the
   target's own known-issues page, a previous report - this decides novelty and eligibility. Run
   the dup-map (`dup-map.md`) and read the program's scope: some programs exclude known or
   upstream issues, or pay them only if the target's own code is affected, or cap them.
6. **Confirm the deployed revision** (`verify-deployment`, the chain's released binary version)
   before claiming live impact.

## Ethics

A public upstream fix that the target has not merged is an exploitable gap for everyone who reads
the upstream log - which is exactly why it must be handled quietly. Report it **privately** to the
program through its official channel, never in a public issue, PR, tweet or chat, and never
exercise it against a live deployment. If the target has no program, use the upstream's security
contact or the chain's disclosed security contact. Keep `nday-scan.json` in the private run
directory; it is a list of unpatched weaknesses.
