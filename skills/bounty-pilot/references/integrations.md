# Optional upstream integrations

Bounty Pilot is original orchestration with built-in lenses. It does not vendor or automatically
install anything below, and no comparative benchmark establishes a performance claim for any
combination. `compare.md` holds the detailed comparison with `solidity-auditor` and the recommended
division of labour — read it before delegating a stage.

| Upstream | Selected contribution | Repository |
| --- | --- | --- |
| Pashov | `solidity-auditor` for the classic Solidity bug-class sweep, `x-ray` for readiness and threat modelling, `fizz` for invariant suites | https://github.com/pashov/skills |
| Trail of Bits | differential review, variant analysis, false-positive checking, property-based testing, spec-to-code compliance | https://github.com/trailofbits/skills |
| 0xSimao | independent accounting-focused review | https://github.com/0xsimao/0xsimao-ai |
| QuillShield | targeted semantic guards, invariants and integration checks | https://github.com/quillai-network/quillshield_skills |
| Sanbir | additional EVM vectors, overlapping with Pashov | https://github.com/sanbir/solidity-auditor-skills |
| claudit / Solodit | search publicly disclosed audit findings by class, surface and protocol | https://github.com/marchev/claudit |

For `claudit`, a Solodit API key and a configured MCP server are required. Use it only as a public
known-finding search: it cannot see a program's private queue. Search with a generic mechanism and
project identifier; never send private report text, unpublished exploit steps or target credentials.
Copy relevant public results into `dup-map.json` with the source and a mechanism comparison. A
result proposes a collision; it does not decide one.

## Stack-specific references

| Upstream | Use when | Limit |
| --- | --- | --- |
| OpenZeppelin Skills | The target uses OpenZeppelin contracts or upgrade tooling; check APIs and version-specific upgrade assumptions | Development guidance, not an auditor; inspect its AGPL-3.0 licence before redistribution |

https://github.com/OpenZeppelin/openzeppelin-skills

## Vetted additions by stage

Checked on 2026-10-17 by reading each repository's files at its HEAD, without installing or running
anything. Pin the commit you review; an update needs a new review. None is bundled, none has a
measured effect on findings, and every one is optional.

| Upstream | Stage or lens it serves | What it adds here | Before you use it |
| --- | --- | --- | --- |
| [trailofbits/slither-mcp](https://github.com/trailofbits/slither-mcp) | Bundles; `privileged-path`, `upgrade`, `seam` | Compiler-accurate queries by function: callers, callees, modifiers, inheritance, storage layout | AGPL-3.0. Telemetry is on by default — run with `--disable-metrics`, never `--enhanced-error-reporting`. Installs from an unpinned `git+` URL: pin a commit. Writes `artifacts/` into the target, so use a disposable checkout |
| [cdump/evmole](https://github.com/cdump/evmole) (`agent/mcp`, `evm-bytecode-analysis`) | `verify-deployment`, `live-reality` | Selectors, arguments, mutability and storage access recovered from deployed bytecode, offline — functions live on chain but absent from the source, unverified implementations | MIT. Pin the version instead of `@latest`. Recovered signatures are inference, not fact |
| [cholakovvv/foundry-poc-mainnet-fork](https://github.com/cholakovvv/foundry-poc-mainnet-fork) | Stage 5 (EVM) | Rules that keep a fork PoC honest: real deployed addresses, no mid-chain `vm.store`, no `deal` into protocol contracts, end at realised impact | MIT. Pass your own RPC (it falls back to public ones). It writes no negative control; this workflow still requires one |
| [zksecurity/zk-skills](https://github.com/zksecurity/zk-skills) `circom-auditor` | A ZK circuit stage this package does not have | Constraint soundness: under-constrained signals, range checks, field arithmetic, binding | MIT, v0.1. Circom only, sized for small circuits. It is a multi-agent orchestrator: delegate a bounded stage, never nest it |
| [pantheraudits/move-auditor](https://github.com/pantheraudits/move-auditor) | `adapters/move.md` | Sui and Aptos checklists, DeFi packs and a false-positive catalogue far deeper than the adapter here | README says MIT but there is no LICENSE file. It auto-activates on `.move` files and starts its own phases — read it as reference, do not install it globally |
| [keep-starknet-strange/starknet-agentic](https://github.com/keep-starknet-strange/starknet-agentic) `skills/cairo-auditor` | `adapters/cairo.md` | About thirty Cairo bug classes from real audits, Semgrep rules, a findings schema | MIT. Its SKILL.md shows a state-changing `invoke` with a private key for "exploit-path validation" — that breaks this workflow's read-only rule; never run it. Copy only the skill folder |
| [sanbir/ton-auditor-skills](https://github.com/sanbir/ton-auditor-skills), [solana-auditor-skills](https://github.com/sanbir/solana-auditor-skills) | TON (no adapter here); Solana | 120 FunC/Tact vectors (bounce handling, send modes, async re-entrancy, spoofed jetton notifications); 105 Solana vectors | MIT, textbook level, not updated since March. Each run fetches a remote VERSION file — remove that line |
| [trailofbits/skills](https://github.com/trailofbits/skills) newer modules | `economics`, `accounting`; CosmWasm; entry points on non-EVM stacks | `dimensional-analysis` (units, decimals, WAD/RAY), `cosmos-vulnerability-scanner`, `entry-point-analyzer` | Licence is CC-BY-SA-4.0. `dimensional-analysis` writes comments and a scope file into the target — disposable checkout only |
| [J4X-Security/K.I.T](https://github.com/J4X-Security/K.I.T) | Stage 1 `dup-map.json`, `audit-inventory` | Turns audit PDFs and folders into a known-issues list and checks a candidate against it — the PDF reading `audit-inventory` does not do | MIT; needs `pdfplumber` and `pypdf`. Copy what it finds into `dup-map.json` with the source; a match proposes a collision, it does not decide one |
| [hackenproof-public/skills](https://github.com/hackenproof-public/skills) | Stage 7, HackenProof programs only | The platform's own PoC and report rubrics | No LICENSE file. It rates `forge test --fork-url` PoCs as invalid and a mainnet attack transaction as top evidence — never act on that tier; this workflow never broadcasts. Check the program's own PoC rule |
| [han-sec/trident-fuzz-skill](https://github.com/han-sec/trident-fuzz-skill) | Stage 5, Solana invariant campaigns | A five-phase Trident procedure | Small and young; pin it |

For finding more, [pashov/ai-web3-security](https://github.com/pashov/ai-web3-security) is the best
maintained index seen, and [gonzaloetjo/awesome-solidity-skills](https://github.com/gonzaloetjo/awesome-solidity-skills)
keeps a table of risky repositories.

### Looked at and not recommended

| Repository | Why not |
| --- | --- |
| PraneshASP/foundry-mcp-server, mcpdotdirect/evm-mcp-server | Read a private key from the environment and can send transactions; `cast` in the shell already reads everything needed |
| bountyoperator/bounty-operator | Its hosted review sends source, report and API key to a third-party service |
| JoranHonig/grimoire | Its session hook loads a `GRIMOIRE.md` from the project into context, so a target repository can inject instructions |
| DarkNavySecurity/web3-skills | Needs explorer and RPC keys plus extra tooling, overlaps this workflow, fetches a remote VERSION each run |
| heavyw8t/The-Judge | No licence; generic invalidation reasons conflict with the anchored-objection rule |
| monad-developers/ultrafuzz | Runs agents with permissions skipped; its own authors say to use a throwaway VM |
| Solodit wrappers other than claudit, generic Solidity sweeps, web2 bounty dumps | Duplicate what is already integrated |

## Optional analysis and test tools

Choose a tool only when it fits the repository's pinned stack. Run it against the existing build
and tests where possible; first write the security property it is meant to check. A clean scanner
result is not proof of safety, and a fuzzer run without a meaningful property is not useful
coverage.

| Tool | Useful for | Keep in mind |
| --- | --- | --- |
| [Slither](https://github.com/crytic/slither) | Static triage and code-structure queries for Solidity/Vyper | AGPL-3.0; review findings against the exact build, since detectors are leads, not proofs |
| [Echidna](https://github.com/crytic/echidna) | ABI-driven stateful property fuzzing and Solidity assertions | Define invariants and realistic actor/state setup before the campaign |
| [Medusa](https://github.com/crytic/medusa) | Parallel, coverage-guided stateful EVM fuzzing | Pin the installed version and record campaign budget, corpus and result; AGPL-3.0 |
| [Crytic properties](https://github.com/crytic/properties) | Example properties for ERC-20, ERC-721, ERC-4626 and fixed-point math | Treat them as adaptable examples; confirm they match the protocol's intended semantics |
| [Trident](https://github.com/Ackee-Blockchain/trident) | Fuzzing Anchor/Solana programs with adversarial transaction sequences | Requires a compatible Anchor harness and properties; it is not a general Rust fuzzer |
| [Aptos Move Prover](https://aptos.dev/build/smart-contracts/prover) | Formal checks of supported Aptos Move specifications | Applies only where the actual chain/runtime and specifications support it; do not assume Sui compatibility |

When requested or already installed:

1. Inspect the upstream `SKILL.md`, its scripts, its licence and its runtime requirements. Record the
   exact commit and the selected module in `integrations.json` in the private run. Do not execute a
   fetched install script blindly.
2. Install into the runtime's documented skill location with distinct names, so a fork does not
   overwrite another installation of the same name. Pin a reviewed commit; an update needs a new
   review and a new recorded revision.
3. Delegate a **bounded stage**, not the whole orchestration, and never nest two multi-pass
   orchestrators — that multiplies cost and makes coverage unreadable. Pass the same target revision,
   the same scope and, where the upstream accepts context, the ranked surfaces and the dup map.
4. Normalise what comes back into `findings.json` as `hypothesis` records. An upstream's confidence
   score, severity label or textual PoC is not evidence under `evidence.md` and does not transfer.
5. Record availability, actual invocation and failures. If a module was unavailable, fall back to the
   corresponding built-in lens and disclose the fallback in the summary.

Respect each upstream's licence for redistribution. The MIT licence of this package covers only the
original content in this repository. Linked projects are not affiliated and do not endorse this one.
