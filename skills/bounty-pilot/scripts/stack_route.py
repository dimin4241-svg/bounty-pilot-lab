#!/usr/bin/env python3
"""Evidence-labelled, conservative multi-stack routing. No code is executed."""
import argparse
import json
import re
import subprocess
from pathlib import Path

# The target checkout is untrusted: its .git/config can name an fsmonitor or hooks program
# that git would run even for a read-only `ls-files` or `status`.
GIT_HARDENING = ("--no-optional-locks", "-c", "core.fsmonitor=false",
                 "-c", "core.hooksPath=/dev/null")

ADAPTERS = {
    "solidity-evm": "lenses.md",
    "rust-native": "adapters/rust-native.md",
    "rust-solana": "adapters/rust-solana.md",
    "rust-cosmwasm": "adapters/rust-cosmwasm.md",
    "rust-substrate": "adapters/rust-substrate.md",
    "move": "adapters/move.md",
    "cairo-starknet": "adapters/cairo.md",
    "go": "adapters/go.md",
    "web-backend": "adapters/web-backend.md",
    "zk": "adapters/zk.md",
    "cosmos-sdk": "adapters/cosmos-sdk.md",
}
LENSES = {
    "solidity-evm": ["impact-first", "privileged-path", "accounting", "business-logic", "temporal-logic"],
    "rust-native": ["impact-first", "recovery-failure", "semantic-mismatch", "business-logic",
                    "node-client"],
    "rust-solana": ["impact-first", "anchor-account", "privileged-path", "business-logic", "temporal-logic"],
    "rust-cosmwasm": ["business-logic", "temporal-logic", "integration-auth"],
    "rust-substrate": ["impact-first", "privileged-path", "composition", "accounting",
                       "live-reality", "upstream-diff", "node-client"],
    "move": ["privileged-path", "business-logic", "temporal-logic"],
    "cairo-starknet": ["privileged-path", "business-logic", "temporal-logic"],
    "go": ["recovery-failure", "business-logic", "semantic-mismatch", "node-client"],
    "web-backend": ["privileged-path", "recovery-failure", "semantic-mismatch",
                    "web-api-boundary", "web-integrity"],
    # Circuits, verifiers and zkVMs: soundness is the class that pays here, and a prover is a
    # client - malformed input and nondeterministic hints are node-client ground.
    "zk": ["zk-soundness", "node-client", "business-logic"],
    # An app chain is a node: the bank/staking/vesting modules, precompiles and IBC are where
    # the 2026 Cosmos EVM loss came from, and a fork's untaken upstream fixes are upstream-diff.
    "cosmos-sdk": ["node-client", "privileged-path", "accounting", "upstream-diff",
                   "composition"],
}

# Surfaces that call for a dedicated lens whatever the stack. Each entry is matched against
# path words (camelCase split, see _path_words) and against dependency manifests. A signal is
# a reading allocation, never a claim that the surface is present or vulnerable.
SURFACE_PATH_TOKENS = {
    "oracle-listing": ("oracle", "pricefeed", "priceoracle", "pyth", "chainlink", "redstone",
                       "supra", "switchboard", "twap"),
    "governance-capture": ("governor", "governance", "timelock", "voting", "dao",
                           "proposal", "quorum"),
    "account-abstraction": ("paymaster", "entrypoint", "useroperation", "userop",
                            "smartaccount", "eip7702", "passkey", "webauthn", "p256",
                            "sessionkey"),
    "hooks-keepers": ("hook", "keeper", "automation", "multicall"),
}
SURFACE_DEPS = {
    "oracle-listing": ("@pythnetwork", "pyth-sdk", "@chainlink/contracts", "@redstone-finance",
                       "switchboard"),
    "governance-capture": ("@openzeppelin/governance", "compound-governance"),
    "account-abstraction": ("@account-abstraction", "account-abstraction", "permissionless",
                            "@zerodev", "safe4337", "@biconomy", "@alchemy/aa",
                            "p256-verifier"),
    "hooks-keepers": ("v4-core", "v4-periphery", "@uniswap/v4-core", "@gelatonetwork",
                      "@chainlink/automation"),
}
ZK_DEPS = ("halo2_proofs", "halo2-", "plonky2", "plonky3", "p3-", "ark-groth16",
           "ark-relations", "sp1-zkvm", "sp1-sdk", "risc0-zkvm", "jolt-core",
           "openvm", "bellman", "gnark", "circomlib", "snarkjs", "@noir-lang", "nova-snark")
COSMOS_DEPS = ("github.com/cosmos/cosmos-sdk", "github.com/cometbft/cometbft",
               "github.com/tendermint/tendermint", "github.com/cosmos/evm",
               "github.com/evmos/", "github.com/cosmos/ibc-go")
AGENT_LLM_DEPS = ("openai", "@anthropic-ai/sdk", "anthropic", "langchain", "@langchain",
                  "llamaindex", "@modelcontextprotocol", "@ai-sdk", "@elizaos",
                  "goat-sdk", "@coinbase/agentkit")
AGENT_WALLET_DEPS = ("ethers", "viem", "web3", "@solana/web3.js", "wagmi", "@coinbase/cdp-sdk",
                     "@coinbase/agentkit", "goat-sdk")
SURFACE_SOURCE_SUFFIXES = {".sol", ".vy", ".rs", ".move", ".cairo", ".go", ".nr", ".circom"}
SURFACE_MANIFESTS = ("package.json", "cargo.toml", "remappings.txt", "foundry.toml",
                     "go.mod", "move.toml", "scarb.toml", "requirements.txt", "pyproject.toml",
                     "nargo.toml", ".gitmodules")


def _dep_hit(text, dep):
    """A dependency name matched at a name boundary, never inside a longer name."""
    pattern = (r"(?<![a-z0-9])" + re.escape(dep)
               + (r"(?![a-z0-9])" if dep[-1].isalnum() else ""))
    return re.search(pattern, text) is not None

BACKEND_JS_DEPS = ("express", "fastify", "@nestjs", "koa", "@hapi/hapi", "hapi",
                   "apollo-server", "@apollo/server", "graphql-yoga", "socket.io",
                   "hono", "restify", "polka", "micro", "@feathersjs", "sails",
                   "loopback", "adonis", "@adonisjs", "nestjs")
BACKEND_PY_DEPS = ("flask", "fastapi", "django", "aiohttp", "tornado", "sanic",
                   "starlette", "bottle", "falcon", "uvicorn", "gunicorn", "hypercorn")


# Cross-chain messaging: a bridge, a relayer or keeper, or a messaging SDK. Whatever the stack,
# the trust boundary is who may deliver a message and whether its origin is authenticated, which
# is the integration-auth lens. Every name matches as a whole word, never inside another one:
# `OFTAdapter` names `oft` and `OApp` names `oapp`, and `Cambridge` names no bridge.
MESSAGING_PATH_TOKENS = ("bridge", "relayer", "relay", "messenger", "messaging", "crosschain",
                         "layerzero", "wormhole", "hyperlane", "axelar", "ccip", "lzreceive",
                         "oapp", "oft", "xcm", "ibc", "lz", "cctp")
# Words that also end common compounds (`BookKeeper`, an accounting ledger) count only as a
# whole path segment - `keeper/`, `keeper.rs`, `keeper-bot` - never as a camelCase part.
MESSAGING_PATH_SEGMENTS = ("keeper",)
MESSAGING_DEPS = ("@layerzerolabs", "layerzero", "wormhole", "@hyperlane-xyz", "hyperlane",
                  "@axelar-network", "axelar", "contracts-ccip", "@chainlink/ccip", "ibc-",
                  "cosmwasm-ibc", "xcm", "@eth-optimism", "@arbitrum/nitro-contracts",
                  "@across-protocol", "@connext", "@debridge")
# A dependency name is matched at a name boundary: `libc-` does not declare `ibc-`.
MESSAGING_DEP_PATTERNS = tuple(
    (dep, re.compile(r"(?<![a-z0-9])" + re.escape(dep)
                     + (r"(?![a-z0-9])" if dep[-1].isalnum() else "")))
    for dep in MESSAGING_DEPS)


def _path_words(name):
    """Words of a path: split at separators, at camelCase and at acronym ends, so
    `OFTAdapter.sol` is `oft adapter sol` and `IBCHandler` is `ibc handler`. Adjacent words are
    also joined, so `LayerZero` and `OApp` still read as `layerzero` and `oapp`."""
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name)
    spaced = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1 \2", spaced)
    words = [w for w in re.split(r"[^a-z0-9]+", spaced.lower()) if w]
    joined = [a + b for a, b in zip(words, words[1:])]
    return set(words) | set(joined) | {w[:-1] for w in words if w.endswith("s")}


def _read(path, cap=400000):
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > cap:
            return ""
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _backend_signals(root, files, lower):
    """Real server-side signals, not merely the presence of .ts/.js/.py (which in an
    EVM repo are usually config, deploy scripts or a frontend)."""
    signals = []
    names = {Path(x).name.lower(): x for x in files}
    for manifest in [x for x in files if Path(x).name.lower() == "package.json"]:
        text = _read(root / manifest).lower()
        hit = [d for d in BACKEND_JS_DEPS if '"' + d in text or "'" + d in text or '"' + d + '/' in text]
        if hit:
            signals.append(manifest + " declares server framework: " + ", ".join(sorted(set(hit))))
    for manifest in [x for x in files if Path(x).name.lower() in
                     ("requirements.txt", "pyproject.toml", "setup.py", "setup.cfg", "pipfile")]:
        text = _read(root / manifest).lower()
        hit = [d for d in BACKEND_PY_DEPS if d in text]
        if hit:
            signals.append(manifest + " declares Python web framework: " + ", ".join(sorted(set(hit))))
    for entry in ("manage.py", "wsgi.py", "asgi.py", "server.js", "server.ts",
                  "server.mjs", "app.py", "main.go"):
        if entry in names:
            signals.append("server entry point: " + names[entry])
    for docker in [x for x in files if Path(x).name.lower().startswith("dockerfile")]:
        text = _read(root / docker).upper()
        if "EXPOSE" in text or "ENTRYPOINT" in text or "CMD" in text:
            signals.append(docker + " defines a runnable service")
    return signals


def _messaging_signals(root, files):
    """Evidence that the repository sends or receives cross-chain messages."""
    signals = []
    words = set()
    for name in files:
        tokens = _path_words(name)
        segments = set(re.split(r"[^a-z0-9]+", name.lower()))
        segments |= {w[:-1] for w in segments if w.endswith("s")}
        hit = next((t for t in MESSAGING_PATH_TOKENS if t in tokens), None) or \
            next((t for t in MESSAGING_PATH_SEGMENTS if t in segments), None)
        if hit and hit not in words:
            words.add(hit)
            signals.append("path names " + repr(hit) + ": " + name)
    for manifest in [x for x in files if Path(x).name.lower() in
                     ("package.json", "cargo.toml", "remappings.txt", "foundry.toml",
                      "go.mod", "move.toml", "scarb.toml")]:
        text = _read(root / manifest).lower()
        hit = sorted({dep for dep, pattern in MESSAGING_DEP_PATTERNS if pattern.search(text)})
        if hit:
            signals.append(manifest + " declares messaging dependency: " + ", ".join(hit))
    return signals[:20]



# Off-chain signing clues are routed as reading leads, never as findings.
# A Solidity WalletSigner is not evidence of a signer control plane.
SIGNING_PATH_TERMS = {"signer", "signing", "hsm", "mpc", "kms", "withdrawal",
                      "withdrawals", "hotwallet", "custody"}
SIGNING_CONTEXT_TERMS = {"api", "worker", "workers", "service", "services", "queue",
                         "queues", "backend", "server", "internal", "signer",
                         "signing", "hsm", "mpc", "kms"}
SIGNING_SOURCE_SUFFIXES = {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".py",
                           ".rs", ".go", ".java", ".kt"}
SIGNING_CALL = re.compile(
    r"\b(?:signTransaction|sign_transaction|authorizationList|authorization_list|"
    r"signRawTransaction|sign_raw_transaction|mpc\.sign|hsm\.sign)\b", re.I)


def _signing_signals(root, files):
    """Bounded passive naming/code clues; no code execution or live network."""
    signals = []
    for name in files:
        path = Path(name)
        if path.suffix.lower() not in SIGNING_SOURCE_SUFFIXES:
            continue
        words = _path_words(name)
        if words & SIGNING_PATH_TERMS and words & SIGNING_CONTEXT_TERMS:
            signals.append("off-chain signing path: " + name)
        elif words & SIGNING_CONTEXT_TERMS and SIGNING_CALL.search(
                _read(root / name, cap=65536)):
            signals.append("off-chain signing call in: " + name)
        if len(signals) >= 20:
            break
    return signals


def _surface_signals(root, files):
    """Lens -> bounded evidence list for the dedicated surface lenses. Passive, no execution."""
    found = {}

    def note(lens, evidence):
        rows = found.setdefault(lens, [])
        if len(rows) < 5 and evidence not in rows:
            rows.append(evidence)

    for name in files:
        low = "/" + name.lower()
        if any(part in low for part in ("/test", "/mock", "/node_modules/", "/lib/")):
            continue
        # Contract and node sources only: a frontend's `hooks/` directory is React, not v4.
        if Path(name).suffix.lower() not in SURFACE_SOURCE_SUFFIXES:
            continue
        words = _path_words(name)
        for lens, tokens in SURFACE_PATH_TOKENS.items():
            hit = next((tok for tok in tokens if tok in words), None)
            if hit:
                note(lens, "path names " + repr(hit) + ": " + name)
    for manifest in [x for x in files if Path(x).name.lower() in SURFACE_MANIFESTS]:
        text = _read(root / manifest).lower()
        for lens, deps in SURFACE_DEPS.items():
            hit = sorted(dep for dep in deps if _dep_hit(text, dep))
            if hit:
                note(lens, manifest + " declares: " + ", ".join(hit))
        llm = sorted(dep for dep in AGENT_LLM_DEPS if _dep_hit(text, dep))
        wallet = sorted(dep for dep in AGENT_WALLET_DEPS if _dep_hit(text, dep))
        # An LLM SDK alone is a chatbot; it is an agent wallet only beside a signing library.
        if llm and wallet:
            note("agent-wallet", manifest + " declares LLM " + ", ".join(llm)
                 + " beside wallet " + ", ".join(wallet))
    return found


def route(repo):
    root = Path(repo).resolve()
    raw = subprocess.run(["git", *GIT_HARDENING, "-C", str(root), "ls-files", "-z"],
                         check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    files = sorted(x for x in raw.stdout.decode("utf-8", "replace").split("\0") if x)
    lower = {x.lower() for x in files}
    matches, warnings = {}, []
    def add(stack, evidence):
        matches.setdefault(stack, set()).add(evidence)
    hardhat_names = ("hardhat.config.ts", "hardhat.config.js", "hardhat.config.cjs",
                     "hardhat.config.mjs")
    if any(x.endswith((".sol", ".vy")) for x in lower) or any(
            Path(x).name in ("foundry.toml",) + hardhat_names for x in lower):
        add("solidity-evm", "solidity/vyper source or EVM build manifest")
    if any(Path(x).name == "move.toml" for x in lower) or any(x.endswith(".move") for x in lower):
        add("move", "Move.toml or .move source (exact VM must be confirmed)")
    if any(Path(x).name == "scarb.toml" for x in lower) or any(x.endswith(".cairo") for x in lower):
        add("cairo-starknet", "Scarb.toml or Cairo source (deployment type unconfirmed)")
    if any(Path(x).name == "go.mod" for x in lower) or any(x.endswith(".go") for x in lower):
        add("go", "Go manifest or .go source")
    for manifest in [x for x in files if Path(x).name.lower() == "go.mod"]:
        text = _read(root / manifest).lower()
        hit = sorted(dep for dep in COSMOS_DEPS if dep in text)
        if hit:
            add("cosmos-sdk", manifest + " requires " + ", ".join(hit))
    if any(x.endswith(".circom") for x in lower):
        add("zk", "Circom circuit source")
    if any(Path(x).name == "nargo.toml" for x in lower) or any(x.endswith(".nr") for x in lower):
        add("zk", "Noir project (Nargo.toml or .nr source)")
    for manifest in [x for x in files if Path(x).name.lower() in
                     ("cargo.toml", "go.mod", "package.json")]:
        text = _read(root / manifest).lower()
        hit = sorted(dep for dep in ZK_DEPS if _dep_hit(text, dep))
        if hit:
            add("zk", manifest + " declares proving dependency: " + ", ".join(hit))
    # Only route web-backend on real server signals. A plain Hardhat/DeFi repo (its
    # .ts/.js are config, scripts or a frontend) must not acquire a backend tag, or
    # it displaces lenses such as accounting.
    has_web_source = any(x.endswith((".ts", ".tsx", ".js", ".jsx", ".py")) for x in lower)
    backend = _backend_signals(root, files, lower)
    if backend:
        for evidence in backend:
            add("web-backend", evidence)
    elif has_web_source:
        warnings.append("TS/JS/Python present but no server framework or service entry point "
                        "detected; not routed as web-backend (likely config, scripts or frontend).")
    cargo = [x for x in files if Path(x).name.lower() == "cargo.toml"]
    anchors = [x for x in lower if Path(x).name == "anchor.toml"]
    if anchors:
        for x in anchors:
            add("rust-solana", "Anchor workspace manifest: " + x)
    for manifest in cargo:
        path = root / manifest
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 200000:
            warnings.append("skipped unreadable/oversized Rust manifest: " + manifest)
            continue
        data = path.read_text(encoding="utf-8", errors="replace").lower()
        solana = any(s in data for s in ("anchor-lang", "solana-program", "solana-sdk", "anchor-spl"))
        cosmwasm = any(s in data for s in ("cosmwasm-std", "cw-storage-plus", "cw-multi-test"))
        # FRAME/Substrate is NOT ordinary Rust: dispatchables behind a fee/weight/validation
        # pipeline, and most exploitable composition sits in the per-chain runtime config.
        substrate = any(s in data for s in ("frame-support", "frame-system", "sp-runtime",
                                            "polkadot-sdk", "frame-benchmarking", "sp-io"))
        is_workspace = "[workspace]" in data
        has_package = "[package]" in data
        has_deps = "[dependencies]" in data or "[dependencies." in data
        if solana:
            add("rust-solana", manifest + " contains Solana/Anchor dependency")
        if cosmwasm:
            add("rust-cosmwasm", manifest + " contains CosmWasm dependency")
        if substrate:
            # Detected independently of the workspace-root branch below: a Substrate monorepo
            # root declares its deps under [workspace.dependencies], which `has_deps` misses,
            # so the root would otherwise be dropped with a workspace-only warning.
            add("rust-substrate", manifest + " contains FRAME/Substrate dependency")
        if not solana and not cosmwasm and not substrate:
            if is_workspace and not has_package and not has_deps:
                # A pure [workspace] root declares no crate of its own; its members
                # carry the real runtime (e.g. an Anchor programs/* directory).
                warnings.append(manifest + " is a workspace root only; runtime comes from "
                                "member crates, not rust-native")
            else:
                add("rust-native", manifest + " (no Solana/CosmWasm/Substrate dependency in this manifest)")
    if any(x.endswith(".rs") for x in lower) and not cargo:
        warnings.append("Rust source without tracked Cargo.toml: runtime unknown")
    stacks = [{"stack": s, "evidence": sorted(ev), "adapter": ADAPTERS[s],
               "recommended_lenses": LENSES[s]} for s, ev in sorted(matches.items())]
    if len(stacks) > 1:
        warnings.append("Mixed-language/repo detection is not component ownership. Inspect real process and trust boundaries.")
    signing = _signing_signals(root, files)
    report = {"schema": 1, "method": "manifest-and-extension-heuristics",
            "stacks": stacks, "warnings": warnings, "native_execution_verified": False,
            "messaging_signals": _messaging_signals(root, files),
            "signing_signals": signing,
            "surface_signals": _surface_signals(root, files),
            "suggested_cross_stack_lenses":
            (["semantic-mismatch", "recovery-failure", "composition"]
             if len(stacks) > 1 else []) + (["signing-control-plane"] if signing else []),
            "notice": "Routing only. A file extension does not prove a runtime, deployment or coverage."}
    report["prioritization"] = prioritize(report)
    return report

SURFACE_LENSES = ("zk-soundness", "bridge-messaging", "oracle-listing", "governance-capture",
                  "account-abstraction", "hooks-keepers", "agent-wallet")


def prioritize(route_report, budget=6):
    """Rank diverse lenses from *evidence of stack*, never predicted vulnerability odds."""
    if isinstance(budget, bool) or not isinstance(budget, int) or not 1 <= budget <= 19:
        raise ValueError("budget must be 1..19")
    base = {"impact-first": 8, "privileged-path": 6, "coverage-gap": 5, "business-logic": 5,
            "temporal-logic": 3, "composition": 3, "semantic-mismatch": 2,
            "recovery-failure": 2, "integration-auth": 2, "accounting": 2,
            "external-call": 2, "economics": 2, "liveness": 2,
            "anchor-account": 0, "upgrade": 1, "live-reality": 1,
            "delta": 1, "upstream-diff": 1, "seam": 1,
            # Ranks like any specialised lens once a stack asks for it, and is dropped outright
            # when none does: a node lens on a contracts-only target reads nothing.
            "node-client": 3, "signing-control-plane": 3, "web-api-boundary": 4,
            "web-integrity": 2,
            # Dedicated surface lenses: dropped unless a stack or surface signal asks for them.
            "zk-soundness": 3, "bridge-messaging": 3, "oracle-listing": 2,
            "governance-capture": 2, "account-abstraction": 2, "hooks-keepers": 2,
            "agent-wallet": 2}
    reasons = {name: ["general baseline"] for name in base}
    hinted = set()
    for stack in route_report["stacks"]:
        for lens in stack["recommended_lenses"]:
            base[lens] += 5
            hinted.add(lens)
            reasons[lens].append("manifest hint: " + stack["stack"])
    if len(route_report["stacks"]) > 1:
        for name in ("semantic-mismatch", "recovery-failure", "composition"):
            base[name] += 4
            reasons[name].append("multiple language/runtime candidates")
    messaging = route_report.get("messaging_signals") or []
    if messaging:
        base["integration-auth"] += 8
        reasons["integration-auth"].append("bridge/relayer/messaging signal: " + messaging[0])
    if messaging:
        base["bridge-messaging"] += 7
        reasons["bridge-messaging"].append("bridge/relayer/messaging signal: " + messaging[0])
        hinted.add("bridge-messaging")
    for lens, evidence in sorted((route_report.get("surface_signals") or {}).items()):
        if lens in base and evidence:
            base[lens] += 4
            reasons[lens].append("surface signal: " + evidence[0])
            hinted.add(lens)
    signing = route_report.get("signing_signals") or []
    if signing:
        base["signing-control-plane"] += 10
        reasons["signing-control-plane"].append("off-chain signing signal: " + signing[0])
    # Anchor's account model must never be force-selected on ordinary Rust.
    if "rust-solana" not in {x["stack"] for x in route_report["stacks"]}:
        base.pop("anchor-account")
    # The node lens belongs to a client or runtime stack. No stack asked for it means the
    # target is contracts or an application, where it would read nothing.
    if "node-client" not in hinted:
        base.pop("node-client", None)
    if not signing:
        base.pop("signing-control-plane", None)
    if "web-api-boundary" not in hinted:
        base.pop("web-api-boundary", None)
    if "web-integrity" not in hinted:
        base.pop("web-integrity", None)
    for lens in SURFACE_LENSES:
        if lens not in hinted:
            base.pop(lens, None)
    ranked = sorted(base, key=lambda name: (-base[name], name))
    # Who may deliver a message is the boundary every bridge and relayer turns on: with any
    # messaging signal, integration-auth is selected whatever the budget.
    if messaging and "integration-auth" not in ranked[:budget]:
        ranked.remove("integration-auth")
        ranked.insert(budget - 1, "integration-auth")
    # Keep a signer-boundary review in the bounded shortlist only when source
    # shows an off-chain signer. Preserve a forced messaging lens if both exist.
    if signing and "signing-control-plane" not in ranked[:budget]:
        ranked.remove("signing-control-plane")
        position = budget - 1
        if messaging and budget > 1 and ranked[position] == "integration-auth":
            position -= 1
        ranked.insert(position, "signing-control-plane")
    return {"budget": budget, "selected": ranked[:budget],
            "not_selected": ranked[budget:],
            "rationale": {x: reasons[x] for x in ranked[:budget]},
            "disclaimer": "Heuristic reading allocation, not measured bug yield or audited code coverage."}

def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--repo", required=True)
    p.add_argument("--out")
    args = p.parse_args(argv)
    try:
        report = route(args.repo)
    except (OSError, subprocess.SubprocessError) as exc:
        p.error(str(exc))
    body = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    if args.out:
        Path(args.out).write_text(body, encoding="utf-8")
        print(json.dumps({"out": args.out, "stacks": [x["stack"] for x in report["stacks"]]}))
    else:
        print(body, end="")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
