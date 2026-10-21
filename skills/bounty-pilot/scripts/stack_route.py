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
}
LENSES = {
    "solidity-evm": ["impact-first", "privileged-path", "accounting", "business-logic", "temporal-logic"],
    "rust-native": ["impact-first", "recovery-failure", "semantic-mismatch", "business-logic"],
    "rust-solana": ["impact-first", "anchor-account", "privileged-path", "business-logic", "temporal-logic"],
    "rust-cosmwasm": ["business-logic", "temporal-logic", "integration-auth"],
    "rust-substrate": ["impact-first", "privileged-path", "composition", "accounting", "live-reality", "upstream-diff"],
    "move": ["privileged-path", "business-logic", "temporal-logic"],
    "cairo-starknet": ["privileged-path", "business-logic", "temporal-logic"],
    "go": ["recovery-failure", "business-logic", "semantic-mismatch"],
    "web-backend": ["privileged-path", "recovery-failure", "semantic-mismatch"],
}

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
    report = {"schema": 1, "method": "manifest-and-extension-heuristics",
            "stacks": stacks, "warnings": warnings, "native_execution_verified": False,
            "messaging_signals": _messaging_signals(root, files),
            "suggested_cross_stack_lenses": ["semantic-mismatch", "recovery-failure", "composition"]
            if len(stacks) > 1 else [],
            "notice": "Routing only. A file extension does not prove a runtime, deployment or coverage."}
    report["prioritization"] = prioritize(report)
    return report

def prioritize(route_report, budget=6):
    """Rank diverse lenses from *evidence of stack*, never predicted vulnerability odds."""
    if isinstance(budget, bool) or not isinstance(budget, int) or not 1 <= budget <= 19:
        raise ValueError("budget must be 1..19")
    base = {"impact-first": 8, "privileged-path": 6, "coverage-gap": 5, "business-logic": 5,
            "temporal-logic": 3, "composition": 3, "semantic-mismatch": 2,
            "recovery-failure": 2, "integration-auth": 2, "accounting": 2,
            "external-call": 2, "economics": 2, "liveness": 2,
            "anchor-account": 0, "upgrade": 1, "live-reality": 1,
            "delta": 1, "upstream-diff": 1, "seam": 1}
    reasons = {name: ["general baseline"] for name in base}
    for stack in route_report["stacks"]:
        for lens in stack["recommended_lenses"]:
            base[lens] += 5
            reasons[lens].append("manifest hint: " + stack["stack"])
    if len(route_report["stacks"]) > 1:
        for name in ("semantic-mismatch", "recovery-failure", "composition"):
            base[name] += 4
            reasons[name].append("multiple language/runtime candidates")
    messaging = route_report.get("messaging_signals") or []
    if messaging:
        base["integration-auth"] += 8
        reasons["integration-auth"].append("bridge/relayer/messaging signal: " + messaging[0])
    # Anchor's account model must never be force-selected on ordinary Rust.
    if "rust-solana" not in {x["stack"] for x in route_report["stacks"]}:
        base.pop("anchor-account")
    ranked = sorted(base, key=lambda name: (-base[name], name))
    # Who may deliver a message is the boundary every bridge and relayer turns on: with any
    # messaging signal, integration-auth is selected whatever the budget.
    if messaging and "integration-auth" not in ranked[:budget]:
        ranked.remove("integration-auth")
        ranked.insert(budget - 1, "integration-auth")
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
