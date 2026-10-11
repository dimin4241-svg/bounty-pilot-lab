#!/usr/bin/env python3
"""Compiler-aware source graph for Solidity AST and Python AST (stdlib only).

Solidity: explicitly supplied solc standard-json output / Foundry build-info JSON.
Python: ast.parse of git-tracked .py source. This does not execute target code.
Edges are syntactic call references and possible state dependencies, NOT verified
runtime exploit paths. Rust and other stacks remain on the heuristic adapter path.
"""
import argparse
import ast
import json
import subprocess
from collections import defaultdict
from pathlib import Path

SINK_TERMS = {
    "asset-movement": ("transfer", "transferfrom", "safetransfer", "withdraw",
                       "redeem", "release", "burn", "mint", "sweep"),
    "debt-solvency": ("borrow", "liquidat", "repay", "baddebt", "collateral"),
    "privileged-power": ("upgrade", "grantrole", "setowner", "ownership",
                         "authoriz", "admin", "delegate"),
    "settlement": ("claim", "settle", "finaliz", "acknowledge", "processmessage"),
    "price-oracle": ("price", "oracle", "twap", "exchange_rate"),
}
MAX_AST_BYTES = 256_000_000
MAX_NODES = 150_000
EDGE_CAP = 7500

def walk_json(node):
    todo = [node]
    count = 0
    while todo:
        x = todo.pop()
        count += 1
        if count > MAX_NODES:
            raise ValueError("compiler AST too large")
        if isinstance(x, dict):
            yield x
            todo.extend(reversed([v for v in x.values() if isinstance(v, (dict, list))]))
        elif isinstance(x, list):
            todo.extend(reversed(x))

BUILD_INFO_HINT = (
    "Foundry build-info without AST: a plain `forge build` writes a minimal build-info "
    "(id/source_id_to_path/language, no AST). Run `forge build --build-info` and point this "
    "at the resulting out/build-info/*.json, or pass solc standard-json compiled with "
    "outputSelection including sources.*.ast.")


def load_solc(path, max_ast_bytes=MAX_AST_BYTES):
    p = Path(path)
    if p.stat().st_size > max_ast_bytes:
        raise ValueError("compiler JSON exceeds size cap (%d bytes); raise --max-ast-mb" % max_ast_bytes)
    raw = json.loads(p.read_text(encoding="utf-8"))
    data = raw
    if "output" in data and isinstance(data["output"], dict):
        data = data["output"]
    sources = data.get("sources", {})
    if not isinstance(sources, dict):
        raise ValueError("Solidity compiler JSON missing sources")
    # A minimal `forge build` build-info has source_id_to_path but no compiled output.
    if not sources and (isinstance(raw.get("source_id_to_path"), dict)
                        or ("language" in raw and "output" not in raw)):
        raise ValueError(BUILD_INFO_HINT)
    trees = []
    saw_source_entry = False
    for filename, desc in sorted(sources.items()):
        if not isinstance(desc, dict):
            continue
        saw_source_entry = True
        tree = desc.get("ast")
        if isinstance(tree, dict) and tree.get("nodeType") == "SourceUnit":
            trees.append((filename, tree))
    if not trees:
        if saw_source_entry:
            # sources present but none carry an AST → the AST output was not requested.
            raise ValueError(BUILD_INFO_HINT)
        raise ValueError("no Solidity SourceUnit AST; " + BUILD_INFO_HINT)
    return trees

ETH_MOVE_MEMBERS = ("send", "transfer")


def _analyze_body(body, decls, funcs):
    """Collect state reads/writes, resolved calls, called-member names and ETH
    movement from a function or modifier body. Returns a dict of sets."""
    reads, writes, calls, callnames = set(), set(), set(), set()
    eth_move = False
    # Pass 1: map local storage pointers (`Pos storage p = pos[x];`) to their state var.
    local_ptr = {}
    for x in walk_json(body):
        if x.get("nodeType") != "VariableDeclarationStatement":
            continue
        target_decl = None
        for d in x.get("declarations") or []:
            if isinstance(d, dict) and d.get("storageLocation") == "storage" and isinstance(d.get("id"), int):
                target_decl = d["id"]
                break
        if target_decl is None:
            continue
        for ref in walk_json(x.get("initialValue") or {}):
            rid = ref.get("referencedDeclaration")
            if rid in decls:
                local_ptr[target_decl] = decls[rid]
                break

    def resolve_write(ref_id):
        if ref_id in decls:
            writes.add(decls[ref_id])
        elif ref_id in local_ptr:
            writes.add(local_ptr[ref_id])

    for x in walk_json(body):
        nt = x.get("nodeType")
        if nt in ("Identifier", "MemberAccess"):
            rid = x.get("referencedDeclaration")
            if rid in decls:
                reads.add(decls[rid])
            elif rid in local_ptr:
                reads.add(local_ptr[rid])
        elif nt == "Assignment":
            for lhs in walk_json(x.get("leftHandSide") or {}):
                resolve_write(lhs.get("referencedDeclaration"))
        elif nt == "UnaryOperation" and x.get("operator") in ("++", "--", "delete"):
            for lhs in walk_json(x.get("subExpression") or {}):
                resolve_write(lhs.get("referencedDeclaration"))
        elif nt == "FunctionCallOptions":
            # `addr.call{value: ...}(...)` moves ETH.
            if "value" in (x.get("names") or []):
                eth_move = True
        elif nt == "FunctionCall":
            expression = x.get("expression") or {}
            if expression.get("nodeType") == "MemberAccess":
                member = expression.get("memberName")
                if isinstance(member, str):
                    callnames.add(member)
                    if member in ETH_MOVE_MEMBERS:
                        eth_move = True  # addr.send / addr.transfer
                    if member in ("push", "pop"):
                        for ref in walk_json(expression.get("expression") or {}):
                            resolve_write(ref.get("referencedDeclaration"))
            target = expression.get("referencedDeclaration")
            if target in funcs:
                calls.add(funcs[target]["id"])
                callnames.add(funcs[target]["short"])
    return {"reads": reads, "writes": writes, "calls": calls,
            "callnames": callnames, "eth_move": eth_move}


def solidity_symbols(trees):
    decls, parent = {}, {}
    modifier_defs = {}
    for path, tree in trees:
        for node in walk_json(tree):
            nt = node.get("nodeType")
            if nt == "VariableDeclaration" and node.get("stateVariable"):
                ident = node.get("id")
                if isinstance(ident, int):
                    decls[ident] = str(path) + ":" + str(node.get("name", ident))
            if nt == "ContractDefinition":
                cname = node.get("name", "")
                for child in node.get("nodes", []):
                    if isinstance(child, dict):
                        parent[child.get("id")] = cname
            if nt == "ModifierDefinition" and isinstance(node.get("id"), int):
                modifier_defs[node["id"]] = node
    funcs = {}
    for path, tree in trees:
        for node in walk_json(tree):
            if node.get("nodeType") != "FunctionDefinition":
                continue
            num = node.get("id")
            if not isinstance(num, int):
                continue
            short = str(node.get("name") or node.get("kind") or "unnamed")
            funcs[num] = {"id": "solc:" + str(num), "path": str(path),
                          "name": str(parent.get(num, "")) + "." + short, "short": short,
                          "declaration": num, "language": "solidity",
                          "implemented": node.get("implemented", True),
                          "entry": (node.get("visibility") in ("external", "public")
                                    and node.get("implemented", True)),
                          "visibility": node.get("visibility", "unknown"),
                          "line": None, "source_span": node.get("src"),
                          "modifiers_unverified": [str((m.get("modifierName") or {}).get("name", "unknown"))
                              for m in node.get("modifiers", []) if isinstance(m, dict)],
                          "writes": [], "reads": [],
                          "calls": [], "sinks": [], "source": "compiler-ast"}
    # Pre-compute each modifier's own effects so a function inherits them.
    modifier_effects = {mid: _analyze_body(node.get("body") or {}, decls, funcs)
                        for mid, node in modifier_defs.items()}
    for path, tree in trees:
        for node in walk_json(tree):
            if node.get("nodeType") != "FunctionDefinition" or node.get("id") not in funcs:
                continue
            current = funcs[node["id"]]
            if not current["implemented"]:
                # Interfaces / abstract declarations have no body: never a source or sink.
                continue
            eff = _analyze_body(node.get("body") or {}, decls, funcs)
            writes, reads, calls = set(eff["writes"]), set(eff["reads"]), set(eff["calls"])
            callnames, eth_move = set(eff["callnames"]), eff["eth_move"]
            # Inherit the reads/writes/calls of every applied modifier (nonReentrant's
            # write to `locked`, onlyOwner's read of `owner`, ...).
            for m in node.get("modifiers", []) or []:
                if not isinstance(m, dict):
                    continue
                mid = (m.get("modifierName") or {}).get("referencedDeclaration")
                meff = modifier_effects.get(mid)
                if meff:
                    writes |= meff["writes"]
                    reads |= meff["reads"]
                    calls |= meff["calls"]
                    callnames |= meff["callnames"]
                    eth_move = eth_move or meff["eth_move"]
            current["writes"] = sorted(writes)
            current["reads"] = sorted(reads)
            current["calls"] = sorted(calls)
            # Classify from the function's OWN name and the names it calls, never the
            # contract name or an emitted event identifier.
            current["sinks"] = classify({current["short"]} | callnames, eth_move)
    for f in funcs.values():
        f.pop("short", None)
    return list(funcs.values())


def classify(names, eth_move=False):
    joined = " ".join(str(n).lower() for n in names)
    sinks = {key for key, words in SINK_TERMS.items() if any(w in joined for w in words)}
    if eth_move:
        sinks.add("asset-movement")
    return sorted(sinks)

def attr_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = attr_name(node.value)
        return (prefix + "." if prefix else "") + node.attr
    return ""

def py_symbols(root):
    root = Path(root).resolve()
    raw = subprocess.run(["git", "-C", str(root), "ls-files", "-z"],
                         check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    tracked = raw.stdout.decode("utf-8", "replace").split("\0")
    defs = []
    files = [x for x in tracked if x.endswith(".py") and
             not set(Path(x).parts).intersection(
                 {"test", "tests", "vendor", "node_modules", "build", "dist", ".git", "secrets", "credentials", ".env"})]
    if len(files) > 2000:
        raise ValueError("too many Python files; narrow repository")
    for path in sorted(files):
        p = root / path
        if p.is_symlink() or not p.is_file() or p.stat().st_size > 250_000:
            continue
        try:
            tree = ast.parse(p.read_text(encoding="utf-8"), filename=path)
        except (SyntaxError, UnicodeDecodeError):
            continue
        funcs = []
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                funcs.append(("", node))
            elif isinstance(node, ast.ClassDef):
                funcs.extend((node.name, child) for child in node.body
                             if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)))
        by_name = {name + "." + n.name if name else n.name for name, n in funcs}
        for owner, n in funcs:
            fullname = owner + "." + n.name if owner else n.name
            writes, reads, calls, names = set(), set(), set(), {fullname}
            for v in ast.walk(n):
                if isinstance(v, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                    lhs = v.targets if isinstance(v, ast.Assign) else [v.target]
                    for target in lhs:
                        for item in ast.walk(target):
                            if isinstance(item, ast.Attribute) and isinstance(item.value, ast.Name) and item.value.id in ("self", "cls"):
                                writes.add(item.attr)
                if isinstance(v, ast.Attribute) and isinstance(v.value, ast.Name) and v.value.id in ("self", "cls"):
                    reads.add(v.attr)
                if isinstance(v, ast.Call):
                    symbol = attr_name(v.func)
                    names.add(symbol)
                    if symbol in by_name:
                        calls.add(path + ":" + symbol)
                    elif owner and symbol in ("self." + x.name for _, x in funcs):
                        calls.add(path + ":" + owner + "." + symbol.split(".", 1)[1])
            defs.append({"id": path + ":" + fullname, "path": path,
                         "name": fullname, "declaration": None,
                         "language": "python", "entry": False,
                         "visibility": "unknown", "line": n.lineno,
                         "writes": sorted(writes), "reads": sorted(reads),
                         "calls": sorted(calls), "sinks": classify(names),
                         "source": "python-ast"})
    return defs

def build(symbols):
    symbols = sorted(symbols, key=lambda x: x["id"])
    known = {x["id"] for x in symbols}
    edges = []
    for s in symbols:
        for callee in s["calls"]:
            if callee in known:
                edges.append({"from": s["id"], "to": callee,
                              "kind": "static-call-reference", "confidence": "ast-reference"})
    call_edges = len(edges)
    truncated = False
    readers = defaultdict(list)
    for s in symbols:
        for name in s["reads"]:
            readers[name].append(s["id"])
    for s in symbols:
        for name in s["writes"]:
            for other in readers[name][:150]:
                if other != s["id"]:
                    edges.append({"from": s["id"], "to": other,
                                  "kind": "writer-reader-overlap", "state": name,
                                  "confidence": "candidate-only"})
                if len(edges) >= EDGE_CAP:
                    truncated = True
                    break
            if truncated:
                break
        if truncated:
            break
    edges = edges[:EDGE_CAP]
    return {"schema": 1, "method": "compiler-ast-plus-python-ast",
            "symbols": symbols, "edges": edges,
            "truncated": truncated,
            "edge_counts": {"total": len(edges), "static_call_reference": call_edges,
                            "writer_reader_overlap": len(edges) - call_edges, "cap": EDGE_CAP},
            "semantic_scope": "Solidity compiler-resolved declarations and calls; Python syntax only",
            "reachable_verified": False,
            "warning": "Solidity calls are static references, not full dynamic dispatch. Writer-reader "
                       "overlap is NOT an executable path. Python entrypoints/calls can be unresolved. "
                       "No Rust/Move/Cairo semantics are claimed."
                       + (" Edge cap reached: graph is TRUNCATED and some overlaps are omitted."
                          if truncated else "")}

def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo", help="git checkout for Python AST; optional when --solc provided")
    ap.add_argument("--solc", help="solc output/build-info JSON with sources AST")
    ap.add_argument("--max-ast-mb", type=int, default=MAX_AST_BYTES // 1_000_000,
                    help="size cap for the compiler JSON (default %d MB)" % (MAX_AST_BYTES // 1_000_000))
    ap.add_argument("--out")
    args = ap.parse_args(argv)
    if not args.repo and not args.solc:
        ap.error("pass --repo or --solc")
    if args.max_ast_mb < 1 or args.max_ast_mb > 4096:
        ap.error("--max-ast-mb must be between 1 and 4096")
    try:
        symbols = []
        if args.solc:
            symbols += solidity_symbols(load_solc(args.solc, args.max_ast_mb * 1_000_000))
        if args.repo:
            symbols += py_symbols(args.repo)
        report = build(symbols)
    except (ValueError, OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        ap.error(str(exc))
    payload = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    if args.out:
        Path(args.out).write_text(payload, encoding="utf-8")
        print(json.dumps({"out": args.out, "symbols": len(report["symbols"]),
                          "edges": len(report["edges"])}))
    else:
        print(payload, end="")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
