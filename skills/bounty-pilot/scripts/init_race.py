#!/usr/bin/env python3
"""Was each proxy deployed and initialized in one transaction? Deploy evidence and initializers.

Kinto (July 2025, about $1.55M): an ERC1967 proxy was deployed and initialized in separate
transactions and the initialize call was front-run. EVMbench carries a proxy initialization race
that every one of 26 agent configurations missed, and an implementation left initializable is the
Parity 2017 shape. The source rarely shows the gap; the deploy scripts and their broadcast logs do.

Three readings, all offline and lexical - no target code runs, no chain is queried:

a. Foundry broadcast logs (`broadcast/**/run-*.json`, tracked or only in the working tree, and
   which is said): a proxy CREATE whose constructor init data is empty, followed by a CALL to
   that address naming `initialize*` in a LATER transaction is `split-deploy-init`, with the
   transaction distance and the block gap when receipts are present; no such call at all is
   `no-init-call-seen`; non-empty init data is `atomic` and only counted. `dry-run/` logs were
   simulated, never broadcast, and say so.
b. hardhat-deploy `deployments/<network>/*.json` and OpenZeppelin `.openzeppelin/*.json`
   manifests: proxies and implementations listed; a hardhat-deploy proxy record with no `execute`
   is `proxy-no-recorded-init` (best effort, labelled).
c. Solidity source in scope (non-test): `implementation-initializable` (an initializer contract
   whose constructor neither calls `_disableInitializers()` nor carries `initializer`),
   `unguarded-initialize` (an external/public `initialize*` with no `initializer` /
   `reinitializer` / `onlyInitializing` and no explicit flag check), and deploy scripts that pass
   empty init data to `new ...Proxy(...)` or `deployProxy(..., {initializer: false})` as
   `script-empty-init-data`.

Every row is a lead. Target files are data: nothing in them is followed.
"""
import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
SKILL_ROOT = SCRIPTS.parent
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from keccak import keccak256  # noqa: E402

# The target checkout is untrusted: its .git/config can name an fsmonitor or hooks program
# that git would run even for a read-only `ls-files`.
GIT_HARDENING = ("--no-optional-locks", "-c", "core.fsmonitor=false",
                 "-c", "core.hooksPath=/dev/null")
PROXY_NAME = re.compile(r"^(?:UUPS\w*|\w*Proxy)$")
INIT_FUNCTION = re.compile(r"^(?:initiali[sz]e\w*|reinitiali[sz]e\w*|init|__\w+_init\w*)\s*(?:\(|$)",
                           re.I)
GUARD_MODIFIERS = re.compile(r"\b(?:initializer|reinitializer|onlyInitializing)\b")
FLAG_CHECK = re.compile(r"(?:require\s*\(\s*!\s*\w*initiali[sz]ed|"
                        r"if\s*\(\s*\w*initiali[sz]ed\w*(?:\s*\(\s*\))?\s*\)\s*(?:\{\s*)?revert|"
                        r"\w*initiali[sz]ed\w*\s*==\s*false|_checkNotInitiali|"
                        r"require\s*\(\s*\w*(?:initiali[sz]ed|version)\w*\s*(?:==|<)\s*)", re.I)
SKIP_DIRS = {".git", "node_modules", "lib", "out", "cache", "artifacts", "typechain",
             "typechain-types", "coverage"}
TEST_PATH = re.compile(r"(^|/)(tests?|mocks?|certora|echidna|medusa)(/|$)|\.t\.sol$|Mock\w*\.sol$",
                       re.I)
VENDORED = re.compile(r"(^|/)(lib|node_modules|vendor|dependencies)(/|$)")
MAX_JSON_BYTES = 32 * 1024 * 1024
NOTICE = ("Leads, not findings. A split deploy is exploitable only if the window was real on the "
          "live chain AND initialize is still callable or was front-run: check the live proxy's "
          "initialized slot (OZ v5: oz_v5_initializable_slot, derived here; OZ v4 packs "
          "_initialized into the first storage slot of the layout) at a pinned block with the "
          "existing eth-call / verify-deployment commands. An already-initialized proxy is "
          "history, not a finding, unless re-initialization is possible. Broadcast logs record "
          "what the deployer submitted, not what the chain confirmed; dry-run logs were never "
          "broadcast. Source rows are lexical: an initializer inherited from a base, a guard in a "
          "custom modifier or an assembly flag is invisible here.")


def initializable_slot():
    """OZ v5 ERC-7201 slot of Initializable, derived from its namespace label."""
    inner = int.from_bytes(keccak256(b"openzeppelin.storage.Initializable"), "big") - 1
    outer = int.from_bytes(keccak256(inner.to_bytes(32, "big")), "big")
    return "0x%064x" % (outer & ~0xff & ((1 << 256) - 1))


def _tracked(root):
    try:
        raw = subprocess.run(["git", *GIT_HARDENING, "-C", str(root), "ls-files", "-z"],
                             check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except (OSError, subprocess.CalledProcessError):
        return None
    return sorted(x for x in raw.stdout.decode("utf-8", "replace").split("\0") if x)


def _present(root, wanted):
    """Working-tree files under a directory named like `wanted`, pruning dependencies."""
    found = []
    for base, dirs, files in os.walk(root, followlinks=False):
        rel_base = Path(base).relative_to(root)
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not (Path(base) / d).is_symlink()]
        if not any(part in wanted for part in rel_base.parts):
            continue
        for name in files:
            path = Path(base) / name
            if name.endswith(".json") and not path.is_symlink():
                found.append(path.relative_to(root).as_posix())
    return found


def _load(path):
    try:
        if path.stat().st_size > MAX_JSON_BYTES:
            return None
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeDecodeError):
        return None


def _int(value):
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 16) if value.lower().startswith("0x") else int(value)
        except ValueError:
            return None
    return None


def _addr(value):
    return value.lower() if isinstance(value, str) and value.startswith("0x") else None


def _empty_data(value):
    return isinstance(value, str) and value.strip().lower() in ("", "0x", '""', "''")


def _function_name(tx):
    fn = tx.get("function")
    return fn.strip() if isinstance(fn, str) else ""


def _broadcasts(root, files, tracked):
    """(rows, proxies, leads, atomic count) from Foundry broadcast logs, grouped per chain dir."""
    runs = [f for f in files if re.search(r"(^|/)broadcast/.+/run-[^/]*\.json$", f)]
    by_dir = {}
    for f in runs:
        by_dir.setdefault(str(Path(f).parent), []).append(f)
    read, chains = [], {}
    for directory, names in sorted(by_dir.items()):
        # run-latest.json is a copy of the newest run-<timestamp>.json.
        stamped = [n for n in names if not n.endswith("run-latest.json")]
        for name in sorted(stamped or names):
            data = _load(root / name)
            dry = "dry-run" in Path(name).parts
            read.append({"file": name, "tracked": name in tracked, "dry_run": dry,
                         "parsed": isinstance(data, dict)})
            if not isinstance(data, dict):
                continue
            chain = Path(directory).name if not dry else Path(directory).parent.name
            stamp = _int(data.get("timestamp")) or _int(
                (re.search(r"run-(\d+)", name) or [None, None])[1]) or 0
            blocks = {}
            for receipt in data.get("receipts") or []:
                if isinstance(receipt, dict) and isinstance(receipt.get("transactionHash"), str):
                    blocks[receipt["transactionHash"].lower()] = _int(receipt.get("blockNumber"))
            for index, tx in enumerate(data.get("transactions") or []):
                if isinstance(tx, dict):
                    tx_hash = tx.get("hash").lower() if isinstance(tx.get("hash"), str) else None
                    chains.setdefault((chain, dry), []).append(
                        {"file": name, "stamp": stamp, "index": index, "tx": tx, "hash": tx_hash,
                         "block": blocks.get(tx_hash) if tx_hash else None})
    proxies, leads, atomic = [], [], 0
    for (chain, dry), rows in sorted(chains.items()):
        rows.sort(key=lambda r: (r["stamp"], r["file"], r["index"]))
        seen, ordered = set(), []
        for r in rows:
            key = r["hash"] or (r["file"], r["index"])
            if key not in seen:
                seen.add(key)
                ordered.append(r)
        for pos, r in enumerate(ordered):
            tx = r["tx"]
            name = tx.get("contractName") if isinstance(tx.get("contractName"), str) else ""
            if str(tx.get("transactionType", "")).upper() not in ("CREATE", "CREATE2") \
                    or not PROXY_NAME.match(name):
                continue
            proxy = _addr(tx.get("contractAddress"))
            args = tx.get("arguments")
            if isinstance(args, list) and args:
                init_data, known = args[-1], True
            else:
                init_data, known = None, False
            row = {"chain": chain, "dry_run": dry, "file": r["file"], "tx_index": r["index"],
                   "contract": name, "address": proxy, "block": r["block"],
                   "init_data": "empty" if known and _empty_data(init_data) else
                                "present" if known else "not recorded"}
            proxies.append(row)
            if known and not _empty_data(init_data):
                row["status"] = "atomic"
                atomic += 1
                continue
            later, guessed = None, False
            for nxt in ordered[pos + 1:]:
                t = nxt["tx"]
                inner = t.get("transaction") if isinstance(t.get("transaction"), dict) else {}
                to = _addr(t.get("contractAddress")) or _addr(inner.get("to"))
                if str(t.get("transactionType", "")).upper() != "CALL" or not proxy or to != proxy:
                    continue
                fn = _function_name(t)
                if INIT_FUNCTION.match(fn):
                    later, guessed = nxt, False
                    break
                if not fn and later is None:
                    later, guessed = nxt, True  # first undecoded call: maybe the initializer
            where = "%s tx %d" % (r["file"], r["index"])
            suffix = " (dry-run: simulated, never broadcast)" if dry else ""
            if later is None:
                row["status"] = "no-init-call-seen"
                leads.append({"code": "no-init-call-seen", "file": r["file"],
                              "detail": "%s at %s created at %s with %s init data and no later "
                                        "initialize call in the logs read%s"
                                        % (name, proxy, where, row["init_data"], suffix),
                              "confidence": "low" if dry or not known else "medium"})
                continue
            gap_tx = (ordered.index(later) - pos)
            block_gap = (later["block"] - r["block"]
                         if later["block"] is not None and r["block"] is not None else None)
            row.update({"status": "split-deploy-init", "init_file": later["file"],
                        "init_tx_index": later["index"], "init_function":
                        _function_name(later["tx"]) or "undecoded", "tx_distance": gap_tx,
                        "block_gap": block_gap})
            confidence = "high" if known and not guessed and not dry else (
                "low" if dry or guessed else "medium")
            leads.append({"code": "split-deploy-init", "file": r["file"],
                          "detail": "%s at %s created at %s with %s init data; initialized %d "
                                    "transaction(s) later by %s in %s tx %d; block gap %s%s%s"
                                    % (name, proxy, where, row["init_data"], gap_tx,
                                       row["init_function"], later["file"], later["index"],
                                       "unknown (no receipts)" if block_gap is None else block_gap,
                                       " (same block: still two transactions)"
                                       if block_gap == 0 else "", suffix),
                          "confidence": confidence})
    return read, proxies, leads, atomic


def _deployment_records(root, files, tracked):
    read, proxies, leads, atomic = [], [], [], 0
    for f in files:
        parts = Path(f).parts
        if len(parts) >= 3 and parts[-3] == "deployments" and not parts[-1].startswith("."):
            data = _load(root / f)
            read.append({"file": f, "tracked": f in tracked, "kind": "hardhat-deploy"})
            if not isinstance(data, dict):
                continue
            stem = Path(f).stem
            is_proxy = "implementation" in data or stem.endswith("_Proxy")
            if not is_proxy or stem.endswith("_Implementation"):
                continue
            execute = data.get("execute") if isinstance(data.get("execute"), dict) else None
            method = None
            if execute:
                method = execute.get("methodName") or (execute.get("init") or {}).get("methodName")
            row = {"source": "hardhat-deploy", "file": f, "network": parts[-2],
                   "address": _addr(data.get("address")),
                   "implementation": _addr(data.get("implementation")),
                   "transaction": data.get("transactionHash"), "init_method": method}
            proxies.append(row)
            if method:
                row["status"] = "atomic"
                atomic += 1
            else:
                row["status"] = "no-recorded-init"
                leads.append({"code": "proxy-no-recorded-init", "file": f,
                              "detail": "hardhat-deploy proxy %s on %s has no `execute` init in "
                                        "its deployment record" % (row["address"], parts[-2]),
                              "confidence": "low (best effort: the record format varies and an "
                                            "init may have run in a separate execute)"})
        elif len(parts) >= 2 and parts[-2] == ".openzeppelin" and f.endswith(".json"):
            data = _load(root / f)
            read.append({"file": f, "tracked": f in tracked, "kind": "openzeppelin-manifest"})
            if not isinstance(data, dict):
                continue
            for p in data.get("proxies") or []:
                if isinstance(p, dict):
                    proxies.append({"source": "openzeppelin-manifest", "file": f,
                                    "address": _addr(p.get("address")), "kind": p.get("kind"),
                                    "transaction": p.get("txHash"),
                                    "status": "unknown (manifest records no init call)"})
            impls = data.get("impls") if isinstance(data.get("impls"), dict) else {}
            for impl in impls.values():
                if isinstance(impl, dict):
                    proxies.append({"source": "openzeppelin-manifest", "file": f,
                                    "implementation": _addr(impl.get("address")),
                                    "transaction": impl.get("txHash"),
                                    "status": "implementation: check it is not initializable"})
    return read, proxies, leads, atomic


def _strip_comments(text):
    """Comments blanked to spaces (newlines kept) so offsets and line numbers survive."""
    out, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        if c in "\"'":
            j = i + 1
            while j < n and text[j] != c and text[j] != "\n":
                j += 2 if text[j] == "\\" else 1
            out.append(text[i:j + 1])
            i = j + 1
        elif text.startswith("//", i):
            j = text.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i))
            i = j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append(re.sub(r"[^\n]", " ", text[i:j]))
            i = j
        else:
            out.append(c)
            i += 1
    return "".join(out)


def _block(text, open_at):
    """Index just past the brace matching text[open_at] == '{'."""
    depth = 0
    for i in range(open_at, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return i + 1
    return len(text)


def _line(text, offset):
    return text.count("\n", 0, offset) + 1


def _functions(body, base):
    """(name, header, body text, offset) of functions and the constructor in a contract body."""
    found = []
    for m in re.finditer(r"\b(function\s+(\w+)|constructor)\s*\(", body):
        brace, semi = body.find("{", m.end()), body.find(";", m.end())
        if brace < 0 or (0 <= semi < brace):
            continue  # declaration without a body
        header = body[m.end():brace]
        end = _block(body, brace)
        found.append((m.group(2) or "constructor", header, body[brace:end], base + m.start()))
    return found


def _source_leads(rel, text):
    leads = []
    clean = _strip_comments(text)
    for m in re.finditer(r"\b(abstract\s+)?(contract|interface|library)\s+(\w+)[^{;]*\{", clean):
        if m.group(2) != "contract":
            continue
        start = m.end() - 1
        body = clean[start:_block(clean, start)]
        fns = _functions(body, start)
        inits = [f for f in fns if f[0] != "constructor" and (
            INIT_FUNCTION.match(f[0]) or GUARD_MODIFIERS.search(f[1]))]
        if not inits:
            continue
        name = m.group(3)
        ctors = [f for f in fns if f[0] == "constructor"]
        disabled = any("_disableInitializers" in f[2] or re.search(r"\binitializer\b", f[1])
                       for f in ctors)
        if not m.group(1) and not disabled:
            leads.append({"code": "implementation-initializable",
                          "file": "%s:%d" % (rel, _line(clean, m.start())),
                          "detail": "contract %s has initializer function(s) %s and %s; if it is "
                                    "deployed as an implementation behind a proxy, anyone can "
                                    "initialize the implementation itself"
                                    % (name, ", ".join(sorted({f[0] for f in inits})),
                                       "a constructor without _disableInitializers()" if ctors
                                       else "no constructor"),
                          "confidence": "medium"})
        for fname, header, fbody, offset in inits:
            if not re.match(r"^(?:initiali[sz]e|reinitiali[sz]e)\w*$|^init$", fname, re.I):
                continue
            if not re.search(r"\b(external|public)\b", header):
                continue
            if GUARD_MODIFIERS.search(header) or FLAG_CHECK.search(fbody):
                continue
            mods = [w for w in re.findall(r"\b(only\w+|auth\w*|whenNotPaused)\b", header)]
            leads.append({"code": "unguarded-initialize",
                          "file": "%s:%d" % (rel, _line(clean, offset)),
                          "detail": "%s.%s is external/public with no initializer/reinitializer/"
                                    "onlyInitializing modifier and no visible initialized-flag "
                                    "check%s" % (name, fname, "; restricted by " + ", ".join(mods)
                                                 if mods else ""),
                          "confidence": "low" if mods else "medium"})
    return leads


def _script_leads(rel, text):
    leads = []
    clean = _strip_comments(text)
    for m in re.finditer(r"\bnew\s+(\w*Proxy)\s*\(", clean):
        depth, i = 1, m.end()
        while i < len(clean) and depth:
            depth += {"(": 1, ")": -1}.get(clean[i], 0)
            i += 1
        args = clean[m.end():i - 1]
        last = args.split(",")[-1].strip() if args.strip() else ""
        if re.fullmatch(r'""|\'\'|hex""|bytes\(\s*""\s*\)|new\s+bytes\(\s*0\s*\)|"0x"|\'0x\'', last):
            leads.append({"code": "script-empty-init-data",
                          "file": "%s:%d" % (rel, _line(clean, m.start())),
                          "detail": "new %s(...) with empty init data (%s): deploy and initialize "
                                    "are separate transactions unless the script batches them"
                                    % (m.group(1), last),
                          "confidence": "medium"})
    for m in re.finditer(r"\bdeployProxy\s*\([^;]*?initializer\s*:\s*false", clean, re.S):
        leads.append({"code": "script-empty-init-data",
                      "file": "%s:%d" % (rel, _line(clean, m.start())),
                      "detail": "deployProxy(..., {initializer: false}): the proxy is deployed "
                                "uninitialized",
                      "confidence": "medium"})
    return leads


def _in_scope(path, scope):
    return not scope or any(path == s.rstrip("/") or path.startswith(s.rstrip("/") + "/")
                            for s in scope)


def analyze(repo, scope=None):
    root = Path(repo).expanduser().resolve()
    if not root.is_dir():
        raise ValueError("--repo must be a directory")
    tracked_list = _tracked(root)
    tracked = set(tracked_list or [])
    present = _present(root, {"broadcast", "deployments", ".openzeppelin"})
    deploy_files = sorted(set(present) | {f for f in tracked
                                          if re.search(r"(^|/)(broadcast|deployments|"
                                                       r"\.openzeppelin)/", f)
                                          and (root / f).is_file()})
    b_read, b_proxies, b_leads, b_atomic = _broadcasts(root, deploy_files, tracked)
    d_read, d_proxies, d_leads, d_atomic = _deployment_records(root, deploy_files, tracked)
    source_files = tracked_list if tracked_list is not None else []
    s_leads, scanned, scripts = [], 0, 0
    for rel in source_files:
        if VENDORED.search(rel) or not (root / rel).is_file() or (root / rel).is_symlink():
            continue
        is_script = rel.endswith(".s.sol") or (
            re.search(r"(^|/)(deploy|scripts?)/", rel) and rel.endswith((".ts", ".js")))
        try:
            if is_script:
                s_leads += _script_leads(rel, (root / rel).read_text(encoding="utf-8",
                                                                     errors="replace"))
                scripts += 1
            elif rel.endswith(".sol") and not TEST_PATH.search(rel) and _in_scope(rel, scope):
                s_leads += _source_leads(rel, (root / rel).read_text(encoding="utf-8",
                                                                     errors="replace"))
                scanned += 1
        except OSError:
            continue
    leads = b_leads + d_leads + s_leads
    counts = {}
    for lead in leads:
        counts[lead["code"]] = counts.get(lead["code"], 0) + 1
    counts.update({"atomic": b_atomic + d_atomic, "proxies": len(b_proxies) + len(d_proxies),
                   "solidity_sources_scanned": scanned, "deploy_scripts_scanned": scripts})
    return {"schema_version": 1, "repo": str(root), "git_tracked": tracked_list is not None,
            "scope": list(scope or []),
            "broadcasts_read": b_read, "deployment_records_read": d_read,
            "proxies": b_proxies + d_proxies, "leads": leads, "counts": counts,
            "oz_v5_initializable_slot": initializable_slot(),
            "scope_note": "--scope filters Solidity sources only; broadcast logs, deployment "
                          "records and deploy scripts are read wherever they are",
            "notice": NOTICE}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--repo", required=True, help="target checkout (read only)")
    p.add_argument("--scope", action="append", help="repository-relative source prefix; repeatable")
    p.add_argument("--out", help="private JSON output, outside the checkout")
    a = p.parse_args(argv)
    try:
        if a.out:
            out = Path(a.out).expanduser().resolve()
            for root in (SKILL_ROOT, Path(a.repo).expanduser().resolve()):
                if out == root or root in out.parents:
                    raise ValueError("--out must be outside the target checkout and skill package")
        report = analyze(a.repo, a.scope)
    except ValueError as exc:
        p.error(str(exc))
    payload = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if a.out:
        Path(a.out).write_text(payload, encoding="utf-8")
        print(json.dumps({"out": a.out, "counts": report["counts"]}))
    else:
        print(payload, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
