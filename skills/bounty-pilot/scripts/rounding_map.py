#!/usr/bin/env python3
"""Rounding sites in Solidity, ranked by direction x repeatability.

One call's rounding error is a wei and looks harmless, so a reviewer - human or model - reads it,
agrees it is a wei, and moves on. The bug is never the single rounding. It is the *direction* (does
the wei go to the caller or to the protocol?) multiplied by *repeatability* (can the caller take
that step a thousand times in one transaction, with borrowed capital, for less than the drift it
creates?). That product is the class audits and AI reviewers miss most: the EVMbench
re-evaluation (arXiv 2603.10795) measured rounding / multi-step classes detected about 4% of the
time by AI agents.

The calibration incidents, each the same shape - a favourable rounding, then repetition:

- **Balancer v2, Nov 2025 (~$128M).** `_upscale` rounds down; 65 micro `batchSwap` GIVEN_OUT
  steps in one transaction deflated the invariant D. Trail of Bits flagged that rounding in 2021
  and could not prove it exploitable - single-call reasoning.
- **Bunni, Sep 2025 ($8.4M).** Rounding direction in the withdraw idle-balance update, amplified by
  flash-loaned repetition.
- **Yearn yETH, Nov 2025 (~$9M).** Stableswap solver math; a huge mint from dust.
- **zkLend, Feb 2025 ($9.5M).** An accumulator inflated in an empty market, then a rounding repeated.
- **Resupply, Jun 2025.** An exchange rate rounding to 0 after a donation.

What this reports, per in-scope function body (lexically; target source is data, never executed):

- every rounding site - integer `/`, `mulDiv*`, `div/mul*Up|Down`, Wad/Ray half-up math, any call
  carrying an OpenZeppelin `Rounding.X` argument, `mulDivRoundingUp`, `>>` on an amount, `sqrt` -
  with its direction (down | up | half | unknown);
- what the rounded value feeds (out | in | shares-minted | shares-burned | state | unknown), by name
  flow through assignments, returns into callers and arguments into callees;
- `favors_user` when the standard round-against-the-user convention is violated: down on what the
  user pays or on shares burned from them, up on what they receive or shares minted to them;
- whether an entry point reaching it is repeatable (batching surface, or nothing per-tx limits it),
  plus flash-loan presence and empty-market / first-depositor shape.

Every row is a lead, not a verdict. `references/rounding-map.md` has the triage steps and
`templates/RepetitionDrift.t.sol` the measurement.
"""
import argparse
import json
import os
import re
import subprocess
from pathlib import Path

SCHEMA_VERSION = 1
GIT_HARDENING = ("--no-optional-locks", "-c", "core.fsmonitor=false",
                 "-c", "core.hooksPath=/dev/null")
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_DEPTH = 4

SKIP_RULES = (
    (re.compile(r"\.t\.sol$"), "test file"),
    (re.compile(r"\.s\.sol$"), "script file"),
    (re.compile(r"(^|/)tests?/"), "test directory"),
    (re.compile(r"(^|/)mocks?/"), "mock directory"),
    (re.compile(r"(^|/)scripts?/"), "script directory"),
)

IDENT = r"[A-Za-z_$][\w$]*"
UP_CALLS = {"mulDivUp", "mulDivRoundingUp", "divUp", "divWadUp", "mulWadUp", "ceilDiv",
            "divRoundUp", "rawDivUp", "fullMulDivUp", "mulDivCeil", "divCeil"}
DOWN_CALLS = {"mulDivDown", "divDown", "divWadDown", "mulWadDown", "divWad", "mulWad",
              "fullMulDiv", "mulDivFloor"}
HALF_CALLS = {"rayDiv", "rayMul", "wadDiv", "wadMul", "percentMul", "percentDiv"}
ROUNDING_ARG = re.compile(r"\bRounding\s*\.\s*(Ceil|Floor|Up|Down|Expand|Trunc|Zero)\b")
ROUNDING_DIRECTION = {"Ceil": "up", "Up": "up", "Expand": "up",
                      "Floor": "down", "Down": "down", "Trunc": "down", "Zero": "down"}
CALL = re.compile(r"(?<![\w$])(" + IDENT + r")\s*\(")
AMOUNTISH = re.compile(r"(?i)amount|asset|share|value|balance|liquidity|price|reserve|supply|"
                       r"debt|fee|reward|index|rate|ratio|deposit|collateral")
KEYWORDS = {"if", "for", "while", "return", "require", "assert", "revert", "emit", "new",
            "function", "returns", "mapping", "type", "address", "payable", "keccak256", "abi",
            "uint256", "int256", "uint", "int", "bytes", "string", "bool", "unchecked"}
OUT_NAMES = re.compile(r"(?i)^_?(withdraw|redeem|borrow|claim|exit|remove|unstake|harvest|"
                       r"collect|swap\w*out|getreward)")
IN_NAMES = re.compile(r"(?i)^_?(deposit|mint|repay|join|add|stake|supply|donate|swap\w*in$)")
SENDERS = r"(?:msg\.sender|_msgSender\(\s*\)|tx\.origin)"
LIMIT_MODIFIER = re.compile(r"(?i)perblock|onceper|cooldown|ratelimit|onlyeoa|throttle")
MIN_CHECK = re.compile(
    r"\b(?:require|if)\s*\(\s*!?\s*\(?\s*(" + IDENT + r")\s*(>=|>|<|<=)\s*(" + IDENT + r"|\d+)")
EMPTY_SUPPLY = re.compile(r"(?i)\b_?totalSupply\s*(\(\s*\))?\s*==\s*0\b|\b0\s*==\s*_?totalSupply")
OFFSET = re.compile(r"(?i)decimalsOffset|virtual_?(shares|assets)|DEAD_SHARES|MINIMUM_LIQUIDITY|"
                    r"VIRTUAL_|MIN_SHARES|INITIAL_SHARES")
FLASH = re.compile(r"(?i)\bflash\w*\s*\(|\bonFlashLoan\b|\bflashLoan\b|\bIERC3156")
BATCH_DECL = re.compile(r"\bfunction\s+(multicall|batch\w*|multiCall|aggregate|execute(Batch|Many))"
                        r"\s*\(", re.I)
NUMERIC = re.compile(r"^\(*\s*(\d[\d_]*(\.\d+)?(e\d+)?|0x[0-9a-fA-F]+)"
                     r"(\s*(wei|gwei|ether|seconds|minutes|hours|days|weeks))?\s*\)*$")
CONSTANT_NAME = re.compile(r"^\(*\s*[A-Z_][A-Z0-9_]*\s*\)*$")
TYPE_MAX = re.compile(r"^type\s*\(\s*\w+\s*\)\s*\.\s*(max|min)$")


def _strip(text):
    """Blank comments and string contents with spaces, keeping every offset and newline."""
    out, i, n = list(text), 0, len(text)
    while i < n:
        c = text[i]
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] != "\n":
                out[i] = " "
                i += 1
        elif c == "/" and i + 1 < n and text[i + 1] == "*":
            end = text.find("*/", i + 2)
            end = n if end < 0 else end + 2
            for k in range(i, end):
                if text[k] != "\n":
                    out[k] = " "
            i = end
        elif c in "\"'":
            k = i + 1
            while k < n and text[k] != c and text[k] != "\n":
                if text[k] == "\\":
                    out[k] = " "
                    k += 1
                if k < n and text[k] != "\n":
                    out[k] = " "
                k += 1
            i = k + 1
        else:
            i += 1
    return "".join(out)


def _match(text, i, open_c, close_c):
    """Index of the bracket closing the one at `i`, or -1."""
    depth = 0
    for k in range(i, len(text)):
        if text[k] == open_c:
            depth += 1
        elif text[k] == close_c:
            depth -= 1
            if depth == 0:
                return k
    return -1


def _split_args(text):
    args, depth, start = [], 0, 0
    for k, c in enumerate(text):
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == "," and depth == 0:
            args.append((start, k))
            start = k + 1
    if text.strip():
        args.append((start, len(text)))
    return args


def _line(text, offset):
    return text.count("\n", 0, offset) + 1


def _clean(s, cap=180):
    s = " ".join(s.split())
    return s if len(s) <= cap else s[:cap - 3] + "..."


# --- structure --------------------------------------------------------------------------------

CONTRACT = re.compile(r"\b(abstract\s+contract|contract|library|interface)\s+(" + IDENT + r")")
FUNC = re.compile(r"\b(?:function\s+(" + IDENT + r")|(constructor|fallback|receive))\s*\(")
MODIFIER = re.compile(r"\bmodifier\s+(" + IDENT + r")")


def _contracts(s):
    found = []
    for m in CONTRACT.finditer(s):
        brace = s.find("{", m.end())
        semi = s.find(";", m.end())
        if brace < 0 or (0 <= semi < brace):
            continue
        end = _match(s, brace, "{", "}")
        found.append({"kind": m.group(1).split()[-1], "name": m.group(2),
                      "header": s[m.end():brace], "start": brace, "end": end if end > 0 else len(s)})
    return found


def _header_parts(header, in_interface):
    returns_vars = []
    rm = re.search(r"\breturns\s*\(", header)
    if rm:
        close = _match(header, rm.end() - 1, "(", ")")
        for a, b in _split_args(header[rm.end():close]):
            words = re.findall(IDENT, header[rm.end():close][a:b])
            if len(words) >= 2 and words[-1] not in ("memory", "calldata", "storage"):
                returns_vars.append(words[-1])
        header = header[:rm.start()] + " " + header[close + 1:]
    tokens = re.findall(IDENT, re.sub(r"\([^()]*\)", " ", header))
    visibility = next((t for t in tokens if t in ("external", "public", "internal", "private")),
                      "external" if in_interface else "unspecified")
    mutability = next((t for t in tokens if t in ("view", "pure", "payable")), "nonpayable")
    modifiers = [t for t in tokens if t not in (
        "external", "public", "internal", "private", "view", "pure", "payable", "virtual",
        "override", "constant")]
    return visibility, mutability, modifiers, returns_vars


def _functions(s, contracts, path):
    out = []
    for m in FUNC.finditer(s):
        name = m.group(1) or m.group(2)
        paren = m.end() - 1
        close = _match(s, paren, "(", ")")
        if close < 0:
            continue
        k, depth = close + 1, 0
        while k < len(s):
            if s[k] == "(":
                depth += 1
            elif s[k] == ")":
                depth -= 1
            elif depth == 0 and s[k] in "{;":
                break
            k += 1
        if k >= len(s) or s[k] == ";":
            continue
        end = _match(s, k, "{", "}")
        if end < 0:
            continue
        owner = next((c for c in contracts if c["start"] < m.start() < c["end"]), None)
        vis, mut, mods, rets = _header_parts(s[close + 1:k], owner and owner["kind"] == "interface")
        if name in ("fallback", "receive"):
            vis = "external"
        params = []
        for a, b in _split_args(s[paren + 1:close]):
            words = re.findall(IDENT, s[paren + 1:close][a:b])
            if len(words) >= 2:
                params.append(words[-1])
            else:
                params.append(None)
        out.append({"name": name, "contract": owner["name"] if owner else "<file>",
                    "contract_ref": owner, "path": path, "line": _line(s, m.start()),
                    "visibility": vis, "mutability": mut, "modifiers": mods,
                    "params": params, "returns": rets, "body_start": k + 1, "body_end": end,
                    "text": s})
    return out


def _body(fn):
    return fn["text"][fn["body_start"]:fn["body_end"]]


def _statements(fn):
    """(start, end) absolute spans, split on `;` and block braces (not `{value: ...}` options)."""
    s, a, b = fn["text"], fn["body_start"], fn["body_end"]
    spans, start, options = [], a, 0
    k = a
    while k < b:
        c = s[k]
        if c == "{" and re.match(r"\s*(value|gas|salt)\s*:", s[k + 1:k + 40]):
            options += 1
        elif c == "}" and options:
            options -= 1
        elif c == ";" or c in "{}":
            if s[start:k].strip():
                spans.append((start, k))
            start = k + 1
        k += 1
    if s[start:b].strip():
        spans.append((start, b))
    return spans


def _locals(fn):
    body = _body(fn)
    decl = re.compile(r"\b(?:u?int\d*|address|bool|bytes\d*|string|[A-Z]\w*(?:\.\w+)?)"
                      r"(?:\[\])?\s+(?:memory\s+|storage\s+|calldata\s+|payable\s+)?(" + IDENT
                      + r")\s*(?=[=;,)])")
    names = {m.group(1) for m in decl.finditer(body)}
    return names | {p for p in fn["params"] if p} | set(fn["returns"])


# --- rounding sites ---------------------------------------------------------------------------

def _operand_back(s, i, floor):
    """(text, start) of the operand left of the operator at `i`, across a `*` chain."""
    k = i - 1
    while k >= floor and s[k].isspace():
        k -= 1
    end = k + 1
    while k >= floor:
        if s[k] in ")]":
            depth = 0
            while k >= floor:
                if s[k] in ")]":
                    depth += 1
                elif s[k] in "([":
                    depth -= 1
                    if depth == 0:
                        break
                k -= 1
            k -= 1
        elif re.match(r"[\w$.]", s[k]):
            k -= 1
        else:
            j = k
            while j >= floor and s[j].isspace():
                j -= 1
            if j > floor and s[j] == "*" and s[j - 1] != "*" and k + 1 < end:
                k = j - 1
                while k >= floor and s[k].isspace():
                    k -= 1
                continue
            break
    return s[k + 1:end].strip(), k + 1 + (len(s[k + 1:end]) - len(s[k + 1:end].lstrip()))


def _operand_fwd(s, i, ceil):
    """(text, end) of the operand right of an operator ending before `i`."""
    k = i
    while k < ceil and s[k].isspace():
        k += 1
    start = k
    if k < ceil and s[k] == "-":
        k += 1
    while k < ceil:
        if s[k] in "([":
            close = _match(s, k, s[k], ")" if s[k] == "(" else "]")
            if close < 0:
                break
            k = close + 1
        elif re.match(r"[\w$.]", s[k]):
            k += 1
        else:
            break
    return s[start:k].strip(), k


def _constantish(expr):
    parts = [p.strip() for p in expr.split("*") if p.strip()]
    return bool(parts) and all(NUMERIC.match(p) or CONSTANT_NAME.match(p) or TYPE_MAX.match(p)
                               for p in parts)


def _rounding_arg_direction(args_text):
    m = ROUNDING_ARG.search(args_text)
    return ROUNDING_DIRECTION[m.group(1)] if m else None


def _sites_in(fn):
    s, a, b = fn["text"], fn["body_start"], fn["body_end"]
    sites = []
    for m in CALL.finditer(s, a, b):
        name = m.group(1)
        paren = m.end() - 1
        close = _match(s, paren, "(", ")")
        if close < 0 or close > b:
            continue
        args = s[paren + 1:close]
        kind = direction = None
        note = None
        if name in UP_CALLS:
            kind, direction = name, "up"
        elif name in DOWN_CALLS:
            kind, direction = name, "down"
        elif name in HALF_CALLS:
            kind, direction = name, "half"
        elif name in ("mulDiv", "sqrt"):
            kind = name
            explicit = _rounding_arg_direction(args)
            arg_spans = _split_args(args)
            if explicit:
                direction = explicit
            elif (name == "mulDiv" and len(arg_spans) == 4) or \
                    (name == "sqrt" and len(arg_spans) == 2) or \
                    (name == "mulDiv" and len(arg_spans) == 3 and
                     re.search(r"(?i)round", args[arg_spans[-1][0]:arg_spans[-1][1]])):
                direction, note = "unknown", "rounding chosen by a caller-supplied argument"
            else:
                direction = "down"
        else:
            explicit = _rounding_arg_direction(args)
            if explicit and name not in KEYWORDS:
                kind, direction = f"{name}(Rounding)", explicit
        if kind:
            sites.append({"kind": kind, "direction": direction, "offset": m.start(),
                          "end": close + 1, "note": note})
    for m in re.finditer(r"(?<![/*])/(?![/*])(=?)", s[a:b]):
        pos = a + m.start()
        left, lstart = _operand_back(s, pos, a)
        right, rend = _operand_fwd(s, pos + 1 + len(m.group(1)), b)
        if not left or not right:
            continue
        if _constantish(left) and _constantish(right):
            continue
        direction, kind = "down", "/" + m.group(1)
        if re.search(r"\+.*-\s*1\s*\)\s*$", left):
            direction, kind = "up", "ceil-div (x + d - 1) / d"
        sites.append({"kind": kind, "direction": direction, "offset": lstart,
                      "end": rend, "note": None})
    for m in re.finditer(r">>(=?)", s[a:b]):
        pos = a + m.start()
        left, lstart = _operand_back(s, pos, a)
        right, rend = _operand_fwd(s, pos + 2 + len(m.group(1)), b)
        if not left or (_constantish(left) and _constantish(right)):
            continue
        if not AMOUNTISH.search(left):
            continue
        sites.append({"kind": ">>" + m.group(1), "direction": "down", "offset": lstart,
                      "end": rend, "note": None})
    sites.sort(key=lambda x: x["offset"])
    return sites


# --- flow -------------------------------------------------------------------------------------

SINKS = (
    # name regex, feed resolver(args list of str) -> feed, amount arg selector
    (re.compile(r"^(safeTransfer|transfer|sendValue|safeTransferETH|forceSafeTransferETH)$"),
     lambda args: "out"),
    (re.compile(r"^(safeTransferFrom|transferFrom)$"),
     lambda args: "out" if len(args) >= 3 and re.match(r"^address\s*\(\s*this\s*\)$",
                                                         args[-3].strip()) else "in"),
    (re.compile(r"^_mint$"), lambda args: "shares-minted"),
    (re.compile(r"^_burn$"), lambda args: "shares-burned"),
    (re.compile(r"^mint$"), lambda args: "out"),
    (re.compile(r"^burn$"), lambda args: "in"),
)


SHARE_BOOK = re.compile(r"share|balance|supply|stake", re.I)
DEBT_BOOK = re.compile(r"debt|borrow|owed|liabilit", re.I)


def _sink(name):
    for rx, resolver in SINKS:
        if rx.match(name):
            return resolver
    return None


class _Taint:
    def __init__(self, names=(), calls=(), span=None):
        self.names, self.calls, self.span = set(names), set(calls), span

    def hit(self, s, a, b):
        seg = s[a:b]
        if self.span and a <= self.span[0] and self.span[1] <= b + 1:
            return True
        if any(re.search(r"(?<![\w$.])" + re.escape(n) + r"(?![\w$])", seg) for n in self.names):
            return True
        return any(re.search(r"(?<![\w$])" + re.escape(c) + r"\s*\(", seg) for c in self.calls)


def _assign_targets(stmt):
    st = stmt.strip()
    if st.startswith("("):
        close = _match(st, 0, "(", ")")
        if close > 0 and re.match(r"\s*=(?!=)", st[close + 1:]):
            names = []
            for part in st[1:close].split(","):
                names += re.findall(IDENT, part)[-1:]
            return names, "="
    m = re.match(r"^(?:[\w$.]+(?:\[\])?\s+(?:memory\s+|storage\s+)?)?(" + IDENT
                 + r")((?:\s*\[[^\]]*\]|\s*\.\s*" + IDENT + r")*)\s*([+\-*/]?=)(?!=)", st)
    if m and m.group(1) not in KEYWORDS:
        return [m.group(1)], m.group(3)
    return [], None


def _flow(fn, taint, index, depth, seen):
    """Feeds reached from the tainted values in `fn`: list of (feed, via)."""
    key = (fn["path"], fn["contract"], fn["name"], fn["line"], frozenset(taint.names),
           frozenset(taint.calls), taint.span)
    if key in seen or depth > MAX_DEPTH:
        return []
    seen.add(key)
    s = fn["text"]
    local = _locals(fn)
    feeds, returns = [], False
    spans = _statements(fn)
    for _ in range(2):
        for a, b in spans:
            if not taint.hit(s, a, b):
                continue
            stmt = s[a:b]
            if re.match(r"\s*return\b", stmt):
                returns = True
            for m in CALL.finditer(s, a, b):
                name = m.group(1)
                close = _match(s, m.end() - 1, "(", ")")
                if close < 0:
                    continue
                arg_spans = [(m.end() + x, m.end() + y) for x, y in _split_args(s[m.end():close])]
                resolver = _sink(name)
                if resolver:
                    args = [s[x:y] for x, y in arg_spans]
                    amount = arg_spans[-1:] if len(arg_spans) > 1 else arg_spans
                    if any(taint.hit(s, x, y) for x, y in amount):
                        feeds.append((resolver(args), f"{fn['contract']}.{fn['name']}:{name}"))
                    continue
                if name in KEYWORDS:
                    continue
                for callee in index.get(name, []):
                    if callee is fn or len(callee["params"]) != len(arg_spans):
                        continue
                    for pos, (x, y) in enumerate(arg_spans):
                        param = callee["params"][pos]
                        if param and taint.hit(s, x, y):
                            for feed, via in _flow(callee, _Taint(names=[param]), index,
                                                   depth + 1, seen):
                                feeds.append((feed, f"{fn['name']}->{via}"))
            if re.search(r"\.call\s*\{\s*value\s*:", stmt):
                opt = re.search(r"\{\s*value\s*:([^}]*)\}", stmt)
                if opt and taint.hit(s, a + opt.start(1), a + opt.end(1)):
                    feeds.append(("out", f"{fn['contract']}.{fn['name']}:call{{value}}"))
            targets, op = _assign_targets(re.sub(r"^\s*return\b", "", stmt))
            for t in targets:
                if t in fn["returns"]:
                    returns = True
                elif t not in local:
                    # Hand-rolled share books - `shares[owner] -= s; totalShares -= s;` - are the
                    # same burn and mint as _burn/_mint. Debt is deliberately not share-like: a
                    # `debt += x` is the user paying, the opposite of a mint.
                    if op in ("-=", "+=") and SHARE_BOOK.search(t) and not DEBT_BOOK.search(t):
                        feeds.append(("shares-burned" if op == "-=" else "shares-minted",
                                      f"{fn['contract']}.{fn['name']}:{t} {op}"))
                    else:
                        feeds.append(("state", f"{fn['contract']}.{fn['name']}:{t} {op}"))
                taint.names.add(t)
    if returns:
        for caller in index.get("<callers>", {}).get(fn["name"], []):
            if caller is fn:
                continue
            for feed, via in _flow(caller, _Taint(calls=[fn["name"]]), index, depth + 1, seen):
                feeds.append((feed, f"{fn['name']}<-{via}"))
    return feeds


def _callers_index(functions):
    callers = {}
    for g in functions:
        body = _body(g)
        for name in set(m.group(1) for m in CALL.finditer(body)):
            callers.setdefault(name, []).append(g)
    return callers


def _entries(fn, callers, depth=0, seen=None):
    seen = seen if seen is not None else set()
    if id(fn) in seen or depth > MAX_DEPTH:
        return []
    seen.add(id(fn))
    out = []
    if _is_entry(fn):
        out.append(fn)
    for g in callers.get(fn["name"], []):
        if g is not fn:
            out += _entries(g, callers, depth + 1, seen)
    return out


def _is_entry(fn):
    return fn["visibility"] in ("external", "public") and \
        fn["mutability"] not in ("view", "pure") and fn["name"] != "constructor"


# --- per-function classification --------------------------------------------------------------

def _direction(fn):
    body, params = _body(fn), [p for p in fn["params"] if p]
    who = SENDERS + ("|" + "|".join(re.escape(p) for p in params) if params else "")
    receives, pays = [], []
    if OUT_NAMES.match(fn["name"]):
        receives.append(f"name `{fn['name']}`")
    if IN_NAMES.match(fn["name"]):
        pays.append(f"name `{fn['name']}`")
    for m in re.finditer(r"\b(safeTransfer|transfer|_mint|mint|sendValue|safeTransferETH)\s*\("
                         r"\s*(?:" + IDENT + r"\s*,\s*)?(" + who + r")\s*[,)]", body):
        receives.append(_clean(m.group(0), 60))
    if re.search(r"\.call\s*\{\s*value\s*:", body):
        receives.append("call{value:}")
    for m in re.finditer(r"\b(safeTransferFrom|transferFrom)\s*\(\s*(?:" + IDENT
                         + r"\s*,\s*)?(" + who + r")\s*,", body):
        pays.append(_clean(m.group(0), 60))
    for m in re.finditer(r"\b(_burn|burn)\s*\(", body):
        pays.append(_clean(m.group(0), 60))
    if receives and pays:
        return "mixed", receives + pays
    if receives:
        return "user-receives", receives
    if pays:
        return "user-pays", pays
    return "unknown", []


def _limiters(fn, modifier_bodies):
    body, out = _body(fn), []
    for mod in fn["modifiers"]:
        if LIMIT_MODIFIER.search(mod) or "block.number" in modifier_bodies.get(mod, ""):
            out.append(f"modifier `{mod}` (per-block / rate limit)")
    if re.search(r"block\.number", body):
        out.append("per-block check on block.number in body")
    for m in MIN_CHECK.finditer(body):
        op, right = m.group(2), m.group(3)
        if op in (">=", ">") and (re.search(r"(?i)min", right) or right == "0"):
            out.append(_clean(m.group(0) + "...", 80))
        elif op in ("<", "<=") and re.search(r"(?i)min", right):
            out.append(_clean(m.group(0) + "...", 80))
    return out


def _batching(fn, contract_text, file_text, header, functions):
    ev = []
    if BATCH_DECL.search(contract_text):
        ev.append("contract declares " + BATCH_DECL.search(contract_text).group(1) + "()")
    elif BATCH_DECL.search(file_text):
        ev.append("file declares " + BATCH_DECL.search(file_text).group(1) + "()")
    inherited = re.findall(r"\b(\w*(?:Multicall|Batch)\w*)\b", header or "", re.I)
    ev += [f"inherits {name}" for name in inherited]
    if re.search(r"\bbatchSwap\b", file_text):
        ev.append("batchSwap present in file")
    if re.search(r"\bdelegatecall\s*\(", contract_text) and \
            re.search(r"address\s*\(\s*this\s*\)|msg\.data|data\s*\[", contract_text):
        ev.append("delegatecall to self")
    for g in functions:
        if g is fn or not _is_entry(g) or g["path"] != fn["path"]:
            continue
        body = _body(g)
        if re.search(r"\b(for|while)\s*\(", body) and \
                re.search(r"(?<![\w$])" + re.escape(fn["name"]) + r"\s*\(", body) and \
                re.search(r"\[\s*\w+\s*\]", body):
            ev.append(f"loop in {g['name']}() calls {fn['name']}() over an array")
    return sorted(set(ev))


# --- verdict ----------------------------------------------------------------------------------

def _verdict(direction, feed):
    if direction in ("half", "unknown"):
        return "needs_reading"
    if feed in ("state", "unknown", None):
        return "needs_reading"
    favors = (direction == "down" and feed in ("in", "shares-burned")) or \
             (direction == "up" and feed in ("out", "shares-minted"))
    return "favors_user" if favors else "favors_protocol"


def _tier(verdict, repeatable):
    order = {("favors_user", True): 0, ("needs_reading", True): 1, ("favors_user", False): 2,
             ("needs_reading", False): 3}
    return order.get((verdict, repeatable), 4)


# --- inputs -----------------------------------------------------------------------------------

def _skip_reason(rel):
    low = rel.replace("\\", "/").lower()
    for rx, reason in SKIP_RULES:
        if rx.search(low):
            return reason
    return None


def _in_scope(rel, scope):
    if not scope:
        return True
    rel = rel.replace("\\", "/")
    return any(rel == p.rstrip("/") or rel.startswith(p.rstrip("/") + "/") or
               (not p.endswith("/") and rel.startswith(p)) for p in scope)


def _git_files(repo):
    raw = subprocess.run(["git", *GIT_HARDENING, "-C", str(repo), "ls-files", "-z"],
                         check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return sorted(x for x in raw.stdout.decode("utf-8", "replace").split("\0") if x)


def _read(root, rel, skipped):
    path = (root / rel) if root else Path(rel)
    try:
        if path.is_symlink():
            skipped.append({"path": rel, "reason": "symlink not followed"})
            return None
        if root:
            resolved = path.resolve()
            if not str(resolved).startswith(str(root.resolve()) + os.sep):
                skipped.append({"path": rel, "reason": "outside the repository"})
                return None
        if path.stat().st_size > MAX_FILE_BYTES:
            skipped.append({"path": rel, "reason": "larger than 2 MiB"})
            return None
        return path.read_bytes().decode("utf-8", "replace")
    except OSError as exc:
        skipped.append({"path": rel, "reason": f"unreadable: {type(exc).__name__}"})
        return None


def _collect(repo, files, scope, build_info, skipped):
    sources = []
    if build_info:
        data = json.loads(Path(build_info).read_text(encoding="utf-8"))
        srcs = (data.get("input") or {}).get("sources") or {}
        candidates = [(rel, (v or {}).get("content")) for rel, v in sorted(srcs.items())]
    else:
        root = Path(repo) if repo else None
        names = list(files) if files else (_git_files(root) if root else [])
        candidates = []
        for rel in names:
            if root and Path(rel).is_absolute():
                try:
                    rel = str(Path(rel).resolve().relative_to(root.resolve()))
                except ValueError:
                    pass
            candidates.append((rel, None))
    for rel, content in candidates:
        if not rel.endswith(".sol") or not _in_scope(rel, scope):
            continue
        reason = _skip_reason(rel)
        if reason:
            skipped.append({"path": rel, "reason": reason})
            continue
        if content is None:
            if build_info:
                skipped.append({"path": rel, "reason": "no content in build-info"})
                continue
            content = _read(Path(repo) if repo else None, rel, skipped)
            if content is None:
                continue
        sources.append((rel, content))
    return sources


# --- analysis ---------------------------------------------------------------------------------

NOTICE = ("Lexical leads, not findings, and nothing here proves profit. The parse strips comments "
          "and strings and matches braces; it does not see assembly, inlined library math it was "
          "not given, inheritance across files beyond name matching, or which overload a call "
          "resolves to. A favourable rounding is exploitable only if one repetition costs less "
          "than the drift it creates - gas, fees, minimum amounts, per-block limits - so measure "
          "it with templates/RepetitionDrift.t.sol (candidate AND negative control). The "
          "round-against-the-user convention is sometimes violated on purpose with an offsetting "
          "fee; read the fee before claiming. Confirm every row on the unmodified source at the "
          "deployed revision.")


def analyze(repo=None, files=None, scope=None, build_info=None, limit=500):
    skipped = []
    sources = _collect(repo, files, scope or [], build_info, skipped)
    functions, contract_info, flash_files = [], {}, []
    texts = {}
    for rel, raw in sources:
        s = _strip(raw)
        texts[rel] = s
        if FLASH.search(s):
            flash_files.append(rel)
        contracts = _contracts(s)
        for c in contracts:
            body = s[c["start"]:c["end"]]
            contract_info[(rel, c["name"])] = {
                "empty_supply_branch": bool(EMPTY_SUPPLY.search(body)),
                "offset_or_virtual_shares": bool(OFFSET.search(body)),
            }
        functions += _functions(s, contracts, rel)
    by_name, modifier_bodies = {}, {}
    for fn in functions:
        by_name.setdefault(fn["name"], []).append(fn)
    for rel, s in texts.items():
        for m in MODIFIER.finditer(s):
            brace = s.find("{", m.end())
            end = _match(s, brace, "{", "}") if brace >= 0 else -1
            if end > 0:
                modifier_bodies[m.group(1)] = s[brace:end]
    callers = _callers_index(functions)
    index = dict(by_name)
    index["<callers>"] = callers

    fn_meta = {}

    def meta(fn):
        key = id(fn)
        if key not in fn_meta:
            c = fn["contract_ref"]
            ctext = fn["text"][c["start"]:c["end"]] if c else ""
            direction, evidence = _direction(fn)
            batching = _batching(fn, ctext, fn["text"], c["header"] if c else "", functions) \
                if _is_entry(fn) else []
            limits = _limiters(fn, modifier_bodies) if _is_entry(fn) else []
            fn_meta[key] = {
                "contract": fn["contract"], "function": fn["name"], "file": fn["path"],
                "line": fn["line"], "visibility": fn["visibility"],
                "mutability": fn["mutability"], "modifiers": fn["modifiers"],
                "direction": direction, "direction_evidence": evidence[:6],
                "repeatable": _is_entry(fn) and bool(batching or not limits),
                "batching_evidence": batching, "limiters": limits, "sites": [],
            }
        return fn_meta[key]

    sites = []
    for fn in functions:
        for raw_site in _sites_in(fn):
            s = fn["text"]
            spans = _statements(fn)
            stmt = next(((a, b) for a, b in spans if a <= raw_site["offset"] < b),
                        (raw_site["offset"], raw_site["end"]))
            feeds = _flow(fn, _Taint(span=(raw_site["offset"], raw_site["end"])), index, 0, set())
            verdicts = [(_verdict(raw_site["direction"], feed), feed, via) for feed, via in feeds]
            if not verdicts:
                verdicts = [(_verdict(raw_site["direction"], "unknown"), "unknown", None)]
            rank = {"favors_user": 0, "needs_reading": 1, "favors_protocol": 2}
            verdicts.sort(key=lambda v: rank[v[0]])
            verdict, feed, via = verdicts[0]
            entries = _entries(fn, callers)
            seen_e, entry_meta = set(), []
            for e in entries:
                if id(e) not in seen_e:
                    seen_e.add(id(e))
                    entry_meta.append(meta(e))
            repeatable = any(m["repeatable"] for m in entry_meta)
            info = contract_info.get((fn["path"], fn["contract"]), {})
            context = []
            if flash_files:
                context.append("flash-loan surface in scanned source (capital-free repetition)")
            if info.get("empty_supply_branch") and not info.get("offset_or_virtual_shares"):
                context.append("empty-market branch (totalSupply == 0) with no virtual "
                               "shares / decimals offset / dead shares")
            sites.append({
                "file": fn["path"], "line": _line(s, raw_site["offset"]),
                "contract": fn["contract"], "function": fn["name"],
                "kind": raw_site["kind"], "direction": raw_site["direction"],
                "expression": _clean(s[raw_site["offset"]:raw_site["end"]], 120),
                "statement": _clean(s[stmt[0]:stmt[1]]),
                "feeds": feed, "feed_via": via,
                "feeds_all": sorted({f for f, _ in feeds}) or ["unknown"],
                "verdict": verdict, "favors_user": verdict == "favors_user",
                "needs_reading": verdict == "needs_reading",
                "repeatable": repeatable,
                "entry_points": [f"{m['contract']}.{m['function']}" for m in entry_meta],
                "context": context,
                "note": raw_site["note"],
                "_fn": fn, "_entries": entry_meta,
            })
    sites.sort(key=lambda x: (x["file"], x["line"], x["expression"]))
    for n, site in enumerate(sites, 1):
        site["id"] = f"R{n}"
        site["tier"] = _tier(site["verdict"], site["repeatable"])
    ranked = sorted(sites, key=lambda x: (x["tier"], x["file"], x["line"]))
    kept, dropped = ranked[:max(0, limit)], ranked[max(0, limit):]
    kept_ids = {x["id"] for x in kept}
    fn_rows = {}
    for site in ranked:
        for m in [meta(site["_fn"])] + site["_entries"]:
            row = fn_rows.setdefault(id(m), m)
            if site["id"] in kept_ids and site["id"] not in row["sites"]:
                row["sites"].append(site["id"])
            row["_tier"] = min(row.get("_tier", 9), site["tier"])
    functions_out = sorted((r for r in fn_rows.values() if r["sites"]),
                           key=lambda r: (r["_tier"], r["file"], r["line"]))
    for r in functions_out:
        r.pop("_tier", None)
    for r in fn_rows.values():
        r.pop("_tier", None)
    out_sites = []
    for site in kept:
        site = {k: v for k, v in site.items() if not k.startswith("_")}
        out_sites.append(site)
    tiers = ("favors_user+repeatable", "needs_reading+repeatable", "favors_user",
             "needs_reading", "favors_protocol")
    summary = {
        "sites": len(sites),
        "favors_user": sum(1 for x in sites if x["verdict"] == "favors_user"),
        "needs_reading": sum(1 for x in sites if x["verdict"] == "needs_reading"),
        "favors_protocol": sum(1 for x in sites if x["verdict"] == "favors_protocol"),
        "repeatable": sum(1 for x in sites if x["repeatable"]),
        "favors_user_and_repeatable": sum(1 for x in sites if x["tier"] == 0),
        "by_tier": {t: sum(1 for x in sites if x["tier"] == i) for i, t in enumerate(tiers)},
        "functions": len(functions_out),
        "skipped": len(skipped),
        "omitted": len(dropped),
        "omitted_by_tier": {t: sum(1 for x in dropped if x["tier"] == i)
                            for i, t in enumerate(tiers) if any(x["tier"] == i for x in dropped)},
    }
    notice = NOTICE
    if not sources:
        notice += (" No in-scope Solidity source was read: an empty map here means nothing was "
                   "scanned, not that nothing rounds. Vyper, Move, Rust and Cairo are not parsed.")
    return {"schema_version": SCHEMA_VERSION, "files_scanned": [rel for rel, _ in sources],
            "skipped": skipped, "flash_loan_surface": flash_files, "sites": out_sites,
            "functions": functions_out, "summary": summary, "notice": notice}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--repo", help="git checkout; tracked *.sol files are read, never executed")
    p.add_argument("--file", action="append", default=[],
                   help="explicit source file (relative to --repo when given); repeatable")
    p.add_argument("--scope", action="append", default=[], help="path prefix; repeatable")
    p.add_argument("--solc", dest="build_info",
                   help="solc/Foundry/Hardhat build-info JSON; only input.sources[*].content "
                        "is read")
    p.add_argument("--limit", type=int, default=500)
    p.add_argument("--out")
    a = p.parse_args(argv)
    if not a.repo and not a.build_info and not a.file:
        p.error("one of --repo, --solc or --file is required")
    try:
        report = analyze(repo=a.repo, files=a.file or None, scope=a.scope,
                         build_info=a.build_info, limit=a.limit)
    except subprocess.CalledProcessError as exc:
        p.error("git ls-files failed: " + exc.stderr.decode("utf-8", "replace").strip()[:200])
    except (OSError, ValueError) as exc:
        p.error(f"{type(exc).__name__}: {exc}")
    payload = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if a.out:
        Path(a.out).write_text(payload, encoding="utf-8")
        print(json.dumps({"out": a.out, "summary": report["summary"]}))
    else:
        print(payload, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
