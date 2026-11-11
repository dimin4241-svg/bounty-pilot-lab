#!/usr/bin/env python3
"""A stateful invariant harness skeleton: one handler call per state-changing entry point.

Multi-transaction state machines are the class automated readers find worst. On EVMbench's
re-evaluation (arXiv 2603.10795) a signature state machine with nested calls was found by none of
26 agent configurations and multi-step state inconsistency by about 4%. GMX v1 (July 2025: a
refund callback re-entered and increasePosition skewed globalShortAveragePrices) and Abracadabra
(October 2025: a cook() action flag reset that skipped the solvency check) were sequence bugs. A
reading cannot enumerate sequences; a handler-based campaign can - once a human writes the
property.

So this draws only the machinery around the property:

- `<Contract>Handler.sol`: one `call_<fn>` per external/public non-view, non-pure, non-payable
  function, with uints clamped by `bound()`, an actor picked from a `makeAddr` pool and pranked,
  addresses drawn from that pool plus the system contracts, bytes and arrays kept short, and every
  call wrapped in try/catch so `calls[selector]` and `reverts[selector]` show what the campaign
  actually reached;
- `<Contract>Invariants.t.sol`: a setUp that deploys nothing (TODO: deploy or fork - no address is
  ever filled in), `targetContract` + `targetSelector`, one `invariant_<name>()` per `INVARIANT:`
  line of model.md whose body is `assertTrue(false, "TODO: ...")`, and a call summary;
- `harness-plan.json`: what was included, what was skipped and why.

The suite FAILS until a human writes each property. It never contains an attack sequence or
exploit logic, and target ABI text is data: names that are not plain identifiers are skipped.
"""
import argparse
import json
import re
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
SKILL_ROOT = SCRIPTS.parent
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from keccak import selector as _selector  # noqa: E402

IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
SCALAR = re.compile(r"^(?:(u?int)(\d*)|address|bool|bytes(\d+)|bytes|string)$")
ARRAY = re.compile(r"^(.+?)\[(\d*)\]$")
MAX_FIXED = 16          # a fixed array longer than this is skipped, not unrolled
PRAGMA = "pragma solidity ^0.8.13;"
NOTICE = ("A skeleton, not a test result. Every property stub fails until a human writes it; a "
          "clean campaign is coverage of the properties that were written, never evidence of "
          "safety. A broken invariant is a candidate that still needs a concrete, minimised PoC "
          "against unmodified source and a negative control. Record the tool and its version, the "
          "seed, runs and depth of every campaign in experiments.json. Watch reverts[selector]: a "
          "handler whose calls mostly revert explored nothing.")


def _canonical(abi_type):
    t = abi_type.replace(" ", "")
    if t.startswith("addresspayable"):
        t = "address" + t[len("addresspayable"):]
    t = re.sub(r"^(u?int)(?=$|\[)", r"\g<1>256", t)
    return t


def classify(abi_type):
    """`(kind, detail)` for one ABI parameter type, or `(None, reason)` when unsupported.

    kind is `scalar` (detail: the scalar type) or `array` (detail: (element, length or None))."""
    t = _canonical(abi_type)
    if t.startswith("tuple"):
        return None, "unsupported type %s: tuple/struct argument, write that handler by hand" % t
    m = ARRAY.match(t)
    if m:
        element, length = m.group(1), m.group(2)
        if ARRAY.match(element) or not SCALAR.match(element):
            return None, "unsupported type %s: nested or non-scalar array" % t
        if length and int(length) > MAX_FIXED:
            return None, "unsupported type %s: fixed array longer than %d" % (t, MAX_FIXED)
        return "array", (element, int(length) if length else None)
    m = SCALAR.match(t)
    if not m:
        return None, "unsupported type %s: not an ABI scalar (struct, enum alias or user type)" % t
    if m.group(1) and m.group(2) and not (8 <= int(m.group(2)) <= 256 and int(m.group(2)) % 8 == 0):
        return None, "unsupported type %s: invalid integer width" % t
    if m.group(3) and not 1 <= int(m.group(3)) <= 32:
        return None, "unsupported type %s: invalid bytesN width" % t
    return "scalar", t


def _reference(t):
    return t in ("bytes", "string") or t.endswith("]")


def _input_type(element):
    """What the fuzzer supplies for one element: an address is a pool index."""
    return "uint256" if element == "address" else element


def _convert(element, expr):
    """Solidity expression turning a fuzzer-supplied element into the argument value."""
    if element == "address":
        return "_pick(%s)" % expr
    if element == "uint256":
        return "bound(%s, 0, MAX_AMOUNT)" % expr
    m = re.match(r"^uint(\d+)$", element)
    if m:
        width = int(m.group(1))
        ceiling = "MAX_AMOUNT" if width >= 128 else "uint256(type(%s).max)" % element
        return "%s(bound(uint256(%s), 0, %s))" % (element, expr, ceiling)
    if element == "bytes":
        return "_capBytes(%s)" % expr
    if element == "string":
        return "string(_capBytes(bytes(%s)))" % expr
    return expr  # intN, bool, bytesN: passed through; narrow by hand if the domain is smaller


def _loc(t):
    return t + " memory" if _reference(t) else t


def _handler_function(contract, fn):
    """Lines of one handler function. `fn` carries name, handler name, types and param names."""
    params, prep, args = ["uint256 actorSeed"], [], []
    for i, (abi_type, pname) in enumerate(zip(fn["types"], fn["param_names"])):
        kind, detail = classify(abi_type)
        local = "a%d" % i + ("_" + pname if pname else "")
        raw = local + "Raw"
        if kind == "scalar":
            supplied = _input_type(detail)
            converted = _convert(detail, raw)
            if converted == raw:
                params.append("%s %s" % (_loc(supplied), local))
            else:
                params.append("%s %s" % (_loc(supplied), raw))
                prep.append("        %s %s = %s;" % (_loc(detail), local, converted))
            args.append(local)
            continue
        element, length = detail
        supplied = _input_type(element)
        idx = "j%d" % i
        if length is None:
            params.append("%s[] memory %s" % (supplied, raw))
            prep += ["        uint256 n%d = %s.length < MAX_ARRAY ? %s.length : MAX_ARRAY;"
                     % (i, raw, raw),
                     "        %s[] memory %s = new %s[](n%d);" % (element, local, element, i),
                     "        for (uint256 %s = 0; %s < n%d; %s++) {" % (idx, idx, i, idx),
                     "            %s[%s] = %s;" % (local, idx, _convert(element, "%s[%s]" % (raw, idx))),
                     "        }"]
        else:
            params.append("%s[%d] memory %s" % (supplied, length, raw))
            prep += ["        %s[%d] memory %s;" % (element, length, local),
                     "        for (uint256 %s = 0; %s < %d; %s++) {" % (idx, idx, length, idx),
                     "            %s[%s] = %s;" % (local, idx, _convert(element, "%s[%s]" % (raw, idx))),
                     "        }"]
        args.append(local)
    lines = ["    /// %s" % fn["signature"],
             "    function %s(%s) external {" % (fn["handler"], ", ".join(params)),
             "        address actor = actors[bound(actorSeed, 0, actors.length - 1)];"]
    lines += prep
    lines += ['        bytes4 sel = bytes4(keccak256("%s"));' % fn["signature"],
              "        calls[sel]++;",
              "        vm.startPrank(actor);",
              "        try target.%s(%s) {" % (fn["name"], ", ".join(args)),
              "            // TODO: update ghost variables from the observed effect, never from the",
              "            // arguments alone.",
              "        } catch {",
              "            reverts[sel]++;",
              "        }",
              "        vm.stopPrank();",
              "    }"]
    return lines


def _interface_line(fn):
    types = []
    for abi_type in fn["types"]:
        t = _canonical(abi_type)
        types.append(t + " calldata" if _reference(t) else t)
    return "    function %s(%s) external;" % (fn["name"], ", ".join(types))


def render_handler(contract, functions, actors):
    iface = "I%sTarget" % contract
    out = ["// SPDX-License-Identifier: UNLICENSED", PRAGMA, "",
           "// Generated skeleton (bounty-pilot harness_gen.py). It contains no attack sequence and",
           "// no exploit logic: the fuzzer chooses the order of calls, a human writes the property.",
           "// Run it in a DISPOSABLE copy or worktree of the target, never the working tree.",
           "",
           'import {Test, console} from "forge-std/Test.sol";', "",
           "/// Only the functions this handler drives; ABI-shaped, so no target import is needed.",
           "interface %s {" % iface]
    out += [_interface_line(fn) for fn in functions]
    out += ["}", "",
            "contract %sHandler is Test {" % contract,
            "    %s public immutable target;" % iface,
            "    address[] public actors;",
            "    address[] internal pool;   // actors + the target + the system contracts",
            "",
            "    // TODO: narrow to the real domain (token supply, caps, decimals). A bound that is",
            "    // too wide makes most calls revert; one that is too narrow hides edge cases.",
            "    uint256 internal constant MAX_AMOUNT = type(uint128).max;",
            "    uint256 internal constant MAX_ARRAY = 4;",
            "    uint256 internal constant MAX_BYTES = 64;",
            "",
            "    // Coverage ghosts: how often each selector was called and how often it reverted.",
            "    mapping(bytes4 => uint256) public calls;",
            "    mapping(bytes4 => uint256) public reverts;",
            "    bytes4[] public selectors;",
            "    string[] public signatures;",
            "",
            "    // ---- Ghost variables -------------------------------------------------------",
            "    // TODO: running totals the properties are recomputed against (sum deposited,",
            "    // sum withdrawn, per-actor balances, last index seen). Update them only from",
            "    // observed effects inside the try branch.",
            "",
            "    constructor(address target_, address[] memory system_) {",
            "        target = %s(target_);" % iface,
            "        for (uint256 i = 0; i < %d; i++) {" % actors,
            '            address a = makeAddr(string.concat("actor", vm.toString(i)));',
            "            actors.push(a);",
            "            pool.push(a);",
            "        }",
            "        pool.push(target_);",
            "        for (uint256 i = 0; i < system_.length; i++) {",
            "            pool.push(system_[i]);",
            "        }",
            "        // TODO: fund and approve every actor here (deal + approve), or most calls",
            "        // revert for a boring reason and the campaign tests nothing.",
            ]
    for fn in functions:
        out.append('        _register("%s");' % fn["signature"])
    out += ["    }", "",
            "    function _register(string memory signature) internal {",
            "        selectors.push(bytes4(keccak256(bytes(signature))));",
            "        signatures.push(signature);",
            "    }", "",
            "    function _pick(uint256 seed) internal view returns (address) {",
            "        return pool[bound(seed, 0, pool.length - 1)];",
            "    }", "",
            "    function _capBytes(bytes memory b) internal pure returns (bytes memory c) {",
            "        uint256 n = b.length < MAX_BYTES ? b.length : MAX_BYTES;",
            "        c = new bytes(n);",
            "        for (uint256 i = 0; i < n; i++) {",
            "            c[i] = b[i];",
            "        }",
            "    }", ""]
    for fn in functions:
        out += _handler_function(contract, fn)
        out.append("")
    out += ["    /// Coverage, printed by invariant_callSummary. Not a target selector.",
            "    function callSummary() external view {",
            "        for (uint256 i = 0; i < selectors.length; i++) {",
            "            console.log(signatures[i], calls[selectors[i]], reverts[selectors[i]]);",
            "        }",
            "    }",
            "}", ""]
    return "\n".join(out)


def _sol_string(text):
    """Printable-ASCII Solidity string literal body: model text is data, never code."""
    clean = "".join(ch if 32 <= ord(ch) < 127 else "?" for ch in text)[:200]
    return clean.replace("\\", "\\\\").replace('"', '\\"')


def render_invariants(contract, functions, properties, framework, preset=None, fork=None):
    handler = "%sHandler" % contract
    out = ["// SPDX-License-Identifier: UNLICENSED", PRAGMA, "",
           "// Generated skeleton (bounty-pilot harness_gen.py). DELIBERATELY FAILING: every",
           "// property below asserts false until a human writes it. A clean run of a written",
           "// property is coverage of that property, not safety; a broken one is a candidate",
           "// that still needs a concrete PoC and a negative control.",
           "",
           'import {Test} from "forge-std/Test.sol";',
           'import {StdInvariant} from "forge-std/StdInvariant.sol";',
           'import {%s} from "./%s.sol";' % (handler, handler), "",
           "contract %sInvariants is StdInvariant, Test {" % contract,
           "    %s internal handler;" % handler,
           "    address internal target;", "",
           "    function setUp() public {",
           "        // TODO deploy: target = address(new %s(<arguments from the project's deploy" % contract,
           "        //   script>)), with its dependencies, exactly as the project deploys it; or",
           "        // TODO fork: vm.createSelectFork(vm.envString(\"<RPC env var>\"), <pinned block>);",
           "        //   target = <in-scope deployed address, from the program page>.",
           "        // No address is filled in on purpose.",
           '        require(target.code.length > 0, "TODO: deploy or fork the target in setUp");',
           "        address[] memory system = new address[](0); // TODO: tokens, oracles, routers",
           "        handler = new %s(target, system);" % handler,
           "        targetContract(address(handler));",
           "        bytes4[] memory selectors = new bytes4[](%d);" % len(functions)]
    if fork is not None:
        require_line = '        require(target.code.length > 0, "TODO: deploy or fork the target in setUp");'
        at = out.index(require_line)
        out[at:at] = [
            '        vm.createSelectFork(vm.envString("%s"), %d);'
            % (fork["rpc_env"], fork["block"]),
            '        target = %s;' % fork["address"],
        ]
    if preset == "erc4626-direct-custody":
        before_contract = out.index("contract %sInvariants is StdInvariant, Test {" % contract)
        out[before_contract:before_contract] = [
            "interface IBPDirectCustodyVault {",
            "    function asset() external view returns (address);",
            "    function totalAssets() external view returns (uint256);",
            "}",
            "interface IBPCustodyToken {",
            "    function balanceOf(address) external view returns (uint256);",
            "}", "",
        ]
    for i, fn in enumerate(functions):
        out.append("        selectors[%d] = %s.%s.selector;" % (i, handler, fn["handler"]))
    out += ["        targetSelector(FuzzSelector({addr: address(handler), selectors: selectors}));",
            "    }", ""]
    props = properties or ([] if preset else [{"name": "todo_property",
                            "text": "no INVARIANT: line was supplied; write at least one"}])
    for prop in props:
        out += ["    /// %s" % _sol_string(prop["text"]),
                "    function invariant_%s() public {" % prop["name"],
                '        assertTrue(false, "TODO: write the property: %s");' % _sol_string(prop["text"]),
                "    }", ""]
    if preset == "erc4626-direct-custody":
        # NOT universal: only for a reviewer-confirmed direct-custody vault
        # with no lending/strategies, fee-on-transfer or rebasing token.
        out += [
            "    /// ONLY when totalAssets must be fully backed by the vault's own asset balance.",
            "    function invariant_directCustodyBacking() public view {",
            "        IBPDirectCustodyVault v = IBPDirectCustodyVault(target);",
            "        uint256 claim = v.totalAssets();",
            "        uint256 backing = IBPCustodyToken(v.asset()).balanceOf(target);",
            '        assertLe(claim, backing, "direct custody backing violated");',
            "    }", "",
        ]
    out += ["    function invariant_callSummary() public view {",
            "        handler.callSummary();",
            "    }"]
    if framework == "medusa":
        out += ["",
                "    // ---- Medusa / Echidna -------------------------------------------------",
                "    // These fuzzers call property_* functions and treat `false` as a break. They",
                "    // do not run setUp: deploy in a constructor and point --target-contracts at",
                "    // this contract (or the handler). Same rule: each returns false until written."]
        for prop in props:
            out += ["    function property_%s() public returns (bool) {" % prop["name"],
                    "        // TODO: write the property: %s" % _sol_string(prop["text"]),
                    "        return false;",
                    "    }"]
    out += ["}", ""]
    return "\n".join(out)


def source_backed_properties(spec):
    """Import independently authored property proposals, never the mutation bank.

    The harness still emits deliberately failing property stubs: source
    intent is not silently translated into a passing executable assertion.
    """
    import importlib.util
    script = SCRIPTS / "mutation_lab.py"
    loader = importlib.util.spec_from_file_location("bp_harness_property_schema", script)
    module = importlib.util.module_from_spec(loader)
    loader.exec_module(module)
    module._properties(spec)
    found = []
    for row in spec["rules"]:
        ident = row["id"]
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,40}", ident):
            raise ValueError("Solidity invariant requires a safe short identifier")
        src = row["provenance"]
        found.append({"name": ident,
                      "text": "INDEPENDENT RULE " + ident + " [basis " +
                              src["tier"] + "; source " + src["source_kind"] +
                              "/" + src["source_ref"] +
                              "]: implement the independently verified exact "
                              "assertion and appropriate negative control"})
    return found


def parse_properties(text):
    """`INVARIANT: [name:] text` lines of model.md -> [{name, text}] with unique identifiers."""
    found, used = [], set()
    for line in text.splitlines():
        stripped = line.strip().lstrip("-* ").strip()
        if not stripped.startswith("INVARIANT:"):
            continue
        body = stripped[len("INVARIANT:"):].strip()
        if not body:
            continue
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]{0,40})\s*:\s*(.+)$", body)
        if m:
            name, body = m.group(1), m.group(2).strip()
        else:
            words = re.findall(r"[A-Za-z0-9]+", body)[:6]
            name = "_".join(w.lower() for w in words) or "property"
            if name[0].isdigit():
                name = "p_" + name
        base, n = name, 2
        while name in used:
            name = "%s_%d" % (base, n)
            n += 1
        used.add(name)
        found.append({"name": name, "text": body})
    return found


def _abi_entries(data, origin):
    """[(contract, abi entries, origin)] from an artifact, a bare ABI or a semantic graph."""
    if isinstance(data, dict) and isinstance(data.get("symbols"), list):
        grouped = {}
        for s in data["symbols"]:
            if not isinstance(s, dict) or s.get("language") != "solidity":
                continue
            if not s.get("contract_deployable") or s.get("function_kind") not in ("function", None):
                continue
            if not s.get("entry") or s.get("visibility") not in ("external", "public"):
                continue
            contract = str(s.get("contract", ""))
            name = str(s.get("name", "")).split(".", 1)[-1]
            types = s.get("abi_parameter_types")
            entry = {"type": "function", "name": name,
                     "stateMutability": s.get("state_mutability", "nonpayable"),
                     "inputs": None if types is None else [{"type": t, "name": ""} for t in types]}
            grouped.setdefault(contract, []).append(entry)
        return [(c, entries, origin) for c, entries in sorted(grouped.items())]
    if isinstance(data, dict) and isinstance(data.get("abi"), list):
        name = data.get("contractName") or Path(origin).stem
        return [(str(name), data["abi"], origin)]
    if isinstance(data, list):
        return [(Path(origin).stem, data, origin)]
    raise ValueError("%s: neither an artifact with an \"abi\" list nor a semantic-graph.json"
                     % origin)


def _plan_contract(contract, entries, origin):
    included, skipped, seen, names = [], [], set(), {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        kind = entry.get("type", "function")
        name = str(entry.get("name", ""))
        if kind in ("fallback", "receive"):
            skipped.append({"contract": contract, "signature": kind, "reason":
                            "%s: not generated, add a raw-call handler by hand" % kind})
            continue
        if kind != "function":
            continue
        inputs = entry.get("inputs")
        types = None if inputs is None else [str((i or {}).get("type", "?")) for i in inputs]
        signature = "%s(%s)" % (name, "?" if types is None else ",".join(map(_canonical, types)))
        if signature in seen:
            continue
        seen.add(signature)
        mutability = entry.get("stateMutability") or (
            "view" if entry.get("constant") else "payable" if entry.get("payable") else "nonpayable")
        reason = None
        if not IDENT.match(name):
            reason = "invalid identifier: function name is not a plain Solidity identifier"
        elif mutability in ("view", "pure"):
            reason = "view: %s functions cannot change state" % mutability
        elif mutability == "payable":
            reason = "payable-unhandled: value transfer needs funded actors; write it by hand"
        elif types is None:
            reason = "unsupported type: parameter types unknown in the source graph"
        else:
            for t in types:
                kind_, detail = classify(t)
                if kind_ is None:
                    reason = detail
                    break
        if reason:
            skipped.append({"contract": contract, "signature": signature, "reason": reason})
            continue
        pnames = []
        for i, item in enumerate(inputs):
            pname = str((item or {}).get("name") or "")
            pnames.append(pname if IDENT.match(pname) and len(pname) <= 32 else "")
        count = names.get(name, 0)
        names[name] = count + 1
        handler = "call_" + name + ("_%d" % (count + 1) if count else "")
        included.append({"contract": contract, "name": name, "handler": handler,
                         "signature": signature, "selector": _selector(signature),
                         "types": [_canonical(t) for t in types], "param_names": pnames})
    return included, skipped


def require_private_output(out, repo=None):
    """Private output never lives inside the target checkout or the skill package."""
    out = Path(out).expanduser().resolve()
    for root in [SKILL_ROOT] + ([Path(repo).expanduser().resolve()] if repo else []):
        if out == root or root in out.parents:
            raise ValueError("--out-dir must be outside the target checkout and skill package")
    return out


def generate(abi_sources, out_dir, contracts=None, actors=3, properties=None,
             framework="foundry", repo=None, preset=None, fork=None,
             confirm_direct_custody=False, property_spec=None):
    if framework not in ("foundry", "medusa"):
        raise ValueError("framework must be foundry or medusa")
    if preset not in (None, "erc4626-direct-custody"):
        raise ValueError("unknown invariant property preset")
    if preset and not confirm_direct_custody:
        raise ValueError("property preset requires --confirm-direct-custody assumptions")
    if preset and framework != "foundry":
        raise ValueError("automated ERC4626 custody preset currently supports Foundry only")
    if fork is not None:
        if not isinstance(fork, dict) or not re.fullmatch(r"0x[0-9a-fA-F]{40}", str(fork.get("address", ""))):
            raise ValueError("fork target address must be 20-byte hex")
        if type(fork.get("block")) is not int or fork["block"] < 1:
            raise ValueError("fork block must be a pinned positive integer")
        if not re.fullmatch(r"[A-Z_][A-Z0-9_]{0,63}", str(fork.get("rpc_env", ""))):
            raise ValueError("fork RPC environment variable must be a safe uppercase name")
    if preset and fork is None:
        raise ValueError("automated custody preset requires pinned --target-address/--fork-block/--rpc-env")
    actors = int(actors)
    if not 1 <= actors <= 32:
        raise ValueError("actors must be between 1 and 32")
    dest = require_private_output(out_dir, repo)
    found = []
    for source in abi_sources:
        if isinstance(source, (dict, list)):
            found += _abi_entries(source, "<inline>")
        else:
            path = Path(source)
            found += _abi_entries(json.loads(path.read_text(encoding="utf-8")), str(path))
    wanted = set(contracts or [])
    plan = {"schema_version": 1, "framework": framework, "actors": actors, "contracts": [],
            "functions_included": [], "functions_skipped": [], "contracts_skipped": [],
            "properties": list(properties or []), "files": [], "notice": NOTICE,
            "property_preset": preset,
            "property_provenance": ([{"id": rule["id"], **rule["provenance"]}
                                    for rule in property_spec["rules"]]
                                   if property_spec is not None else []),
            "mutation_bank_read": False,
            "property_author_independence": (
                "OPERATOR_ASSERTED_NOT_VERIFIED" if property_spec is not None
                else "not-asserted"),
            "fork_block": fork["block"] if fork else None,
            "direct_custody_assumptions_operator_confirmed": bool(preset and confirm_direct_custody)}
    writes = {}
    for contract, entries, origin in found:
        if wanted and contract not in wanted:
            continue
        if not IDENT.match(contract):
            plan["contracts_skipped"].append({"contract": contract[:80], "source": origin,
                                              "reason": "invalid identifier"})
            continue
        if preset == "erc4626-direct-custody":
            getters = {e.get("name"): e for e in entries if isinstance(e, dict)
                       and e.get("type") == "function"
                       and e.get("name") in ("asset", "totalAssets")
                       and e.get("inputs") == []}
            if set(getters) != {"asset", "totalAssets"} or any(
                    getters[n].get("stateMutability") not in ("view", "pure")
                    for n in ("asset", "totalAssets")):
                raise ValueError("custody preset requires view asset() and totalAssets() ABI getters")
            if [x.get("type") for x in getters["asset"].get("outputs", [])] != ["address"]:
                raise ValueError("asset() must return address for custody preset")
            if [x.get("type") for x in getters["totalAssets"].get("outputs", [])] != ["uint256"]:
                raise ValueError("totalAssets() must return uint256 for custody preset")
        included, skipped = _plan_contract(contract, entries, origin)
        plan["functions_skipped"] += skipped
        if not included:
            plan["contracts_skipped"].append({"contract": contract, "source": origin,
                                              "reason": "no state-changing function to drive"})
            continue
        handler_file, inv_file = contract + "Handler.sol", contract + "Invariants.t.sol"
        writes[handler_file] = render_handler(contract, included, actors)
        writes[inv_file] = render_invariants(contract, included, plan["properties"], framework,
                                              preset=preset, fork=fork)
        plan["contracts"].append({"name": contract, "source": origin, "handler": handler_file,
                                  "invariants": inv_file, "functions": len(included)})
        plan["functions_included"] += [{k: fn[k] for k in ("contract", "signature", "selector",
                                                           "handler")} for fn in included]
    missing = sorted(wanted - {c for c, _, _ in found})
    if missing:
        plan["contracts_not_found"] = missing
    if not writes:
        raise ValueError("no contract with a state-changing function to drive; see the skip "
                         "reasons: " + json.dumps(plan["functions_skipped"][:5]))
    existing = [n for n in list(writes) + ["harness-plan.json"] if (dest / n).exists()]
    if existing:
        raise ValueError("refusing to overwrite existing harness files (written properties "
                         "would be lost): " + ", ".join(existing))
    dest.mkdir(parents=True, exist_ok=True)
    for name, text in writes.items():
        (dest / name).write_text(text, encoding="utf-8")
        plan["files"].append(str(dest / name))
    plan["files"].append(str(dest / "harness-plan.json"))
    (dest / "harness-plan.json").write_text(json.dumps(plan, ensure_ascii=False, indent=2) + "\n",
                                            encoding="utf-8")
    return plan


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--artifact", action="append", default=[],
                   help="Foundry out/<X>.sol/<X>.json or Hardhat artifact; repeatable")
    p.add_argument("--semantic-graph", help="<run>/semantic-graph.json from impact-plan")
    p.add_argument("--contract", action="append", help="only these contracts; repeatable")
    p.add_argument("--actors", type=int, default=3)
    p.add_argument("--model", help="<run>/model.md; `INVARIANT:` lines become property stubs")
    p.add_argument("--property-spec", help="source-backed independently authored JSON proposals; not mutation bank")
    p.add_argument("--out-dir", required=True, help="private directory outside the checkout")
    p.add_argument("--repo", help="target checkout, so --out-dir can be refused inside it")
    p.add_argument("--framework", choices=("foundry", "medusa"), default="foundry")
    p.add_argument("--property-preset", choices=("erc4626-direct-custody",))
    p.add_argument("--confirm-direct-custody", action="store_true",
                   help="operator confirms no strategies, rebasing, fee-on-transfer or external reserves")
    p.add_argument("--target-address", help="explicit pinned target address, written into local harness")
    p.add_argument("--fork-block", type=int)
    p.add_argument("--rpc-env", help="uppercase environment variable containing read-only fork RPC URL")
    a = p.parse_args(argv)
    sources = list(a.artifact) + ([a.semantic_graph] if a.semantic_graph else [])
    if not sources:
        p.error("give at least one --artifact or --semantic-graph")
    try:
        if a.model and a.property_spec:
            raise ValueError("--model and --property-spec cannot be mixed")
        intent = (json.loads(Path(a.property_spec).read_text(encoding="utf-8"))
                  if a.property_spec else None)
        props = (source_backed_properties(intent) if intent is not None else
                 parse_properties(Path(a.model).read_text(encoding="utf-8"))
                 if a.model else [])
        fork = None
        if a.target_address or a.fork_block or a.rpc_env:
            if not (a.target_address and a.fork_block and a.rpc_env):
                raise ValueError("target-address, fork-block and rpc-env must be supplied together")
            fork = {"address": a.target_address, "block": a.fork_block, "rpc_env": a.rpc_env}
        plan = generate(sources, a.out_dir, a.contract, a.actors, props, a.framework, a.repo,
                        preset=a.property_preset, fork=fork,
                        confirm_direct_custody=a.confirm_direct_custody,
                        property_spec=intent)
    except (OSError, ValueError) as exc:
        p.error(str(exc))
    print(json.dumps({"out_dir": str(Path(a.out_dir).resolve()),
                      "contracts": [c["name"] for c in plan["contracts"]],
                      "functions_included": len(plan["functions_included"]),
                      "functions_skipped": len(plan["functions_skipped"]),
                      "properties": len(plan["properties"]), "notice": plan["notice"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
