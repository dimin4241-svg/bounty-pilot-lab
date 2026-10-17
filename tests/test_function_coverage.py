"""Tests for guard extraction, call sinks, odd-one-out leads, function coverage and the
coverage-floor directory rule. Solidity inputs are hand-built solc compact-AST fixtures."""
import contextlib
import importlib.util
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills/bounty-pilot/scripts"


def module(name):
    spec = importlib.util.spec_from_file_location("test_bp_fc_" + name,
                                                  SCRIPTS / (name + ".py"))
    imported = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(imported)
    return imported


semantic = module("semantic_graph")
impact = module("impact_paths")
odd = module("odd_one_out")
bounty = module("bounty")

# solc gives magic names negative declaration ids.
MSG, TX, BLOCK, REQUIRE, REVERT, SELFDESTRUCT, THIS, SUPER = -15, -26, -4, -18, -19, -21, -28, -25


class Ast:
    """Builds solc compact-AST nodes with unique ids."""

    def __init__(self):
        self.next_id = 5000

    def nid(self):
        self.next_id += 1
        return self.next_id

    def ident(self, name, ref=None, type_string=None):
        node = {"nodeType": "Identifier", "id": self.nid(), "name": name,
                "referencedDeclaration": ref}
        if type_string:
            node["typeDescriptions"] = {"typeString": type_string}
        return node

    def member(self, expr, name, ref=None):
        return {"nodeType": "MemberAccess", "id": self.nid(), "expression": expr,
                "memberName": name, "referencedDeclaration": ref}

    def call(self, expr, *args, kind="functionCall"):
        return {"nodeType": "FunctionCall", "id": self.nid(), "kind": kind,
                "expression": expr, "arguments": list(args), "src": "%d:1:0" % self.nid()}

    def options(self, expr, **values):
        return {"nodeType": "FunctionCallOptions", "id": self.nid(), "expression": expr,
                "names": list(values), "options": list(values.values())}

    def lit(self, value="", kind="string"):
        return {"nodeType": "Literal", "id": self.nid(), "kind": kind, "value": value,
                "hexValue": value.encode().hex() if isinstance(value, str) else ""}

    def binop(self, left, op, right):
        return {"nodeType": "BinaryOperation", "id": self.nid(), "operator": op,
                "leftExpression": left, "rightExpression": right}

    def unop(self, op, sub):
        return {"nodeType": "UnaryOperation", "id": self.nid(), "operator": op,
                "subExpression": sub, "prefix": True}

    def index(self, base, idx):
        return {"nodeType": "IndexAccess", "id": self.nid(), "baseExpression": base,
                "indexExpression": idx}

    def stmt(self, expr):
        return {"nodeType": "ExpressionStatement", "id": self.nid(), "expression": expr}

    def assign(self, lhs, rhs, op="="):
        return self.stmt({"nodeType": "Assignment", "id": self.nid(), "operator": op,
                          "leftHandSide": lhs, "rightHandSide": rhs})

    def msg_sender(self):
        return self.member(self.ident("msg", MSG), "sender")

    def require(self, cond):
        return self.stmt(self.call(self.ident("require", REQUIRE), cond))

    def if_revert(self, cond, error="Unauthorized"):
        return {"nodeType": "IfStatement", "id": self.nid(), "condition": cond,
                "trueBody": {"nodeType": "Block", "id": self.nid(), "statements": [
                    {"nodeType": "RevertStatement", "id": self.nid(),
                     "errorCall": self.call(self.ident(error, self.nid()))}]}}

    def param(self, ident, name):
        return {"nodeType": "VariableDeclaration", "id": ident, "name": name,
                "stateVariable": False, "storageLocation": "default"}

    def var(self, ident, name, mutability="mutable"):
        return {"nodeType": "VariableDeclaration", "id": ident, "name": name,
                "stateVariable": True, "mutability": mutability,
                "constant": mutability == "constant"}

    def mod(self, name, ref):
        return {"nodeType": "ModifierInvocation", "id": self.nid(), "kind": "modifierInvocation",
                "modifierName": {"nodeType": "IdentifierPath", "id": self.nid(), "name": name,
                                 "referencedDeclaration": ref}}

    def modifier(self, ident, name, statements):
        return {"nodeType": "ModifierDefinition", "id": ident, "name": name,
                "parameters": {"nodeType": "ParameterList", "parameters": []},
                "body": {"nodeType": "Block", "id": self.nid(), "statements": list(statements) + [
                    {"nodeType": "PlaceholderStatement", "id": self.nid()}]}}

    def func(self, ident, name, statements=(), visibility="external", modifiers=(),
             params=(), kind="function", mutability="nonpayable", implemented=True,
             base_functions=()):
        node = {"nodeType": "FunctionDefinition", "id": ident, "name": name, "kind": kind,
                "visibility": visibility, "stateMutability": mutability,
                "implemented": implemented, "virtual": False, "modifiers": list(modifiers),
                "baseFunctions": list(base_functions), "src": "%d:10:0" % ident,
                "parameters": {"nodeType": "ParameterList", "id": self.nid(),
                               "parameters": list(params)},
                "returnParameters": {"nodeType": "ParameterList", "id": self.nid(),
                                     "parameters": []}}
        if implemented:
            node["body"] = {"nodeType": "Block", "id": self.nid(), "statements": list(statements)}
        return node

    @staticmethod
    def contract(ident, name, nodes, kind="contract", bases=()):
        return {"nodeType": "ContractDefinition", "id": ident, "name": name,
                "contractKind": kind, "linearizedBaseContracts": [ident] + list(bases),
                "nodes": list(nodes)}

    @staticmethod
    def unit(*contracts):
        return {"nodeType": "SourceUnit", "nodes": list(contracts)}


def vault_fixture():
    """src/Vault.sol: VaultBase (abstract) <- Vault, plus an Address library and an interface.

    State ids 10-29, modifiers 50-59, functions 100-199. Ids are referenced by hand below.
    """
    a = Ast()
    st = {name: ident for ident, name in (
        (10, "owner"), (11, "paused"), (12, "balances"), (13, "totalSupply"), (14, "debt"),
        (15, "totalDebt"), (16, "locked"), (17, "WETH"), (18, "router"), (19, "config"),
        (20, "totalDeposits"), (21, "deadline"), (22, "roles"))}

    def s(name):
        return a.ident(name, st[name])

    address_lib = a.contract(300, "Address", [
        a.func(301, "functionCall", [], visibility="internal",
               params=[a.param(302, "target"), a.param(303, "data")]),
    ], kind="library")
    permit_iface = a.contract(310, "IERC20Permit", [
        a.func(311, "permit", implemented=False),
        a.func(312, "transferFrom", implemented=False),
    ], kind="interface")
    base = a.contract(200, "VaultBase", [
        a.var(10, "owner"), a.var(11, "paused"), a.var(12, "balances"),
        a.var(13, "totalSupply"), a.var(16, "locked"), a.var(20, "totalDeposits"),
        a.var(22, "roles"),
        a.modifier(50, "onlyOwner", [a.require(a.binop(a.msg_sender(), "==", s("owner")))]),
        a.modifier(51, "nonReentrant", [a.if_revert(a.binop(s("locked"), "!=", a.lit("0", "number"))),
                                        a.assign(s("locked"), a.lit("1", "number"))]),
        a.modifier(52, "initializer", []),
        # function _requireNotPaused() internal view { if (paused) revert Paused(); }
        a.func(110, "_requireNotPaused", [a.if_revert(s("paused"), "Paused")],
               visibility="internal", mutability="view"),
        # function deposit(uint a) external nonReentrant { _requireNotPaused();
        #   balances[msg.sender] += a; totalDeposits += a; }
        a.func(111, "deposit", [
            a.stmt(a.call(a.ident("_requireNotPaused", 110))),
            a.assign(a.index(s("balances"), a.msg_sender()), a.ident("a", 113), "+="),
            a.assign(s("totalDeposits"), a.ident("a", 113), "+=")],
            modifiers=[a.mod("nonReentrant", 51)], params=[a.param(113, "a")]),
        # function withdraw(uint a) external nonReentrant {
        #   require(balances[msg.sender] >= a); balances[msg.sender] -= a;
        #   payable(msg.sender).call{value: a}(""); }
        a.func(112, "withdraw", [
            a.require(a.binop(a.index(s("balances"), a.msg_sender()), ">=", a.ident("a", 114))),
            a.assign(a.index(s("balances"), a.msg_sender()), a.ident("a", 114), "-="),
            a.stmt(a.call(a.options(a.member(a.call(a.ident("payable", None), a.msg_sender(),
                                                         kind="typeConversion"), "call"),
                                    value=a.ident("a", 114)), a.lit("")))],
            modifiers=[a.mod("nonReentrant", 51)], params=[a.param(114, "a")]),
        # abstract hook every upgrade path goes through
        a.func(115, "_authorizeUpgrade", visibility="internal", implemented=False),
        a.func(116, "upgradeTo", [a.stmt(a.call(a.ident("_authorizeUpgrade", 115)))],
               params=[a.param(117, "impl")]),
    ], kind="contract", bases=())
    vault = a.contract(201, "Vault", [
        a.var(14, "debt"), a.var(15, "totalDebt"), a.var(17, "WETH", "constant"),
        a.var(18, "router", "immutable"), a.var(19, "config"), a.var(21, "deadline"),
        # constructor() { owner = msg.sender; config = 1; }
        a.func(100, "", [a.assign(s("owner"), a.msg_sender()), a.assign(s("config"), a.lit("1", "number"))],
               visibility="public", kind="constructor"),
        a.func(101, "initialize", [a.assign(s("config"), a.lit("2", "number"))],
               modifiers=[a.mod("initializer", 52)]),
        # function _checkOwner() internal view {
        #   if (owner() != _msgSender()) revert Unauthorized(); }
        a.func(120, "_checkOwner", [a.if_revert(a.binop(a.call(a.ident("ownerOf", 122)), "!=",
                                                         a.call(a.ident("_msgSender", 121))))],
               visibility="internal", mutability="view"),
        a.func(121, "_msgSender", [], visibility="internal", mutability="view"),
        a.func(122, "ownerOf", [a.stmt(s("owner"))], visibility="public", mutability="view"),
        a.func(130, "setConfigA", [a.assign(s("config"), a.ident("v", 131))],
               modifiers=[a.mod("onlyOwner", 50)], params=[a.param(131, "v")]),
        a.func(132, "setConfigB", [a.assign(s("config"), a.ident("v", 133))],
               modifiers=[a.mod("onlyOwner", 50)], params=[a.param(133, "v")]),
        # the odd one out: no owner check at all
        a.func(134, "setConfigC", [a.assign(s("config"), a.ident("v", 135))],
               params=[a.param(135, "v")]),
        # an equivalent inline check under another name: must not be flagged
        a.func(136, "setConfigD", [a.stmt(a.call(a.ident("_checkOwner", 120))),
                                   a.assign(s("config"), a.ident("v", 137))],
               params=[a.param(137, "v")]),
        # paired writes reached through an internal call
        a.func(140, "_increaseDebt", [
            a.assign(a.index(s("debt"), a.ident("u", 141)), a.ident("x", 142), "+="),
            a.assign(s("totalDebt"), a.ident("x", 142), "+=")],
            visibility="internal", params=[a.param(141, "u"), a.param(142, "x")]),
        a.func(143, "borrow", [a.stmt(a.call(a.ident("_increaseDebt", 140), a.msg_sender(),
                                             a.ident("x", 144)))],
               params=[a.param(144, "x")]),
        a.func(145, "repay", [
            a.assign(a.index(s("debt"), a.msg_sender()), a.ident("x", 146), "-="),
            a.assign(s("totalDebt"), a.ident("x", 146), "-=")], params=[a.param(146, "x")]),
        a.func(147, "liquidate", [
            a.assign(a.index(s("debt"), a.ident("u", 148)), a.lit("0", "number"))],
            params=[a.param(148, "u")]),
        # sinks
        a.func(150, "execute", [a.stmt(a.call(a.options(a.member(a.ident("target", 151), "call"),
                                                         value=a.member(a.ident("msg", MSG), "value")),
                                               a.ident("data", 152)))],
               params=[a.param(151, "target"), a.param(152, "data")], mutability="payable"),
        a.func(153, "kill", [a.stmt(a.call(a.ident("selfdestruct", SELFDESTRUCT),
                                           a.call(a.ident("payable", None), s("owner"),
                                                  kind="typeConversion")))],
               modifiers=[a.mod("onlyOwner", 50)]),
        a.func(154, "multicall", [a.stmt(a.call(a.member(
            a.call(a.ident("address", None), a.ident("this", THIS), kind="typeConversion"),
            "delegatecall"), a.index(a.ident("data", 155), a.lit("0", "number"))))],
            params=[a.param(155, "data")]),
        a.func(156, "permitAndSwap", [
            a.stmt(a.call(a.member(a.call(a.ident("IERC20Permit", 310), s("router"),
                                          kind="typeConversion"), "permit", 311),
                          a.ident("holder", 157), a.ident("amount", 158))),
            a.stmt(a.call(a.member(a.call(a.ident("IERC20Permit", 310), s("router"),
                                          kind="typeConversion"), "transferFrom", 312),
                          a.ident("holder", 157), a.call(a.ident("address", None),
                                                         a.ident("this", THIS),
                                                         kind="typeConversion"),
                          a.ident("amount", 158)))],
            params=[a.param(157, "holder"), a.param(158, "amount")]),
        a.func(159, "pokeWeth", [a.stmt(a.call(a.member(s("WETH"), "call"),
                                               a.ident("d", 160)))],
               params=[a.param(160, "d")]),
        a.func(161, "relay", [a.stmt(a.call(a.member(a.ident("Address", 300,
                                                               "type(library Address)"),
                                                     "functionCall", 301),
                                            a.ident("t", 162), a.ident("d", 163)))],
               params=[a.param(162, "t"), a.param(163, "d")]),
        # guard tokens: tx.origin, block.timestamp, a role check, a state flag
        a.func(170, "guarded", [
            a.require(a.binop(a.member(a.ident("tx", TX), "origin"), "==", a.msg_sender())),
            a.if_revert(a.binop(a.member(a.ident("block", BLOCK), "timestamp"), ">", s("deadline")),
                        "Expired"),
            a.require(a.call(a.ident("hasRole", 172), a.lit("0x01", "number"), a.msg_sender()))]),
        a.func(172, "hasRole", [a.stmt(s("roles"))], visibility="public", mutability="view"),
        # mutual recursion: guard closure must terminate and share tokens
        a.func(173, "_ping", [a.require(s("paused")), a.stmt(a.call(a.ident("_pong", 174)))],
               visibility="internal"),
        a.func(174, "_pong", [a.require(a.binop(a.msg_sender(), "==", s("owner"))),
                              a.stmt(a.call(a.ident("_ping", 173)))],
               visibility="internal"),
        a.func(175, "pingPong", [a.stmt(a.call(a.ident("_ping", 173)))]),
        # the override every upgrade reaches
        a.func(176, "_authorizeUpgrade", [], visibility="internal",
               modifiers=[a.mod("onlyOwner", 50)], base_functions=[115]),
        a.func(177, "status", [a.stmt(s("config"))], mutability="view"),
        # require(IERC20(router).transferFrom(from, this, x)): a success check, not a guard
        a.func(178, "pull", [a.require(a.call(a.member(
            a.call(a.ident("IERC20Permit", 310), s("router"), kind="typeConversion"),
            "transferFrom", 312), a.ident("from", 179), a.ident("this", THIS),
            a.ident("x", 180)))], params=[a.param(179, "from"), a.param(180, "x")]),
    ], bases=[200])
    return {"output": {"sources": {"src/Vault.sol": {
        "ast": Ast.unit(address_lib, permit_iface, base, vault)}}}}


def write_fixture(folder):
    path = Path(folder) / "build-info.json"
    path.write_text(json.dumps(vault_fixture()), encoding="utf-8")
    return path


def graph_of(folder):
    return semantic.build(semantic.solidity_symbols(semantic.load_solc(write_fixture(folder))))


def by_name(graph):
    return {s["name"]: s for s in graph["symbols"]}


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.graph = graph_of(self.temp.name)
        self.sym = by_name(self.graph)

    def test_existing_fields_stay_and_new_ones_are_added(self):
        deposit = self.sym["VaultBase.deposit"]
        for field in ("id", "path", "name", "declaration", "language", "implemented", "entry",
                      "visibility", "line", "source_span", "modifiers_unverified", "writes",
                      "reads", "calls", "sinks", "source"):
            self.assertIn(field, deposit)
        for field in ("guards", "internal_calls", "writes_transitive", "writes_via_modifiers",
                      "sink_details", "contract", "contract_kind", "function_kind",
                      "state_mutability", "inherited_by"):
            self.assertIn(field, deposit)
        self.assertEqual(deposit["modifiers_unverified"], ["nonReentrant"])

    def test_modifier_name_and_its_condition_are_guards(self):
        guards = self.sym["Vault.setConfigA"]["guards"]
        self.assertIn("onlyOwner", guards)
        self.assertIn("msg.sender", guards)
        self.assertIn("src/Vault.sol:owner", guards)

    def test_internal_call_guards_are_inherited_through_the_chain(self):
        deposit = self.sym["VaultBase.deposit"]["guards"]
        self.assertIn("src/Vault.sol:paused", deposit)       # _requireNotPaused()
        self.assertIn("nonReentrant", deposit)
        self.assertIn("src/Vault.sol:locked", deposit)       # the modifier's if-revert
        inline = self.sym["Vault.setConfigD"]["guards"]
        # _checkOwner(): ownerOf() is named, its read of owner joins, _msgSender is msg.sender
        self.assertIn("ownerOf", inline)
        self.assertIn("src/Vault.sol:owner", inline)
        self.assertIn("msg.sender", inline)
        self.assertNotIn("_msgSender", inline)

    def test_env_role_and_state_tokens(self):
        guards = self.sym["Vault.guarded"]["guards"]
        for token in ("tx.origin", "msg.sender", "block.timestamp", "src/Vault.sol:deadline",
                      "hasRole", "src/Vault.sol:roles"):
            self.assertIn(token, guards)

    def test_msg_sender_as_a_mapping_key_is_not_an_identity_check(self):
        guards = self.sym["VaultBase.withdraw"]["guards"]
        self.assertIn("src/Vault.sol:balances", guards)
        self.assertNotIn("msg.sender", guards)

    def test_recursive_internal_calls_terminate_and_share_guards(self):
        guards = self.sym["Vault.pingPong"]["guards"]
        self.assertIn("src/Vault.sol:paused", guards)
        self.assertIn("src/Vault.sol:owner", guards)
        self.assertEqual(self.sym["Vault._ping"]["guards"], self.sym["Vault._pong"]["guards"])

    def test_virtual_internal_call_reaches_the_override_guard(self):
        self.assertIn("onlyOwner", self.sym["VaultBase.upgradeTo"]["guards"])

    def test_a_checked_transfer_is_a_sink_not_a_guard(self):
        pull = self.sym["Vault.pull"]
        self.assertEqual(pull["guards"], [])
        self.assertIn("token-pull", pull["sinks"])

    def test_unguarded_setter_has_no_owner_guard(self):
        self.assertEqual(self.sym["Vault.setConfigC"]["guards"], [])

    def test_writes_follow_internal_calls_and_modifier_writes_are_marked(self):
        borrow = self.sym["Vault.borrow"]
        self.assertEqual(borrow["writes"], [])
        self.assertEqual(borrow["writes_transitive"],
                         ["src/Vault.sol:debt", "src/Vault.sol:totalDebt"])
        self.assertEqual(self.sym["VaultBase.deposit"]["writes_via_modifiers"],
                         ["src/Vault.sol:locked"])

    def test_inherited_functions_name_their_heirs(self):
        self.assertEqual(self.sym["VaultBase.deposit"]["inherited_by"], ["Vault"])
        self.assertEqual(self.sym["VaultBase._authorizeUpgrade"]["inherited_by"], [])

    def test_constructor_is_labelled(self):
        self.assertEqual(self.sym["Vault.constructor"]["function_kind"], "constructor")


class SinkTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.graph = graph_of(self.temp.name)
        self.sym = by_name(self.graph)

    def details(self, name):
        return self.sym[name]["sink_details"]

    def test_arbitrary_call_with_a_parameter_target(self):
        execute = self.sym["Vault.execute"]
        self.assertIn("arbitrary-call", execute["sinks"])
        self.assertIn("asset-movement", execute["sinks"])  # call{value: ...}
        detail = execute["sink_details"][0]
        self.assertEqual((detail["kind"], detail["target_source"], detail["dynamic_target"]),
                         ("low-level-call", "parameter", True))

    def test_selfdestruct_and_its_beneficiary(self):
        kill = self.sym["Vault.kill"]
        self.assertIn("self-destruct", kill["sinks"])
        self.assertEqual(kill["sink_details"][0]["beneficiary_source"], "state")

    def test_multicall_delegatecall_to_this_is_not_arbitrary(self):
        multicall = self.sym["Vault.multicall"]
        self.assertIn("delegatecall", multicall["sinks"])
        self.assertNotIn("arbitrary-call", multicall["sinks"])
        self.assertFalse(multicall["sink_details"][0]["dynamic_target"])

    def test_permit_and_transfer_from_a_parameter(self):
        sym = self.sym["Vault.permitAndSwap"]
        self.assertIn("permit", sym["sinks"])
        self.assertIn("token-pull", sym["sinks"])
        kinds = {d["kind"]: d for d in sym["sink_details"]}
        self.assertEqual(kinds["permit"]["owner_source"], "parameter")
        self.assertEqual(kinds["token-pull"]["from_source"], "parameter")

    def test_constant_target_is_not_dynamic(self):
        poke = self.sym["Vault.pokeWeth"]
        self.assertEqual(poke["sink_details"][0]["target_source"], "constant")
        self.assertFalse(poke["sink_details"][0]["dynamic_target"])
        self.assertEqual([s for s in poke["sinks"] if s in semantic.AST_SINK_FAMILIES],
                         ["low-level-call"])

    def test_eth_send_to_the_caller_is_not_an_arbitrary_call(self):
        withdraw = self.sym["VaultBase.withdraw"]
        self.assertIn("low-level-call", withdraw["sinks"])
        self.assertNotIn("arbitrary-call", withdraw["sinks"])
        self.assertTrue(withdraw["sink_details"][0]["empty_data"])
        self.assertEqual(withdraw["sink_details"][0]["target_source"], "msg.sender")

    def test_address_library_function_call_takes_its_first_argument_as_target(self):
        relay = self.sym["Vault.relay"]
        self.assertEqual(relay["sink_details"][0]["kind"], "address-functioncall")
        self.assertEqual(relay["sink_details"][0]["target_source"], "parameter")
        self.assertIn("arbitrary-call", relay["sinks"])

    def test_name_words_only(self):
        self.assertIn("permit", semantic.classify({"permitAndSwap"}))
        self.assertNotIn("permit", semantic.classify({"isPermitted"}))

    def test_arbitrary_call_with_standing_approvals_ranks_first(self):
        ranked = impact.rank(self.graph)["ranked"]
        top = ranked[0]
        self.assertEqual(top["sink"], self.sym["Vault.execute"]["id"])
        self.assertEqual(top["priority_heuristic"], impact.CLASS_WEIGHTS["arbitrary-call"] + 2)
        self.assertEqual(len(top["priority_reasons"]), 2)
        pull = next(r for r in ranked if r["sink"] == self.sym["Vault.permitAndSwap"]["id"])
        self.assertIn("transferFrom pulls from an address that is not msg.sender",
                      pull["priority_reasons"])
        weth = next(r for r in ranked if r["sink"] == self.sym["Vault.pokeWeth"]["id"])
        self.assertLess(weth["priority_heuristic"], top["priority_heuristic"])


class OddOneOutTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.graph = graph_of(self.temp.name)
        self.report = odd.analyze(self.graph)
        self.leads = self.report["leads"]

    def of(self, kind):
        return [lead for lead in self.leads if lead["kind"] == kind]

    def test_guard_asymmetry_flags_the_unguarded_writer_only(self):
        rows = [r for r in self.of("guard-asymmetry")
                if "src/Vault.sol:config" in r["variables"]]
        flagged = {r["functions"][0]["name"] for r in rows}
        self.assertEqual(flagged, {"Vault.setConfigC"})
        row = rows[0]
        self.assertEqual(row["missing_guards"],
                         ["msg.sender", "onlyOwner", "src/Vault.sol:owner"])
        # what onlyOwner itself checks is named once, through the modifier
        self.assertEqual(row["missing_guards_primary"], ["onlyOwner"])
        self.assertIn("without onlyOwner, which", row["question"])
        self.assertEqual(row["setup_writers_not_compared"],
                         ["Vault.constructor", "Vault.initialize"])
        self.assertIn("setConfigC", row["question"])
        self.assertEqual(row["support"]["of_other_writers"], 3)

    def test_paired_write_omission_flags_liquidate(self):
        rows = self.of("paired-write-omission")
        hit = [r for r in rows if r["variable"] == "src/Vault.sol:debt"]
        self.assertEqual(len(hit), 1)
        self.assertEqual(hit[0]["functions"][0]["name"], "Vault.liquidate")
        self.assertEqual(hit[0]["skipped_partners"], ["src/Vault.sol:totalDebt"])
        self.assertEqual(hit[0]["evidence"]["src/Vault.sol:totalDebt"],
                         ["Vault.borrow", "Vault.repay"])

    def test_sibling_asymmetry_reports_the_differences(self):
        rows = [r for r in self.of("sibling-asymmetry") if r["pair"] == ["deposit", "withdraw"]]
        self.assertEqual(len(rows), 1)
        diff = rows[0]["difference"]
        self.assertIn("src/Vault.sol:paused", diff["guards_only_in_first"])
        self.assertIn("src/Vault.sol:totalDeposits", diff["writes_only_in_first"])
        # the reentrancy lock is a guard, not accounting
        self.assertNotIn("src/Vault.sol:locked", diff["writes_only_in_first"]
                         + diff["writes_only_in_second"])

    def test_every_lead_is_shaped_for_the_hunter(self):
        self.assertTrue(self.leads)
        for lead in self.leads:
            for field in ("id", "kind", "functions", "path", "question"):
                self.assertIn(field, lead)
            self.assertTrue(lead["id"].startswith("ooo-"))
        self.assertEqual(len({lead["id"] for lead in self.leads}), len(self.leads))
        self.assertIn("not a finding", self.report["notice"])
        self.assertEqual(self.report["review_state"], "unreviewed-leads")

    def test_ids_are_stable_across_compilations(self):
        again = odd.analyze(graph_of(self.temp.name))
        self.assertEqual([lead["id"] for lead in again["leads"]],
                         [lead["id"] for lead in self.leads])

    def test_an_old_graph_without_guards_warns_instead_of_failing(self):
        for sym in self.graph["symbols"]:
            sym.pop("guards", None)
        self.assertIn("warning", odd.analyze(self.graph))

    def test_cli_writes_the_file(self):
        graph_file = Path(self.temp.name) / "semantic-graph.json"
        graph_file.write_text(json.dumps(self.graph), encoding="utf-8")
        out = Path(self.temp.name) / "odd-one-out.json"
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(odd.main(["--graph", str(graph_file), "--out", str(out)]), 0)
        self.assertEqual(json.loads(out.read_text())["leads"], self.leads)


def git(repo, *args):
    subprocess.run(["git", "-C", str(repo), *args], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def commit(repo, message="fixture"):
    git(repo, "add", "-A")
    git(repo, "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
        "commit", "-qm", message)


class RunCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.repo = self.base / "repo"
        (self.repo / "src").mkdir(parents=True)
        git(self.repo, "init", "-q")
        (self.repo / "src/Vault.sol").write_text("contract Vault {}\n")
        commit(self.repo)
        self.run = self.base / "run"
        bounty.initialize(self.repo, self.run)

    def coverage(self, *surfaces):
        body = ("# Coverage\n\n| Surface / invariant | Lens | Pass | Experiment | Result |\n"
                "| --- | --- | --- | --- | --- |\n")
        for surface in surfaces:
            body += "| " + surface + " | accounting | 1 | ran | nothing |\n"
        (self.run / "coverage.md").write_text(body, encoding="utf-8")

    def examined(self, data):
        text = data if isinstance(data, str) else json.dumps(data)
        (self.run / "examined.json").write_text(text, encoding="utf-8")


class FunctionCoverageTests(RunCase):
    def setUp(self):
        super().setUp()
        self.plan = bounty.impact_plan(solc=write_fixture(self.base), out=self.run)

    def measure(self, **kwargs):
        return bounty.function_coverage(self.run, **kwargs)

    def examined_names(self):
        return [row["name"] for row in bounty.read_json(self.run / "function-coverage.json")
                ["examined_entry_points"]]

    def test_impact_plan_also_writes_odd_one_out(self):
        self.assertTrue((self.run / "odd-one-out.json").is_file())
        self.assertEqual(self.plan["odd_one_out"], str(self.run / "odd-one-out.json"))
        self.assertGreaterEqual(self.plan["odd_one_out_leads"]["guard-asymmetry"], 1)
        self.assertIn("never findings", self.plan["notice"])

    def test_a_directory_row_and_a_file_row_credit_no_function(self):
        self.coverage("src/", "src/Vault.sol")
        result = self.measure()
        self.assertEqual(result["examined"], 0)
        self.assertEqual(result["state"], "below-floor")
        self.assertGreater(result["entry_points"], 20)
        self.assertIn("src/Vault.sol", result["surfaces_naming_no_function"])
        self.assertEqual(result["view_or_pure_entry_points"], 3)  # ownerOf, hasRole, status

    def test_the_three_forms_match_whole_identifiers(self):
        self.coverage("src/Vault.sol:Vault.execute", "Vault.kill, VaultBase.withdraw(uint256)",
                      "src/Vault.sol:borrow", "Vault.exec", "Vaul.relay", "multicall",
                      "Vault.permitAndSwapX", "lib/Other.sol:repay")
        self.measure()
        # VaultBase is abstract: its withdraw is counted as Vault's, and naming the declaring
        # contract credits the heir that resolves it the same way.
        self.assertEqual(sorted(self.examined_names()),
                         ["Vault.borrow", "Vault.execute", "Vault.kill", "Vault.withdraw"])

    def test_an_heir_names_an_inherited_function(self):
        # The abstract VaultBase is deployed only as Vault: its deposit is Vault's entry point.
        self.coverage("src/Vault.sol:Vault.deposit")
        self.measure()
        self.assertEqual(self.examined_names(), ["Vault.deposit"])

    def test_every_source_credits_and_is_counted(self):
        self.coverage("Vault.execute")
        (self.run / "known-hypotheses.md").write_text(
            "| src/Vault.sol:Vault.kill | selfdestruct | closed | onlyOwner |\n", encoding="utf-8")
        record = bounty.template()
        record.update(id="BP-001", affected_paths=["src/Vault.sol:Vault.relay"])
        bounty.dump(self.run / "findings.json", [record])
        self.examined({"version": 1, "examined": [
            {"surface": "src/Vault.sol:Vault.multicall", "sources": ["r1.md"]},
            {"surface": "src/", "sources": ["r1.md"]}], "not_reached": [
            {"surface": "src/Vault.sol:Vault.liquidate", "why": "ran out of budget",
             "sources": ["r2.md"]},
            {"surface": "Vault.execute", "why": "skipped", "sources": ["r2.md"]}]})
        result = self.measure()
        self.assertEqual(result["examined_by_source"],
                         {"coverage.md": 1, "known-hypotheses.md": 1, "findings.json": 1,
                          "examined.json": 1})
        self.assertEqual(result["examined"], 4)
        self.assertEqual(result["not_reached"],
                         [{"surface": "src/Vault.sol:Vault.liquidate", "why": "ran out of budget",
                           "sources": ["r2.md"], "entry_points": ["Vault.liquidate"]}])

    def test_malformed_examined_json_is_no_credit_and_is_reported(self):
        self.examined("{not json")
        result = self.measure()
        self.assertEqual(result["examined_by_source"]["examined.json"], 0)
        self.assertIn("examined.json", result["unparsed_coverage_files"])
        self.assertIn("warning", result)
        self.examined({"examined": "src/Vault.sol:Vault.execute"})
        self.assertIn("examined.json", self.measure()["unparsed_coverage_files"])

    def test_unexamined_puts_sinks_first_then_state_writers(self):
        result = self.measure()
        tiers = [row["priority_tier"] for row in result["unexamined"]]
        self.assertEqual(tiers, sorted(tiers, key=["value-moving-or-sink", "state-writing",
                                                   "unknown-writes", "no-state-write"].index))
        self.assertEqual(result["unexamined"][0]["name"], "Vault.execute")
        self.assertIn("Vault.setConfigC", [r["name"] for r in result["unexamined"]
                                           if r["priority_tier"] == "state-writing"])
        self.assertEqual(result["unexamined"][-1]["priority_tier"], "no-state-write")

    def test_gate_and_floor(self):
        argv = ["function-coverage", "--run", str(self.run), "--gate"]
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(bounty.main(argv), 1)
        result = json.loads(out.getvalue())
        self.assertEqual(result["min_fraction"], bounty.COVERAGE_FLOOR_DEFAULT)
        everything = [r["name"] for r in bounty.read_json(self.run / "function-coverage.json")
                      ["unexamined"]]
        self.coverage(*everything)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(bounty.main(argv), 0)
        written = bounty.read_json(self.run / "function-coverage.json")
        self.assertEqual(written["examined_fraction"], 1.0)
        self.assertEqual(written["state"], "at-or-above-floor")

    def test_scope_and_test_paths_are_excluded_and_counted(self):
        result = self.measure(scope_prefixes=["contracts"])
        self.assertEqual(result["entry_points"], 0)
        self.assertEqual(result["state"], "no-entry-points")
        self.assertGreater(result["excluded"]["out-of-scope"], 0)

    def test_queue_reports_both_files(self):
        self.measure()
        queue = bounty.lead_queue(self.run)
        self.assertEqual(queue["function_coverage"]["state"], "below-floor")
        self.assertEqual(len(queue["function_coverage"]["unexamined_first"]),
                         bounty.QUEUE_UNEXAMINED_FUNCTIONS)
        self.assertEqual(queue["function_coverage"]["unexamined_first"][0]["name"],
                         "Vault.execute")
        self.assertEqual(queue["odd_one_out"]["state"], "unreviewed-leads")
        self.assertEqual(sum(queue["odd_one_out"]["by_kind"].values()),
                         queue["odd_one_out"]["total"])

    def test_queue_without_either_file(self):
        (self.run / "odd-one-out.json").unlink()
        queue = bounty.lead_queue(self.run)
        self.assertIsNone(queue["function_coverage"])
        self.assertIsNone(queue["odd_one_out"])

    def test_missing_graph_without_repo_is_an_error(self):
        (self.run / "semantic-graph.json").unlink()
        with self.assertRaises(ValueError):
            self.measure()
        with self.assertRaises(ValueError):
            self.measure(graph=str(self.base / "nope.json"))

    def test_cli_is_wired(self):
        args = bounty.build_parser().parse_args(
            ["function-coverage", "--run", "x", "--graph", "g", "--repo", "r", "--scope", "src",
             "--min-fraction", "0.5", "--gate"])
        self.assertEqual((args.run, args.graph, args.repo, args.scope, args.min_fraction,
                          args.gate), ("x", "g", "r", ["src"], 0.5, True))


VYPER = '''# @external def fake(): in a comment
"""
@external
def docstring_fake():
"""
interface Token:
    def transfer(to: address, amount: uint256) -> bool: nonpayable

@deploy
def __init__():
    pass

@external
@nonreentrant
def withdraw(amount: uint256):
    pass

@internal
def _helper():
    pass

@view
@external
def balance() -> uint256:
    return 0
'''

ANCHOR = '''use anchor_lang::prelude::*;
declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS");

#[program]
pub mod vault {
    use super::*;
    // pub fn commented_out() {}
    pub fn deposit(ctx: Context<Deposit>, seed: [u8; 32], amount: u64) -> Result<()> {
        let s = "pub fn in_a_string() {";
        Ok(())
    }
    pub fn withdraw<'info>(ctx: Context<'_, '_, '_, 'info, Withdraw<'info>>) -> Result<()> {
        let c = '{';
        Ok(())
    }
}

fn helper() {}

#[derive(Accounts)]
pub struct Deposit<'info> {
    pub user: Signer<'info>,
}
'''

NATIVE = '''use solana_program::entrypoint;
entrypoint!(process_instruction);

pub fn process_instruction(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    Processor::process(program_id, accounts, data)
}

pub struct Processor;
impl Processor {
    pub fn process_deposit(accounts: &[AccountInfo]) -> ProgramResult { Ok(()) }
    fn process_private(accounts: &[AccountInfo]) -> ProgramResult { Ok(()) }
    pub fn unrelated() {}
}
'''

RELAYER = '''pub fn process_message(m: &str) {}
'''

MOVE = '''module 0x1::vault {
    use std::signer;
    public entry fun deposit(account: &signer, amount: u64) acquires Vault { }
    public fun balance(addr: address): u64 { 0 }
    public(friend) fun internal_move(): u64 { 0 }
    public(package) entry fun admin_entry() { }
    fun private_helper() { }
    entry fun claim(account: &signer) { }
}
'''

CAIRO = '''#[starknet::contract]
mod Vault {
    #[storage]
    struct Storage { total: u256 }

    #[abi(embed_v0)]
    impl VaultImpl of super::IVault<ContractState> {
        fn deposit(ref self: ContractState, amount: u256) { }
        fn total(self: @ContractState) -> u256 { 0 }
    }

    #[external(v0)]
    fn rescue(ref self: ContractState) { }

    #[generate_trait]
    impl InternalImpl of InternalTrait {
        fn _internal(ref self: ContractState) { }
    }
}
'''

SOLIDITY = '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
interface IPool { function swap(uint256 a) external; }
/* function commented(uint a) external {} */
abstract contract Pool is IPool {
    uint256[] public reserves;
    constructor() {}
    function swap(uint256 a) external override { string memory s = "}{"; }
    function quote(uint256 a) public view returns (uint256) { return a; }
    function _internal() internal {}
    receive() external payable {}
}
library Lib { function helper() internal pure {} }
'''


class LexicalTests(RunCase):
    def write(self, files):
        for rel, text in files.items():
            path = self.repo / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        commit(self.repo, "lexical")

    def test_each_stack_yields_its_entry_points_marked_lexical(self):
        self.write({"contracts/Pool.vy": VYPER,
                    "programs/vault/Cargo.toml": "[package]\nname='vault'\n",
                    "programs/vault/src/lib.rs": ANCHOR,
                    "native/Cargo.toml": "[package]\nname='native'\n",
                    "native/src/lib.rs": NATIVE,
                    "relayer/Cargo.toml": "[package]\nname='relayer'\n",
                    "relayer/src/main.rs": RELAYER,
                    "sources/vault.move": MOVE,
                    "cairo/src/vault.cairo": CAIRO,
                    "src/Pool.sol": SOLIDITY})
        result = bounty.function_coverage(self.run, repo=self.repo)
        self.assertEqual(result["source"], "lexical")
        rows = bounty.read_json(self.run / "function-coverage.json")["unexamined"]
        self.assertTrue(all(row["source"] == "lexical" for row in rows))
        found = {(row["path"], row["name"]) for row in rows}
        expected = {
            ("contracts/Pool.vy", "Pool.__init__"), ("contracts/Pool.vy", "Pool.withdraw"),
            ("contracts/Pool.vy", "Pool.balance"),
            ("programs/vault/src/lib.rs", "vault.deposit"),
            ("programs/vault/src/lib.rs", "vault.withdraw"),
            ("native/src/lib.rs", "lib.process_instruction"),
            ("native/src/lib.rs", "Processor.process_deposit"),
            ("sources/vault.move", "vault.deposit"), ("sources/vault.move", "vault.balance"),
            ("sources/vault.move", "vault.admin_entry"), ("sources/vault.move", "vault.claim"),
            ("cairo/src/vault.cairo", "Vault.deposit"), ("cairo/src/vault.cairo", "Vault.total"),
            ("cairo/src/vault.cairo", "Vault.rescue"),
            ("src/Pool.sol", "Pool.constructor"), ("src/Pool.sol", "Pool.swap"),
            ("src/Pool.sol", "Pool.quote"), ("src/Pool.sol", "Pool.receive"),
        }
        self.assertEqual(found, expected)

    def test_lexical_entries_are_credited_by_the_same_rules(self):
        self.write({"sources/vault.move": MOVE})
        self.coverage("sources/vault.move:vault::deposit", "vault.claim", "sources/vault.move")
        result = bounty.function_coverage(self.run, repo=self.repo)
        self.assertEqual(result["examined"], 2)
        self.assertEqual(result["entry_points"], 4)

    def test_lexical_exclusions_are_counted_in_files(self):
        self.write({"contracts/Pool.vy": VYPER, "test/Mock.vy": VYPER,
                    "lib/dep/Dep.vy": VYPER})
        result = bounty.function_coverage(self.run, repo=self.repo, scope_prefixes=["contracts"])
        self.assertEqual(result["entry_points"], 3)
        self.assertEqual(result["excluded"], {"lexical-files-out-of-scope": 3})
        result = bounty.function_coverage(self.run, repo=self.repo)
        self.assertEqual(result["excluded"], {"lexical-files-test-or-script": 1,
                                              "lexical-files-vendored": 1})

    def test_graph_and_lexical_combine_for_a_mixed_repository(self):
        self.write({"contracts/Pool.vy": VYPER})
        bounty.impact_plan(solc=write_fixture(self.base), out=self.run)
        result = bounty.function_coverage(self.run, repo=self.repo)
        self.assertEqual(result["source"], "semantic-graph+lexical")
        self.assertEqual(result["lexical_entry_points"], 3)
        rows = bounty.read_json(self.run / "function-coverage.json")["unexamined"]
        self.assertFalse(any(r["source"] == "lexical" and r["path"].endswith(".sol")
                             for r in rows))


class CoverageFloorAdditionsTests(RunCase):
    def setUp(self):
        super().setUp()
        for rel in ("src/Pool.sol", "contracts/Curve.vy", "huff/Router.huff",
                    "sources/vault.move", "test/Vault.t.sol", "lib/oz/ERC20.sol",
                    "programs/vault/src/lib.rs", "relayer/src/main.rs"):
            path = self.repo / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("x\n")
        commit(self.repo, "stacks")

    def floor(self, **kwargs):
        kwargs.setdefault("scope_prefixes", ["src"])
        return bounty.coverage_floor(self.repo, self.run, **kwargs)

    def test_onchain_sources_outside_scope_are_reported_not_gated(self):
        result = self.floor()
        self.assertEqual(result["outside_scope_onchain"],
                         ["contracts/Curve.vy", "huff/Router.huff", "programs/vault/src/lib.rs",
                          "sources/vault.move"])
        self.assertEqual(result["outside_scope_onchain_count"], 4)
        self.assertIn("outside_scope_warning", result)
        self.coverage("src/Vault.sol", "src/Pool.sol")
        argv = ["coverage-floor", "--repo", str(self.repo), "--run", str(self.run),
                "--scope", "src", "--gate"]
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(bounty.main(argv), 0)
        self.assertEqual(self.floor(scope_prefixes=None)["outside_scope_onchain"], [])

    def test_a_directory_row_is_listed_apart_and_a_file_row_still_counts(self):
        self.coverage("src/", "src/Pool.sol:Pool.swap")
        result = self.floor()
        self.assertEqual(result["files_examined"], 1)
        self.assertEqual(result["credited_by_directory_only"], ["src/Vault.sol"])
        self.assertEqual(result["unexamined"], [])
        self.assertEqual(result["examined_fraction"], 0.5)
        self.assertIn("credited_by_directory_only", result["notice"])
        queued = bounty.lead_queue(self.run)["coverage_floor"]
        self.assertEqual(queued["credited_by_directory_only_count"], 1)

    def test_examined_json_credits_the_file_of_each_surface(self):
        self.examined({"version": 1, "examined": [
            {"surface": "src/Pool.sol:Pool.swap", "sources": ["a.md"]}], "not_reached": []})
        result = self.floor()
        self.assertEqual(result["examined_by_source"]["examined.json"], 1)
        self.assertEqual(result["files_examined"], 1)

    def test_malformed_examined_json_is_reported_as_unparsed(self):
        self.examined("[1, 2")
        result = self.floor()
        self.assertEqual(result["unparsed_coverage_files"], ["examined.json"])
        self.assertEqual(result["files_examined"], 0)


if __name__ == "__main__":
    unittest.main()
