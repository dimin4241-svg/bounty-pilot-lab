"""Compiler-AST taint-path leads: helpful source trails, never exploit proofs."""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills/bounty-pilot/scripts"


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    imported = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(imported)
    return imported


semantic = load(SCRIPTS / "semantic_graph.py", "test_bp_taint_semantic_graph")
taint_paths = load(SCRIPTS / "taint_paths.py", "test_bp_taint_paths")
bounty = load(SCRIPTS / "bounty.py", "test_bp_taint_bounty")
_fc = load(ROOT / "tests/test_function_coverage.py", "test_bp_taint_ast_helpers")
Ast = _fc.Ast
git = _fc.git
commit = _fc.commit


def typed(param, type_string):
    return dict(param, typeDescriptions={"typeString": type_string})


def fixture():
    """Representative proxy, token, permit, oracle, and native-value data flows."""
    a = Ast()

    def ref(name, declaration):
        return a.ident(name, declaration)

    def call_sink(target_id, data_id, member="call"):
        return a.stmt(a.call(a.member(ref("target", target_id), member),
                             ref("data", data_id)))

    contract = Ast.contract(300, "Router", [
        a.var(10, "implementation"),
        a.var(11, "owner"),
        a.func(100, "forward", [a.stmt(a.call(ref("_forward", 101),
                                                  ref("target", 102), ref("data", 103)))],
               params=[typed(a.param(102, "target"), "address"),
                       typed(a.param(103, "data"), "bytes calldata")]),
        a.func(101, "_forward", [call_sink(202, 203)], visibility="internal",
               params=[a.param(202, "target"), a.param(203, "data")]),
        a.func(110, "setImplementation", [a.assign(ref("implementation", 10),
                                                     ref("next", 111))],
               params=[a.param(111, "next")]),
        a.func(120, "runUpgrade", [a.stmt(a.call(
            a.member(ref("implementation", 10), "delegatecall"), ref("data", 121)))],
               params=[a.param(121, "data")]),
        a.func(130, "guardedForward", [
            a.require(a.binop(a.msg_sender(), "==", ref("owner", 11))),
            call_sink(131, 132)],
               params=[a.param(131, "target"), a.param(132, "data")]),
        a.func(140, "safe", [a.stmt(ref("value", 141))],
               params=[a.param(141, "value")]),
        a.func(150, "tokenOut", [a.stmt(a.call(
            a.member(a.call(a.ident("IERC20", 400), ref("token", 151),
                            kind="typeConversion"), "transfer", 402),
            ref("to", 152), ref("amount", 153)))],
               params=[a.param(151, "token"), a.param(152, "to"), a.param(153, "amount")]),
        a.func(160, "tokenPull", [a.stmt(a.call(
            a.member(a.call(a.ident("IERC20", 400), ref("token", 161),
                            kind="typeConversion"), "transferFrom", 401),
            ref("from", 162), a.ident("this", -28), ref("amount", 163)))],
               params=[a.param(161, "token"), a.param(162, "from"),
                       a.param(163, "amount")]),
        a.func(170, "permitPull", [a.stmt(a.call(
            a.member(a.call(a.ident("IERC20", 400), ref("token", 171),
                            kind="typeConversion"), "permit", 403),
            ref("owner", 172), a.ident("this", -28), ref("value", 173),
            ref("deadline", 174), ref("v", 175), ref("r", 176), ref("s", 177)))],
               params=[a.param(171, "token"), a.param(172, "owner"),
                       a.param(173, "value"), a.param(174, "deadline"),
                       a.param(175, "v"), a.param(176, "r"), a.param(177, "s")]),
        a.func(180, "oraclePull", [
            {"nodeType": "VariableDeclarationStatement", "id": a.nid(),
             "assignments": [184],
             "declarations": [{"nodeType": "VariableDeclaration", "id": 184,
                               "name": "price", "stateVariable": False,
                               "storageLocation": "default"}],
             "initialValue": dict(a.call(a.member(
                 a.call(a.ident("IOracle", 420), ref("oracle", 181),
                        kind="typeConversion"), "getPrice", 421), ref("token", 182)),
                 typeDescriptions={"typeString": "uint256"})},
            a.stmt(a.call(a.member(a.call(a.ident("IERC20", 400), ref("token", 182),
                                          kind="typeConversion"), "transferFrom", 401),
                          a.member(a.ident("msg", _fc.MSG), "sender"),
                          a.ident("this", -28),
                          a.binop(ref("price", 184), "*", ref("collateral", 183))))],
               params=[a.param(181, "oracle"), a.param(182, "token"),
                       a.param(183, "collateral")]),
        a.func(185, "oracleDirectPull", [a.stmt(a.call(
            a.member(a.call(a.ident("IERC20", 400), ref("token", 186),
                            kind="typeConversion"), "transferFrom", 401),
            a.member(a.ident("msg", _fc.MSG), "sender"), a.ident("this", -28),
            dict(a.call(a.member(a.call(a.ident("IOracle", 420), ref("oracle", 187),
                                        kind="typeConversion"), "getPrice", 421),
                        ref("token", 186)),
                 typeDescriptions={"typeString": "uint256"})))],
               params=[a.param(186, "token"), a.param(187, "oracle")]),
        a.func(188, "syncOwner", [a.assign(ref("owner", 11), dict(a.call(
            a.member(a.call(a.ident("IAuthority", 430), ref("authority", 189),
                            kind="typeConversion"), "currentOwner", 431)),
            typeDescriptions={"typeString": "address"}))],
               params=[a.param(189, "authority")]),
        a.func(190, "sendNative", [a.stmt(a.call(
            a.options(a.member(a.ident("to", 191, "address payable"), "call"),
                      value=ref("amount", 192)), a.lit("")))],
               params=[typed(a.param(191, "to"), "address payable"),
                       a.param(192, "amount")]),
        a.func(200, "sendNativeValue", [a.stmt(a.call(
            a.options(a.member(a.ident("to", 201, "address payable"), "call"),
                      value=a.member(a.ident("msg", _fc.MSG), "value")), a.lit("")))],
               params=[typed(a.param(201, "to"), "address payable")]),
        a.func(210, "transferNative", [a.stmt(a.call(
            a.member(a.ident("to", 211, "address payable"), "transfer"),
            ref("amount", 212)))],
               params=[typed(a.param(211, "to"), "address payable"),
                       a.param(212, "amount")]),
    ])
    interfaces = [
        Ast.contract(400, "IERC20", [
            a.func(401, "transferFrom", implemented=False),
            a.func(402, "transfer", implemented=False),
            a.func(403, "permit", implemented=False),
        ], kind="interface"),
        Ast.contract(420, "IOracle", [a.func(421, "getPrice", implemented=False)],
                     kind="interface"),
        Ast.contract(430, "IAuthority", [a.func(431, "currentOwner", implemented=False)],
                     kind="interface"),
    ]
    return {"output": {"sources": {"src/Router.sol": {
        "ast": Ast.unit(contract, *interfaces),
        "content": "contract Router {\n" * 80,
    }}}}


class TaintPathTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.solc = self.base / "build-info.json"
        self.solc.write_text(json.dumps(fixture()), encoding="utf-8")
        self.trees = semantic.load_solc(self.solc)
        self.symbols = semantic.solidity_symbols(self.trees)
        self.report = taint_paths.analyze(self.trees, self.symbols, semantic)

    def test_external_inputs_cross_internal_call_to_low_level_call(self):
        rows = [row for row in self.report["leads"]
                if row["sink"]["function"] == "Router._forward"]
        self.assertEqual({(row["source"]["function"], row["source"]["parameter"],
                          row["sink"]["operand"]) for row in rows}, {
            ("Router.forward", "target", "target"),
            ("Router.forward", "data", "calldata[0]"),
        })
        for row in rows:
            self.assertEqual(row["confidence"], "static-taint-lead")
            self.assertIn("call-argument", [edge["kind"] for edge in row["flow"]])

    def test_state_path_connects_separate_entry_points_to_delegatecall(self):
        row = next(row for row in self.report["leads"]
                   if row["source"]["function"] == "Router.setImplementation"
                   and row["sink"]["function"] == "Router.runUpgrade"
                   and row["sink"]["operand"] == "target")
        self.assertTrue(row["crosses_persistent_state"])
        self.assertEqual([edge["kind"] for edge in row["flow"]], ["persistent-state-write"])
        self.assertIn("may require multiple transactions", self.report["notice"])

    def test_guarded_sink_is_still_a_lead_and_unrelated_input_is_not(self):
        guarded = [row for row in self.report["leads"]
                   if row["sink"]["function"] == "Router.guardedForward"]
        self.assertEqual({row["source"]["parameter"] for row in guarded}, {"target", "data"})
        self.assertTrue(all("check guards" in " ".join(row["review"]) for row in guarded))
        self.assertFalse(any(row["source"].get("function") == "Router.safe"
                             for row in self.report["leads"]))

    def test_environment_sources_do_not_cross_between_entry_points(self):
        self.assertFalse(any(row["source"]["kind"] == "msg.sender"
                             and row["source"]["function"] == "Router.guardedForward"
                             and row["sink"]["function"] == "Router._forward"
                             for row in self.report["leads"]))

    def test_token_permit_oracle_and_native_asset_niches(self):
        rows = self.report["leads"]
        expected = {
            ("Router.tokenOut", "token-transfer", "amount", "amount"),
            ("Router.tokenOut", "token-transfer", "to", "to"),
            ("Router.tokenPull", "token-pull", "amount", "amount"),
            ("Router.tokenPull", "token-pull", "from", "from"),
            ("Router.permitPull", "permit", "value", "permit-argument[2]"),
            ("Router.oraclePull", "token-pull", "external return value", "amount"),
            ("Router.oracleDirectPull", "token-pull", "external return value", "amount"),
            ("Router.syncOwner", "sensitive-state-write", "external return value",
             "write:owner"),
            ("Router.sendNative", "low-level-call", "amount", "native-value"),
            ("Router.sendNativeValue", "low-level-call", "msg.value", "native-value"),
            ("Router.transferNative", "native-transfer", "amount", "amount"),
            ("Router.transferNative", "native-transfer", "to", "recipient"),
        }
        observed = {(row["sink"]["function"], row["sink"]["kind"],
                     row["source"].get("parameter", row["source"].get("value")),
                     row["sink"]["operand"]) for row in rows}
        self.assertTrue(expected.issubset(observed), expected - observed)

    def test_impact_plan_writes_the_report_and_lead_count(self):
        run = self.base / "private-run"
        result = bounty.impact_plan(solc=self.solc, out=run)
        written = bounty.read_json(run / "taint-paths.json")
        self.assertEqual(result["taint_leads"], written["lead_count"])
        self.assertGreater(written["lead_count"], 0)
        self.assertEqual(written["status"], "analyzed")

        repo = self.base / "repo"
        (repo / "src").mkdir(parents=True)
        (repo / "src/Router.sol").write_text("contract Router {}\n", encoding="utf-8")
        git(repo, "init", "-q")
        commit(repo)
        bounty.bundle(repo, run, ["impact-first", "seam", "high-impact"])
        for lens in ("impact-first", "seam", "privileged-path"):
            text = (run / "bundles" / (lens + "-bundle.md")).read_text(encoding="utf-8")
            self.assertIn("## Precomputed analysis: taint-paths.json", text)


if __name__ == "__main__":
    unittest.main()
