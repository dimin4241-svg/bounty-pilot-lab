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


def fixture_with_input_sources():
    """A real build-info: solc puts the AST under `output`, the text under `input`."""
    data = fixture()
    sources = data["output"]["sources"]
    inputs = {path: {"content": desc.pop("content")} for path, desc in sources.items()}
    return {"input": {"sources": inputs}, "output": {"sources": sources}}


def spanned(param):
    """solc gives every declaration a `src` span; the shared Ast helper does not."""
    return dict(param, src="%d:12:0" % (param["id"] * 7))


def two_file_fixture():
    """One in-scope sink and one vendored sink, each fed by its own public parameters."""
    a = Ast()

    def forwarder(contract_id, name, func_id, inner_id, target_id, data_id,
                  entry_target, entry_data, second=None):
        body = [a.func(inner_id, "_forward", [a.stmt(a.call(
            a.member(a.ident("target", target_id), "call"), a.ident("data", data_id)))],
            visibility="internal",
            params=[spanned(a.param(target_id, "target")), spanned(a.param(data_id, "data"))]),
            a.func(func_id, name, [a.stmt(a.call(a.ident("_forward", inner_id),
                                                 a.ident("target", entry_target),
                                                 a.ident("data", entry_data)))],
                   params=[typed(spanned(a.param(entry_target, "target")), "address"),
                           typed(spanned(a.param(entry_data, "data")), "bytes calldata")])]
        if second:
            body.append(a.func(second[0], second[1],
                               [a.stmt(a.call(a.ident("_forward", inner_id),
                                              a.ident("target", second[2]),
                                              a.ident("data", second[3])))],
                               params=[typed(spanned(a.param(second[2], "target")), "address"),
                                       typed(spanned(a.param(second[3], "data")), "bytes calldata")]))
        return Ast.contract(contract_id, name.capitalize(), body)

    app = forwarder(600, "appForward", 610, 611, 612, 613, 614, 615,
                    second=(616, "appForwardTwo", 617, 618))
    vendor = forwarder(700, "vendorForward", 710, 711, 712, 713, 714, 715)
    return {"output": {"sources": {
        "src/App.sol": {"ast": Ast.unit(app), "content": "contract App {\n" * 40},
        "vendor/Vendor.sol": {"ast": Ast.unit(vendor),
                              "content": "contract Vendor {\n" * 40}}}}


class BuildInfoSourceTextTests(unittest.TestCase):
    """Line numbers need the source text, and no compiler puts it under `output.sources`."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.solc = Path(self.temp.name) / "build-info.json"

    def test_line_numbers_come_from_build_info_input_sources(self):
        self.solc.write_text(json.dumps(fixture_with_input_sources()), encoding="utf-8")
        trees = semantic.load_solc(self.solc)
        self.assertEqual(set(trees.contents), {"src/Router.sol"})
        report = taint_paths.analyze(trees, semantic.solidity_symbols(trees), semantic)
        self.assertTrue(report["leads"])
        resolved = 0
        for lead in report["leads"]:
            # The shared Ast helper leaves some synthetic nodes without a span; every node that
            # does carry one - as every node solc emits does - must resolve to a line.
            if lead["sink"].get("src"):
                self.assertIsNotNone(lead["sink"]["line"], lead["sink"]["function"])
                resolved += 1
        self.assertGreater(resolved, 0)
        self.assertTrue(any(lead["source"]["line"] for lead in report["leads"]))

    def test_source_spans_resolve_to_lines_too(self):
        self.solc.write_text(json.dumps(two_file_fixture()), encoding="utf-8")
        trees = semantic.load_solc(self.solc)
        report = taint_paths.analyze(trees, semantic.solidity_symbols(trees), semantic)
        self.assertTrue(report["leads"])
        for lead in report["leads"]:
            self.assertIsNotNone(lead["source"]["line"], lead["source"]["function"])

    def test_output_only_compiler_json_still_works_without_line_numbers(self):
        self.solc.write_text(json.dumps(fixture()), encoding="utf-8")
        trees = semantic.load_solc(self.solc)
        report = taint_paths.analyze(trees, semantic.solidity_symbols(trees), semantic)
        self.assertEqual(report["status"], "analyzed")
        self.assertTrue(report["leads"])


class TaintScopeTests(unittest.TestCase):
    """`impact-plan --scope` must reach the taint pass, not only the symbol graph."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.solc = Path(self.temp.name) / "build-info.json"
        self.solc.write_text(json.dumps(two_file_fixture()), encoding="utf-8")
        self.trees = semantic.load_solc(self.solc)
        self.symbols = semantic.solidity_symbols(self.trees)

    def test_lead_with_neither_end_in_scope_is_dropped_and_counted(self):
        report = taint_paths.analyze(self.trees, self.symbols, semantic, scope=["src"])
        self.assertTrue(report["leads"])
        self.assertEqual(report["scope_filter"], ["src"])
        for lead in report["leads"]:
            self.assertFalse(lead["sink"]["path"].startswith("vendor/")
                             and lead["source"]["path"].startswith("vendor/"))
        self.assertGreater(report["leads_dropped_by_scope"], 0)
        self.assertTrue(any(lead["sink"]["scope_role"] == "in-scope"
                            for lead in report["leads"]))

    def test_without_scope_every_lead_is_kept(self):
        report = taint_paths.analyze(self.trees, self.symbols, semantic)
        self.assertEqual(report["leads_dropped_by_scope"], 0)
        self.assertTrue(any(lead["sink"]["path"].startswith("vendor/")
                            for lead in report["leads"]))


class LeadBudgetFairnessTests(unittest.TestCase):
    """The budget is per sink: one sink cannot spend the whole cap."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        solc = Path(self.temp.name) / "build-info.json"
        solc.write_text(json.dumps(two_file_fixture()), encoding="utf-8")
        self.trees = semantic.load_solc(solc)
        self.symbols = semantic.solidity_symbols(self.trees)

    def test_each_sink_is_represented_before_any_sink_gets_a_second_lead(self):
        original = taint_paths.MAX_LEADS
        taint_paths.MAX_LEADS = 2
        try:
            report = taint_paths.analyze(self.trees, self.symbols, semantic)
        finally:
            taint_paths.MAX_LEADS = original
        self.assertEqual(report["lead_count"], 2)
        self.assertEqual(len({(lead["sink"]["function"], lead["sink"]["operand"])
                              for lead in report["leads"]}), 2)
        self.assertEqual({lead["sink"]["path"] for lead in report["leads"]}, {"src/App.sol"})
        self.assertTrue(report["truncated"])
        self.assertEqual(report["sinks_represented"], 2)

    def test_counters_state_what_the_caps_left_out(self):
        report = taint_paths.analyze(self.trees, self.symbols, semantic)
        self.assertGreaterEqual(report["sinks_with_leads"], 2)
        self.assertLessEqual(report["sinks_represented"], report["sinks_with_leads"])
        self.assertEqual(report["limits"]["leads_per_sink"], taint_paths.MAX_LEADS_PER_SINK)
        for lead in report["leads"]:
            self.assertIn(lead["sink"]["scope_role"], ("in-scope", "dependency"))


class LeadOrderTests(unittest.TestCase):
    """Reading order: in-scope before vendored, control takeover before a generic call."""

    @staticmethod
    def row(sink_kind="low-level-call", sink_path="src/App.sol", sink_role="in-scope",
            source_role="in-scope", source_path="src/App.sol"):
        return {"source": {"kind": "external-parameter", "path": source_path,
                           "scope_role": source_role, "line": 1},
                "sink": {"kind": sink_kind, "path": sink_path, "scope_role": sink_role,
                         "line": 1},
                "flow": [], "crosses_persistent_state": False}

    def test_in_scope_sink_outranks_a_vendored_sink(self):
        # `@openzeppelin/...` sorts before `contracts/...`, which is how a vendored SafeERC20 call
        # came to own every row of a real run's reading queue.
        own = self.row(sink_path="contracts/protocol/Vault.sol")
        vendored = self.row(sink_path="@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol",
                            sink_role="dependency")
        self.assertLess(taint_paths._lead_order(own), taint_paths._lead_order(vendored))

    def test_delegatecall_outranks_a_generic_external_call(self):
        self.assertLess(taint_paths._lead_order(self.row(sink_kind="delegatecall")),
                        taint_paths._lead_order(self.row(sink_kind="address-functioncall")))
        self.assertLess(taint_paths._lead_order(self.row(sink_kind="selfdestruct")),
                        taint_paths._lead_order(self.row(sink_kind="low-level-call")))


class StableRefOrderTests(unittest.TestCase):
    """The same build-info must give the same queue twice.

    References are gathered in a set that holds both declaration ids and `env:`/external-return
    strings. A set mixing integers and strings iterates in an order that depends on
    `PYTHONHASHSEED`, and that order reached the flow edges, so a run of the same command on the
    same input wrote a different bounded queue each time.
    """

    def setUp(self):
        self.a = Ast()
        self.expr = self.a.call(
            self.a.member(self.a.ident("abi", -1), "encodePacked", 900),
            self.a.ident("b", 7),
            self.a.member(self.a.ident("msg", _fc.MSG), "sender"),
            self.a.ident("a", 3))

    def test_stable_puts_ids_first_ascending_then_string_keys(self):
        self.assertEqual(taint_paths._stable({"env:b", 7, 3, "env:a", 11}),
                         [3, 7, 11, "env:a", "env:b"])

    def test_variable_refs_returns_an_ordered_sequence_not_a_set(self):
        refs = taint_paths._variable_refs(self.expr, {3, 7}, semantic, {})
        self.assertIsInstance(refs, list)
        self.assertEqual(refs, [3, 7, "env:msg.sender"])

    def test_entry_scoped_environment_keys_keep_that_order(self):
        refs = taint_paths._variable_refs(self.expr, {3, 7}, semantic, {},
                                          ("Entry.g", "Entry.f"))
        self.assertEqual(refs, [3, 7, "env:Entry.f:msg.sender", "env:Entry.g:msg.sender"])


def mock_and_production_fixture():
    """A production sink and a mock sink, both inside one declared scope prefix."""
    a = Ast()

    def forwarder(contract_id, name, func_id, target_id, data_id):
        return Ast.contract(contract_id, name, [
            a.func(func_id, "forward", [a.stmt(a.call(
                a.member(a.ident("target", target_id), "call"), a.ident("data", data_id)))],
                params=[typed(spanned(a.param(target_id, "target")), "address"),
                        typed(spanned(a.param(data_id, "data")), "bytes calldata")])])

    return {"output": {"sources": {
        "src/Vault.sol": {"ast": Ast.unit(forwarder(900, "Vault", 901, 902, 903)),
                          "content": "contract Vault {\n" * 40},
        "src/test/mocks/MockVault.sol": {
            "ast": Ast.unit(forwarder(910, "MockVault", 911, 912, 913)),
            "content": "contract MockVault {\n" * 40}}}}


class TestPathRankingTests(unittest.TestCase):
    """Tests, mocks and fixtures are kept, and read after the production code they exercise."""

    def result(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        solc = Path(temp.name) / "build-info.json"
        solc.write_text(json.dumps(mock_and_production_fixture()), encoding="utf-8")
        trees = semantic.load_solc(solc)
        return taint_paths.analyze(trees, semantic.solidity_symbols(trees), semantic,
                                   scope=["src/"])

    def test_production_sink_is_read_before_the_mock(self):
        paths = [lead["sink"]["path"] for lead in self.result()["leads"]]
        self.assertIn("src/Vault.sol", paths)
        self.assertIn("src/test/mocks/MockVault.sol", paths)
        self.assertLess(paths.index("src/Vault.sol"),
                        paths.index("src/test/mocks/MockVault.sol"))

    def test_report_counts_and_flags_the_test_paths_it_kept(self):
        result = self.result()
        self.assertEqual(result["sinks_in_test_paths"], 2)
        self.assertGreaterEqual(result["leads_in_test_paths"], 1)
        flagged = {lead["sink"]["path"]: lead["sink"]["test_path"] for lead in result["leads"]}
        self.assertTrue(flagged["src/test/mocks/MockVault.sol"])
        self.assertFalse(flagged["src/Vault.sol"])

    def test_a_mock_sink_loses_a_scarce_row_to_production_code(self):
        # The budget is what makes the order matter: with one row to spend, it goes to the
        # contract under test, not to the mock that stands in for a counterparty.
        rows = [taint_paths._lead_order(
            {"source": {"kind": "external-parameter", "path": path, "scope_role": "in-scope",
                        "line": 1},
             "sink": {"kind": "low-level-call", "path": path, "scope_role": "in-scope",
                      "test_path": taint_paths._is_test_path(path), "line": 1},
             "flow": [], "crosses_persistent_state": False})
            for path in ("src/test/mocks/MockVault.sol", "src/Vault.sol")]
        self.assertLess(rows[1], rows[0])

    def test_a_production_file_is_not_a_test_file_for_holding_the_word(self):
        self.assertFalse(taint_paths._is_test_path("src/Attestation.sol"))
        self.assertFalse(taint_paths._is_test_path("contracts/protocol/ProtocolBase.sol"))
        for path in ("src/test/Vault.sol", "src/mocks/Thing.sol", "src/MockThing.sol",
                     "test/Vault.t.sol", "src/VaultTest.sol", "src/__tests__/Vault.sol"):
            self.assertTrue(taint_paths._is_test_path(path), path)


if __name__ == "__main__":
    unittest.main()
