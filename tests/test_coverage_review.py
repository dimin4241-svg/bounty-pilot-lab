"""Regressions for the coverage review of 0.19.0: per-contract surfaces and heir symbols,
modifier-own checks, modifier arguments, sender tokens, impact-path ranking, overload-aware
function credit, the lexical fallback, oversized sources and the queue's review and staleness
reporting. Solidity inputs are hand-built solc compact-AST fixtures."""
import contextlib
import importlib.util
import io
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


semantic = load(SCRIPTS / "semantic_graph.py", "test_bp_cr_semantic_graph")
impact = load(SCRIPTS / "impact_paths.py", "test_bp_cr_impact_paths")
odd = load(SCRIPTS / "odd_one_out.py", "test_bp_cr_odd_one_out")
bounty = load(SCRIPTS / "bounty.py", "test_bp_cr_bounty")
# The AST builder and git helpers of the function-coverage tests; only these names are taken.
_fc = load(Path(__file__).resolve().parent / "test_function_coverage.py", "test_bp_cr_fc_helpers")
Ast, MSG, git, commit = _fc.Ast, _fc.MSG, _fc.git, _fc.commit


def typed(param, type_string):
    return dict(param, typeDescriptions={"typeString": type_string})


def with_args(invocation, *args):
    return dict(invocation, arguments=list(args))


def review_fixture():
    """lib/oz/UUPS.sol: an abstract upgrade base; src/*.sol: two heirs (one with an empty
    authorization hook), two tokens on one abstract ledger, a staking contract, a role-guarded
    token, a pool with overloads and an internal pull.

    State ids 10-39, modifiers 50-59, functions 100-299, contracts 300-399."""
    a = Ast()

    def s(name, ident):
        return a.ident(name, ident)

    uups = Ast.contract(300, "UUPS", [
        a.var(10, "impl"),
        a.func(101, "_authorizeUpgrade", visibility="internal", implemented=False,
               params=[typed(a.param(102, "i"), "address")]),
        # function upgradeTo(address i) external { _authorizeUpgrade(i); impl = i; }
        a.func(103, "upgradeTo", [a.stmt(a.call(a.ident("_authorizeUpgrade", 101),
                                                a.ident("i", 104))),
                                  a.assign(s("impl", 10), a.ident("i", 104))],
               params=[typed(a.param(104, "i"), "address")]),
        # function proxiableUUID() external view returns (bytes32)
        a.func(105, "proxiableUUID", [a.stmt(s("impl", 10))], mutability="view"),
    ])
    owned = Ast.contract(310, "Owned", [
        a.var(11, "owner"),
        a.modifier(51, "onlyOwner", [a.require(a.binop(a.msg_sender(), "==", s("owner", 11)))]),
    ])
    proxy_a = Ast.contract(320, "ProxyA", [
        a.func(121, "_authorizeUpgrade", [], visibility="internal",
               modifiers=[a.mod("onlyOwner", 51)], base_functions=[101],
               params=[typed(a.param(122, "i"), "address")]),
    ], bases=[310, 300])
    proxy_b = Ast.contract(330, "ProxyB", [
        # the empty override: anyone may upgrade
        a.func(131, "_authorizeUpgrade", [], visibility="internal", base_functions=[101],
               params=[typed(a.param(132, "i"), "address")]),
    ], bases=[310, 300])
    # Two deployable tokens on one abstract ledger: their writers of `bal` are different
    # contracts and must never be compared with each other.
    ledger = Ast.contract(360, "Ledger", [
        a.var(19, "bal"),
        a.func(161, "_hook", visibility="internal", implemented=False),
    ])
    token_a = Ast.contract(370, "TokenA", [
        a.func(171, "_hook", [], visibility="internal", base_functions=[161]),
        a.func(172, "a1", [a.assign(s("bal", 19), a.lit("1", "number"))],
               modifiers=[a.mod("onlyOwner", 51)]),
        a.func(173, "a2", [a.assign(s("bal", 19), a.lit("2", "number"))],
               modifiers=[a.mod("onlyOwner", 51)]),
        a.func(174, "a3", [a.assign(s("bal", 19), a.lit("3", "number"))],
               modifiers=[a.mod("onlyOwner", 51)]),
    ], bases=[310, 360])
    token_b = Ast.contract(380, "TokenB", [
        a.func(181, "_hook", [], visibility="internal", base_functions=[161]),
        a.func(182, "b1", [a.assign(s("bal", 19), a.lit("1", "number"))]),
        a.func(183, "b2", [a.assign(s("bal", 19), a.lit("2", "number"))]),
    ], bases=[360])
    stake = Ast.contract(340, "Stake", [
        a.var(12, "locked"), a.var(13, "stakes"), a.var(14, "rewardStored"),
        a.modifier(52, "nonReentrant", [
            a.if_revert(a.binop(s("locked", 12), "!=", a.lit("0", "number"))),
            a.assign(s("locked", 12), a.lit("1", "number"))]),
        # updateReward checks nothing: it is accounting, never implied by another check
        a.modifier(53, "updateReward", [a.assign(s("rewardStored", 14), a.lit("1", "number"))]),
    ] + [a.func(141 + i, name, [a.assign(s("stakes", 13), a.lit(str(i), "number"))],
                modifiers=[a.mod("nonReentrant", 52), a.mod("updateReward", 53)])
         for i, name in enumerate(("stake", "unstake", "exit"))] + [
        a.func(145, "withdrawTo", [a.assign(s("stakes", 13), a.lit("9", "number"))],
               modifiers=[a.mod("nonReentrant", 52)]),
        # require(_healthy(msg.sender)): asks about the caller, restricts nobody
        a.func(146, "_healthy", [a.stmt(s("stakes", 13))], visibility="internal",
               mutability="view"),
        a.func(147, "borrowish", [a.require(a.call(a.ident("_healthy", 146), a.msg_sender()))]),
    ], bases=[])
    role = Ast.contract(350, "Role", [
        a.var(15, "roles"), a.var(16, "MINTER", "constant"), a.var(17, "PAUSER", "constant"),
        a.var(18, "supply"),
        a.func(151, "hasRole", [a.stmt(s("roles", 15))], visibility="public", mutability="view"),
        # function _checkRole(bytes32 r) internal view { if (!hasRole(r, msg.sender)) revert; }
        a.func(152, "_checkRole", [a.if_revert(a.unop("!", a.call(a.ident("hasRole", 151),
                                                                  a.ident("r", 153),
                                                                  a.msg_sender())))],
               visibility="internal", mutability="view", params=[a.param(153, "r")]),
        a.modifier(54, "onlyRole", [a.stmt(a.call(a.ident("_checkRole", 152),
                                                  a.ident("role", 55)))]),
        a.func(154, "mint", [a.assign(s("supply", 18), a.lit("1", "number"), "+=")],
               modifiers=[with_args(a.mod("onlyRole", 54), s("MINTER", 16))]),
        a.func(155, "mintBatch", [a.assign(s("supply", 18), a.lit("2", "number"), "+=")],
               modifiers=[with_args(a.mod("onlyRole", 54), s("MINTER", 16))]),
        a.func(156, "emergencyMint", [a.assign(s("supply", 18), a.lit("3", "number"), "+=")],
               modifiers=[with_args(a.mod("onlyRole", 54), s("PAUSER", 17))]),
        a.func(157, "sync", [a.assign(s("supply", 18), a.lit("4", "number"))]),
        a.func(158, "skim", [a.assign(s("supply", 18), a.lit("5", "number"))]),
    ])
    pool = Ast.contract(390, "Pool", [
        a.var(20, "shares"), a.var(21, "token", "immutable"),
        a.func(191, "withdraw", [a.assign(s("shares", 20), a.lit("0", "number"))],
               params=[typed(a.param(192, "amount"), "uint256")]),
        a.func(193, "withdraw", [a.assign(s("shares", 20), a.lit("1", "number"))],
               params=[typed(a.param(194, "amount"), "uint256"),
                       typed(a.param(195, "to"), "address")]),
        a.func(196, "deposit", [a.assign(s("shares", 20), a.lit("2", "number"))],
               params=[typed(a.param(197, "asset"), "contract IERC20"),
                       typed(a.param(198, "amount"), "uint256")]),
        # transferFrom(_msgSender(), ...): the caller, not an arbitrary owner
        a.func(199, "_msgSender", [], visibility="internal", mutability="view"),
        a.func(200, "depositFor", [a.stmt(a.call(
            a.member(a.call(a.ident("IERC20", 400), s("token", 21), kind="typeConversion"),
                     "transferFrom", 401),
            a.call(a.ident("_msgSender", 199)), a.ident("this", -28), a.lit("1", "number")))]),
        # an internal pull from a parameter: depends on each caller
        a.func(201, "_pull", [a.stmt(a.call(
            a.member(a.call(a.ident("IERC20", 400), s("token", 21), kind="typeConversion"),
                     "transferFrom", 401),
            a.ident("from", 202), a.ident("this", -28), a.lit("1", "number")))],
            visibility="internal", params=[a.param(202, "from")]),
        a.func(203, "previewRedeem", [a.stmt(s("shares", 20))], mutability="view"),
    ])
    ierc20 = Ast.contract(410, "IERC20", [
        a.func(401, "transferFrom", implemented=False),
    ], kind="interface")
    return {"output": {"sources": {
        "lib/oz/UUPS.sol": {"ast": Ast.unit(uups)},
        "src/Proxy.sol": {"ast": Ast.unit(owned, proxy_a, proxy_b)},
        "src/Tokens.sol": {"ast": Ast.unit(ledger, token_a, token_b)},
        "src/Stake.sol": {"ast": Ast.unit(stake)},
        "src/Role.sol": {"ast": Ast.unit(role)},
        "src/Pool.sol": {"ast": Ast.unit(ierc20, pool)}}}}


def write_fixture(folder, data=None):
    path = Path(folder) / "build-info.json"
    path.write_text(json.dumps(data or review_fixture()), encoding="utf-8")
    return path


def graph_of(folder):
    trees = semantic.load_solc(write_fixture(folder))
    return semantic.build(semantic.solidity_symbols(trees), getattr(trees, "skipped", []))


def named(graph, name):
    return [s for s in graph["symbols"] if s["name"] == name]


class Case(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.graph = graph_of(self.temp.name)

    def one(self, name):
        found = named(self.graph, name)
        self.assertEqual(len(found), 1, name)
        return found[0]

    def leads(self, kind=None, graph=None):
        report = odd.analyze(graph or self.graph)
        return [lead for lead in report["leads"] if kind is None or lead["kind"] == kind]


class HeirSymbolTests(Case):
    def test_each_heir_resolves_the_virtual_hook_in_its_own_linearization(self):
        proxy_a, proxy_b = self.one("ProxyA.upgradeTo"), self.one("ProxyB.upgradeTo")
        self.assertIn("onlyOwner", proxy_a["guards"])
        self.assertNotIn("onlyOwner", proxy_b["guards"])  # never another heir's override
        for heir in (proxy_a, proxy_b):
            self.assertEqual(heir["inherits"], "solc:103")
            self.assertEqual(heir["inherited_from"], "UUPS")
            self.assertEqual(heir["declaration_path"], "lib/oz/UUPS.sol")
            self.assertEqual(heir["path"], "src/Proxy.sol")
            self.assertTrue(heir["resolution_differs"])
            self.assertTrue(heir["vendored_declaration"])
        # The abstract declaration has no deployment: it still follows every override.
        self.assertIn("onlyOwner", self.one("UUPS.upgradeTo")["guards"])
        self.assertFalse(self.one("UUPS.upgradeTo")["contract_deployable"])
        self.assertEqual(self.one("UUPS.upgradeTo")["deployed_by"],
                         ["src/Proxy.sol:ProxyA", "src/Proxy.sol:ProxyB"])

    def test_inherited_entry_edges_and_existing_fields(self):
        edges = [e for e in self.graph["edges"] if e["kind"] == "inherited-entry"]
        self.assertIn({"from": self.one("ProxyB.upgradeTo")["id"], "to": "solc:103",
                       "kind": "inherited-entry", "confidence": "ast-reference"}, edges)
        self.assertEqual(self.graph["edge_counts"]["inherited_entry"], len(edges))
        self.assertEqual(self.graph["heir_symbols"],
                         sum(1 for s in self.graph["symbols"] if s.get("inherits")))
        heir = self.one("ProxyA.upgradeTo")
        for field in ("id", "path", "name", "declaration", "entry", "guards", "writes",
                      "writes_transitive", "modifiers_unverified", "sinks", "inherited_by"):
            self.assertIn(field, heir)

    def test_super_resolves_in_the_heir_and_terminates(self):
        a = Ast()
        base = Ast.contract(500, "Base", [
            a.var(30, "owner"),
            a.func(501, "_hook", [a.require(a.binop(a.msg_sender(), "==", a.ident("owner", 30)))],
                   visibility="internal"),
            a.func(502, "run", [a.stmt(a.call(a.ident("_hook", 501)))]),
        ])
        child = Ast.contract(510, "Child", [
            a.func(511, "_hook", [a.stmt(a.call(a.member(a.ident("super", -25), "_hook", 501)))],
                   visibility="internal", base_functions=[501]),
        ], bases=[500])
        graph = semantic.build(semantic.solidity_symbols(semantic.load_solc(write_fixture(
            self.temp.name, {"output": {"sources": {"src/C.sol": {
                "ast": Ast.unit(base, child)}}}}))))
        heir = named(graph, "Child.run")[0]
        self.assertIn("src/C.sol:owner", heir["guards"])
        self.assertEqual(heir["internal_calls"], ["solc:511"])
        self.assertIn("solc:501", heir["resolution"])


class SurfaceLeadTests(Case):
    def test_writers_are_compared_only_within_one_contract(self):
        for lead in self.leads("guard-asymmetry"):
            contract = lead["contract"]
            for evidence in lead["evidence"].values():
                self.assertTrue(all(c.startswith(contract + ".") for c in evidence["carriers"]),
                                lead["question"])
        self.assertFalse([l for l in self.leads() if l["contract"] == "TokenB"])

    def test_a_modifier_that_checks_nothing_is_never_implied(self):
        rows = [l for l in self.leads("guard-asymmetry")
                if l["functions"][0]["name"] == "Stake.withdrawTo"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["missing_guards_primary"], ["updateReward"])
        self.assertEqual(self.one("Stake.stake")["modifier_guards"]["updateReward"], [])
        self.assertEqual(self.one("Stake.stake")["modifier_guards"]["nonReentrant"],
                         ["src/Stake.sol:locked"])

    def test_old_intersection_rule_no_longer_hides_the_lead(self):
        # Drop the modifier_guards field: an older graph never suppresses on a guess.
        for sym in self.graph["symbols"]:
            sym.pop("modifier_guards", None)
        names = [l["functions"][0]["name"] for l in self.leads("guard-asymmetry")]
        self.assertIn("Stake.withdrawTo", names)

    def test_modifier_arguments_are_distinct_checks(self):
        mint, emergency = self.one("Role.mint"), self.one("Role.emergencyMint")
        self.assertIn("onlyRole(MINTER)", mint["guards"])
        self.assertIn("src/Role.sol:MINTER", mint["guards"])
        self.assertIn("onlyRole(PAUSER)", emergency["guards"])
        self.assertNotIn("onlyRole(MINTER)", emergency["guards"])
        self.assertEqual(mint["modifier_guards"]["onlyRole(MINTER)"],
                         ["hasRole", "src/Role.sol:MINTER", "src/Role.sol:roles"])
        rows = [l for l in self.leads("guard-asymmetry")
                if l["functions"][0]["name"] == "Role.emergencyMint"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["missing_guards_primary"], ["onlyRole(MINTER)"])
        self.assertEqual(rows[0]["compared_among_modifier_peers"],
                         {"onlyRole(MINTER)": "onlyRole"})
        self.assertIn("applies onlyRole(PAUSER)", rows[0]["question"])
        self.assertEqual(rows[0]["support"], {"carried_by": 2, "of_other_writers": 2})

    def test_empty_authorization_hook_is_a_lead_and_a_guarded_one_is_not(self):
        rows = self.leads("unguarded-hook")
        self.assertEqual([r["hook"] for r in rows], ["ProxyB._authorizeUpgrade"])
        self.assertEqual(rows[0]["contract"], "ProxyB")
        self.assertEqual(rows[0]["entry_points"], ["ProxyB.upgradeTo"])
        self.assertIn("checks nothing", rows[0]["question"])
        self.assertTrue(rows[0]["id"].startswith("ooo-"))

    def test_abstract_declarations_its_heirs_deploy_are_not_compared(self):
        names = {f["name"] for l in self.leads() for f in l["functions"]}
        self.assertNotIn("UUPS.upgradeTo", names)


class SenderTokenTests(Case):
    def test_msg_sender_as_an_argument_is_not_a_sender_guard(self):
        guards = self.one("Stake.borrowish")["guards"]
        self.assertIn("_healthy", guards)
        self.assertNotIn("msg.sender", guards)
        # the role check still guards through hasRole and the state it reads
        self.assertNotIn("msg.sender", self.one("Role.mint")["guards"])
        self.assertIn("hasRole", self.one("Role.mint")["guards"])
        # a comparison keeps it
        self.assertIn("msg.sender", self.one("ProxyA.upgradeTo")["guards"])

    def test_msg_sender_alias_is_the_caller_as_a_value_source(self):
        detail = self.one("Pool.depositFor")["sink_details"][0]
        self.assertEqual(detail["from_source"], "msg.sender")
        ranked = impact.rank(self.graph)["ranked"]
        reasons = {r["sink"]: r["priority_reasons"] for r in ranked}
        self.assertEqual(reasons[self.one("Pool.depositFor")["id"]], [])
        pull = reasons[self.one("Pool._pull")["id"]]
        self.assertEqual(len(pull), 1)
        self.assertIn("internal function", pull[0])


class ImpactRankTests(Case):
    def test_view_functions_named_like_sinks_are_not_sinks(self):
        self.assertEqual(self.one("Pool.previewRedeem")["sinks"], [])
        self.assertEqual(semantic.classify({"getPrice"}, read_only=True), ["price-oracle"])
        self.assertEqual(semantic.classify({"maxWithdraw"}, read_only=True), [])

    def hand_graph(self, extra=()):
        def sym(ident, name, **kw):
            base = {"id": ident, "name": name, "path": "src/X.sol", "contract": "X",
                    "entry": True, "writes": [], "reads": [], "calls": [], "sinks": [],
                    "guards": [], "function_kind": "function"}
            base.update(kw)
            return base
        symbols = [sym("sink", "X.sweep", entry=False, sinks=["asset-movement"])]
        for i in range(6):
            symbols.append(sym("e%d" % i, "X.e%d" % i, calls=["sink"],
                               guards=["onlyOwner"] if i < 4 else []))
        symbols.append(sym("ctor", "X.constructor", function_kind="constructor", calls=["sink"]))
        return semantic.build(symbols + list(extra))

    def test_rows_per_sink_are_capped_unguarded_first_and_constructors_excluded(self):
        result = impact.rank(self.hand_graph())
        rows = [r for r in result["ranked"] if r["sink"] == "sink"]
        self.assertEqual(len(rows), impact.MAX_ROWS_PER_SINK)
        self.assertEqual([r["entry_guard"] for r in rows], ["none", "none", "caller"])
        self.assertNotIn("ctor", [r["entry"] for r in result["ranked"]])
        self.assertEqual(result["paths_beyond_rows_per_sink"], 3)

    def test_heir_entry_ranks_before_the_vendored_declaration_it_deploys(self):
        ranked = impact.rank(self.graph)["ranked"]
        rows = [r for r in ranked if r["sink"] == "solc:103"]
        entries = [r["entry"] for r in rows]
        self.assertEqual(entries[0], self.one("ProxyB.upgradeTo")["id"])  # unguarded heir
        self.assertEqual(rows[0]["entry_guard"], "none")
        declaration = [r for r in rows if r["entry"] == "solc:103"]
        self.assertTrue(all(r["entry_deployed_by_in_scope_heir"] for r in declaration))
        self.assertFalse(any(r["sink"].endswith(("@320", "@330")) for r in ranked))

    def test_scope_keeps_the_vendored_code_an_in_scope_heir_runs(self):
        run = Path(self.temp.name) / "run"
        plan = bounty.impact_plan(solc=write_fixture(self.temp.name), out=run, scope=["src"])
        self.assertGreater(plan["symbols_kept_as_dependencies"], 0)
        graph = bounty.read_json(run / "semantic-graph.json")
        roles = {s["id"]: s.get("scope_role") for s in graph["symbols"]}
        self.assertEqual(roles["solc:103"], "dependency")
        ranked = bounty.read_json(run / "impact-paths.json")["ranked"]
        rows = [r for r in ranked if r["sink"] == "solc:103"]
        self.assertTrue(rows)
        self.assertTrue(all(roles[r["entry"]] == "in-scope" for r in rows))
        self.assertEqual(rows[0]["entry"], "solc:103@330")
        report = bounty.read_json(run / "odd-one-out.json")
        self.assertFalse(any(f["path"].startswith("lib/") for l in report["leads"]
                             for f in l["functions"] if not f.get("inherited_from")))


class FunctionCoverageReviewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.repo = self.base / "repo"
        (self.repo / "src").mkdir(parents=True)
        git(self.repo, "init", "-q")
        (self.repo / "src/Pool.sol").write_text("contract Pool {}\n")
        commit(self.repo)
        self.run = self.base / "run"
        bounty.initialize(self.repo, self.run)
        bounty.impact_plan(solc=write_fixture(self.base), out=self.run)

    def coverage(self, *surfaces):
        body = ("| Surface / invariant | Lens | Pass | Experiment | Result |\n"
                "| --- | --- | --- | --- | --- |\n")
        for surface in surfaces:
            body += "| " + surface + " | accounting | 1 | ran | nothing |\n"
        (self.run / "coverage.md").write_text(body, encoding="utf-8")

    def measure(self):
        result = bounty.function_coverage(self.run)
        written = bounty.read_json(self.run / "function-coverage.json")
        return result, {row["name"] + "|" + str(row.get("signature")): row
                        for row in written["examined_entry_points"]}, written

    def test_inherited_vendored_entries_are_listed_at_the_heir(self):
        result, _, written = self.measure()
        names = [row["name"] for row in written["unexamined"]]
        self.assertIn("ProxyA.upgradeTo", names)
        self.assertIn("ProxyB.upgradeTo", names)
        self.assertNotIn("UUPS.upgradeTo", names)
        self.assertNotIn("ProxyA.proxiableUUID", names)  # read-only vendored code
        self.assertEqual(result["excluded"]["inherited-vendored-read-only"], 2)
        self.assertEqual(result["excluded"]["vendored"], 2)
        self.coverage(*[n for n in names if not n.endswith(".upgradeTo")])
        result, _, _ = self.measure()
        self.assertLess(result["examined_fraction"], 1.0)  # upgradeTo is still unread

    def test_naming_the_vendored_declaration_credits_no_heir_that_resolves_it_differently(self):
        self.coverage("UUPS.upgradeTo", "src/Proxy.sol:ProxyA.upgradeTo")
        _, examined, _ = self.measure()
        self.assertEqual(list(examined), ["ProxyA.upgradeTo|upgradeTo(address)"])
        self.assertEqual(examined["ProxyA.upgradeTo|upgradeTo(address)"]["credited_via"],
                         ["named"])

    def test_an_argument_list_credits_one_overload(self):
        self.coverage("Pool.withdraw(uint256 amount)")
        result, examined, _ = self.measure()
        self.assertEqual(list(examined), ["Pool.withdraw|withdraw(uint256)"])
        self.assertEqual(result["credited_all_overloads"], [])
        self.coverage("Pool.withdraw")
        result, examined, _ = self.measure()
        self.assertEqual(sorted(examined), ["Pool.withdraw|withdraw(uint256)",
                                            "Pool.withdraw|withdraw(uint256,address)"])
        self.assertTrue(all(row["credited_all_overloads"] for row in examined.values()))
        self.assertEqual(result["credited_all_overloads"], ["Pool.withdraw"])

    def test_source_and_abi_types_both_name_an_overload(self):
        for surface in ("Pool.deposit(IERC20 asset, uint amount)",
                        "src/Pool.sol:Pool.deposit(address,uint256)"):
            self.coverage(surface)
            _, examined, _ = self.measure()
            self.assertEqual(list(examined), ["Pool.deposit|deposit(IERC20,uint256)"], surface)
        self.coverage("Pool.deposit(uint256)")
        self.assertEqual(self.measure()[1], {})

    def test_unrooted_paths_are_reported_not_credited(self):
        self.coverage("/home/me/repo/src/Pool.sol:Pool.deposit",
                      "C:\\repo\\src\\Pool.sol:Pool.withdraw")
        result, examined, _ = self.measure()
        self.assertEqual(examined, {})
        self.assertEqual(result["unparsed_surfaces"],
                         ["/home/me/repo/src/Pool.sol:Pool.deposit",
                          "C:/repo/src/Pool.sol:Pool.withdraw"])

    def test_a_bare_file_name_credits_only_when_unique(self):
        self.coverage("Proxy.sol:ProxyA.upgradeTo")
        _, examined, _ = self.measure()
        self.assertEqual(list(examined), ["ProxyA.upgradeTo|upgradeTo(address)"])


class LexicalReviewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name) / "repo"
        self.repo.mkdir()
        git(self.repo, "init", "-q")
        files = {
            "programs/vault/Cargo.toml": "[package]\nname='vault'\n",
            "programs/vault/src/lib.rs": (
                "#[program]\npub mod vault {\n    use super::*;\n"
                "    pub fn deposit(ctx: Context<D>) -> Result<()> { Ok(()) }\n"
                "    pub(crate) fn helper(x: u64) -> u64 { x }\n}\n"
                "#[cfg(test)]\nmod tests {\n    pub fn process_fake() {}\n}\n"),
            "native/Cargo.toml": "[package]\nname='native'\n",
            "native/src/lib.rs": (
                "entrypoint!(process_instruction);\n"
                "fn process_instruction(a: &[u8]) -> ProgramResult { Ok(()) }\n"
                "pub fn process_deposit(a: &[u8]) -> ProgramResult { Ok(()) }\n"
                "pub(crate) fn process_crate(a: &[u8]) -> ProgramResult { Ok(()) }\n"
                "#[cfg(test)]\nmod tests {\n    pub fn process_in_tests() {}\n}\n"),
            "sources/coin.move": (
                "module 0x1::coin {\n    public entry fun stake(s: &signer) {}\n"
                "    #[test]\n    public fun test_stake() {}\n"
                "    #[test(admin = @0x1)]\n    public entry fun test_admin(admin: &signer) {}\n}\n"
                "#[test_only]\nmodule 0x1::coin_tests {\n    public fun helper() {}\n}\n"),
            "src/bridge.cairo": (
                "#[starknet::contract]\nmod Bridge {\n"
                "    #[l1_handler]\n    fn handle_deposit(ref self: ContractState, from: felt252) {}\n"
                "    #[external(v0)]\n    fn withdraw(ref self: ContractState) {}\n"
                "    fn internal(ref self: ContractState) {}\n}\n"),
        }
        for rel, text in files.items():
            path = self.repo / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        commit(self.repo)
        self.run = Path(self.temp.name) / "run"
        bounty.initialize(self.repo, self.run)

    def test_entry_shapes(self):
        bounty.function_coverage(self.run, repo=self.repo)
        rows = bounty.read_json(self.run / "function-coverage.json")["unexamined"]
        self.assertEqual(sorted(row["name"] for row in rows),
                         ["Bridge.handle_deposit", "Bridge.withdraw", "coin.stake",
                          "lib.process_deposit", "lib.process_instruction", "vault.deposit"])


class FloorReviewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name) / "repo"
        self.repo.mkdir()
        git(self.repo, "init", "-q")
        for rel, text in (("src/a/Vault.sol", "x\n"), ("src/b/Vault.sol", "x\n"),
                          ("src/Pool.sol", "x\n"), ("program/src/lib.rs", "x\n"),
                          ("crates/amm/Cargo.toml", "[dependencies]\nanchor-lang = \"0.29\"\n"),
                          ("crates/amm/src/lib.rs", "x\n"),
                          ("relayer/Cargo.toml", "[dependencies]\ntokio = \"1\"\n"),
                          ("relayer/src/main.rs", "x\n")):
            path = self.repo / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        commit(self.repo)
        self.run = Path(self.temp.name) / "run"
        bounty.initialize(self.repo, self.run)

    def floor(self, *surfaces):
        body = "| Surface | Lens | Pass | Experiment | Result |\n| --- | --- | --- | --- | --- |\n"
        body += "".join("| %s | x | 1 | ran | nothing |\n" % s for s in surfaces)
        (self.run / "coverage.md").write_text(body, encoding="utf-8")
        return bounty.coverage_floor(self.repo, self.run, scope_prefixes=["src"])

    def test_bare_names_credit_only_unique_files_and_unrooted_paths_are_reported(self):
        result = self.floor("Vault.sol", "Pool.sol", "../src/a/Vault.sol",
                            "/abs/src/b/Vault.sol")
        self.assertEqual(result["files_examined"], 1)
        self.assertEqual(result["ambiguous_surfaces"], ["Vault.sol"])
        self.assertEqual(result["unparsed_surfaces"], ["../src/a/Vault.sol",
                                                       "/abs/src/b/Vault.sol"])

    def test_onchain_rust_by_directory_and_dependency(self):
        result = self.floor()
        self.assertEqual(result["outside_scope_onchain"],
                         ["crates/amm/src/lib.rs", "program/src/lib.rs"])


class OversizedSourceTests(unittest.TestCase):
    def test_an_oversized_source_is_skipped_and_reported(self):
        with tempfile.TemporaryDirectory() as temp:
            data = review_fixture()
            filler = [{"nodeType": "PragmaDirective"}] * (semantic.MAX_NODES + 10)
            data["output"]["sources"]["src/Flat.sol"] = {
                "ast": {"nodeType": "SourceUnit", "nodes": filler}}
            trees = semantic.load_solc(write_fixture(temp, data))
            self.assertEqual([x["path"] for x in trees.skipped], ["src/Flat.sol"])
            self.assertEqual(len(trees), 6)
            plan = bounty.impact_plan(solc=Path(temp) / "build-info.json",
                                      out=Path(temp) / "run")
            self.assertEqual([x["path"] for x in plan["skipped_sources"]], ["src/Flat.sol"])
            self.assertIn("skipped_sources_warning", plan)
            graph = bounty.read_json(Path(temp) / "run/semantic-graph.json")
            self.assertEqual(len(graph["skipped_sources"]), 1)
            self.assertIn("NOT analysed", graph["warning"])


class QueueReviewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        self.repo = base / "repo"
        (self.repo / "src").mkdir(parents=True)
        git(self.repo, "init", "-q")
        (self.repo / "src/Pool.sol").write_text("contract Pool {}\n")
        commit(self.repo)
        self.run = base / "run"
        bounty.initialize(self.repo, self.run)
        bounty.impact_plan(solc=write_fixture(base), out=self.run)
        self.ids = [lead["id"] for lead in
                    bounty.read_json(self.run / "odd-one-out.json")["leads"]]

    def review(self, data):
        (self.run / "odd-one-out-review.json").write_text(json.dumps(data), encoding="utf-8")
        return bounty.lead_queue(self.run)["odd_one_out"]

    def test_reviewed_leads_leave_the_count(self):
        total = len(self.ids)
        first, second, third = self.ids[:3]
        queued = self.review({
            first: {"status": "intended", "note": "`emergencyWithdraw` skips the pause by design"},
            second: {"status": "lead", "note": "recorded as BP-002"},
            third: {"status": "intended", "note": "probably fine"},
            "ooo-000000000000": {"status": "finding", "note": "stale"}})
        self.assertEqual(queued["total"], total - 2)
        self.assertEqual(sum(queued["by_kind"].values()), queued["total"])
        self.assertEqual(queued["reviewed"], {"intended": 1, "lead": 1})
        self.assertEqual([x["id"] for x in queued["invalid_reviews"]], [third])
        self.assertIn("anchor", queued["invalid_reviews"][0]["problem"])
        self.assertEqual(queued["review_ids_not_in_leads"], ["ooo-000000000000"])
        self.assertEqual(queued["leads_in_file"], total)

    def test_all_reviewed_and_malformed(self):
        queued = self.review({i: {"status": "lead", "note": "recorded"} for i in self.ids})
        self.assertEqual(queued["state"], "all-leads-reviewed")
        (self.run / "odd-one-out-review.json").write_text("[1", encoding="utf-8")
        queued = bounty.lead_queue(self.run)["odd_one_out"]
        self.assertEqual(queued["total"], len(self.ids))
        self.assertIn("warning", queued)

    def test_measurements_older_than_their_inputs_are_stale(self):
        bounty.function_coverage(self.run)
        bounty.coverage_floor(self.repo, self.run, scope_prefixes=["src"])
        queue = bounty.lead_queue(self.run)
        self.assertFalse(queue["function_coverage"]["stale"])
        self.assertFalse(queue["coverage_floor"]["stale"])
        with open(self.run / "coverage.md", "a", encoding="utf-8") as handle:
            handle.write("| src/Pool.sol:Pool.deposit | x | 2 | ran | nothing |\n")
        queue = bounty.lead_queue(self.run)
        self.assertEqual(queue["function_coverage"]["stale_inputs"], ["coverage.md"])
        self.assertEqual(queue["coverage_floor"]["stale_inputs"], ["coverage.md"])
        (self.run / "semantic-graph.json").write_text(json.dumps({"symbols": []}))
        self.assertIn("semantic-graph.json",
                      bounty.lead_queue(self.run)["function_coverage"]["stale_inputs"])


if __name__ == "__main__":
    unittest.main()
