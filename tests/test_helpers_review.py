"""Regression tests for the 0.9.1 review fixes in the bounded hunt helpers.

These never require forge/solc/go/cargo; toolchain-backed checks skip when the tool
is absent and otherwise run in a private scratch directory.
"""
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills/bounty-pilot/scripts"


def load(name):
    spec = importlib.util.spec_from_file_location("bp_rev_" + name, SCRIPTS / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


runner = load("scenario_runner")
native = load("native_fuzz_plan")
fuzz = load("scenario_fuzz")
coverage = load("coverage_graph")
state = load("state_graph")
semantic = load("semantic_graph")
impact = load("impact_paths")
scaffold = load("poc_scaffold")


# ---------------------------------------------------------------------------
# scenario_runner: shell rejection, zero-tests, dotenv, pass_env, redaction
# ---------------------------------------------------------------------------
class RunnerConventionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)

    def _pair(self, argv, marker=None):
        plan = {"cases": [
            {"id": "c", "pair_id": "p", "role": "candidate", "argv": list(argv)},
            {"id": "n", "pair_id": "p", "role": "negative-control", "argv": list(argv)}]}
        if marker:
            # A script is not a recognised test runner: its output counts only through a
            # marker the plan names (scenario_runner fails closed on unknown runners).
            for case in plan["cases"]:
                case["expect_tests_marker"] = marker
        return plan

    def test_rejects_inline_shell_and_interpreter(self):
        for argv in (["bash", "-c", "echo hi"], ["sh", "-c", "true"],
                     ["python3", "-c", "print(1)"], ["node", "-e", "1"],
                     ["env", "FOO=bar", "bash", "-c", "echo"],
                     ["pwsh", "-Command", "ls"]):
            with self.assertRaises(ValueError, msg=argv):
                runner.execute(self._pair(argv), self.repo, allow_exec=False)

    def test_non_object_case_is_a_clean_error(self):
        with self.assertRaises(ValueError):
            runner.execute({"cases": ["not-an-object", {}]}, self.repo)
        with self.assertRaises(ValueError):
            runner.execute("not-a-plan", self.repo)

    def test_timeout_cap_raised_to_1800(self):
        plan = self._pair([sys.executable, "ok.py"], marker="^ok 1 ")
        plan["cases"][0]["timeout_sec"] = 1800
        (self.repo / "ok.py").write_text("print('ok 1 - check')\nraise SystemExit(0)\n")
        # Under the old 120s cap this validated-out; now it is accepted.
        out = runner.execute(plan, self.repo, allow_exec=True)
        self.assertEqual(out["result"], "experiments-conformed")
        plan["cases"][0]["timeout_sec"] = 1801
        with self.assertRaises(ValueError):
            runner.execute(plan, self.repo, allow_exec=True)

    def test_zero_tests_detection_per_tool(self):
        self.assertTrue(runner._zero_tests(
            ["forge", "test", "--match-test", "^x\\("], 0,
            "No files changed\nWarning: no tests match the provided pattern:\n\tmatch-test: `^x\\(`"))
        self.assertFalse(runner._zero_tests(
            ["forge", "test"], 0, "Ran 1 test for test/A.t.sol:A\n[PASS] x()"))
        self.assertTrue(runner._zero_tests(
            ["cargo", "test"], 0, "running 0 tests\n\ntest result: ok. 0 passed"))
        self.assertFalse(runner._zero_tests(
            ["cargo", "test"], 0, "running 1 test\ntest a ... ok"))
        self.assertTrue(runner._zero_tests(
            ["go", "test", ".", "-run", "^X$"], 0, "ok  example  0.2s [no tests to run]"))
        self.assertTrue(runner._zero_tests(
            ["python3", "-m", "pytest"], 5, "no tests ran in 0.01s"))

    def test_zero_tests_marks_case_and_blocks_conformance(self):
        # A fake "forge" on PATH that prints the no-match warning and exits 0.
        bindir = self.repo / "bin"
        bindir.mkdir()
        fake = bindir / "forge"
        fake.write_text("#!/bin/sh\necho 'Warning: no tests match the provided pattern:'\nexit 0\n")
        fake.chmod(0o755)
        plan = self._pair(["forge", "test", "--match-test", "^nope\\("])
        env_path = os.environ.get("PATH", "")
        try:
            os.environ["PATH"] = str(bindir) + os.pathsep + env_path
            out = runner.execute(plan, self.repo, allow_exec=True)
        finally:
            os.environ["PATH"] = env_path
        self.assertTrue(all(c["status"] == "no-tests-ran" for c in out["cases"]))
        self.assertFalse(all(c["matched_expected_exit"] for c in out["cases"]))
        self.assertNotEqual(out["result"], "experiments-conformed")

    def test_dotenv_blocks_unless_allowed(self):
        (self.repo / ".env").write_text("SECRET=xyz\n")
        (self.repo / "ok.py").write_text("print('ok 1 - check')\nraise SystemExit(0)\n")
        plan = self._pair([sys.executable, "ok.py"], marker="^ok 1 ")
        blocked = runner.execute(plan, self.repo, allow_exec=True)
        self.assertTrue(all(c["status"] == "blocked-dotenv" for c in blocked["cases"]))
        self.assertFalse(any(c["executed"] for c in blocked["cases"]))
        allowed = runner.execute(plan, self.repo, allow_exec=True, allow_dotenv=True)
        self.assertEqual(allowed["result"], "experiments-conformed")
        # .env.example is not a secret file and must not block.
        (self.repo / ".env").unlink()
        (self.repo / ".env.example").write_text("SECRET=\n")
        self.assertEqual(runner.execute(plan, self.repo, allow_exec=True)["result"],
                         "experiments-conformed")

    def test_pass_env_copies_only_named_and_redacts_value(self):
        secret = "sk-live-abcdef0123456789"
        (self.repo / "leak.py").write_text(
            "import os\n"
            "print('TOKEN=' + os.environ.get('MY_RPC','<unset>'))\n"
            "print('OTHER=' + os.environ.get('MY_OTHER','<unset>'))\n"
            "raise SystemExit(0)\n")
        plan = {"pass_env": ["MY_RPC"], "cases": [
            {"id": "c", "pair_id": "p", "role": "candidate", "argv": [sys.executable, "leak.py"]},
            {"id": "n", "pair_id": "p", "role": "negative-control", "argv": [sys.executable, "leak.py"]}]}
        try:
            os.environ["MY_RPC"] = secret
            os.environ["MY_OTHER"] = "should-not-pass"
            out = runner.execute(plan, self.repo, allow_exec=True)
        finally:
            os.environ.pop("MY_RPC", None)
            os.environ.pop("MY_OTHER", None)
        blob = json.dumps(out)
        self.assertNotIn(secret, blob)
        self.assertIn("<REDACTED>", blob)
        self.assertIn("MY_RPC", out["cases"][0]["pass_env"])
        self.assertIn("OTHER=<unset>", blob)  # MY_OTHER was not copied in

    def test_redaction_patterns(self):
        scrub = runner._scrub
        self.assertNotIn("abc123", scrub("Authorization: Bearer abc123def"))
        self.assertNotIn("0xDEADBEEF", scrub("ETH_PRIVATE_KEY=0xDEADBEEF"))
        self.assertNotIn("supersecretmnemonic", scrub('{"mnemonic": "supersecretmnemonic"}'))
        self.assertNotIn("keyinpath9999", scrub("https://eth-mainnet.g.alchemy.com/v2/keyinpath9999"))
        self.assertNotIn("abckey12345678", scrub("https://mainnet.infura.io/v3/abckey12345678"))
        self.assertIn("<REDACTED>", scrub('"private_key":"0xabc"'))
        # A bare 64-hex value (tx hash / slot) is evidence and must NOT be redacted.
        txhash = "0x" + "a" * 64
        self.assertIn(txhash, scrub("tx mined: " + txhash))


# ---------------------------------------------------------------------------
# native_fuzz_plan: anchored forge selector, no option-injection
# ---------------------------------------------------------------------------
class NativePlanTests(unittest.TestCase):
    def test_forge_selector_is_anchored(self):
        argv = native.argv_for("foundry", "test_claim")
        self.assertEqual(argv, ["forge", "test", "--match-test", r"^test_claim\(", "-vv"])

    def test_rejects_option_like_selector(self):
        with self.assertRaises(ValueError):
            native.argv_for("pytest", "-pevil")
        spec = {"cases": [{"id": "x", "candidate": "-ptrick", "control": "ok_control"}]}
        with self.assertRaises(ValueError):
            native.plan(spec, "pytest")


# ---------------------------------------------------------------------------
# scenario_fuzz: wall-clock budget and clear float error
# ---------------------------------------------------------------------------
class FuzzBudgetTests(unittest.TestCase):
    def model(self):
        return {"actors": ["a"], "state": {"x": "0"},
                "invariants": [{"id": "ok", "kind": "compare",
                                "left": {"path": "x"}, "op": "ge", "right": "0"}],
                "actions": [{"name": "inc-{actor}", "actor": "*",
                             "effects": [{"op": "add", "path": "x", "value": "1"}]}]}

    def test_time_budget_stops_cleanly(self):
        out = fuzz.explore(self.model(), depth=8, max_states=20000, max_seconds=0.000001)
        self.assertEqual(out["stopped"], "time-budget")
        self.assertEqual(out["status"], "bounded-search-incomplete")

    def test_float_gives_clear_error(self):
        bad = self.model()
        bad["state"]["x"] = 1.5
        with self.assertRaises(ValueError) as ctx:
            fuzz.explore(bad)
        self.assertIn("floating-point", str(ctx.exception))
        self.assertNotIn("starting state must satisfy", str(ctx.exception))


# ---------------------------------------------------------------------------
# coverage_graph: clean errors on bad JSON
# ---------------------------------------------------------------------------
class CoverageErrorTests(unittest.TestCase):
    def test_non_object_graph_rejected(self):
        with self.assertRaises(ValueError):
            coverage.gaps(["not", "a", "graph"], set())
        with self.assertRaises(ValueError):
            coverage.gaps({"method": "something-else"}, set())


# ---------------------------------------------------------------------------
# state_graph: generics/lifetimes, non-git fallback, Solidity bare writes
# ---------------------------------------------------------------------------
class StateGraphTests(unittest.TestCase):
    def test_rust_generics_and_lifetimes_are_captured(self):
        with tempfile.TemporaryDirectory() as t:
            repo = Path(t)
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            (repo / "src").mkdir()
            (repo / "src/lib.rs").write_text(
                "pub fn handler<'info>(ctx: Context<'_, '_, '_, 'info, X>) { self.total = 1; }\n"
                "fn generic<T, impl Trait>(x: T) {}\n", encoding="utf-8")
            (repo / "sources").mkdir()
            (repo / "sources/m.move").write_text(
                "public fun f<T: store>(a: u64) { }\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
            g = state.scan(repo)
            syms = {s["symbol"] for s in g["symbols"]}
            self.assertIn("handler", syms)
            self.assertIn("generic", syms)
            self.assertIn("f", syms)

    def test_non_git_directory_does_not_traceback(self):
        with tempfile.TemporaryDirectory() as t:
            repo = Path(t)
            (repo / "src").mkdir()
            (repo / "src/a.rs").write_text("fn go() { }\n")
            g = state.scan(repo)  # no git init
            self.assertEqual(g["file_listing"], "filesystem-walk")
            self.assertTrue(any(s["symbol"] == "go" for s in g["symbols"]))

    def test_solidity_bare_state_write_becomes_edge(self):
        with tempfile.TemporaryDirectory() as t:
            repo = Path(t)
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            (repo / "src").mkdir()
            (repo / "src/V.sol").write_text(
                "pragma solidity ^0.8.20;\n"
                "contract V {\n"
                "  uint256 public total;\n"
                "  function add(uint256 x) external { total += x; }\n"
                "  function peek() external view returns (uint256) { return total; }\n"
                "}\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
            g = state.scan(repo)
            add = next(s for s in g["symbols"] if s["symbol"] == "add")
            self.assertIn("total", add["qualified_writes_approx"])
            self.assertTrue(any(e["token"] == "total" for e in g["edges"]))

    def test_vendored_lib_dir_is_excluded(self):
        with tempfile.TemporaryDirectory() as t:
            repo = Path(t)
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            (repo / "lib").mkdir()
            (repo / "lib/dep.sol").write_text("contract Dep { function f() public {} }\n")
            (repo / "src").mkdir()
            (repo / "src/app.sol").write_text("contract App { function g() public {} }\n")
            subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
            g = state.scan(repo)
            self.assertFalse(any("lib/" in s["path"] for s in g["symbols"]))
            self.assertTrue(any(s["path"].startswith("src/") for s in g["symbols"]))


# ---------------------------------------------------------------------------
# semantic_graph: minimal build-info error + compiler-AST features (via forge)
# ---------------------------------------------------------------------------
class SemanticLoadTests(unittest.TestCase):
    def test_minimal_build_info_points_to_build_info_flag(self):
        with tempfile.TemporaryDirectory() as t:
            f = Path(t) / "minimal.json"
            f.write_text(json.dumps({"id": "abc", "source_id_to_path": {"0": "src/V.sol"},
                                     "language": "Solidity"}))
            with self.assertRaises(ValueError) as ctx:
                semantic.load_solc(f)
            self.assertIn("--build-info", str(ctx.exception))

    def test_sources_without_ast_points_to_build_info_flag(self):
        with tempfile.TemporaryDirectory() as t:
            f = Path(t) / "noast.json"
            f.write_text(json.dumps({"sources": {"src/V.sol": {"id": 3}}}))
            with self.assertRaises(ValueError) as ctx:
                semantic.load_solc(f)
            self.assertIn("--build-info", str(ctx.exception))


SOURCE = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
abstract contract Guard {
    uint256 locked;
    address owner;
    modifier nonReentrant() { require(locked == 0); locked = 1; _; locked = 0; }
    modifier onlyOwner() { require(msg.sender == owner); _; }
    function hook() external virtual;
}
contract PriceFeed is Guard {
    struct Pos { uint256 amt; }
    mapping(address => Pos) pos;
    uint256 total;
    event Transfer(address a, uint256 b);
    function add(uint256 a) external nonReentrant {
        Pos storage p = pos[msg.sender];
        p.amt += a;
        emit Transfer(msg.sender, a);
    }
    function pay(address payable to, uint256 a) external onlyOwner {
        (bool ok,) = to.call{value: a}("");
        require(ok);
    }
    function view1() external view returns (uint256) { return total; }
    function hook() external override {}
}
"""


def _forge_build_info():
    forge = shutil.which("forge")
    if not forge:
        return None
    workdir = Path(tempfile.mkdtemp(prefix="bp_sem_"))
    (workdir / "src").mkdir()
    (workdir / "src/V.sol").write_text(SOURCE)
    (workdir / "foundry.toml").write_text(
        "[profile.default]\nsrc = 'src'\nout = 'out'\nlibs = []\noffline = true\n")
    proc = subprocess.run([forge, "build", "--build-info"], cwd=workdir,
                          capture_output=True, text=True)
    if proc.returncode != 0:
        shutil.rmtree(workdir, ignore_errors=True)
        return None
    infos = list((workdir / "out/build-info").glob("*.json"))
    return (infos[0], workdir) if infos else None


class SemanticAstTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.built = _forge_build_info()
        if not cls.built:
            raise unittest.SkipTest("forge not available or build failed")
        cls.graph = semantic.build(semantic.solidity_symbols(
            semantic.load_solc(cls.built[0])))
        cls.by_name = {}
        for s in cls.graph["symbols"]:
            cls.by_name.setdefault(s["name"].split(".")[-1], []).append(s)

    @classmethod
    def tearDownClass(cls):
        if cls.built:
            shutil.rmtree(cls.built[1], ignore_errors=True)

    def one(self, short):
        cands = [s for s in self.by_name[short] if s.get("implemented", True)]
        return cands[0]

    def test_modifier_bodies_are_inherited(self):
        add = self.one("add")
        self.assertTrue(any(w.endswith(":locked") for w in add["writes"]),
                        "nonReentrant write to locked should be inherited")
        pay = self.one("pay")
        self.assertTrue(any(r.endswith(":owner") for r in pay["reads"]),
                        "onlyOwner read of owner should be inherited")

    def test_local_storage_pointer_write_tracked(self):
        add = self.one("add")
        self.assertTrue(any(w.endswith(":pos") for w in add["writes"]),
                        "write through `Pos storage p = pos[...]` should map to pos")

    def test_eth_movement_tagged_as_asset_movement(self):
        self.assertIn("asset-movement", self.one("pay")["sinks"])

    def test_sink_not_polluted_by_contract_or_event_name(self):
        # Contract is PriceFeed and emits Transfer, but `add` moves no assets.
        self.assertEqual(self.one("add")["sinks"], [])
        self.assertEqual(self.one("view1")["sinks"], [])

    def test_unimplemented_function_is_not_entry(self):
        abstract_hooks = [s for s in self.by_name["hook"] if not s.get("implemented", True)]
        self.assertTrue(abstract_hooks)
        self.assertTrue(all(not s["entry"] for s in abstract_hooks))


class SemanticTruncationTests(unittest.TestCase):
    def test_truncated_flag_propagates_to_impact_paths(self):
        # Build a hand graph with an impact sink and mark it truncated.
        graph = semantic.build([{"id": "a", "name": "C.withdraw", "sinks": ["asset-movement"],
                                 "entry": True, "writes": [], "reads": [], "calls": []}])
        graph["truncated"] = True
        ranked = impact.rank(graph)
        self.assertTrue(ranked["graph_truncated"])


# ---------------------------------------------------------------------------
# poc_scaffold: pytest-collectable filename + convention in comments
# ---------------------------------------------------------------------------
class ScaffoldNamingTests(unittest.TestCase):
    def test_writes_test_prefixed_files_with_convention(self):
        finding = {"id": "BP-9", "invariant": "one payout per claim",
                   "entry_point": "claim", "attacker_capabilities": "public",
                   "steps": ["a", "b"]}
        import contextlib
        import io
        with tempfile.TemporaryDirectory() as t:
            out = Path(t) / "run"
            with contextlib.redirect_stdout(io.StringIO()):
                rc = scaffold.main(["--finding", str(self._write(t, finding)),
                                    "--stack", "python", "--out-dir", str(out)])
            self.assertEqual(rc, 0)
            files = {p.name for p in out.iterdir()}
            self.assertTrue(any(n.startswith("test_bp_") and n.endswith(".py") for n in files))
            body = next(out.glob("test_bp_*.py")).read_text()
            self.assertIn("CONVENTION", body)
            self.assertIn("vulnerability is demonstrated", body)

    def _write(self, t, finding):
        p = Path(t) / "finding.json"
        p.write_text(json.dumps(finding))
        return p


if __name__ == "__main__":
    unittest.main()
