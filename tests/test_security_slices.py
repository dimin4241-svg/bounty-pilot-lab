"""Cross-shard dependency planning preserves source and exposes unread relationships."""
import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path

FILE = Path(__file__).resolve().parents[1] / "skills/bounty-pilot/scripts/security_slices.py"
spec = importlib.util.spec_from_file_location("security_slices", FILE)
slices = importlib.util.module_from_spec(spec)
spec.loader.exec_module(slices)


class SecuritySlicesTests(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.repo = Path(t.name) / "target"
        (self.repo / "src").mkdir(parents=True)
        (self.repo / "lib").mkdir(parents=True)
        (self.repo / "lib/Vault.sol").write_text(
            "contract Vault { function withdraw() public {} }\n" + (" " * 700))
        (self.repo / "src/Dummy.sol").write_text("contract Dummy {}\n" + (" " * 1100))
        (self.repo / "src/Router.sol").write_text(
            'import "../lib/Vault.sol";\ncontract Router { Vault vault; }\n' + (" " * 700))
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        subprocess.run(["git", "-C", str(self.repo), "add", "-A"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "-c", "user.name=Fixture",
                        "-c", "user.email=fixture@example.invalid", "commit",
                        "-qm", "fixtures"], check=True)

    def test_bridge_restores_cross_shard_source_context(self):
        report = slices.plan(self.repo, max_source_bytes=1600)
        primary = [x for x in report["shards"] if x["kind"] == "primary-with-context"]
        names = [p for x in primary for p in x["core_paths"]]
        self.assertEqual(set(names), {"lib/Vault.sol", "src/Dummy.sol", "src/Router.sol"})
        self.assertEqual(len(names), len(set(names)))
        self.assertTrue(any({"lib/Vault.sol", "src/Router.sol"}.issubset(x["paths"])
                            for x in report["shards"]))
        self.assertTrue(all(x["source_bytes"] <= 1600 or x["requires_manual_file_split"]
                            for x in report["shards"]))

    def test_unresolved_edges_are_visible_when_bridge_budget_is_zero(self):
        result = slices.plan(self.repo, max_source_bytes=1350, max_bridges=0)
        self.assertEqual(result["bridge_shards"], 0)
        self.assertTrue(any(x["to"] == "lib/Vault.sol" for x
                            in result["unrepresented_cross_shard_edges"]))

    def test_traversal_import_cannot_escape_checkout(self):
        self.assertIsNone(slices._resolve("../../../../etc/passwd", "src/Router.sol",
                                          {"src/Router.sol"}))


def commit_repo(repo):
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(repo), "-c", "user.name=Fixture",
                    "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false",
                    "commit", "-qm", "fixtures"], check=True)


class GoPackageImportTests(unittest.TestCase):
    """A Go import names a package directory, so it resolves to that package's files.

    Measured before this existed: Obol charon `--scope core` produced 256 dependency edges and
    not one was an import — every edge was a shared filename stem. go-ethereum `--scope core`
    behaved the same way.
    """

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.repo = Path(temp.name) / "target"
        (self.repo / "core").mkdir(parents=True)
        (self.repo / "dep").mkdir(parents=True)
        (self.repo / "go.mod").write_text("module example.com/app\n\ngo 1.27\n")
        (self.repo / "core/router.go").write_text(
            'package core\n\nimport (\n\t"fmt"\n\t"github.com/third/party/log"\n'
            '\t"example.com/app/dep"\n)\n\nfunc Route() { fmt.Println(dep.Name) }\n'
            + ("// padding\n" * 40))
        (self.repo / "dep/name.go").write_text(
            'package dep\n\nvar Name = "dep"\n' + ("// padding\n" * 40))
        (self.repo / "dep/helper.go").write_text(
            'package dep\n\nfunc Helper() {}\n' + ("// padding\n" * 40))
        commit_repo(self.repo)

    def edges(self):
        return slices._cues(self.repo, ["core/router.go", "dep/name.go", "dep/helper.go"])[0]

    def test_grouped_import_resolves_to_every_file_of_that_package(self):
        deps = self.edges()["core/router.go"]
        self.assertEqual(deps.get("dep/name.go"), "go-package-import-cue")
        self.assertEqual(deps.get("dep/helper.go"), "go-package-import-cue")

    def test_third_party_and_stdlib_imports_resolve_to_nothing(self):
        for dest in self.edges()["core/router.go"]:
            self.assertTrue(dest.startswith("dep/"), dest)

    def test_plan_puts_an_imported_package_in_the_importer_shard(self):
        report = slices.plan(self.repo, scope=["core", "dep"], max_source_bytes=2048)
        self.assertEqual(report["dependency_edges"], 2)
        self.assertTrue(any({"core/router.go", "dep/name.go", "dep/helper.go"}.issubset(
            shard["paths"]) for shard in report["shards"]),
            "the imported package never reached the importer's shard")

    def test_an_edge_that_does_not_fit_is_reported_rather_than_claimed(self):
        report = slices.plan(self.repo, scope=["core", "dep"], max_source_bytes=1024)
        self.assertEqual([(edge["to"], edge["cue"]) for edge in
                          report["unrepresented_cross_shard_edges"]],
                         [("dep/helper.go", "go-package-import-cue"),
                          ("dep/name.go", "go-package-import-cue")])

    def test_an_import_outranks_a_filename_coincidence_for_a_scarce_bridge(self):
        # charon's `core` alone produces more real import edges than max_bridges allows, so the
        # order decides whether the shards hold evidence or coincidences.
        self.assertLess(slices.CUE_RANK["go-package-import-cue"],
                        slices.CUE_RANK["unique-file-stem-cue"])
        self.assertLess(slices.CUE_RANK["local-import-cue"],
                        slices.CUE_RANK["unique-file-stem-cue"])

    def test_module_path_comes_from_go_mod(self):
        self.assertEqual(slices._go_module(self.repo), "example.com/app")
        self.assertIsNone(slices._go_module(self.repo / "core"))

    def test_a_module_prefix_that_only_looks_like_one_is_not_stripped(self):
        self.assertEqual(slices._go_package_files("example.com/apples/dep", "core/router.go",
                                                  "example.com/app", {"dep": ["dep/name.go"]}), [])


if __name__ == "__main__":
    unittest.main()
