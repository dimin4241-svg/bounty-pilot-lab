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
            "contract Vault { function withdraw() public {} }\n" + (" " * 400))
        (self.repo / "src/Dummy.sol").write_text("contract Dummy {}\n" + (" " * 1100))
        (self.repo / "src/Router.sol").write_text(
            'import "../lib/Vault.sol";\ncontract Router { Vault vault; }\n' + (" " * 400))
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        subprocess.run(["git", "-C", str(self.repo), "add", "-A"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "-c", "user.name=Fixture",
                        "-c", "user.email=fixture@example.invalid", "commit",
                        "-qm", "fixtures"], check=True)

    def test_bridge_restores_cross_shard_source_context(self):
        report = slices.plan(self.repo, max_source_bytes=1350)
        primary = [x for x in report["shards"] if x["kind"] == "primary-with-context"]
        names = [p for x in primary for p in x["core_paths"]]
        self.assertEqual(set(names), {"lib/Vault.sol", "src/Dummy.sol", "src/Router.sol"})
        self.assertEqual(len(names), len(set(names)))
        self.assertTrue(any({"lib/Vault.sol", "src/Router.sol"}.issubset(x["paths"])
                            for x in report["shards"]))
        self.assertTrue(all(x["source_bytes"] <= 1350 or x["requires_manual_file_split"]
                            for x in report["shards"]))

    def test_unresolved_edges_are_visible_when_bridge_budget_is_zero(self):
        result = slices.plan(self.repo, max_source_bytes=1350, max_bridges=0)
        self.assertEqual(result["bridge_shards"], 0)
        self.assertTrue(any(x["to"] == "lib/Vault.sol" for x
                            in result["unrepresented_cross_shard_edges"]))

    def test_traversal_import_cannot_escape_checkout(self):
        self.assertIsNone(slices._resolve("../../../../etc/passwd", "src/Router.sol",
                                          {"src/Router.sol"}))


if __name__ == "__main__":
    unittest.main()
