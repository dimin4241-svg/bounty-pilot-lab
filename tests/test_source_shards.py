"""Source scope partitioning must not silently lose source or merge oversized files."""
import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "skills/bounty-pilot/scripts/source_shards.py"
spec = importlib.util.spec_from_file_location("test_lab_source_shards", SCRIPT)
shards = importlib.util.module_from_spec(spec)
spec.loader.exec_module(shards)


class SourceShardTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "target"
        (self.root / "src").mkdir(parents=True)
        (self.root / "other").mkdir(parents=True)
        (self.root / "src/a.go").write_text("a" * 700)
        (self.root / "src/b.go").write_text("b" * 700)
        (self.root / "other/c.py").write_text("c" * 700)
        (self.root / "other/big.rs").write_text("d" * 2600)
        (self.root / "src/a_test.go").write_text("not a source for scope")
        (self.root / "src/client.vue").write_text("<template>app</template>")
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        subprocess.run(["git", "-C", str(self.root), "add", "-A"], check=True)
        subprocess.run(["git", "-C", str(self.root), "-c", "user.name=Fixture",
                        "-c", "user.email=fixture@example.invalid", "commit",
                        "-qm", "fixture"], check=True)

    def test_all_non_test_source_preserved_in_distinct_shards(self):
        result = shards.plan(self.root, max_source_bytes=1200)
        names = [p for shard in result["shards"] for p in shard["paths"]]
        self.assertEqual(sorted(names), sorted(
            ["src/a.go", "src/b.go", "other/c.py", "other/big.rs"]))
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual(result["oversized_single_files"], ["other/big.rs"])
        self.assertTrue(all(s["source_bytes"] <= 1200 or
                            s["requires_manual_file_split"] for s in result["shards"]))

    def test_scope_limits_to_named_files_without_root_escape(self):
        result = shards.plan(self.root, scope=["src"], max_source_bytes=1200)
        paths = [p for s in result["shards"] for p in s["paths"]]
        self.assertEqual(sorted(paths), ["src/a.go", "src/b.go"])
        self.assertEqual(result["excluded"], [])

    def test_small_budget_and_subdirectory_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "1024"):
            shards.plan(self.root, max_source_bytes=100)
        with self.assertRaisesRegex(ValueError, "checkout root"):
            shards.plan(self.root / "src")


if __name__ == "__main__":
    unittest.main()
