"""Dependency resolver must follow nearby Rust modules and Solidity imports."""
import importlib.util
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "skills/bounty-pilot/scripts/security_slices.py"
spec = importlib.util.spec_from_file_location("lab050_dependency", SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class DependencyTests(unittest.TestCase):
    def test_rust_module_next_to_importer(self):
        self.assertEqual(
            mod._resolve("state", "src/router.rs", {"src/state.rs", "src/router.rs"}),
            "src/state.rs")

    def test_solidity_relative_parent(self):
        self.assertEqual(
            mod._resolve("../lib/Vault.sol", "src/Router.sol",
                         {"lib/Vault.sol", "src/Router.sol"}),
            "lib/Vault.sol")

    def test_traversal_does_not_escape_checkout_root(self):
        self.assertIsNone(
            mod._resolve("../../../../etc/passwd", "src/Router.sol",
                         {"etc/passwd"}))


if __name__ == "__main__":
    unittest.main()
