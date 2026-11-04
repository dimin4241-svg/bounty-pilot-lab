"""Compiler graph bridge: exact source byte offset, commit binding, static-only edges."""
import importlib.util
import tempfile
import unittest
from pathlib import Path

FILE = Path(__file__).resolve().parents[1] / "skills/bounty-pilot/scripts/semantic_state_bridge.py"
spec = importlib.util.spec_from_file_location("semantic_state_bridge", FILE)
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)


class SemanticStateBridgeTests(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.repo = Path(t.name)
        (self.repo / "src").mkdir()
        (self.repo / "src/Vault.sol").write_text(
            "contract Vault {\n  function deposit() external {}\n"
            "  function withdraw() external {}\n}\n")
        self.rev = "e" * 40
        self.doc = {"method": "compiler-ast-plus-python-ast",
                    "source_revision": self.rev,
                    "symbols": [
                        {"id": "solc:1", "path": "src/Vault.sol", "source_span": "17:40:0",
                         "name": "Vault.deposit", "reads": ["shares"],
                         "writes": ["shares"], "entry": True, "sinks": ["asset"]},
                        {"id": "solc:2", "path": "src/Vault.sol", "source_span": "55:42:0",
                         "name": "Vault.withdraw", "reads": ["shares"], "writes": ["shares"]}],
                    "edges": [{"from": "solc:1", "to": "solc:2",
                               "kind": "static-call-reference"}]}

    def test_preserves_compiler_edges_and_state_identity(self):
        report = bridge.adapt(self.doc, self.repo, self.rev)
        self.assertEqual(len(report["symbols"]), 2)
        self.assertEqual(report["edges"][0]["confidence"], "medium")
        self.assertEqual(report["edges"][0]["reason"], "compiler-static-call-reference")
        self.assertFalse(report["reachability_verified"])

    def test_mismatched_revision_rejected(self):
        with self.assertRaisesRegex(ValueError, "revision"):
            bridge.adapt(self.doc, self.repo, "b" * 40)

    def test_missing_path_is_visible_not_silently_confirmed(self):
        self.doc["symbols"][0]["path"] = "../Vault.sol"
        result = bridge.adapt(self.doc, self.repo, self.rev)
        self.assertEqual(len(result["skipped_symbols"]), 1)
        self.assertEqual(len(result["edges"]), 0)


if __name__ == "__main__":
    unittest.main()
