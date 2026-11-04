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

    def test_ast_writer_reader_overlap_is_eligible_for_avre_invariant_lead(self):
        # Compiler-backed write/read overlap must not be discarded by the
        # older regex-only reason filter.
        self.doc["edges"] = [{"from": "solc:1", "to": "solc:2",
                              "kind": "writer-reader-overlap", "state": "shares"}]
        converted = bridge.adapt(self.doc, self.repo, self.rev)
        from importlib.util import spec_from_file_location, module_from_spec
        script = FILE.parent / "avre.py"
        sp = spec_from_file_location("avre_ast_test", script)
        avre = module_from_spec(sp)
        sp.loader.exec_module(avre)
        class Ecosystem:
            @staticmethod
            def redact_text(x):
                return x
        result = avre._operation_pairs(converted, self.repo, Ecosystem(),
                                       {"classification": "IN_SCOPE"})
        self.assertTrue(result)
        self.assertEqual(result[0]["evidence"][0]["analysis_method"],
                         "compiler-ast-static-effect-bridge")

    def test_mismatched_revision_rejected(self):
        with self.assertRaisesRegex(ValueError, "revision"):
            bridge.adapt(self.doc, self.repo, "b" * 40)

    def test_bind_graph_records_source_hashes_not_compiler_provenance(self):
        import subprocess
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        subprocess.run(["git", "-C", str(self.repo), "add", "-A"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "-c", "user.name=Fixture",
                        "-c", "user.email=fixture@example.invalid",
                        "commit", "-qm", "fixture"], check=True)
        unbound = dict(self.doc)
        unbound.pop("source_revision")
        bound = bridge.bind_graph(unbound, self.repo)
        self.assertEqual(len(bound["source_revision"]), 40)
        self.assertFalse(bound["source_snapshot"]["compiled_input_equality_verified"])
        self.assertIn("src/Vault.sol", bound["source_snapshot"]["sha256_by_path"])
        result = bridge.adapt(bound, self.repo, bound["source_revision"])
        self.assertEqual(len(result["symbols"]), 2)
        (self.repo / "src/Vault.sol").write_text("changed source")
        with self.assertRaisesRegex(ValueError, "source bytes changed"):
            bridge.adapt(bound, self.repo, bound["source_revision"])

    def test_missing_path_is_visible_not_silently_confirmed(self):
        self.doc["symbols"][0]["path"] = "../Vault.sol"
        result = bridge.adapt(self.doc, self.repo, self.rev)
        self.assertEqual(len(result["skipped_symbols"]), 1)
        self.assertEqual(len(result["edges"]), 0)


if __name__ == "__main__":
    unittest.main()
