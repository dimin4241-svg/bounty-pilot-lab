"""Lab 0.50 public Bounty Pilot command-line integration regression checks."""
import importlib.util
import io
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "skills/bounty-pilot/scripts/bounty.py"
spec = importlib.util.spec_from_file_location("lab050_bounty_cli", SCRIPT)
bounty = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bounty)


class Lab050CLITests(unittest.TestCase):
    def test_new_avre_flags_are_accepted_by_public_entrypoint(self):
        args = bounty.build_parser().parse_args([
            "avre", "--repo", "/tmp/checkout", "--scope", "/tmp/scope.json",
            "--out", "/tmp/private-run", "--feedback", "/tmp/replay.json",
            "--semantic-graph", "/tmp/compiler-graph.json",
        ])
        self.assertEqual(args.feedback, "/tmp/replay.json")
        self.assertEqual(args.semantic_graph, "/tmp/compiler-graph.json")

    def test_flags_reach_avre_analyze_without_running_target(self):
        class Fake:
            calls = []
            @classmethod
            def analyze(cls, *args):
                cls.calls.append(args)
                return {"status": "test-only"}
        with patch.object(bounty, "load_impact_helper", return_value=Fake):
            with redirect_stdout(io.StringIO()):
                code = bounty.main([
                    "avre", "--repo", "/tmp/checkout",
                    "--scope", "/tmp/scope.json", "--out", "/tmp/private-run",
                    "--feedback", "/tmp/replay.json",
                    "--semantic-graph", "/tmp/compiler-graph.json",
                ])
        self.assertEqual(code, 0)
        self.assertEqual(Fake.calls[0][-2:],
                         ("/tmp/replay.json", "/tmp/compiler-graph.json"))

    def test_existing_avre_invocations_remain_backward_compatible(self):
        args = bounty.build_parser().parse_args([
            "avre", "--repo", "/tmp/repo",
            "--scope", "/tmp/scope.json", "--out", "/tmp/out",
        ])
        self.assertIsNone(args.feedback)
        self.assertIsNone(args.semantic_graph)


if __name__ == "__main__":
    unittest.main()
