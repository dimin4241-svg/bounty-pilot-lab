"""Validate the reality-boundary hunt lens and source bundle wiring."""
import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills/bounty-pilot/scripts"
LENS = ROOT / "skills/bounty-pilot/references/hunt-agents/reality-boundary-agent.md"
spec = importlib.util.spec_from_file_location("reality_lens_bounty", SCRIPTS / "bounty.py")
bounty = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bounty)


class RealityBoundaryLensTests(unittest.TestCase):
    def test_scope_evidence_negative_control_and_falsifier_are_required(self):
        instructions = LENS.read_text(encoding="utf-8")
        for phrase in ("file:line", "negative control", "falsifier", "native",
                       "settlement", "outcome", "context", "source revision",
                       "CONTROL_ALSO_VIOLATES", "untrusted"):
            self.assertIn(phrase.lower(), instructions.lower())
        self.assertIn("reality-boundary", bounty.LENSES)
        self.assertIn("reality-boundary", bounty.CROSS_STACK_LENSES)
        self.assertIn("reality-boundary", bounty.HIGH_IMPACT_LENSES)

    def test_cross_stack_bundle_contains_real_source_and_instructions(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "target"
            root.mkdir()
            (root / "src").mkdir()
            (root / "src/Vault.sol").write_text(
                "contract Vault { function deposit() public {} }\n", encoding="utf-8")
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            subprocess.run(["git", "-C", str(root), "add", "."], check=True)
            subprocess.run(["git", "-C", str(root), "-c", "user.name=Fixture",
                            "-c", "user.email=fixture@example.invalid",
                            "-c", "commit.gpgsign=false", "commit", "-qm", "fixture"], check=True)
            run = Path(tmp) / "run"
            bounty.initialize(root, run)
            result = bounty.bundle(root, run, ["cross-stack"])
            self.assertIn("reality-boundary", [x["lens"] for x in result["bundles"]])
            bundle = (run / "bundles/reality-boundary-bundle.md").read_text()
            self.assertIn("contract Vault", bundle)
            self.assertIn("Settlement truth", bundle)
            self.assertIn("negative control", bundle)


if __name__ == "__main__":
    unittest.main()
