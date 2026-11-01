"""Verify the advanced Web3 integrity lens is dispatched with local source."""
import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
S = ROOT / "skills/bounty-pilot/scripts"
SPEC = importlib.util.spec_from_file_location("test_web_integrity_bounty", S / "bounty.py")
bounty = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bounty)
AGENT = ROOT / "skills/bounty-pilot/references/hunt-agents/web-integrity-agent.md"


class WebIntegrityLensTests(unittest.TestCase):
    def test_registered_and_evidence_bound(self):
        self.assertIn("web-integrity", bounty.WEB_LENSES)
        self.assertIn("web-integrity", bounty.LENSES)
        body = AGENT.read_text(encoding="utf-8").lower()
        for s in ("negative control", "file:line", "runtime-provenance",
                  "signed-intent-mirror", "business-invariants", "offline",
                  "attacker", "falsifier"):
            self.assertIn(s.lower(), body)

    def test_web_bundle_contains_integrity_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            (root / "app").mkdir(parents=True)
            (root / "app/index.tsx").write_text("sendTransaction({ to: recipient });\n")
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            subprocess.run(["git", "-C", str(root), "add", "."], check=True)
            subprocess.run(["git", "-C", str(root), "-c", "user.name=Test",
                            "-c", "user.email=fixture@example.invalid",
                            "-c", "commit.gpgsign=false", "commit", "-qm", "fixture"], check=True)
            private = Path(tmp) / "run"
            bounty.initialize(root, private)
            data = bounty.bundle(root, private, ["web"])
            self.assertEqual([x["lens"] for x in data["bundles"]],
                             ["web-frontend", "web-api-boundary", "web-integrity"])
            content = (private / "bundles/web-integrity-bundle.md").read_text()
            self.assertIn("sendTransaction", content)
            self.assertIn("Financial business invariant", content)


if __name__ == "__main__":
    unittest.main()
