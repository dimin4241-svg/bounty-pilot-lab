"""Check web boundary hunt is genuinely included in a source bundle."""
import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills/bounty-pilot/scripts"
AGENT = ROOT / "skills/bounty-pilot/references/hunt-agents/web-api-boundary-agent.md"
spec = importlib.util.spec_from_file_location("bp_test_web_lens", SCRIPTS / "bounty.py")
bounty = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bounty)


class Web3BoundaryLensTests(unittest.TestCase):
    def test_web_group_registers_web_api_boundary_and_frontend(self):
        self.assertIn("web-api-boundary", bounty.LENSES)
        self.assertIn("web-api-boundary", bounty.WEB_LENSES)
        self.assertIn("web-frontend", bounty.WEB_LENSES)
        content = AGENT.read_text(encoding="utf-8")
        for phrase in ("negative control", "source", "file:line", "wallet",
                       "SIWE", "webhook", "scope", "offline", "authorization"):
            self.assertIn(phrase.lower(), content.lower())

    def test_web_bundle_carries_real_app_code(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "checkout"
            (root / "api").mkdir(parents=True)
            (root / "api/server.ts").write_text('app.post("/withdraw", f);\n')
            (root / "api/settlement.go").write_text('package api\nfunc Settle() {}\n')
            (root / "api/authorization.py").write_text('def authorize_user(): return True\n')
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            subprocess.run(["git", "-C", str(root), "add", "."], check=True)
            subprocess.run(["git", "-C", str(root), "-c", "user.name=Fixture",
                            "-c", "user.email=fixture@example.invalid",
                            "-c", "commit.gpgsign=false", "commit", "-qm", "fixture"], check=True)
            out = Path(tmp) / "run"
            bounty.initialize(root, out)
            result = bounty.bundle(root, out, ["web"])
            lenses = [x["lens"] for x in result["bundles"]]
            self.assertIn("web-api-boundary", lenses)
            self.assertIn("web-frontend", lenses)
            body = (out / "bundles/web-api-boundary-bundle.md").read_text()
            self.assertIn("/withdraw", body)
            self.assertIn("func Settle()", body)
            self.assertIn("authorize_user", body)
            self.assertIn("func Settle()", (out / "bundles/web-integrity-bundle.md").read_text())
            self.assertNotIn("func Settle()", (out / "bundles/web-frontend-bundle.md").read_text())
            self.assertIn("negative control", body)


if __name__ == "__main__":
    unittest.main()
