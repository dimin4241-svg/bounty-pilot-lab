"""Source-only A/B harness regressions: no remote network and no target execution."""
import hashlib
import importlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[1] / "skills/bounty-pilot/scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))
ab = importlib.import_module("web_ab_diagnostic")


class SourceProbeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "repo"
        self.root.mkdir()
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        subprocess.run(["git", "-C", str(self.root), "config", "user.name", "Fixture"], check=True)
        subprocess.run(["git", "-C", str(self.root), "config", "user.email", "fixture@example.invalid"], check=True)

    def fixture(self, code, path="core.js"):
        p = self.root / path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(code, encoding="utf-8")
        subprocess.run(["git", "-C", str(self.root), "add", "-A"], check=True)
        subprocess.run(["git", "-C", str(self.root), "commit", "-qm", "fixture"], check=True)
        return ab.git(self.root, "rev-parse", "HEAD")

    def test_genuine_file_bytes_scanned_under_identical_budget(self):
        self.fixture("const x=signTypedData();\nconst y=navigator.clipboard.writeText(addr)\n")
        meta, source = ab.source_window(self.root, "https://github.com/brix/crypto-js")
        a, b = ab.one_arm(source, "baseline"), ab.one_arm(source, "extended")
        self.assertEqual(meta["source_file_count"], 1)
        self.assertEqual(meta["source_lines"], 2)
        self.assertRegex(meta["source_digest"], r"^[0-9a-f]{64}$")
        self.assertEqual(a["finding_count"], 0)
        self.assertEqual(b["finding_count"], 0)
        self.assertGreaterEqual(b["lexical_cues"], a["lexical_cues"])
        self.assertIn("runtime-address-mutation", b["counts"])

    def test_local_source_change_changes_fingerprint(self):
        self.fixture("const z = signTypedData(x);\n")
        before, _ = ab.source_window(self.root, "https://github.com/brix/crypto-js")
        (self.root / "core.js").write_text("const z = signTypedData(y);\n")
        after, _ = ab.source_window(self.root, "https://github.com/brix/crypto-js")
        self.assertNotEqual(before["source_digest"], after["source_digest"])

    def test_unapproved_public_repository_blocked_before_download(self):
        with self.assertRaisesRegex(ValueError, "preapproved"):
            ab.fetch_official_snapshot({"repository_url": "https://github.com/user/my-secret-repo",
                                        "source_revision": "a"*40},
                                       Path(self.tmp.name) / "new-clone")

    def test_pinned_commit_mismatch_detected_by_verify(self):
        sha = self.fixture("const x=1\n")
        queue = {"tasks": [{"task_id": "WB-0123456789abcdef",
                             "repository_url": "https://github.com/brix/crypto-js",
                             "source_revision": "0"*40,
                             "scope_prefixes": [], "budget_minutes": 60}]}
        with self.assertRaisesRegex(ValueError, "pinned Git commit"):
            ab.hist.verify_checkout(queue, "WB-0123456789abcdef", self.root)

    def test_budget_is_bounded(self):
        self.fixture("const a=1\n" * 100, path="core.js")
        with mock.patch.dict(ab.BUDGET, {"max_files": 120, "max_lines": 25,
                                         "max_bytes": 1000000, "per_file_bytes": 100000}):
            with self.assertRaisesRegex(ValueError, "no source files"):
                ab.source_window(self.root, "https://github.com/brix/crypto-js")

    def test_cues_do_not_become_security_findings(self):
        data = [("web/app.ts", ["router.post('/withdraw', handler)",
                                "signTypedData();", "navigator.clipboard.writeText(address)"])]
        for arm in ("baseline", "extended"):
            res = ab.one_arm(data, arm)
            self.assertGreater(res["lexical_cues"], 0)
            self.assertEqual(res["verified_root_causes"], 0)
            self.assertEqual(res["classification"], "SOURCE_TRIAGE_NOT_VULNERABILITY_FINDINGS")


if __name__ == "__main__":
    unittest.main()
