"""Multi-engine offline orchestrator: scoped, private and nonexecuting controls."""
import hashlib
import json
import plistlib
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "skills" / "bounty-pilot" / "scripts"
sys.path.insert(0, str(SCRIPTS))
import research_run_hub as hub


class ResearchHubTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name) / "work"
        self.root.mkdir()
        self.policy = self.root / "scope-policy.txt"
        self.policy.write_text("operator-authorized synthetic fixtures only")
        self.ent = self.root / "electron"
        self.ent.mkdir()
        (self.ent / "main.js").write_text(
            "new BrowserWindow({ webPreferences: { contextIsolation: false } });")
        (self.root / "oauth.json").write_text(json.dumps({
            "schema_version": 1,
            "policy": {
                "invalidate_unredeemed_codes": True,
                "invalidate_refresh_on_revoke": True,
                "role_actions": {"read": ["read"]}},
            "events": [
                {"id": "r1", "seq": 1, "type": "set_role",
                 "actor": "tester", "role": "read"},
                {"id": "r2", "seq": 2, "type": "action", "actor": "tester",
                 "action": "read", "accepted": True}
            ],
        }))
        graph = {"nodes": [
            {"id": "entry", "kind": "entry", "guard_present": False},
            {"id": "sink", "kind": "sink", "guard_present": False}],
                 "edges": [{"from": "entry", "to": "sink"}]}
        (self.root / "graph.json").write_text(json.dumps({
            "schema_version": 1, "before": graph, "after": graph,
        }))
        (self.root / "Info.plist").write_bytes(plistlib.dumps({
            "CFBundleIdentifier": "org.fixture.app",
            "CFBundleURLTypes": [{"CFBundleURLSchemes": ["fixture"]}],
        }))

    def manifest(self, jobs=None):
        if jobs is None:
            jobs = [
                {"id": "electron-a", "engine": "electron", "path": "electron"},
                {"id": "oauth-a", "engine": "oauth", "path": "oauth.json"},
                {"id": "variant-a", "engine": "graph-variant", "path": "graph.json"},
                {"id": "ios-a", "engine": "ios-trust", "path": "Info.plist"},
            ]
        return {
            "schema_version": 1,
            "scope": {"operator_confirmed": True, "policy_file": "scope-policy.txt",
                      "policy_sha256": hashlib.sha256(
                          self.policy.read_bytes()).hexdigest()},
            "jobs": jobs,
        }

    def test_runs_four_engines_without_network_or_execution(self):
        out = self.root.parent / "results"
        report = hub.analyze(self.manifest(), self.root, out)
        self.assertEqual(len(report["jobs"]), 4)
        self.assertFalse(report["native_execution"])
        self.assertEqual(report["network_requests"], 0)
        self.assertEqual(report["findings_independently_verified"], 0)
        self.assertEqual(out.stat().st_mode & 0o777, 0o700)
        for entry in report["jobs"]:
            path = out / entry["result_file"]
            self.assertTrue(path.is_file())
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertFalse(entry["impact_verified_by_orchestrator"])
        self.assertTrue((out / "index.json").is_file())

    def test_scope_confirmation_is_required(self):
        case = self.manifest()
        case["scope"]["operator_confirmed"] = False
        with self.assertRaisesRegex(ValueError, "scope"):
            hub.analyze(case, self.root, self.root.parent / "results")

    def test_scope_snapshot_sha256_mismatch_rejected(self):
        case = self.manifest()
        case["scope"]["policy_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "differs"):
            hub.analyze(case, self.root, self.root.parent / "results")

    def test_path_traversal_job_rejected(self):
        case = self.manifest([{
            "id": "x", "engine": "electron", "path": "../outside"}])
        with self.assertRaisesRegex(ValueError, "unsafe"):
            hub.analyze(case, self.root, self.root.parent / "results")

    def test_symlink_job_rejected(self):
        (self.root / "link").symlink_to(self.ent, target_is_directory=True)
        case = self.manifest([{"id": "x", "engine": "electron", "path": "link"}])
        with self.assertRaisesRegex(ValueError, "symlink"):
            hub.analyze(case, self.root, self.root.parent / "results")

    def test_duplicate_jobs_rejected_before_output_creation(self):
        jobs = [{"id": "same", "engine": "electron", "path": "electron"}] * 2
        case = self.manifest(jobs)
        target = self.root.parent / "results"
        with self.assertRaisesRegex(ValueError, "unique"):
            hub.analyze(case, self.root, target)
        self.assertFalse(target.exists())

    def test_reused_output_refused(self):
        out = self.root.parent / "results"
        hub.analyze(self.manifest(), self.root, out)
        with self.assertRaisesRegex(ValueError, "new directory"):
            hub.analyze(self.manifest(), self.root, out)

    def test_no_output_inside_work_root(self):
        with self.assertRaisesRegex(ValueError, "outside"):
            hub.analyze(self.manifest(), self.root, self.root / "result")

    def test_unknown_engine_rejected(self):
        with self.assertRaisesRegex(ValueError, "unsupported"):
            hub.analyze(self.manifest([{"id": "x", "engine": "shell",
                                       "path": "electron"}]),
                        self.root, self.root.parent / "results")


if __name__ == "__main__":
    unittest.main()
