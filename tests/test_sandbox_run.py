"""Safety and argument tests for the opt-in Docker paired-PoC wrapper."""
import importlib.util
import os
import tempfile
import unittest
from pathlib import Path

MOD = Path(__file__).resolve().parents[1] / "skills/bounty-pilot/scripts/sandbox_run.py"
spec = importlib.util.spec_from_file_location("sandbox_run", MOD)
sandbox = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sandbox)
IMAGE = "example/test-toolchain@sha256:" + "a" * 64


@unittest.skipUnless(os.name == "posix", "POSIX-only sandbox")
class SandboxWrapperTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.repo = base / "target"
        self.repo.mkdir()
        self.plan = base / "plan.json"
        self.plan.write_text('{"cases":[]}', encoding="utf-8")
        self.logs = base / "logs"
        self.logs.mkdir()
        self.out = self.logs / "results.json"

    def build(self, **changes):
        params = dict(repo=self.repo, plan=self.plan, out=self.out, image=IMAGE, uid=1001, gid=1001)
        params.update(changes)
        return sandbox.build_command(**params)

    def test_native_foundry_harness_is_opt_in_readonly_and_offline(self):
        plan = self.plan
        plan.write_text('{"schema_version":1,"contracts":[{"name":"Vault"}],"functions_included":[{"contract":"Vault","signature":"deposit(uint256)"}]}')
        cmd = sandbox.build_foundry_command(
            self.repo, plan, self.out, IMAGE, "VaultInvariants",
            uid=1001, gid=1001)
        self.assertIn("--network=none", cmd)
        self.assertIn("--pull=never", cmd)
        self.assertIn("--read-only", cmd)
        self.assertIn("--inside-forge", cmd)
        self.assertIn("VaultInvariants", cmd)
        self.assertTrue(any(",dst=/target,readonly" in arg for arg in cmd))
        self.assertTrue(any(arg == "--env=FOUNDRY_OUT=/tmp/out" for arg in cmd))
        self.assertTrue(any(arg == "--env=FOUNDRY_CACHE_PATH=/tmp/cache" for arg in cmd))

    def test_native_foundry_rejects_arbitrary_harness_names(self):
        for invalid in ("Vault", "../../VaultInvariants",
                        "VaultInvariants; touch /tmp/pwned"):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    sandbox.build_foundry_command(
                        self.repo, self.plan, self.out,
                        IMAGE, invalid, uid=1001, gid=1001)

    def test_handler_counter_parser_marks_mostly_reverts_as_unexplored(self):
        text = "deposit(uint256) 100 94\\nwithdraw(uint256) 50 1\\n"
        # File contents generated in a local fixture, no forge process.
        result = sandbox.handler_coverage_from_log(
            text.replace("\\n", "\n"), ["deposit(uint256)", "withdraw(uint256)"])
        self.assertEqual(result["total_calls"], 150)
        self.assertEqual(result["total_reverts"], 95)
        self.assertFalse(result["coverage_verified"])
        self.assertIn("deposit(uint256)", result["zero_or_high_revert_handlers"])

    def test_handler_counter_parser_fails_closed_on_missing_or_invalid_logs(self):
        result = sandbox.handler_coverage_from_log(
            "unknown output", ["deposit(uint256)"])
        self.assertFalse(result["all_handler_counts_available"])
        self.assertFalse(result["coverage_verified"])
        with self.assertRaises(ValueError):
            sandbox.handler_coverage_from_log(
                "deposit(uint256) 2 3", ["deposit(uint256)"])

    def test_mutation_scoring_uses_same_offline_isolation_without_target_mount(self):
        rules = self.logs / "rules.json"
        rules.write_text('{"rules":[]}')
        command = sandbox.build_mutation_command(
            self.repo, self.plan, rules, self.out, IMAGE,
            uid=1001, gid=1001)
        self.assertIn("--network=none", command)
        self.assertIn("--read-only", command)
        self.assertIn("--pull=never", command)
        self.assertIn("score", command)
        self.assertIn("/input/rules.json", command)
        self.assertIn("/pilot/mutation_lab.py", command)
        self.assertNotIn("/pilot/scenario_runner.py", command)
        self.assertFalse(any(",dst=/target" in arg for arg in command))
        self.assertTrue(any(",dst=/input/rules.json,readonly" in arg
                            for arg in command))

    def test_mutation_property_spec_cannot_be_target_source(self):
        inside = self.repo / "rules.json"
        inside.write_text("{}")
        with self.assertRaises(ValueError):
            sandbox.build_mutation_command(
                self.repo, self.plan, inside, self.out, IMAGE,
                uid=1001, gid=1001)

    def test_isolated_command_mounts_only_required_paths(self):
        command = self.build()
        for flag in ("--network=none", "--cap-drop=ALL", "--security-opt=no-new-privileges",
                     "--read-only", "--pull=never", "--user=1001:1001"):
            self.assertIn(flag, command)
        self.assertIn("--allow-exec", command)
        self.assertIn("--entrypoint=python3", command)
        self.assertFalse(any("--mount" in x and str(Path.home()) == x for x in command))
        self.assertNotIn("--allow-dotenv", command)

    def test_rejects_non_immutable_image(self):
        with self.assertRaisesRegex(ValueError, "immutable"):
            self.build(image="python:latest")

    def test_rejects_root_user(self):
        with self.assertRaisesRegex(ValueError, "root"):
            self.build(uid=0, gid=0)

    def test_rejects_out_inside_target(self):
        with self.assertRaisesRegex(ValueError, "outside"):
            self.build(out=self.repo / "results.json")

    def test_rejects_existing_evidence(self):
        self.out.write_text("old", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "new JSON"):
            self.build()

    def test_rejects_plan_symlink(self):
        link = Path(self.tmp.name) / "other.json"
        link.symlink_to(self.plan)
        with self.assertRaisesRegex(ValueError, "symlink"):
            self.build(plan=link)

    def test_rejects_unsafe_docker_program(self):
        with self.assertRaisesRegex(ValueError, "executable name"):
            self.build(docker="/bin/sh")

    def test_refuses_out_directory_containing_checkout(self):
        with self.assertRaisesRegex(ValueError, "outside"):
            self.build(out=Path(self.tmp.name) / "results.json")


if __name__ == "__main__":
    unittest.main()
