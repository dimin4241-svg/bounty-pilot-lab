"""No real devices or targets: fake executor and in-memory fixture receipts."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "bounty-pilot" / "scripts"))
import mobile_native_probe as probe


def witness(phase, nonce="0" * 32, seen=True, build="a" * 64):
    return {"schema_version": 1, "phase": phase, "nonce": nonce,
            "fixture_package": probe.PACKAGE,
            "fixture_build_sha256": build, "sink_seen": seen}


class NativeFixtureProbeTests(unittest.TestCase):
    def test_offline_plan_never_requires_runtime(self):
        for platform in ("android", "ios"):
            plan = probe.plan(platform)
            self.assertEqual(plan["mode"], "plan-only-no-execution")
            self.assertEqual(plan["fixture_package"], "org.bountypilot.fixture")

    def test_commands_only_target_fixed_fixture_scheme(self):
        commands = probe.commands("android", "emulator-5554", "0" * 32)
        self.assertIn("bpilottest://probe/candidate?nonce=", " ".join(commands["candidate"]))
        self.assertIn("org.bountypilot.fixture", commands["candidate"])
        self.assertNotIn("evil.invalid", " ".join(commands["candidate"]))

    def test_rejects_real_android_device_ids(self):
        for serial in ("R7D12345", "192.168.1.2:5555", "emulator-5554;rm -rf x"):
            with self.assertRaises(ValueError):
                probe.commands("android", serial, "0" * 32)

    def test_rejects_invalid_simulator_id(self):
        with self.assertRaises(ValueError):
            probe.commands("ios", "booted", "0" * 32)

    def test_rejects_incorrect_nonce(self):
        with self.assertRaises(ValueError):
            probe.commands("android", "emulator-5554", "x")
        with self.assertRaises(ValueError):
            probe.validate_pair(witness("candidate"), witness("control"),
                                "not-a-nonce", "android")

    def test_pair_differential_is_only_self_reported(self):
        result = probe.validate_pair(witness("candidate", seen=True),
                                     witness("control", seen=False),
                                     "0" * 32, "android")
        self.assertTrue(result["pair_distinguishes_candidate"])
        self.assertEqual(result["witness_authentication"], "UNATTESTED_SELF_REPORT")
        self.assertTrue(result["no_real_target_or_severity_proven"])

    def test_no_unique_effect_when_both_true(self):
        result = probe.validate_pair(witness("candidate", seen=True),
                                     witness("control", seen=True),
                                     "0" * 32, "ios")
        self.assertEqual(result["status"], "NO_UNIQUE_CANDIDATE_EFFECT")

    def test_rejects_old_nonce(self):
        with self.assertRaises(ValueError):
            probe.validate_pair(witness("candidate", nonce="f" * 32),
                                witness("control", seen=False), "0" * 32, "android")

    def test_rejects_different_fixture_build(self):
        with self.assertRaises(ValueError):
            probe.validate_pair(witness("candidate"), witness("control",
                                build="b" * 64), "0" * 32, "ios")

    def test_rejects_missing_or_nonboolean_effect(self):
        bad = witness("candidate")
        bad["sink_seen"] = 1
        with self.assertRaises(ValueError):
            probe.validate_pair(bad, witness("control", seen=False),
                                "0" * 32, "android")

    def test_no_device_execution_without_approval(self):
        called = []
        with self.assertRaisesRegex(ValueError, "confirm-owned-fixture"):
            probe.run_fixture("android", "emulator-5554", executor=lambda x: called.append(x))
        self.assertEqual(called, [])

    def test_android_fake_fixture_execution_both_phases(self):
        commands = []
        def executor(argv):
            commands.append(argv)
            if argv[-2:] == ["getprop", "ro.kernel.qemu"]:
                return "1\n"
            return ""
        def collector(platform, device_id, phase, executor):
            return witness(phase, seen=phase == "candidate")
        result = probe.run_fixture(
            "android", "emulator-5554", True,
            executor=executor, collector=collector, nonce="0" * 32)
        self.assertTrue(result["pair_distinguishes_candidate"])
        self.assertEqual(len(commands), 3)
        self.assertTrue(all(c[:3] == ["adb", "-s", "emulator-5554"]
                            for c in commands))

    def test_ios_fake_fixture_execution_both_phases(self):
        device = "12345678-ABCD-ABCD-ABCD-1234567890AB"
        commands = []
        def executor(argv):
            commands.append(argv)
            if argv[2:5] == ["list", "devices", "booted"]:
                return json.dumps({"devices": {
                    "iOS 18": [{"udid": device, "state": "Booted"}]}})
            return ""
        def collector(platform, device_id, phase, executor):
            return witness(phase, seen=phase == "candidate")
        result = probe.run_fixture("ios", device, True, executor,
                                   collector, nonce="0" * 32)
        self.assertTrue(result["pair_distinguishes_candidate"])
        self.assertEqual(len(commands), 3)
        self.assertIn("openurl", commands[1])

    def test_negative_emulator_kernel_blocks(self):
        def executor(argv):
            return "0" if argv[-2:] == ["getprop", "ro.kernel.qemu"] else ""
        with self.assertRaisesRegex(ValueError, "did not report emulator"):
            probe.run_fixture("android", "emulator-5554", True, executor,
                              lambda *a: witness("candidate"), nonce="0" * 32)

    def test_witness_files_are_private_json_and_never_execute(self):
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / "witness.json"
            file.write_text(json.dumps(witness("candidate")), encoding="utf-8")
            original = json.loads(file.read_text())
            self.assertEqual(original["fixture_package"], probe.PACKAGE)


if __name__ == "__main__":
    unittest.main()
