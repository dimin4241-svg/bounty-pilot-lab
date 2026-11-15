#!/usr/bin/env python3
"""Opt-in owned-fixture Android Emulator / iOS Simulator paired observation runner.

Only fixed Bounty Pilot synthetic fixture identifiers and the bpilottest scheme
are accepted. This does not install apps, execute arbitrary test scripts, target
real devices, or authenticate the instrumented app's self-reported outcomes.
"""
import json
import os
import re
import secrets
import subprocess
import time
from pathlib import Path

import mobile_lab

PACKAGE = "org.bountypilot.fixture"
SCHEME = "bpilottest"
MAX_WITNESS = 4096
ANDROID_SERIAL = re.compile(r"emulator-[0-9]{4,5}\Z")
IOS_SIMULATOR = re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
NONCE = re.compile(r"[0-9a-f]{32}\Z")
PHASES = ("candidate", "control")


def _device_valid(platform, device_id):
    if platform not in ("android", "ios"):
        raise ValueError("platform must be android or ios")
    pattern = ANDROID_SERIAL if platform == "android" else IOS_SIMULATOR
    if not isinstance(device_id, str) or not pattern.fullmatch(device_id):
        raise ValueError("device id must be a restricted emulator or simulator identifier")


def commands(platform, device_id, nonce):
    _device_valid(platform, device_id)
    if not NONCE.fullmatch(nonce):
        raise ValueError("nonce must be 16 random bytes in hex")
    out = {}
    for phase in PHASES:
        url = "%s://probe/%s?nonce=%s" % (SCHEME, phase, nonce)
        if platform == "android":
            out[phase] = [
                "adb", "-s", device_id, "shell", "am", "start", "-W",
                "-a", "android.intent.action.VIEW", "-d", url,
                "-p", PACKAGE,
            ]
        else:
            out[phase] = ["xcrun", "simctl", "openurl", device_id, url]
    return out


def plan(platform):
    if platform not in ("android", "ios"):
        raise ValueError("platform must be android or ios")
    return {
        "schema_version": 1, "tool": "mobile-native-probe",
        "mode": "plan-only-no-execution", "platform": platform,
        "fixture_package": PACKAGE, "scheme": SCHEME,
        "requires": ["operator-owned instrumented synthetic fixture",
                     "booted Android Emulator or iOS Simulator",
                     "candidate/control witness files from the fixture",
                     "explicit --confirm-owned-fixture for run"],
        "witness_schema": {
            "schema_version": 1,
            "phase": "candidate|control", "nonce": "fresh-32-hex",
            "fixture_package": PACKAGE, "fixture_build_sha256": "64 lowercase hex",
            "sink_seen": "boolean",
        },
        "limitation": "Neither a plan nor fixture self-reported effects prove an app vulnerability.",
    }


def _execute(argv, timeout=12):
    try:
        result = subprocess.run(argv, capture_output=True, text=True,
                                timeout=timeout, check=False,
                                env={k: v for k, v in os.environ.items()
                                     if k in ("PATH", "HOME", "ANDROID_HOME",
                                              "ANDROID_SDK_ROOT", "DEVELOPER_DIR",
                                              "TMPDIR", "LANG")})
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError("native fixture command unavailable or timed out") from exc
    if result.returncode:
        raise ValueError("native fixture command failed (exit=%d)" % result.returncode)
    if len(result.stdout) > 16000:
        raise ValueError("native tool output exceeded bound")
    return result.stdout


def _booted(platform, device_id, executor):
    if platform == "android":
        output = executor(["adb", "-s", device_id, "shell",
                           "getprop", "ro.kernel.qemu"]).strip()
        if output != "1":
            raise ValueError("selected Android serial did not report emulator kernel")
    else:
        payload = executor(["xcrun", "simctl", "list", "devices", "booted", "-j"])
        try:
            devices = json.loads(payload).get("devices", {})
        except (ValueError, AttributeError) as exc:
            raise ValueError("invalid simulator device listing") from exc
        if not any(
            isinstance(value, list)
            and any(isinstance(device, dict)
                    and device.get("udid", "").lower() == device_id.lower()
                    and device.get("state") == "Booted"
                    for device in value)
            for value in devices.values()
        ):
            raise ValueError("selected iOS simulator is not booted")


def _witness(platform, device_id, phase, executor):
    if platform == "android":
        data = executor([
            "adb", "-s", device_id, "exec-out", "run-as", PACKAGE,
            "cat", "files/bpilot-%s.json" % phase,
        ])
        if len(data.encode("utf-8")) > MAX_WITNESS:
            raise ValueError("fixture witness too large")
        return json.loads(data)
    container = executor(["xcrun", "simctl", "get_app_container",
                          device_id, PACKAGE, "data"]).strip()
    if not container:
        raise ValueError("fixture app container not available")
    root = Path(container).resolve(strict=True)
    if not root.is_dir():
        raise ValueError("invalid fixture app container")
    path = root / "Documents" / ("bpilot-%s.json" % phase)
    return json.loads(mobile_lab._regular_file(path, MAX_WITNESS).decode("utf-8"))


def validate_pair(candidate, control, nonce, platform):
    if not NONCE.fullmatch(nonce) or platform not in ("android", "ios"):
        raise ValueError("invalid pair context")
    outcomes = []
    for phase, data in zip(PHASES, (candidate, control)):
        if not isinstance(data, dict):
            raise ValueError("fixture witness must be a JSON object")
        if (data.get("schema_version") != 1
                or data.get("phase") != phase
                or data.get("nonce") != nonce
                or data.get("fixture_package") != PACKAGE
                or not SHA256.fullmatch(str(data.get("fixture_build_sha256", "")))
                or type(data.get("sink_seen")) is not bool):
            raise ValueError("stale, malformed or mismatched fixture witness")
        outcomes.append(data["sink_seen"])
    if candidate["fixture_build_sha256"] != control["fixture_build_sha256"]:
        raise ValueError("candidate and control used different fixture builds")
    differential = outcomes == [True, False]
    return {
        "schema_version": 1,
        "engine": "mobile-native-probe",
        "status": ("PAIRED_SYNTHETIC_FIXTURE_OBSERVATION"
                   if differential else "NO_UNIQUE_CANDIDATE_EFFECT"),
        "platform": platform, "fixture_package": PACKAGE,
        "fixture_build_sha256": candidate["fixture_build_sha256"],
        "device_kind": "emulator" if platform == "android" else "simulator",
        "candidate_sink_seen": outcomes[0],
        "control_sink_seen": outcomes[1],
        "pair_distinguishes_candidate": differential,
        "native_execution": "OPERATOR_LOCAL_FIXTURE_ONLY",
        "witness_authentication": "UNATTESTED_SELF_REPORT",
        "no_real_target_or_severity_proven": True,
        "limitations": ["fixture-reported sink flag is not independently authenticated",
                        "no cross-app permissions or production behavior inferred",
                        "no full UI interaction coverage or root-cause proof"],
    }


def run_fixture(platform, device_id, confirm_owned_fixture=False, executor=None,
                collector=None, nonce=None, retries=6):
    _device_valid(platform, device_id)
    if not confirm_owned_fixture:
        raise ValueError("explicit --confirm-owned-fixture required")
    if type(retries) is not int or not 1 <= retries <= 10:
        raise ValueError("retries must be 1..10")
    nonce = nonce if nonce is not None else secrets.token_hex(16)
    argv = commands(platform, device_id, nonce)
    executor = executor or _execute
    collector = collector or _witness
    _booted(platform, device_id, executor)
    observations = {}
    for phase in PHASES:
        executor(argv[phase])
        latest = None
        for attempt in range(retries):
            try:
                latest = collector(platform, device_id, phase, executor)
                if (isinstance(latest, dict) and latest.get("nonce") == nonce
                        and latest.get("phase") == phase):
                    break
            except (OSError, ValueError, json.JSONDecodeError):
                latest = None
            if attempt + 1 < retries:
                time.sleep(0.3)
        if latest is None or latest.get("nonce") != nonce:
            raise ValueError("fixture did not return fresh matching witness")
        observations[phase] = latest
    return validate_pair(observations["candidate"], observations["control"],
                         nonce, platform)
