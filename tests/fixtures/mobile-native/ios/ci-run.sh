#!/bin/sh
# GitHub-hosted disposable iOS Simulator; no connected iPhone.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
OUT="$RUNNER_TEMP/bpilot-native-ios.json"
xcodebuild -version
UDID=$(python3 - <<'PY'
import json
import subprocess
data = json.loads(subprocess.check_output(
    ["xcrun", "simctl", "list", "devices", "available", "-j"], text=True))
devices = []
for runtime, entries in data["devices"].items():
    if not runtime.startswith("com.apple.CoreSimulator.SimRuntime.iOS-"):
        continue
    for entry in entries:
        if entry.get("isAvailable", True) and "iPhone" in entry.get("name", ""):
            devices.append(entry)
if not devices:
    raise SystemExit("No available iOS iPhone Simulator device on runner")
devices.sort(key=lambda e: (e.get("state") != "Booted", e["name"], e["udid"]))
print(devices[0]["udid"])
PY
)
echo "Chosen simulator: $UDID"
echo "Requesting simulator boot with strict timeout"
python3 - "$UDID" <<'PY'
import subprocess
import sys
cmd = ["xcrun", "simctl", "boot", sys.argv[1]]
try:
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
except subprocess.TimeoutExpired:
    raise SystemExit("simctl boot stalled: simulator service unavailable after 120 seconds")
if p.returncode and "Current state: Booted" not in p.stderr:
    raise SystemExit("simctl boot failed: " + p.stderr[-900:])
print("Simulator boot request sent.")
PY
echo "Waiting for iOS Simulator boot completion"
python3 - "$UDID" <<'PY'
import subprocess
import sys
try:
    subprocess.run(["xcrun", "simctl", "bootstatus", sys.argv[1], "-b"],
                   timeout=180, check=True)
except subprocess.TimeoutExpired:
    raise SystemExit("simctl bootstatus stalled: simulator not ready after 180 seconds")
print("iOS simulator fully booted.")
PY
echo "Compiling owned fixture with Xcode"
sh "$ROOT/build-sim.sh"
echo "Installing owned fixture on simulator"
xcrun simctl install "$UDID" "$ROOT/build/BountyPilotFixture.app"
python3 skills/bounty-pilot/scripts/bounty.py mobile-lab native-run \
    --platform ios --device-id "$UDID" \
    --confirm-owned-fixture --out "$OUT"
python3 - "$OUT" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as handle:
    data = json.load(handle)
assert data["pair_distinguishes_candidate"] is True, data
assert data["native_execution"] == "OPERATOR_LOCAL_FIXTURE_ONLY", data
assert data["no_real_target_or_severity_proven"] is True, data
print("iOS synthetic fixture: fresh paired observation confirmed.")
PY
