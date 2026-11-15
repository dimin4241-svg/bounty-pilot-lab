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
if ! xcrun simctl list devices booted | grep -F "$UDID"; then
    xcrun simctl boot "$UDID"
fi
xcrun simctl bootstatus "$UDID" -b
sh "$ROOT/build-sim.sh"
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
