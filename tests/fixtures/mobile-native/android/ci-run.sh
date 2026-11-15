#!/bin/sh
# GitHub-hosted disposable Android Emulator, fixed owned fixture only.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
OUT="$RUNNER_TEMP/bpilot-native-android.json"
gradle -p "$ROOT" :app:assembleDebug --no-daemon
adb -s emulator-5554 install -r "$ROOT/app/build/outputs/apk/debug/app-debug.apk"
python3 skills/bounty-pilot/scripts/bounty.py mobile-lab native-run \
    --platform android --device-id emulator-5554 \
    --confirm-owned-fixture --out "$OUT"
python3 - "$OUT" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as handle:
    data = json.load(handle)
assert data["pair_distinguishes_candidate"] is True, data
assert data["native_execution"] == "OPERATOR_LOCAL_FIXTURE_ONLY", data
assert data["no_real_target_or_severity_proven"] is True, data
print("Android synthetic fixture: fresh paired observation confirmed.")
PY
