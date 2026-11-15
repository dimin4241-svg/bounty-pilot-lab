#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SDK=$(xcrun --sdk iphonesimulator --show-sdk-path)
ARCH=$(uname -m)
case "$ARCH" in arm64|x86_64) ;; *) echo "unsupported arch" >&2; exit 2 ;; esac
OUT="$ROOT/build/BountyPilotFixture.app"
if [ "$#" -gt 0 ]; then OUT="$1"; fi
mkdir -p "$OUT"
cp "$ROOT/Info.plist" "$OUT/Info.plist"
xcrun --sdk iphonesimulator swiftc -parse-as-library -sdk "$SDK" \
    -target "$ARCH-apple-ios16.0-simulator" -module-name BountyPilotFixture \
    -o "$OUT/BountyPilotFixture" "$ROOT/AppDelegate.swift"
echo "Fixture built: $OUT"
