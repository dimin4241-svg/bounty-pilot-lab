# Mobile native synthetic fixtures (Android/iOS)

These are owned, intentionally tiny reference apps using only the fixed
package/bundle org.bountypilot.fixture and custom scheme bpilottest.
They have no Internet permission or external service. Candidate writes a
nonce to an application-private file; control deletes the file. Each
writes a fresh self-reported JSON witness in the app's own storage.

Android (JDK 17, Android SDK 35, Gradle 8.9+):

    gradle -p tests/fixtures/mobile-native/android :app:assembleDebug
    adb -s emulator-5554 install tests/fixtures/mobile-native/android/app/build/outputs/apk/debug/app-debug.apk

The debug-built app has run-as access for the Python runner.

iOS (Xcode and iOS Simulator, operator invoked):

    sh tests/fixtures/mobile-native/ios/build-sim.sh
    xcrun simctl install YOUR_SIMULATOR_UDID tests/fixtures/mobile-native/ios/build/BountyPilotFixture.app

With either fixture installed, run the operator-confirmed
bounty.py mobile-lab native-run on that emulator/simulator. The runner
will open candidate and control deep links with a fresh per-run nonce.

The field fixture_build_sha256 is the SHA-256 of a shared protocol-version
literal (bpilot-mobilefixture-protocol-v1), NOT a signed or independently
validated APK/IPA code hash. Witnesses are unauthenticated, originate from
the fixture itself, and prove no exploit or third-party app reachability.

GitHub-hosted Python CI tests only fake commands and witness contracts;
the Java/Swift apps here are not built or executed in CI. Do not submit
a real bug bounty report based on a synthetic fixture result.
