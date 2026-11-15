# Mobile Lab v0.1 — offline Android and iOS trust-boundary inventory

This is an **experimental first stage**, not an APK/IPA decompiler, mobile
exploitation framework, complete call graph or bug-finding benchmark.
It adds source-anchored *review leads* to the existing Bounty Pilot workflow.

## What works now

- APK: reads AndroidManifest.xml, including common binary AXML, inventory of
  activities, aliases, services, receivers, providers, permissions, intent
  filters and declared export status. Counts DEX and native-library members
  **without interpreting their code**.
- AAB: reads metadata only where XML is actually decodable. Most protobuf
  manifests remain manifest_error / unsupported rather than fabricated.
- IPA: reads Info.plist, URL schemes, document-type count and optionally
  archived-expanded-entitlements.xcent when actually present. It does NOT
  parse signed entitlements or decrypt app binaries.
- Android decompiled Java/Kotlin/Smali/Dart or iOS Swift/ObjC source:
  reads bounded plaintext source and generates code-co-location review leads
  for IPC/result, WebView/JS bridge, content file streams, OAuth and app-intent
  combinations. These are **syntactic candidates**, not actual data flow.
- Builds a small manifest/component to filename graph. A filename match is
  not a verified class resolution, call graph, permission check or exploit.
- Produces JSON with SHA-256 of every matched source file and exact line
  numbers, while **not copying matched raw source lines** into output.
- Two toy paired synthetic controls in the benchmark command. These
  evaluate regressions only, NOT historical CVE recall or model performance.

## Run

Prepare APK/IPA yourself through the program's allowed distribution process
and, if needed, an independently vetted local decompiler. This helper never
downloads APKs, installs untrusted dependencies or starts an emulator.
Define BP=skills/bounty-pilot/scripts/bounty.py in your shell before running.

    python3 "$BP" mobile-lab analyze \
      --artifact /private/artifacts/owned-test.apk \
      --sources /private/decompiled-src \
      --out /private/run/mobile-android.json

For source-only tests:

    python3 "$BP" mobile-lab analyze \
      --sources /private/own-ios-src --platform ios \
      --out /private/run/mobile-ios.json

Run synthetic controls:

    python3 "$BP" mobile-lab benchmark \
      --out /private/run/mobile-synthetic.json

All outputs must be NEW paths under an existing private directory, and
outside the source checkout. Never put target reports, real credentials or
proprietary client code in a public Git repository or issue.

## Trust boundaries and evidence model

The review families correspond to patterns in published research, but
detection of a family is not a rediscovery:

| Family | Questions requiring manual/native proof |
|---|---|
| IPC_TO_WEBVIEW_REVIEW | Is the external value reachable and loaded? What origin? |
| WEBVIEW_BRIDGE_REVIEW | Is the JS bridge reachable from an untrusted document? |
| EXTERNAL_RESULT_REVIEW | What data returns to which actual caller? |
| UNTRUSTED_FILENAME_REVIEW | Who supplies the name; where is it stored? |
| FILE_TO_CODE_REVIEW | Is stored content later executed or interpreted? |
| MOBILE_AUTH_REVIEW | Is state/PKCE bound to correct session and callback? |
| IOS_CALLBACK_BINDING_REVIEW | Which application actually receives the OAuth result? |
| IOS_APP_INTENT_GUARD_REVIEW | Do shortcuts preserve normal authorization gates? |

Entrypoints are included only for matching Android file names with
declared explicit/legacy export. No iOS entrypoint or external attacker
capability is inferred from mere URL scheme presence.

Before treating a lead as a reportable finding, verify exact app/OS/SDK version,
scope, real caller identity, runtime reachability, the protected action, paired
candidate/negative control, independent authorization policy and reviewer
adjudication. Use the existing experimenter, program-scope and evidence-gate
machinery for these subsequent steps. **This version has no dynamic mobile
runner, no native taint analysis and no independently authenticated receipts.**

## Input safety and reproducibility

- Read-only, local files. Artifact must be a regular, non-symlink file of at
  most 200 MiB. The analyzer never extracts its ZIP contents to disk.
- Reject duplicate, traversal and symlink archive entries; bound member counts
  and metadata sizes to avoid casual archive bombs.
- Source walk is bounded to 1500 files, 12 MiB and 2000 matched anchors.
  Generated leads are capped at 150; flags show when coverage truncates.
- Does not run app build scripts, invoke tools from the target, execute
  runtime tests, contact domains or read credential stores.
- ABI-, reflection-, annotation-, compiler- and coroutine-sensitive flows
  require separate CodeQL/real analyzer work and native validation.
- Re-running with the same untouched bytes yields the same lead IDs; source
  line changes produce a new ID. Duplicate grouping is not yet native-aware.

## Next implementation stages

1. Real Java/Kotlin/Smali and Swift symbol resolution with function-scoped
   data-flow, control-flow guards, callback/caller semantics and SDK/targetSdk
   dependent permission models.
2. Deep-link / App Link / OAuth callback protocol checks with actual origin
   binding and app-claimant validation, not keyword matching.
3. Operator-approved isolated Android/iOS runtime candidate+negative-control
   receipts attached to code-version anchors.
4. Independently licensed historical CVE fixtures, corrected paired variants
   and blind A/B evaluation against existing Bounty Pilot.
5. Analysis of native parsers and dependency provenance.

Do not label the planned stages as implemented.
