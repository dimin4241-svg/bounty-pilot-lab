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
Set BP=skills/bounty-pilot/scripts/bounty.py; use it for commands below.

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

## Phase 2: optional function-level lexical flow review

The new flow subcommand traces simple explicit input API/entrypoint values
through local assignments to sensitive calls in Java, Kotlin and Swift.
Smali support follows basic object registers and invoke/move-result pairs.
It also follows an **unambiguous same-file helper call** up to two hops.
This improves on file-wide co-location. It is still a conservative lexical
def-use review: no compiler AST, SSA, branch feasibility, overload/dynamic
dispatch, cross-file calls, Swift closures, ObjC message semantics or
comprehensive Smali register-range handling.

Run this *after* extracting source in your isolated workstation:

    python3 "$BP" mobile-lab flow \
      --sources /private/decompiled-src --platform android \
      --out /private/run/mobile-flow.json

For Swift source use platform ios. Output includes source/sink line numbers,
file SHA-256, helper hop anchors, and candidate Android component-to-filename
matches including manifest export/permission metadata. These matches are
explicitly UNVERIFIED_FILENAME_HEURISTIC, not established Android caller
reachability. Result statuses:
LEXICAL_DEF_USE_REVIEW_UNVERIFIED and NOT_ESTABLISHED. No arbitrary target
source text or real authentication values are stored. Entry-point seeds are
heuristic and not proof that an external attacker can reach the sink.

The flow command does **not** dynamically execute APK/IPA, test real devices,
or claim authorization, information disclosure, credential exfiltration or RCE.
Paired synthetic controls test that constants and irrelevant methods do not
produce the same chain; a successful synthetic test is not proof on a target.

## Phase 3: conservative cross-file calls and owned-fixture native probes

The crossfile subcommand links *explicit* and *uniquely matched*
Java/Kotlin class or constructed-instance calls, plus Swift class/struct
qualified calls, across files. It propagates an observed local source
assignment or selected mobile entrypoint parameter through up to three
inter-file edges to a sensitive sink. It does not resolve dynamic dispatch,
overloads, imported static method aliases, nested argument calls,
cross-file return values, Objective-C messages or Smali inter-file methods.
The source and sink each carry an independent file digest and line anchor.
Class/receiver matching remains a conservative **lexical approximation**,
not compiler resolution or evidence that an external actor can invoke it.

    python3 "$BP" mobile-lab crossfile \
      --sources /private/decompiled-src --platform android \
      --out /private/run/mobile-crossfile.json

For Swift source, use platform ios. On ambiguity the analyzer *drops*
the edge rather than picking a target. Source and sink bytes are never
included in the resulting JSON. Findings remain UNVERIFIED and
NOT_ESTABLISHED.

The native-plan command produces an offline protocol description for a
dedicated **operator-owned synthetic fixture**; the native-run command is
separately opted-in. Its hard-coded package/bundle is
org.bountypilot.fixture and its deep-link scheme is bpilottest. It refuses
physical Android serials and non-UDID iOS targets, and checks emulator or
booted simulator status before issuing any app action.

    python3 "$BP" mobile-lab native-plan \
      --platform android --out /private/run/mobile-native-plan.json

    python3 "$BP" mobile-lab native-run \
      --platform android --device-id emulator-5554 \
      --confirm-owned-fixture --out /private/run/mobile-native-pair.json

For a booted iOS Simulator supply platform ios and its literal UUID
device identifier. This runner only works **after you independently build
and install an owned synthetic fixture** implementing the following
protocol: register bpilottest://probe/candidate and /control; accept a
fresh nonce query; write files/bpilot-{phase}.json in Android app storage
or Documents/bpilot-{phase}.json in the iOS app data container. Each
document must contain schema_version=1, phase, nonce,
fixture_package=org.bountypilot.fixture, a lowercase 64-digit
fixture_build_sha256, and a boolean sink_seen, consistent across the pair.
The app must issue a new witness on each invocation, not replay old data.
A comparison expects candidate=true, control=false as a differential
observation **of that fixture only**.

The runner invokes fixed adb or xcrun commands without an arbitrary shell,
external endpoints, injected package names or credentials. It does not
install APK/IPA, generate test accounts, test other applications, or
intercept user data. A clean paired outcome is labelled
PAIRED_SYNTHETIC_FIXTURE_OBSERVATION with UNATTESTED_SELF_REPORT, **never**
a proven vulnerability or verified source-to-sink path in production.

CI exercises mocked native execution with paired witnesses and rejects
stale nonces, non-emulator serials, missing confirmation and controls with
the same effect. It does not boot a real simulator or run a real native app.

## Phase 4: static manifest gating and native fixture CI

For decoded Android source and an AndroidManifest.xml in the root:

    python3 "$BP" mobile-lab reachability \
      --sources /private/decompiled-src \
      --out /private/run/manifest-context.json

This overlays conservative cross-file leads with exact fully-qualified
component class matches. The output distinguishes exported, internal,
permission-gated and platform-dependent Android components, targetSdk
defaults, inherited application permission, custom permission definitions
and activity-alias targets. A missing android:exported with intent filter
at targetSdk >= 31 is reported as install-invalid on Android 12+.
Providers have separate read/write operation considerations.

These fields are *metadata context only*. They do not establish that
a particular entry method executes from an external caller, that the
caller has/does not have a permission, or that any sink has exploitable
impact. All lead severities remain unassessed and all runtime effects
unproven.

The native integration workflow at
.github/workflows/mobile-native-fixture.yml runs Android Emulator
build+install+candidate/control on eligible pull requests and also
compiles the owned Swift iOS Simulator fixture (without booting an
iOS simulator). GitHub-hosted CoreSimulator repeatedly stalled during
its initial data migration; consequently iOS runtime execution is
separately available through workflow_dispatch only, with bounded
boot checks and explicit errors. **An iOS compile pass is not an iOS
runtime pass**. Native test results are self-reported by only our own
org.bountypilot.fixture applications, never third-party targets.
Actual native verification is claimed only when a runtime job succeeds.

## Phase 5: Android callback-name and enabled-state context

The reachability report now includes an entry-method review signal from the first cross-file hop's caller method, compared to the framework callback vocabulary for the matching Android component kind. An activity's onCreate and onNewIntent are candidates, whereas an arbitrary helper called open receives NO_DIRECT_FRAMEWORK_CALLBACK_NAME_MATCH. An activity callback does not match a broadcast receiver callback.

These are method-name comparisons, **not verified framework invocation**. A method with a familiar name can still be unreachable, overloaded, or subject to runtime authorization checks.

Manifest application/component android:enabled=false now prevents POSSIBLE_EXTERNAL_STATIC_ENTRY classification. Resource-backed values or dynamic enablement remain unknown. Activity-alias target class matching is only a string-level clue.

Provider reviews preserve operation-specific readPermission and writePermission, counts of path-permission and grant-uri-permission entries, and flag possible URI grant overrides. Without a specific URI, operation, caller and device version, effective access is unknown.

The framework_callback_review_priority field is a queue-order hint, **not** a severity or exploitability assessment. All detected findings remain unverified.

## Phase 6: Java compiler-backed call-target alignment

This stage introduces a separate **JDK 17+ compiler AST** inventory for
Java sources. It fixes a major limitation of purely text-based call matching:
overloaded methods and same-named methods in separate packages can be
distinguished by the compiler's resolved method symbol. The shipped helper
is compiled with JDK javac and asks the Java compiler to parse/analyze the
operator's Java source under an empty, isolated project classpath with
annotation processing disabled; it does **not** compile the target app to
classes, run its methods or install an APK.

First, extract sources from a lawfully obtained, in-scope APK using the
separate operator-approved decompiler adapter, or supply an existing Java
source tree. Then run:

    python3 skills/bounty-pilot/scripts/bounty.py mobile-lab compiler-java \
      --sources /private/decompiled-application \
      --out /private/reports/java-symbols.json

To compare the compiler-backed source-call map with the existing lexical
source-to-sink **hypotheses**, optionally pass the produced graph:

    python3 skills/bounty-pilot/scripts/bounty.py mobile-lab crossfile \
      --sources /private/decompiled-application --platform android \
      --compiler-graph /private/reports/java-symbols.json \
      --out /private/reports/java-crossfile-comparison.json

Every candidate receives a separate compiler_alignment status:
ALL_HOPS_AST_SYMBOL_ALIGNED, SOME_HOPS_NOT_AST_ALIGNED, or
JAVA_ONLY_NOT_APPLICABLE. Every hop is matched on both source files,
caller/callee method names, the call line, target declaration line, and
current source SHA-256. A stale or changed source hash fails closed.
The original candidate's impact and severity **do not change**, because
matching a call target does not prove the value flowing into that call,
branch feasibility, authorization, export reachability or app runtime.

The symbol extractor limits Java files to 350, input source to 8 MiB,
individual files to 350 KiB, emitted edges to 3,000 and Java heap to
384 MiB. Source files are neither executed nor loaded as annotation
processors; third-party build scripts, Gradle, Maven and target classes
are not launched. A source path through a symlink is refused. Compiler
diagnostic counts and truncated coverage are included in the report;
absence of a resolved call is **not** evidence that a call is impossible
when the project has missing Android SDK dependencies or other errors.

The JDK code is a shipped trusted helper. It runs with a stripped
environment and isolated compilation classpath, but this is **not**
an operating-system network sandbox. For untrusted target source, use
a disposable no-network VM and a trusted local JDK. Native Kotlin,
Swift, Smali, reflection, interface dispatch at runtime, and Android
permission models remain outside compiler-backed coverage.

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
machinery for these subsequent steps. **This version only has an opt-in synthetic fixture runner, no native taint
analysis, no production target execution and no independently authenticated receipts.**

## Input safety and reproducibility

- Read-only, local files. Artifact must be a regular, non-symlink file of at
  most 2 GiB; it is hashed in 1 MiB chunks, without whole-archive reads. The analyzer never extracts its ZIP contents to disk.
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

1. Extend the shipped Java AST call-target alignment to Kotlin/Smali and
   Swift; develop compiler-resolved cross-file taint, branch/callback flows,
   precise Android runtime permissions and dynamic-dispatch modelling.
   This stage currently proves call-target binding only for eligible Java
   method calls, not dataflow or exploit reachability.
2. Deep-link / App Link / OAuth callback protocol checks with actual origin
   binding and app-claimant validation, not keyword matching.
3. Ship and test a maintained Android/iOS synthetic fixture app, and expand
   scoped runtime receipts beyond the current fixture-only self-report protocol.
4. Independently licensed historical CVE fixtures, corrected paired variants
   and blind A/B evaluation against existing Bounty Pilot.
5. Analysis of native parsers and dependency provenance.

Do not label the planned stages as implemented.

## Large APK/IPA streaming inventory

Archives up to 2 GiB are hashed in 1 MiB chunks; only explicitly selected small manifest/plist metadata members are decompressed. ZIP central-directory entry count, names, duplicates and declared uncompressed sizes are bounded (16 GiB total / 4 GiB per member). No ZIP members are extracted to disk or executed. A sparse synthetic APK over the previous 200 MiB cap is exercised in CI. This does **not** decode DEX or install the APK: source decompilation and permission-granted native execution require independent steps.
