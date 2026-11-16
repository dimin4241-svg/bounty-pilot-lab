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

## Phase 7: Bounded JDK AST Java argument-flow reviewer

This stage adds an additional **compiler-symbol-backed** Java-only
straight-line argument/dataflow reviewer. It is separate from the existing
lexical crossfile engine and from the JDK AST call graph introduced in Phase 6.

    python3 skills/bounty-pilot/scripts/bounty.py mobile-lab flow-java \
      --sources /private/decompiled-app \
      --out /private/reports/java-argument-flow.json

The shipped Java 17 helper parses/analyzes source with annotation processing
disabled, an empty application classpath and no execution of target classes.
The helper follows a **small subset** of explicit program behavior:

- Direct local assignments and copies, with overwrite invalidation.
- An Intent-source expression shaped like getIntent().getDataString(),
  getIntent().getStringExtra(), etc. The claimed Android origin is only a
  **syntax cue**, not a proven Android SDK method or attacker input.
- The first onNewIntent method parameter is a **method-name cue**, not a
  verified framework callback.
- Actual Java compiler ExecutableElement target binding at inter-file calls,
  carrying only directly tainted identifiers or the explicitly recognized
  source expression to the callee's corresponding formal parameters.
- Up to three resolved inter-file method calls, then a **sink-name cue**
  such as loadUrl or setResult. It is not an Android/WebView type check.

To avoid fabricating paths, the helper **does not** traverse conditional
branches, loops or try/catch. Encountering these clears the local taint
state, so false negatives are expected. Method returns, fields, dynamic
dispatch, lambdas, captures, Kotlin and Smali are not analyzed as dataflow
sources. An expression such as sanitize(value) is not assumed to return
tainted input; the analyzer may miss vulnerable variants behind wrappers.

The JSON report records pinned SHA-256 files, exact compiler-bound
inter-file method symbols, source and sink code lines, diagnostic errors,
unsupported control-flow statements, budget limits and evidence caveats.
Every finding is a **static review candidate** with unassessed severity,
unknown external reachability and impact NOT_ESTABLISHED. Runtime tests and
independent caller/permission validation remain separate.

A syntactically named getIntent method can be an unrelated user-defined
helper; likewise, a user-defined loadUrl may not be a real WebView sink.
Future versions should bind Android framework SDK stubs and extend the
abstract interpretation model. The JDK process is not OS-network-sandboxed;
use a trusted local JDK within an isolated, no-network environment for
untrusted applications.

## Phase 8: Fixed-dispatch Java calls and restricted conditional joins

The `flow-java` review also follows **compiler-bound same-file calls** when
the call has fixed dispatch: `static`, `private`, `final` methods, members
on `final` classes, or explicit `super` calls. This extends the prior
interfile-only argument flow; **a compiler-resolved virtual method does not
prove which overriding implementation executes at runtime**. Calls whose
dispatch can vary are not traversed. Each traversed method call counts
toward the existing three-hop budget, including same-file edges.

For limited `if`/`else` statements, the helper symbolically evaluates
only simple, side-effect-free conditions and direct assignments/copies of
local variables. The state after the conditional retains an input origin
**only when both outcomes carry the exact same origin**. A missing
`else` is treated as the unchanged incoming state. Sanitization on
only one branch therefore removes the assertion of flow. Complex
conditions, method calls in branches, loops, nested branches, try/catch,
object field writes and other unsupported statements still invalidate
the state; sinks inside such branches are not reviewed.

This is **not general control-flow reachability**. Conditional expressions
are not evaluated to true/false; no dynamic dispatch, Android framework
callback, field, return value, asynchronous message, Kotlin, or runtime
method is modeled. The diagnostic counter for unsupported/partially
reviewed conditional statements remains nonzero even where the limited
assignment join succeeds. The parser/report schema and historical
`impact: NOT_ESTABLISHED` convention are unchanged.

This stage is verified only with local synthetic Java fixtures; actual
APK attacks, production app reachability and authorization bypasses
must be established independently on permitted test systems.

## Phase 9: Pure Java return summaries and private current-object fields

The `flow-java` analyzer now follows two additional **strictly bounded**
static dataflow patterns:

- **Pure returns:** a compiler-resolved fixed-dispatch helper may return
  one of its arguments (including through straightforward local copies).
  Its complete body must consist solely of local declarations and direct
  assignments followed by one final return. Branches, field access, side
  effects, unknown method calls, and virtual dispatch reject this summary.
  Return provenance is explicit: the report records a METHOD_CALL edge
  into the helper and RETURN_TO_CALLER edge back to the original method,
  validated as a balanced stack before subsequent calls.
- **Private current-object fields:** the analyzer can follow direct writes
  and reads of `this.privateField` or an unqualified private instance field
  in the **same method invocation**, with compiler-resolved field symbols.
  Unknown top-level method calls invalidate the field map. Arbitrary receiver
  fields such as `other.payload`, public/static fields, object aliases,
  arrays, cross-method field persistence, and concurrent mutations are
  **not** analyzed. This is not general heap or alias analysis.

The Phase 9 baseline used three provenance edges. Phase 10 increases the
shared provenance ceiling to six edges (while retaining a separate
three-call interprocedural traversal limit) to represent setter and getter
call/return pairs plus the final sink entry. Backward return edges are
**not** actual Java method invocations. Older 8-column hop records remain
parser-compatible, while new records name their edge kind explicitly.

This stage is a conservative offline static review, not Android API binding,
entrypoint reachability, an external attacker primitive, a proven protected
sink effect, or a validated vulnerability. `impact` remains
`NOT_ESTABLISHED`, severity remains unassessed, and no target application
is run by the JDK analysis.

## Phase 10: Fresh-object aliases and bounded setter/getter heap summaries

The Java-only `flow-java` reviewer includes one deliberately narrow heap
model, implemented in the shipped, trusted JDK helper:

- Track freshly allocated `final` Java classes with source-visible, no-arg
  default construction and **no user-defined constructors, inheriting classes,
  escaping instance initializer, or dynamic allocation body**. Eligible member
  classes must be `static`.
- Recognize exact compiler-resolved copies/reassignments of *local object
  reference variables*; two `new Box()` occurrences are separate identities
  and `Box alias = original` keeps identity.
- Summarize only compiler-bound, fixed-dispatch direct setter methods whose
  entire body assigns one `String` parameter to a **private instance String
  field of that same class**, and direct getters whose entire body returns
  that same field. The setter and getter must be called through tracked
  local receivers. No arbitrary return value, call, branch, sanitizer,
  callback, array or object field receiver is accepted.
- Record call and return edges for each setter/getter, and retain evidence
  only while the object has **not escaped**. An unknown receiver method,
  passing the reference to another function, storing it into an array/field,
  unsupported statement or unknown alias invalidates the tracked object
  and its stored origins. An escaped object is not re-certified by a later
  setter.
- A read may subsequently flow through an independently compiler-bound
  local/cross-file helper to an existing sink-name cue. Each provenance
  route is validated using balanced typed METHOD_CALL and
  RETURN_TO_CALLER edges; maximum 6 edges, maximum 3 nested call frames.

This is **not** whole-program points-to analysis, global/inter-thread heap
analysis, accurate Android framework API binding, real execution, or a
bypass/exfiltration finding. Constructors, non-final classes, complex
accessors, public/static/non-String fields, escaped objects, reflection,
serializers, coroutines, callbacks and non-identity object transformations
remain outside the model. The limitation is intentional, and false
negatives are expected.

Synthetic differential controls cover distinct allocations, reassignments,
alias copies, literal overwrites, escaped aliases, constructor effects,
unknown receiver mutations and unsupported branches. Every finding stays
`impact: NOT_ESTABLISHED`, `reachability: UNKNOWN` and severity unassessed.

## Phase 11: Kotlin receiver guards and exact Smali static descriptors

The cross-file Kotlin *lexical* path matcher now distinguishes two receiver
forms instead of treating all class qualifiers as equivalent:

- Calls like `Router.forward(value)` require a uniquely indexed Kotlin
  `object Router` declaration. An ordinary `class Router` is not a valid
  static receiver and is rejected.
- Calls through a locally created instance (`val router = Router()`;
  `router.forward(value)`) require a uniquely indexed Kotlin **final class**
  rather than `open`, `abstract` or `sealed` classes.
- Java/Kotlin cross-language call guesses are not promoted to Kotlin edges.
  The Kotlin edges are still *lexical* and not bound by the Kotlin compiler.
  Inline functions, generated bridges, companion objects, constructors with
  arguments, extension functions, type aliases, runtime overrides, implicit
  receivers, nested calls, lambdas, coroutines and Android framework types
  remain outside this narrow model.

The new **Smali cross-file descriptor** analyzer is an independent optional
offline command:

```sh
python3 skills/bounty-pilot/scripts/bounty.py mobile-lab smali-crossfile \
  --sources /private/decompiled/smali \
  --out /private/reports/smali-descriptor-review.json
```

Its bounded parser indexes exact DEX class descriptors, and matches
`invoke-static {vN}, Lpackage/Class;->method(Ljava/lang/String;)V` only
to a **unique exact static declaration** with that full class, method,
parameter and return descriptor. It propagates a string provenance register
via `move-result-object` and `move-object`, up to three inter-file calls.
An Intent-source syntax cue requires a local
`Activity.getIntent():Intent` return followed by a matching
`Intent.getDataString():String` or `getStringExtra(String):String`.
A supported sink cue is the exact
`WebView.loadUrl(String):void` descriptor. Exact names are still *bytecode
syntax*, not authenticated Android SDK provenance, caller control or actual
network navigation.

Unknown operations, branching, exception instructions, range invokes,
result or heap aliases and dynamic dispatch do not create positive
chains. Duplicate class descriptors, signature/arity mismatches, register
overwrites, unrelated same-named methods and missing move-results are
negative controls. The parser never executes or loads a target dex/Smali
method, app or build script. Source files are hashed and bounded, and JSON
report paths are private/no-overwrite.

Smali and Kotlin reports remain **unverified static leads** with
`reachability: UNKNOWN`, `severity: unassessed` and
`impact: NOT_ESTABLISHED`. This stage does **not** unify Java, Kotlin and
Smali symbols into a single verified call graph, and does not claim to
reproduce a bug on any third-party app.

## Phase 12: Smali range calls, pure return routes, and optional Kotlin JVM alignment

The independent Smali descriptor review additionally recognizes explicit
`invoke-static/range {v3 .. v3}` and `invoke-virtual/range {v0 .. v1}`
**only** when all registers share one register bank, the bounded range
expands exactly to the signature's required narrow reference parameters
and the method descriptor is already among supported cases. Wide types,
mixed `v`/`p` banks, dynamic/interface dispatch, nontrivial ranges and
unknown instructions still fail closed.

A one-argument `invoke-static` with an exact
`(Ljava/lang/String;)Ljava/lang/String;` descriptor may return input taint
through a source-visible **pure method** consisting only of direct
`move-object` copies or constant assignments and a final `return-object`.
No calls, object fields, `check-cast`, arithmetic, branches, catches,
exception edges or side effects are summarized. The flow report explicitly
records `STATIC_CALL` and `RETURN_TO_CALLER` edges; these must form a
balanced method-descriptor route. The overall provenance is limited to six
edges, and forward static calls to three nested frames. `move-result-object`
must immediately follow the producer instruction, except non-executable
source directives; even `nop` invalidates the pending result.

For a **separately provided** Kotlin JVM class tree, optionally compare
lexical Kotlin cross-file candidates to actual JVM callsite metadata:

```sh
python3 skills/bounty-pilot/scripts/bounty.py mobile-lab crossfile \
  --sources /private/decompiled/kotlin \
  --platform android \
  --jvm-classes /private/compiled-jvm-classes \
  --out /private/reports/kotlin-jvm-review.json
```

The bounded read-only classfile parser checks exact JVM class owner, Kotlin
metadata marker, `SourceFile`, caller method, bytecode callsite source line,
unique invocation and the callee's exact JVM `(String):void` descriptor.
Only explicitly identified Kotlin singleton or final-instance invocation
candidates are eligible. Classfile and source SHA-256 fingerprints are
reported; classes are never loaded or executed.

**Critical limitation:** provided classfiles are *not cryptographically
proven* to have been built from the current `.kt` files. A matching
bytecode callsite is only `ALL_HOPS_JVM_BYTECODE_ALIGNED_UNATTESTED_SOURCE_BUILD`.
The report explicitly records `source_build_freshness_verified: false`,
`compiler_provenance_authenticated: false` and
`runtime_effect_verified: false`. Stale, substituted or malicious
classfiles can mislead this comparison. For actual source-to-bytecode
attestation, the build needs pinned inputs, compiler version, dependencies
and independently verified reproducible outputs.

The Kotlin matcher remains lexical when no classfiles are provided. Smali
and Kotlin findings remain `reachability: UNKNOWN`,
`severity: unassessed`, `impact: NOT_ESTABLISHED` and never prove
exploitation of an Android application.

## Phase 13: Smali forward-only CFG joins and Kotlin operator hash locks

The `smali-crossfile` reviewer now builds a strictly forward-only,
acyclic control-flow graph for `if-eqz`, `if-nez`, `goto`,
`goto/16`, `goto/32` and unique in-method labels. All branch targets
must resolve to later instructions. At a join, a register retains origin
only if **every reachable predecessor** carries the identical origin
and full call/return provenance. The analysis limits method length,
branch count, call depth and total visited instruction steps.

Loops/backward edges, try/catch, exception handlers, switches, monitors,
unrecognized instructions and malformed labels remain unsupported. The
review retains `branch_feasibility_verified: false`, unknown runtime
reachability, unassessed severity and `impact: NOT_ESTABLISHED`.

For separately compiled Kotlin JVM classfiles, an optional **unsigned
operator-supplied snapshot lock** compares exact current `.kt` source
and `.class` owner SHA-256 digests against a JSON manifest. For each
Kotlin-only cross-file hop, both caller/callee source and class digests
must match. Missing or changed bytes downgrade otherwise matching
bytecode evidence to `JVM_SNAPSHOT_LOCK_MISMATCH_OR_MISSING`. Invalid
hashes, path traversal, duplicate JSON keys and wrong schema are
rejected.

Example operator-created lock (replace placeholders with observed hashes):

```json
{
  "schema_version": 1,
  "kind": "operator-pinned-kotlin-jvm-snapshot",
  "source_sha256": {
    "app/Entry.kt": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  },
  "class_sha256": {
    "app/Entry": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  }
}
```

```sh
python3 skills/bounty-pilot/scripts/bounty.py mobile-lab crossfile \\
  --sources /private/source --platform android \\
  --jvm-classes /private/classes \\
  --jvm-snapshot-lock /private/operator-lock.json \\
  --out /private/reports/kotlin-jvm-locked-review.json
```

A matching snapshot is `OPERATOR_PINNED_BYTES_MATCH_UNATTESTED_BUILD`,
**NOT a verified source-to-compiler-to-bytecode build**. The manifest
may itself be stale or forged. The report always sets
`independently_signed: false`, `reproducible_build_verified: false`
and `source_build_freshness_verified: false`. Truly reproducible builds
require an independently trusted version-pinned compiler, dependencies,
isolated build inputs and byte-for-byte rebuild comparison. These remain
unimplemented. No target app classes or Gradle scripts are executed.

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

1. Implement independent Kotlin byte-for-byte reproducible builds with
   a trusted immutable compiler and dependencies, not just an unsigned
   operator SHA-256 lock. Extend JVM signatures and Kotlin CFG/receiver
   provenance; add explicitly modeled loop/exception effects and DEX class
   resolution to Smali without guessing. Add Android permission/callback
   and Swift review separately. Static paths do not prove exploitability.
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
