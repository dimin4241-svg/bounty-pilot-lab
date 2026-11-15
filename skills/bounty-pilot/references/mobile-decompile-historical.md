# Operator-opted APK decompilation and paired evaluation

## Local Android decompilation

    python3 skills/bounty-pilot/scripts/bounty.py mobile-decompile \
      --artifact /private/app/authorized.apk \
      --sources-out /private/decompiled/authorized-v1 \
      --tool jadx \
      --confirm-isolated-local-analysis \
      --out /private/reports/decompile-v1.json

Use --tool apktool for Smali/resource output. The selected tool must
already be installed in local PATH; the adapter does not download a
binary, plugin or APK. It invokes a fixed argument list with no shell
interpolation, checks the APK is a bounded ZIP containing
AndroidManifest.xml, streams an exact SHA-256 before and after the tool
runs, and inventories decompiled file extensions. It will only create
NEW source-output directories and report files. A missing tool, changed
input APK, non-regular artifact, symlinked fixture path or unapproved
run is refused. Output is not a validated source-to-sink proof.

IMPORTANT: The adapter does not impose OS-level network isolation
or protect against vulnerabilities in JADX/Apktool itself. Run only
legally obtained, in-scope APKs on an isolated machine, preferably a
disposable VM with network disabled; verify the installed tool and its
dependencies independently. Local execution is explicitly opted in,
and no real app/device is installed or interacted with by the adapter.
On a large APK, decompilation may take considerably more time and
disk space than streaming metadata inspection.

Once the local tool succeeds, use the existing Mobile Lab source
commands on the extracted directory:

    python3 skills/bounty-pilot/scripts/bounty.py mobile-lab crossfile \
      --sources /private/decompiled/authorized-v1 --platform android \
      --out /private/reports/flow-v1.json

    python3 skills/bounty-pilot/scripts/bounty.py mobile-lab reachability \
      --sources /private/decompiled/authorized-v1 \
      --out /private/reports/reachability-v1.json

The second command needs a correctly decoded AndroidManifest.xml at
the expected source root. JADX output layouts and manifest fidelity
vary; lack of a usable manifest is a *coverage limitation*, not a
negative vulnerability result.

## Paired vulnerable/fixed evaluation

    python3 skills/bounty-pilot/scripts/bounty.py historical-paired-eval \
      --answers /private/corpus/answer-keys.json \
      --predictions /private/experiments/model-output.json \
      --out /private/reports/pair-metrics.json

Two separated schema-version 1 JSON files are required:
- answers: cases with case_id, pair_id, variant (vulnerable/fixed),
  source_commit (40 lowercase hex), and license (nonempty).
- predictions: exactly those case_id values with detected boolean.

Each pair must have one vulnerable and one fixed revision with distinct
source commits. The scorer gives TP/FP/TN/FN, precision, recall, false
positive rate, and count of fully correct vulnerable/fixed pairs.
It does NOT prove the GitHub sources, claims, license or hidden
evaluation status are genuine: operators must independently confirm
their provenance, that predictions were made before answer exposure,
and that detection means a real independently confirmed PoC.
The automated tests bundled with this module are synthetic only,
not genuine historical CVE cases or external benchmark performance.
