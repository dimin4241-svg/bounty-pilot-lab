# Offline research-run orchestrator

A bounded, no-network entrypoint for multiple already implemented Bounty
Pilot reviewers. This is useful for one-command, local, AI-free analysis
of prepared files. It never executes an untrusted APK, an Electron app,
a shell command, a native target, a decompiler or a live HTTP request.

    python3 skills/bounty-pilot/scripts/bounty.py research-run \
      --manifest plan.json \
      --work-root /private/pilot-work \
      --out-dir /private/pilot-run-001

The manifest path is relative to work-root, and outputs are NEW files
in a NEW directory OUTSIDE the work-root. The output dir is mode 0700,
individual JSON results are mode 0600.

Example work-root/plan.json:

    {
      "schema_version": 1,
      "scope": {
        "operator_confirmed": true,
        "policy_file": "program-rules.txt",
        "policy_sha256": "REPLACE_WITH_ACTUAL_64_CHAR_SHA256"
      },
      "jobs": [
        {"id": "mobile-1", "engine": "android-entry",
         "path": "unpacked-android"},
        {"id": "electron-1", "engine": "electron",
         "path": "unpacked-electron"},
        {"id": "oauth-1", "engine": "oauth", "path": "oauth-events.json"},
        {"id": "variants-1", "engine": "graph-variant",
         "path": "before-after-graph.json"}
      ]
    }

Calculate the exact digest of your current program rules file using
shasum -a 256 /private/pilot-work/program-rules.txt on Mac. The router
verifies bytes against this supplied SHA-256. This does NOT verify the
scope policy itself or establish legal authorization: the operator must
read and confirm the current program's allowed assets and techniques.

The supported offline engines are android-entry, mobile-crossfile
(requires job.platform android or ios), electron, ios-trust (optional
job.entitlements), impact (job.receipts), oauth, graph-variant, feedback,
and paired-eval (job.answers and job.predictions). Each job is bounded,
does not modify the target and writes an independent report plus index.
Malformed paths, symlinks, duplicate job identifiers, unknown engines,
missing scope confirmation and stale scope-document hashes fail closed.

Non-offline operations are deliberately absent. Decompiling APKs with
mobile-decompile, running Android/iOS native fixtures, or any network
authorization test require their own separate explicit approval and
dedicated isolation. All index results explicitly remain UNVERIFIED:
this job is a reproducible coordinator, not an agent authorized to
invoke external security actions autonomously.
