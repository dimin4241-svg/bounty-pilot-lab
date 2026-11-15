# Variant, Electron, iOS and outcome feedback extensions

All modules run offline on operator-supplied files and make no network requests.

## Graph variant review

    python3 skills/bounty-pilot/scripts/bounty.py graph-variant-lab \
      --case /private/research/graphs.json \
      --out /private/reviews/variants.json

The case is a schema_version 1 JSON document with before and after graphs.
Each graph has nodes with id, kind (entry/method/sink), guard_present
(boolean), and edges with from/to node ids. The graph traversal finds
unguarded paths to a sink and compares them with previously guarded paths.
Output states are lexical GRAPH VARIANTS, not proven authorization bypasses.
Inputs are operator-authored: compiler-resolved call graphs are **not**
automatically supplied by this module. Guard cues do not prove guard
effectiveness. All graph/path enumeration is bounded.

## Electron source trust review

    python3 skills/bounty-pilot/scripts/bounty.py electron-lab \
      --sources /private/unpacked-electron-app \
      --out /private/reviews/electron.json

Use independently vetted, locally extracted source of an authorized app.
This module never executes an Electron app or extracts app.asar.
It inventories line/digest anchors for BrowserWindow, preload, contextBridge,
ipcMain/ipcRenderer, permissions, desktopCapturer, remote navigation and
risky webPreferences values. It does NOT trace actual sender origin,
permission decisions, preload bridge reachability or protected effects.
A project-wide candidate is only a COLOCATION hint.

## iOS schemes and trust declarations

    python3 skills/bounty-pilot/scripts/bounty.py ios-trust-lab \
      --info-plist /private/Info.plist \
      --entitlements-plist /private/entitlements.plist \
      --out /private/reviews/ios.json

The second plist is optional and explicitly NOT asserted to be effective
signed entitlements. Maps URL schemes, associated-domain claims,
application groups and Keychain access-group names. Actual Universal
Links require AASA and OS association verification; signed entitlements
and current-device Keychain authorizations remain UNVERIFIED.

## Adjudicated outcome feedback

    python3 skills/bounty-pilot/scripts/bounty.py bounty-outcome-feedback \
      --history /private/research/outcomes.json \
      --out /private/reviews/outcomes.json

Schema_version 1 input contains reports, each with an opaque report_id,
method (e.g. mobile/webapi/web3), status (submitted/pending/accepted/paid/
duplicate/invalid/informational/rejected/out-of-scope), research_hours
as a non-negative decimal string, payout_amount as a non-negative decimal
string, and currency as ISO three uppercase letters. Only paid reports
may record nonzero payouts. Rates use only adjudicated reports; pending
reports are excluded. Currency totals are NOT added across currencies
or converted. No future payout is predicted. Small sample bias remains.

Existing research facilities and the evidence verifier remain the
system of record. Neither importing skills nor lexical cue matches nor
JSON observations count as confirmed bugs or bounty entitlement.
