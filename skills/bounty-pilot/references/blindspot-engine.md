# Blind-spot data collection

These optional commands turn selected parts of `blind-spots.md`, `misses.md`,
`stateful-search.md`, `impact-first.md` and `coverage-gap` into machine-readable review queues. None
is added to the default audit. Every report says what it observed and what still needs a native test
or independent review.

## P2: invalidation, differential and branch gaps

```sh
python3 <skill-dir>/scripts/blindspot_engine.py state-invalidation \
  --repo <checkout> --out <run>/state-invalidation.json
python3 <skill-dir>/scripts/blindspot_engine.py branches --lcov <coverage.info> \
  --repo <checkout> --out <run>/branch-gaps.json
python3 <skill-dir>/scripts/blindspot_engine.py mutations --results <mutator.json> \
  --out <run>/mutation-gaps.json
```

`state-invalidation` filters the existing lexical state graph to writer/reader overlaps whose
function names resemble transfer/revoke/upgrade/oracle/withdraw/cancel/delete/retry transitions.
It supplies source locations and a concrete next-evidence checklist. Its edges are heuristic, not
a call graph or a reachable sequence. Confirm the same storage, permissions and order in the source,
then write a native candidate and control test.

`branches` reads LCOV `BRDA` records. With `--repo`, it also records the current target commit and
hashes for source files it could map under the checkout. It cannot establish that coverage was
generated at that commit, so retain the build log and pinned command. Uncovered exception paths,
first/last-user cases and disabled tests remain investigation prompts.

`mutations` accepts a JSON object with a `mutants` or `results` array. Survivors and unresolved
mutants become review leads. The tool does not run or apply mutations, and a surviving condition is
not a vulnerability.

Differential test plans are built through `experimenter.py plan`, which uses the safe native-test
selector builders:

```sh
python3 <skill-dir>/scripts/experimenter.py plan --stack foundry \
  --spec <private>/differential-spec.json --out <run>/differential-plan.json
```

The spec includes `kind: differential`, an explicit `equivalence_basis`, the pinned
`source_revision`, an `invariant`, and pairs of existing candidate/control test names. The native
tests must make the comparison; the CLI runner cannot decide whether batch/serial, router/direct,
primary/fallback, old/new, or reordered behavior should be equal. Include documented fee,
rounding and temporal tolerances. To test one large operation against several smaller ones, both
cases must start from equivalent state fixtures.

## P3: old code, fix propagation and trust boundaries

```sh
python3 <skill-dir>/scripts/blindspot_engine.py legacy --repo <checkout> \
  --out <run>/legacy-review.json
python3 <skill-dir>/scripts/blindspot_engine.py patch-propagation --repo <checkout> \
  --commit <security-fix-commit> --out <run>/patch-propagation.json
python3 <skill-dir>/scripts/blindspot_engine.py trust --model <private>/trust-flows.json \
  --out <run>/trust-boundaries.json
```

`legacy` combines git file age with lexical dependency edges, authority and asset-operation signals,
and a test-symbol reference check. The score components are printed per candidate; age is only
context, not risk by itself. `test_symbol_reference_found` is not runtime coverage.

`patch-propagation` reads a local fix commit and proposes same-name sibling functions, falling back
to low-confidence identifier overlap. It does not infer the patch's protection or semantic
equivalence. Compare all alternate handlers/versions/instances and prove reachability before
opening a finding.

`trust` validates a human-built component/flow inventory. Each flow records parameter origin,
signer/authenticator, validation and the value ultimately executed. External components whose
source is not available stay listed as an explicit gap. The tool does not statically infer a full
frontend-to-contract flow or validate a signature implementation.

## P4: live config, capacity and rejected leads

```sh
python3 <skill-dir>/scripts/blindspot_engine.py live-config --snapshot <private>/live-state.json \
  --out <run>/live-config-review.json
python3 <skill-dir>/scripts/blindspot_engine.py live-config --snapshot <private>/live-state.json \
  --query-live --out <run>/live-config-review.json
python3 <skill-dir>/scripts/blindspot_engine.py capacity --measurements <private>/capacity.json \
  --budget 30000000 --out <run>/capacity-review.json
python3 <skill-dir>/scripts/blindspot_engine.py reopen --repo <checkout> \
  --findings <run>/findings.json --out <run>/reopen-review.json
```

The live snapshot explicitly provides expected values and per-instance `calls` (`key`, `to`, ABI
encoded `data`, and static return `decoder`). `rpc_env` names an environment variable holding the
read-only endpoint; the endpoint value is never stored. Without `--query-live`, only supplied values
are compared. With that explicit flag, the module issues `eth_chainId`, `eth_blockNumber` and the
listed `eth_call`s at a pinned block (or the head it just read). It has no transaction method. A
missing RPC value or failed read produces an open `LIVE_STATE_UNVERIFIED` task. A difference is not
automatically unsafe.

Capacity review consumes measured sample rows (`load`, integer `gas`/`compute`/`bytes`, `outcome`,
`recovery`, and evidence reference). It reports the first supplied load above budget or marked as
failed. It never starts a load test. A single revert is not permanent denial of service; test
recovery after load reduction separately.

Rejected leads are queued only when an affected path changed since the recorded revision, new
evidence is attached, or the source delta could not be established. It never changes `refuted` or
`parked`; an independent reviewer decides whether to reopen. No new evidence leaves the prior
decision closed.

All reports belong in the private run. Keep raw RPC endpoints and credentials out of snapshots.
Only the explicit `--query-live` mode makes network calls, and those are limited to the three
read-only JSON-RPC methods listed above; none of these commands sends a transaction.
