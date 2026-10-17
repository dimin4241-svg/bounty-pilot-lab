# Optional verification helpers

Stage 5 helpers. Every one of them produces review material, never exploit evidence on its own: a
claim is verified only by a reproducible test against unmodified production source.

## Mandatory between-pass execution gate (new runs)

Native execution is not optional for the highest-priority testable survivors.
A private experiments.json row points to a scenario_runner.py --allow-exec
result file (candidate and negative-control). Run bounty.py experiment-gate
--run <run> --gate before the next broad reading pass. A genuine toolchain
blocker with an attempted alternative may permit further reading without
confirming any claim. See evidence-first.md.

## Bounded state-model counterexamples

Author an evidence-backed, explicit finite JSON state model (integers and strings, no floats), and
try both the candidate and a protected control. Examples are in `templates/high-impact/`.

```sh
python3 <skill-dir>/scripts/scenario_fuzz.py --model <run>/model.json \
  --control <run>/control.json --depth 5 --max-seconds 60 --out <run>/model-exploration.json
python3 <skill-dir>/scripts/impact_feasibility.py --case <run>/impact-case.json \
  --out <run>/impact-estimate.json
```

A found trace proves an issue only in the *investigator's model*, not in deployed code. No
counterexample within the bounds does not establish safety; cost calculations rely on the supplied
assumptions and do not establish severity.

## PoC skeletons

Deliberately failing candidate and control skeletons for Solidity, native Rust, Python or Go from a
source-anchored hypothesis (example in `templates/stateful/finding.example.json`):

```sh
python3 <skill-dir>/scripts/poc_scaffold.py --finding <run>/hypothesis.json \
  --stack rust --out-dir <run>/poc
```

Move, Cairo, CosmWasm and other ecosystems need native harnesses instead of a generic Rust or
Solidity test. Fill realistic setup, reachable actions and both assertions before running anything.
The candidate test passes when the bug is demonstrated; the control passes when the protection
holds (`templates/README.md`).

## Snapshot invariants and the paired runner

Define explicit, provenance-labelled predicates over captured JSON snapshots, and run paired
candidate/control test commands. For existing native property or fuzz tests, `native_fuzz_plan.py`
writes an unexecuted plan for review.

```sh
python3 <skill-dir>/scripts/invariant_check.py --spec <run>/invariants.json \
  --snapshot <run>/snapshot.json --out <run>/invariant-results.json
python3 <skill-dir>/scripts/scenario_runner.py --plan <run>/test-plan.json \
  --repo <disposable-checkout> --out <run>/scenario-dry-run.json
# Only after reviewing each argv, in an isolated, secret-free test environment:
python3 <skill-dir>/scripts/scenario_runner.py --plan <run>/test-plan.json \
  --repo <disposable-checkout> --allow-exec --out <run>/scenario-results.json
```

The runner rules:

- The plan needs candidate and negative-control cases sharing a `pair_id`.
- It has no shell, rejects shell and interpreter `-c` wrappers, and starts in dry-run mode.
- The environment is an allowlist. A variable a test needs (a fork RPC, say) must be named in
  `pass_env`; values are redacted from the captured output.
- It refuses to run where a `.env` file would be auto-loaded (Foundry does this) unless
  `--allow-dotenv` is passed after you have checked the file holds no secrets.
- A case where the selector matched zero tests is `no-tests-ran`, never a pass.

Both commands returning their expected exit codes is **not** proof of exploit truth; inspect the
assertions and the unchanged target source. Never execute untrusted repo-supplied plans, access
production keys, load-test live infrastructure or broadcast transactions.

## Proving a negative about a guard: mutate your own detector

A fuzz campaign that reports "no violation in 12,000 runs" is worth nothing until you show the harness
could have seen one. The cheap, decisive move is to **mutate the thing under test and confirm the
harness catches the mutant**.

The shape, from a run where it settled the last path to a critical. The question was whether a
pre-execution guard and the executor could be made to parse the same calldata differently — a
guard/effect split. The campaign reported zero splits over three input shapes, including a benign
payload at the strict offset with a hostile one planted elsewhere and the pointer aimed at it. What made
that believable was the control: **420 of 1,500 inputs reached the executor at all** (so the harness was
not just rejecting everything early), and a deliberately mis-written version of the guard was caught on
**331 of those 420**, while the real guard was caught **0** times. Same harness, same inputs, one line
changed. The negative result is now a measurement rather than an absence.

Do the same for an invariant suite: inject the violation you are claiming cannot happen — a one-wei
token leak with `vm.prank`, a one-wei write to the accounting mapping with `vm.store` — and confirm the
detector fires, and that a *legitimate* near-miss does not. Record all three numbers: reached, caught
when mutated, caught when real. Without them, `HELD` means "my test did nothing", and that is the most
common way a run concludes a surface is clean.
