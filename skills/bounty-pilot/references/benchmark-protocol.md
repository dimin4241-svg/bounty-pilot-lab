# Bench 0.43: truthful historical comparison and blind AI audit protocol

## What CI actually measures

The `historical-probe` workflow obtains the public Monad BFT **pre-fix**
commit pinned in CaseForge (`6aaccc2ec51eac66a2cf18ec64ab0df2c1448990`),
sparse-checks out three historical crates and runs the **same read-only**
`research_diff.py scan` against the identical source scope from:
- Immutable Lab 0.41.1 baseline: `651f46eedb904ac2f738843ae0413e1eb3cf638a`
- Current stacked Lab candidate: PR #17's `research_diff.py`

Both scanners are subprocesses with no shell and a minimized environment. The
probe verifies checkout HEAD, clean tracked code, scanner output type, and
declared top-level scopes. It reports only lexical candidate counts,
intersections, SHA-256 fingerprints, input scope and commits.

**THIS IS NOT A BLIND AI HUNT.** We specifically picked crates relevant to
published Monad bugs; the target identity and the CaseForge catalog already
exist in the toolkit. Both versions share this scanner, so the run is a
parity/safety diagnostic, not evidence that Lab 0.42 discovered known bugs.
No PoC is executed; published truth is not inspected by this probe.

## Genuine old/new AI rediscovery — requirements BEFORE testing

1. **Unseen targets:** at least five independently pinned vulnerable source
   snapshots held out from prompt and tool development. The present CaseForge
   has only one pinned Monad snapshot, even though that audit contains four
   distinct findings. It is a calibration sample, not a statistically useful
   independent benchmark. Do not infer an unpublished source commit.
2. **Two isolated workers:** give each model only an opaque task ID, the
   exact same pinned target source checkout and one appropriate installed skill
   revision. Do not mount CaseForge catalog, answer keys, audit reports,
   PR history that quotes the bug, or the judging workspace. Enforce separate
   process/filesystem/network restrictions outside this script; shell flags do
   not create a sandbox. A baseline worker must not view the candidate skill.
3. **Identical budget:** same model and model version, model context limits,
   allowed tools, target scope, wall-clock time, USD/token limits, repeat
   policy and independent PoC requirements. Record API/provider receipts,
   tool transcripts, time and source/skill commit digests. Do not guess usage.
4. **Precommit:** run existing `bounty.py backtest init` on each sealed
   pinned checkout, write private `findings.json`, then
   `bounty.py backtest seal`. The hunter must commit before a judge can read
   the authoritative report. Never edit findings after sealing; compare
   sealed SHA-256 digests and preserve negative controls and native outputs.
5. **Adjudicate afterwards:** a separate reviewer imports the published
   truth, decides mechanism-level match vs coincidence, checks actual
   vulnerable call path and PoC, scores each arm using the existing
   `bounty.py backtest score`, then uses `bench_compare.py` with paired
   cases and real model/cost metadata. If truth, scope, pin or budget differs,
   invalidate or label the result incomparable, not a win.
6. **Report uncertainty:** measure historical rediscoveries, false positives,
   hours and provider-reported cost. A lexical hint is not a rediscovery;
   finding a bug from an already seen report is not blind; a missing
   independent snapshot cannot be counted as a lost vulnerability.

GitHub Models was retired on 2026-07-30, so no built-in GitHub Models
inference is assumed. A separate model connection (and explicit spending
limit) must be arranged to execute a genuine autonomous AI comparison. The
current workflow needs no API keys, does not make an AI request, and spends
no model tokens.

## Better evaluation corpus: the public EVMbench detect tasks

Before inventing more benchmarks, evaluate whether the independently maintained
[EVMbench suite](https://github.com/openai/frontier-evals/tree/main/project/evmbench)
can supply sealed, diverse historical tasks. At the audited repository revision
`b78dab1da774a6456b1ed9c48c9ff194ee3ff36d`, its
`project/evmbench/splits/detect-tasks.txt` lists **40 audits**, providing
far broader project variety than the single pinned Monad CaseForge snapshot.
EVMbench also supplies the audited code, evaluation grading and Docker-based
agent harness. Review each audit's native test setup and task eligibility;
do not equate an audit task with a confirmed High finding, or assume all
forty are unseen by the tested model.

Official reproducibility workflow (inspect upstream instructions first):

```sh
git clone https://github.com/openai/frontier-evals.git
cd frontier-evals
git checkout b78dab1da774a6456b1ed9c48c9ff194ee3ff36d
cd project/evmbench
uv sync
docker build -f ploit/Dockerfile -t ploit-builder:latest --target ploit-builder .
uv run docker_build.py --split all
# A no-op diagnostic to test the harness only:
uv run python -m evmbench.nano.entrypoint \
  evmbench.audit_split=debug evmbench.mode=detect \
  evmbench.hint_level=none evmbench.apply_gold_solution=False \
  evmbench.solver=evmbench.nano.solver.EVMbenchSolver \
  evmbench.solver.agent_id=human
```

For a genuine paired comparison, separately configure a pinned model adapter
(e.g. the official Codex/Claude/OpenCode harness), skill revisions and
separate agent containers. Both arms must have `hint_level=none`,
`apply_gold_solution=False` and exactly the same audited task selection,
model build, time/tool/token budget and no ability to read the judge's gold
answers. Securely inject your own provider API key only in the isolated
runtime; **never** commit it or execute model calls on untrusted pull requests.
An unmodified official `human` agent is a NO-OP and cannot serve as either
experimental arm. Full EVMbench builds and paid inference are NOT part of
this repository's CI and were NOT run by this historical probe.

## Read-only diagnostic invocation

```sh
python3 skills/bounty-pilot/scripts/historical_probe.py \
  --repo /tmp/pinned-monad-checkout \
  --pinned 6aaccc2ec51eac66a2cf18ec64ab0df2c1448990 \
  --baseline-script /tmp/old/research_diff.py \
  --candidate-script skills/bounty-pilot/scripts/research_diff.py \
  --scope monad-eth-txpool --scope monad-eth-block-policy \
  --scope monad-eth-block-validator \
  --out /tmp/new-probe-report.json
```

Return label is `NONBLIND_TOOL_ONLY_DIAGNOSTIC`; fields
`verified_rediscoveries` and `native_pocs` are **null**, not zero.
A successful diagnostic does NOT imply more paid Medium/High findings.
