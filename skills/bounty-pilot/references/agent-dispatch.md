# Isolated agent dispatch

`agent_dispatch.py` is an optional runner for the four supported local agent CLIs. It turns the
latest immutable bundles into separate jobs, starts one fresh process per job, and keeps each
result with its logs and input digest under the private run directory. It never resumes a prior
session or shares another job's reading with a worker.

## Two distinct modes

**Independent blind pass** gives the exact same bundle to multiple fresh processes. Each receives
only that bundle in its own workspace. Use it to measure independent readings of one surface.

```sh
python3 <skill-dir>/scripts/agent_dispatch.py plan --run <run> \
  --mode independent-blind --lens accounting --replicas 3
```

**Diverse strategy pass** dispatches different lens bundles, one fresh process per bundle. The
lens instructions are the strategy. Use this to cover different mechanisms and surfaces; it does
not substitute for an independent blind pass.

```sh
python3 <skill-dir>/scripts/agent_dispatch.py plan --run <run> \
  --mode diverse-strategy --lens privileged-path --lens stateful-search \
  --lens recovery-failure
```

Planning is local and does not start a model. It prints job ids. Run each job explicitly with a
provider CLI:

```sh
python3 <skill-dir>/scripts/agent_dispatch.py run --run <run> \
  --job-id <job-id> --provider codex
python3 <skill-dir>/scripts/agent_dispatch.py run --run <run> \
  --job-id <another-job-id> --provider claude --max-budget-usd 1.00
```

The supported providers are `opencode`, `zcode`, `claude`, and `codex`. CLI versions and output
formats can change, so each result retains the exact command, CLI version probe, binary digest,
process exit, stdout, stderr, session identifier when reported, token usage when reported, and
provider-reported cost when available. A provider without cost metadata is recorded as unknown;
it is never counted as zero. Claude Code's `--max-budget-usd` is a client-side estimate cap. Other
CLIs currently have no generic per-call USD cap exposed here; limit their number of jobs, set a
provider-side spend cap, and keep the timeout bounded before starting them. Each plan is limited to
24 jobs, and each `run` starts exactly one job; this is a count limit, not a monetary cap. The
result records the replica count and wall time for comparing runs.

## Parallel safety, recovery and independence

All `dispatch.json` read/modify/write transactions use the OS advisory lock at
`agents/dispatch.lock`, then atomically replace the JSON file. The lock is held only while reserving
or recording a job, not while a model runs, so four or more `run` processes can progress
concurrently without overwriting one another's state.

Only a zero-exit, parsed provider response is promoted to `readings/`. A successful response is
staged under its attempt directory and published after completion is committed. A parsed response
from a failed or interrupted attempt stays as `draft-reading.md` under that attempt and is never
registered as `latest_result` or placed in `readings/`.

If the dispatcher process dies, use:

```sh
python3 <skill-dir>/scripts/agent_dispatch.py recover --run <run>
python3 <skill-dir>/scripts/agent_dispatch.py retry --run <run> --job-id <job-id>
```

`recover` marks a local attempt failed only when its recorded runner PID is gone. If the provider
child is still alive, the job records that orphan PID and refuses a retry until the process exits.
Attempts from another host remain explicitly unverified and require recovery on that host. Recovery
never promotes an incomplete result.

`status` reports `independence_unverified` when a completed provider did not report a session ID;
duplicate IDs are reported as `independence_conflict`. Only `state: complete` means every planned
job succeeded and every provider reported a unique session ID. `bounty.py check --submission` blocks
while a dispatch plan is queued, running, failed, session-unverified or conflicting. A provider
session ID confirms separate recorded CLI sessions, not the real-world identity of the operator.

For a machine-checkable independent evidence review, start the producer first and dispatch a
separate review job from an independent-blind plan. Pass test-log and impact artifacts as a file
inside the private run:

```sh
python3 <skill-dir>/scripts/agent_dispatch.py run --run <run> \\
  --job-id <review-job> --provider codex --evidence-review \\
  --producer-job-id <producer-job> --evidence-context <run>/review-evidence.md
```

The reviewer output must be the JSON review record itself. Its `session_bindings` include the exact
producer and reviewer `job_id`/`invocation_id`; the verifier reads provider session IDs from the
dispatch ledger and checks the JSON against the exact saved reviewer output digest. Use that
`review-output.json` path as `evidence.independent_review_path`. Different names typed into a
hand-written JSON file no longer satisfy the gate.

The runner uses these documented non-interactive interfaces:

| Provider | Invocation and isolation |
| --- | --- |
| OpenCode | `opencode run --standalone --agent plan --format json --file bundle.md`; fresh standalone run |
| ZCode | `zcode --prompt … --cwd … --mode plan --disallowed-tools Bash,Write,Edit --attach bundle.md --json`; fresh prompt without resume |
| Claude Code | `claude -p … --permission-mode plan --tools Read,Glob,Grep --no-session-persistence --output-format json` |
| Codex | `codex exec --ephemeral --sandbox read-only --json --cd …`; the bundle is piped as untrusted context |

On macOS, if `zcode` is not on `PATH`, the runner checks the official ZCode app bundle's
`Contents/Resources/glm/zcode.cjs`. OpenCode Desktop does not provide a `opencode` command in every
installation; install its CLI separately or pass its executable with `--binary`.

See the [OpenCode CLI reference](https://dev.opencode.ai/v2/docs/cli/commands/), [ZCode CLI
reference](https://github.com/zai-org/ZCode/blob/main/apps/zcode-cli/docs/usage/02-cli-reference.md),
[Claude Code CLI reference](https://code.claude.com/docs/en/cli-usage), and [Codex non-interactive
mode](https://learn.chatgpt.com/docs/non-interactive-mode) for the current provider flags. An
unsupported CLI version exits as a failed attempt, saves its error output, and remains retryable.

## Saved evidence and convergence

- `agents/dispatch.json` is a locked, atomically updated, run-bound ledger of plans, jobs, attempts,
  environment-safe CLI fingerprints, outputs, costs and per-agent mechanism counts.
- `agents/<job-id>/attempt-NN/` holds the read-only bundle copy, complete stdout/stderr and attempt
  metadata. Previous attempts are preserved when a job is retried.
- `readings/` holds only successful normalized discovery outputs that can be passed to `converge`.
- `status --run <run>` reports queued, running and failed jobs; provider-session reuse conflicts;
  unique mechanisms per job and pass; reported-cost totals; and how many runs reported a cost.
  Mechanism counts are exact parsed-reading deduplications, not source-confirmed or validated bug
  counts. Provider cost remains partially unknown where the CLI omits it.

```sh
python3 <skill-dir>/scripts/agent_dispatch.py status --run <run>
python3 <skill-dir>/scripts/bounty.py converge --run <run> --readings <run>/readings
python3 <skill-dir>/scripts/bounty.py queue --run <run>
```

A saved model response is only a research reading. It does not establish source truth, reachability,
PoC reproduction, impact, deployment or eligibility. The experimenter and independent evidence
review remain later stages.
