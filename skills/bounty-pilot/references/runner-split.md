# Split execution: GitHub-hosted CI and private Mac AI

- Automatic **offline Python unit tests** run on GitHub-hosted Linux via
  .github/workflows/portable-tests.yml (3.9 + 3.12, pyflakes).
- Synthetic Foundry/Rust fixtures (no target, no RPC, no secrets) run on a
  GitHub-hosted Linux VM via tests.yml on main.
- Extra feature test workflows are cloud-only and manual. No branch push
  starts an AI or native Mac test automatically.
- **Actual AI research / private test bundles / pinned RPC fork jobs** belong
  on the private Mac and must be explicitly launched by the operator. GitHub
  hosted unit CI cannot access the local private run folder.

Manual AI launcher: .github/workflows/mac-ai-audit.yml.
This is a workflow_dispatch-only task; it starts one already *planned* job
through existing scripts/agent_dispatch.py (read-only discovery mode).

Prerequisites on the runner Mac:
1. Mac runner is listening and Python3 is installed.
2. Codex CLI is installed and has been logged in *locally* with
   `codex login` (or Claude CLI is installed/authenticated).
3. Prepare a private Bounty Pilot run outside the target checkout, e.g.
   `$HOME/bounty-pilot-runs/example-run`, with run.json and dispatched
   bundles + planned jobs (use `agent_dispatch.py plan --run ...`).
4. In Actions > manual AI audit > Run workflow, choose the trusted branch,
   provide run_slug `example-run`, job_id of the existing queued job,
   provider, optional CLI-supported model. The runner does not choose or
   assume a named model; it respects the logged-in CLI's availability.

Mac AI is intentionally read-only, never triggered on pull_request/push, and
has one manual concurrency group so no high-volume CI can starve it.
No tokens, output bundles or private findings are uploaded to GitHub Actions
artifacts. Do NOT persist API secrets in repo or untrusted workflow files.

Foundry fork/Medusa experiments still require separate local isolated execution
with approved scope, a pinned block and no public-network writes.
CI synthetic tests cannot validate exploit impact. On public GitHub
repositories, standard GitHub-hosted runners are free; the repository's
Actions policy may nonetheless restrict workflows or third-party actions.
