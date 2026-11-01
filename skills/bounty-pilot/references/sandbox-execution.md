# Running candidate/control PoCs without exposing the host

The existing \`scenario_runner.py\` has **dry-run as its default**. Its
\`--allow-exec\` flag runs the target's test commands on the **current host**.
It does not create a sandbox. Reading an untrusted repository and running
that repository's tests are different security decisions.

The opt-in \`sandbox_run.py\` wrapper launches the *existing*, unchanged
paired-experiment runner in a Docker container, not on the host. The operator
must supply a trusted toolchain image **pinned by \`@sha256:...\`** and must
install the image before use. No image is bundled or downloaded by the helper.

## Example

First create a **disposable, secret-free clone** of the authorized target,
an explicit, reviewed paired test plan and a private evidence directory
outside that clone:

\`\`\`sh
# Build or pull a trusted toolchain image yourself, then record its actual digest.
# IMAGE='your-registry/your-toolchain@sha256:<64-hex-digest>'
python3 skills/bounty-pilot/scripts/sandbox_run.py \
  --repo /tmp/disposable-authorized-checkout \
  --plan /tmp/reviewed-paired-plan.json \
  --out /tmp/private-poc-evidence/results.json \
  --image "$IMAGE"
\`\`\`

The chosen image must provide Python 3 and the native test runner/toolchains
required by your plan (such as Foundry or Cargo). Docker is required on a
POSIX host. The image **must be present locally**; the wrapper uses
\`--pull=never\` so an unintended tag or network pull cannot occur.

## Exact isolation boundary

- Network disabled; all Linux capabilities removed; no new privileges.
- Read-only container root, temporary /tmp, 256-PID / 4 GiB / 2-CPU limits.
- Non-root execution as the host user's UID/GID.
- No mount of the host home directory or Docker socket by the wrapper.
- Only the target checkout (read/write), approved JSON plan (read-only),
  Bounty Pilot scripts (read-only), and fresh private output directory
  (read/write) are mounted.
- Both candidate and negative-control checks are performed by the original
  runner with its normal test-count and exit-code requirements.
- The target repo remains writable because Solidity/Rust builds commonly
  need local build output. **All modifications to the disposable checkout
  therefore remain on the host volume.** Never point it at valuable files.

This is process isolation, **not a hardened VM**. A vulnerable Docker
daemon/kernel, a compromised toolchain image or dangerous files *already
present in the mounted checkout* can undermine it. Treat image provenance,
host daemon access, symlinks in a mutable target, and local credentials
as operator responsibilities. Do not run on a sensitive host.

The wrapper does not turn tests into exploit proof. Passing candidates
and controls establish only that their recorded assertions executed; an
independent reviewer must inspect the actual predicates and impact.

## Other execution routes

\`research-next native --allow-exec\`, direct agent CLI launchers, custom
Foundry/Cargo invocations and the main \`bounty.py\` commands are **not
automatically routed** through this wrapper. Run them in an external
isolated environment when they execute unknown target code. GitHub Actions'
synthetic fixtures are known local test code; do not confuse them with
real-target safety or rediscovery evidence.

No model keys are required for this container wrapper. The
\`evmbench_pair.py run\` model comparison is separately gated behind
provider billing, explicit spending authorization and a provider-side
hard cap: see \`evmbench-pair-guide.md\`.
