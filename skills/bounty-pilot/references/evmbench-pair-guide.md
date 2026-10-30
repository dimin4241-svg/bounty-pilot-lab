# Paired EVMbench runner — controlled model comparison

This is an **explicitly opt-in** adapter to the official EVMbench detect
harness. Source: [OpenAI frontier-evals](https://github.com/openai/frontier-evals/tree/main/project/evmbench).
The official EVMbench maintains answer keys, Docker isolation and a detect
grader. Our adapter modifies only the *agent-side instructions and skill mount*;
it does NOT alter the audit source, score logic or known answers.

## Exactly what is compared

- Baseline Lab 0.41.1 skill `651f46eedb904ac2f738843ae0413e1eb3cf638a`.
- Candidate Lab 0.42 skill `cd00a9d64dc341ef6ab9b5c32947ebf00d4cf5a1`.
- Upstream EVMbench `b78dab1da774a6456b1ed9c48c9ff194ee3ff36d`.
- Same official detect tasks, same model ID, no hints, no gold solutions,
  independent fresh per-audit agent containers, identical wall-time caps.
- Full local Pilot skill code is mounted inside each agent's isolated
  `/home/agent/pilot-skill` directory; AGENTS.md tells the model to read it.
- The module excludes CaseForge answer catalogs and published Monad case
  discussion from **both** skill bundles, then rejects selected audit IDs
  appearing in the copied agent materials.
- A stable audit-name hash alternates which arm goes first. This reduces
  first-arm bias, but does not enforce equal provider spending.

Do not treat this as an uncontaminated private holdout: EVMbench tasks and
their solutions are published. Public-data memorization is a material bias.
Real-world bounty payout applicability must be measured separately.

## Free, offline preflight (already runs in CI)

```sh
# From a private checkout containing the Pilot git history:
git fetch origin 651f46eedb904ac2f738843ae0413e1eb3cf638a
git fetch origin cd00a9d64dc341ef6ab9b5c32947ebf00d4cf5a1

git clone https://github.com/openai/frontier-evals.git /tmp/pinned-evmbench
git -C /tmp/pinned-evmbench checkout b78dab1da774a6456b1ed9c48c9ff194ee3ff36d

python3 skills/bounty-pilot/scripts/evmbench_pair.py prepare \
  --repo /absolute/path/to/bounty-pilot-lab \
  --official-root /tmp/pinned-evmbench \
  --out /tmp/private-evmbench-comparison \
  --audit 2024-04-noya \
  --audit 2024-06-size \
  --audit 2024-07-basin \
  --audit 2024-08-wildcat \
  --audit 2025-06-panoptic
```

`prepare` does not use a model, build containers or score anything. It
creates fresh private bundles and a manifest, verifies both Git revisions,
and patches the pinned official solver's agent-side skill upload. The
checkout becomes dirty **by design** after preparing the patch; use a fresh
official checkout for a new trial. Do not let benchmark answers or
existing score files into either agent container.

## Paid model run — NOT automatically started in CI

Requires official upstream dependencies (`uv sync`, Docker and the pinned
audit Docker images), a dedicated scoped `OPENAI_API_KEY`, account billing,
and explicit consent to spend. Build the necessary audit images using the
upstream EVMbench instructions (e.g. `docker build -f ploit/Dockerfile ...
&& uv run docker_build.py --audit <audit_id>`).

Important: the official Codex agent is configured to operate inside an
EVMbench container, with elevated rights **inside that container**. Use
a disposable dedicated computer/runtime and an API key with a separate,
independently configured **hard provider spending limit**. This adapter
does not meter, reserve or enforce USD/token spend. Each five-task
comparison could require ten independent model and grading runs, and may
be expensive. Do not put API keys in the repository, logs, chat or
pull-request workflows.

Only when the operator has configured the external spending cap and
explicitly approved usage, run locally:

```sh
export OPENAI_API_KEY=...  # set securely via a secrets manager, not in shell history
python3 skills/bounty-pilot/scripts/evmbench_pair.py run \
  --manifest /tmp/private-evmbench-comparison/manifest.json \
  --model codex-gpt-5.3-codex \
  --timeout 900 \
  --authorize-provider-spend
```

The command writes arm-separated private run logs and per-audit status,
but intentionally marks results `RAN_UNADJUDICATED`, not a Pilot win.
Inspect official EVMbench grader outputs, validate every claimed match
independently, obtain actual usage/cost receipts, check equal effective
resource budgets and contamination, and only then compare paired scores.
If one arm fails, the run is **incomplete**, never a zero-findings result.

## How to interpret

- **Harness preflight green**: both skill revisions can be safely staged
  and the audited upstream can be modified only at its allowed injection
  point. No model invocation occurred.
- **Model runs complete**: both agents produced outputs; this alone is
  not evidence of finding any historical vulnerability.
- **Official detect score**: a mechanism-matching judge's result against
  known historical audits, not necessarily an independently executable
  PoC or a bounty-eligible live vulnerability.
- **Measured skill uplift**: requires the same model/version, equivalent
  token/time and spend budgets, matched samples, independent adjudication,
  and transparent uncertainty; published tasks cannot eliminate
  model-training contamination.

No external network targets or production on-chain state are touched by
the preflight. The actual EVMbench run is constrained to the official
sandboxed audit images and model API gateway.
