# Claude Opus 5 — pinned Charon security research trial

Target: https://github.com/ObolNetwork/charon

Pinned Git revision: `2b534ebb719d168414ca3bf49ae75563c661f6b2`
(checked on November 1, 2026).

**Model:** `claude-opus-5` via Anthropic's official Messages API.

This is a ready-to-run *locally initiated* audit harness. It does NOT
execute a Claude API call from ChatGPT or GitHub CI. Running it requires
a working external network connection and an Anthropic API key configured
on your own computer. This is not a blind historical A/B or a verified
native PoC generator.

## SECURITY: rotate any token pasted into a chat

If you pasted your actual API key into a conversation, revoke it at
https://platform.claude.com/settings/keys before proceeding and create
a new key. Do NOT reuse it, paste another key into a chat, commit a key
to this repository, add it to a shell command or upload it in a log.
The launcher reads `ANTHROPIC_API_KEY` from the local process environment
only. It does not log the key or copy it to result files.

## Anthropic API keys with no workspace scope

Anthropic's authentication documentation requires the HTTP header
`anthropic-workspace-id` when using a personal/service-account API key
that is **not scoped to any specific workspace**. This affected the
previous `--check-model` command and also would have affected paid
`/v1/messages` calls. See
https://platform.claude.com/docs/en/manage-claude/authentication

Find your actual `wrkspc_...` ID at
https://platform.claude.com/settings/workspaces (ID column).
Do **not** use an organization ID or invent a workspace ID.

Since Lab 0.49.3 the launcher reads `ANTHROPIC_WORKSPACE_ID` from the
**local process environment** and adds the header to both the read-only
model lookup and charged Messages requests. For a workspace-scoped API
key, leave `ANTHROPIC_WORKSPACE_ID` unset. The script validates the
workspace ID format and never prints it, persists it or passes it via
CLI arguments.

Run read-only `--check-model` first. On macOS, from the
`bounty-pilot-opus-run` directory (with version 0.49.3 or later):

```bash
bash -c '
read -rp "Workspace ID (wrkspc_...): " ANTHROPIC_WORKSPACE_ID
read -rsp "New Anthropic API key: " ANTHROPIC_API_KEY; echo
export ANTHROPIC_WORKSPACE_ID ANTHROPIC_API_KEY
python3 skills/bounty-pilot/scripts/opus5_charon_audit.py --check-model
unset ANTHROPIC_WORKSPACE_ID ANTHROPIC_API_KEY
'
```

When `MODEL_AVAILABLE` is returned, repeat with the same new key and
workspace ID but replace the last Python line with the bounded Charon
trial (use `--passes 1` before three passes to test paid model access):

```bash
python3 skills/bounty-pilot/scripts/opus5_charon_audit.py \
  --repo "$HOME/charon-opus5" \
  --out "$HOME/opus5-charon-live-$(date +%s)" \
  --passes 1 --max-usd 1
```

The charged command must execute in the same shell with both environment
variables exported. Never echo the key, embed it in scripts or paste it
into a chat. A prior leaked key must be revoked and replaced.

## Debug Anthropic 400 errors without spending money

The Messages API can return HTTP 400 for malformed input **or** an
organization/workspace spending limit. The script now includes the
provider's redacted, length-limited `error.type` and `error.message`
in its output; request IDs are shown if they match the expected shape.
Never send an API key, Authorization headers or raw request payloads
to a public issue or chat.

After rotating any API key previously pasted into chat, test model
access without consuming paid model tokens:

```sh
read -rsp 'Enter your NEW Anthropic API key: ' ANTHROPIC_API_KEY; echo
export ANTHROPIC_API_KEY
python3 skills/bounty-pilot/scripts/opus5_charon_audit.py --check-model
unset ANTHROPIC_API_KEY
```

Possible results:
- `MODEL_AVAILABLE`: this key can retrieve Opus 5 model metadata,
  but it does **not** guarantee successful paid Messages requests.
- `HTTP 400 | invalid_request_error | You have reached...`:
  check organization/workspace spending limits in Anthropic Console.
- `HTTP 401 | authentication_error`: key invalid, revoked or expired.
- `HTTP 404 | not_found_error`: verify model access for this account.
- Other 400: use the now-visible redacted validation message and request ID.

`PARTIAL_API_FAILURE` with `passes_completed=0` indicates no
successful pass and zero locally observed usage; it does NOT provide
a provider billing statement. Do not retry blindly while HTTP 400
persists.

## Run on your machine

Prerequisites: Python 3.9+, Git, internet access to official GitHub
(cloning) and api.anthropic.com (the model). No pip dependencies.

First, clone the EXACT pinned public Charon snapshot:

```sh
git clone --filter=blob:none https://github.com/ObolNetwork/charon.git /tmp/charon-opus5
git -C /tmp/charon-opus5 fetch --depth=1 origin 2b534ebb719d168414ca3bf49ae75563c661f6b2
git -C /tmp/charon-opus5 checkout --detach 2b534ebb719d168414ca3bf49ae75563c661f6b2
git -C /tmp/charon-opus5 status --short
```

The status must be empty. On your local machine from the bounty-pilot-lab
repo, test input selection and conservative cost estimate first:

```sh
python3 skills/bounty-pilot/scripts/opus5_charon_audit.py \
  --repo /tmp/charon-opus5 \
  --out /tmp/opus5-charon-private \
  --passes 3 --max-usd 2 --dry-run
```

Then set a fresh secret without displaying it or leaving it in the shell
command history. For bash/zsh on Linux/macOS:

```sh
read -rsp 'New Anthropic API key: ' ANTHROPIC_API_KEY; echo
export ANTHROPIC_API_KEY
python3 skills/bounty-pilot/scripts/opus5_charon_audit.py \
  --repo /tmp/charon-opus5 \
  --out /tmp/opus5-charon-private \
  --passes 3 --max-usd 2
unset ANTHROPIC_API_KEY
```

This performs up to three chargeable requests, with a *conservative*
estimated preflight cap, exact source SHA-256 for each included file,
and a `--max-usd` cap on tracked token usage. API prices as documented
for Opus 5 are $5 per million input and $25 per million output
tokens. Actual billing can differ for caching/other service charges.
The launcher intentionally cannot issue unrestricted tool calls.

`--passes 1` for a cheaper smoke trial (one call);
`--passes 2` is the default. The third pass includes partial-signature
and broadcast code rather than the existing reported relay circuit
exhaustion. The exact code windows are fixed, bounded and numbered:

1. `partial-exit-and-auth`: Obol API partial exits, fee recipient auth.
2. `beacon-cross-client-boundary`: eth2wrap multiple Beacon client,
   retry, fork readiness, fallback behavior.
3. `partial-signatures-and-broadcast`: partial signature exchange and
   bcast/consensus transport.

## Opus 5 successful HTTP response without final text (Lab 0.49.4)

Claude Opus 5 defaults to **high** thinking effort. In a hard source
review it can consume the old `max_tokens=4500` output budget thinking
and return HTTP 200 with a `thinking` block, no `text` block and
`stop_reason=max_tokens`. **No visible text does not mean free usage.**

The launcher now sets explicit `output_config.effort=medium` and
`max_tokens=8192` for every request. It records non-text responses
safely: stop reason, block *types* and provider usage counters, without
recording internal thinking content or signatures. The first incomplete
or non-text response halts later requests. The manifest includes
`api_responses_received`, `passes_completed`, and the cost estimate
from *all parsed HTTP-success responses*, even when no pass finishes.

`PARTIAL_NO_TEXT_RESPONSE` with `api_responses_received=1` can
have a **nonzero cost**. Inspect the first pass's JSON locally. Never
upload API keys, full provider headers, Claude thinking blocks, VPN
credentials, or secret files into chat or a public repository.

**Do not rerun the earlier request without a fresh key and first
inspecting Anthropic Console usage/spend.** The previous 0.49.3
manifest's `estimated_usd_spent:0.0` did not reflect a 200 response
whose text was unusable. We cannot reconstruct past usage from that
discarded response. Anthropic Console is authoritative for billing.

After upgrading, if `--check-model` is already working, perform
one paid pass in a new local output directory with at least $1
estimated script budget:

```sh
python3 skills/bounty-pilot/scripts/opus5_charon_audit.py \
  --repo "$HOME/charon-opus5" \
  --out "$HOME/opus5-charon-live-$(date +%s)" \
  --passes 1 --max-usd 1
```

Run the command only within the shell where both a **new, rotated**
`ANTHROPIC_API_KEY` and (if unscoped) `ANTHROPIC_WORKSPACE_ID`
were exported. The local limit is a model-usage estimate, **not a
provider billing limit**.

## What outputs look like

Output is a new private directory outside the target checkout. The
script refuses overwriting an existing directory.

- `manifest.json`: model ID, pinned commit, file SHA-256, completed passes
  and estimated actual API token cost. It does not contain any API key.
- `partial-exit-and-auth.json`: source-grounded analysis for pass 1.
- `beacon-cross-client-boundary.json`: pass 2 result.
- `partial-signatures-and-broadcast.json`: pass 3 result.

Every model response is explicitly labeled
`UNVERIFIED_MODEL_HYPOTHESES`. It requests exact path:line anchors,
attacker capability, realistic exploit preconditions, intended invariant,
concrete offline Go PoC candidate/negative control, missing source to
inspect and likely false-positive explanations.

**No report should be submitted on model output alone.** Verify all
anchors against the pinned code, reproduce a test in a disposable
network-isolated environment, compare against the latest active deployed
version, check in-scope authorization and duplicates, and assess genuine
impact. No mainnet interactions, real validator keys, or production
requests are generated by this launcher.

## Limits and privacy

- No model run was performed by this release; unit tests use a mock client
  so they don't spend money or expose credentials.
- The source files are sent to Anthropic to generate suggestions. Only
  use public or sharing-authorized code. Here the target is public.
- This is a bounded *three-angle review*, not exhaustive automated
  exploration of every Charon file. A hypothesis can be wrong or duplicate.
- Exact pinned commit is checked; remote Git identity/signature is not
  cryptographically authenticated.
- Cost limit is conservative but not a provider-side hard spending cap.
  For a strict global cap also configure Anthropic Console spending limits.

Do not add API credentials to GitHub Secrets simply to run this temporary
trial; local execution avoids a new credential-access boundary.
