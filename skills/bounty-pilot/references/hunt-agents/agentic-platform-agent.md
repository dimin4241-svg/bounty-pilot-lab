# Agentic platform agent — a hosted agent that spends, renders, and executes for its user

Run this lens when the target is a **hosted platform whose agent is not the user's**: a creative or
productivity agent that runs generation tools, a code sandbox, a model router, and billing on the
platform's own account. This is not `agent-wallet` (an agent that moves the user's crypto) and not
`agent-runner` (an agent reading hostile repository content). Here the user's loss is money on the
platform, personal media of other users, and code execution on platform infrastructure.

**Your question is: which boundary between "the model chose to call a tool" and "the tool ran,
charged, or read someone else's file" is enforced by code the model cannot reach?**

## Procedure

1. **Map the identity graph.** Two OAuth/MCP servers plus a NextAuth callback, dynamic client
   registration, API keys, one-click connectors, third-party clients (ChatGPT, Claude) and session
   cookies. For each, write the exact bearer that reaches the tool endpoint and who can create it.
   A new `*.glif.app` or `<brand>.app` subdomain that shares one session cookie with the app is a
   first-party origin for CSRF and for OAuth redirection, whatever the public programme says about
   "alternate domains".
2. **Map every tool that spends, writes or executes.** Generation calls (`compose_project`), the
   code sandbox, file upload and signed upload URLs, settings writes, S3/CDN presigns, webhooks.
   For each, find the server-side check between the model's tool call and the effect.
3. **Attack the agent's decision surface.** Prompt injection from uploaded media, filenames, PDFs,
   fetched pages, model output, third-party tool descriptions and MCP server notes. Then ask which
   control is code: a spend limit checked after the model emits the call, a model allowlist, a
   per-turn cap, an approval threshold that also applies to model-chained calls. A limit the model
   is told about is not a limit.
4. **Attack object identity.** Projects, jobs, media assets (`img_`, `vid_`, `aud_`, `doc_`), user
   skills, library items and share links. Every read is `get_project`, `get_job_status`,
   `select_project_images`, `get_user_skill`, presigned media URLs. Try foreign IDs without the
   owner's session; then ask whether an unguessable ID is the only control, and whether a finished
   job record still answers after it "expired".
5. **Attack billing arithmetic.** Idempotency of `compose_project` under retries, concurrency,
   duplicate `project_id`, refresh and reconnect; refund of a failed run; the approval threshold
   versus what the run actually cost; the provider's cost when a model choice is user-influenced.
   Two overlapping runs that both pass the balance check and both complete leave the account
   negative — that is the owner's money that is not collected, and it is a finding only if it
   repeats or scales.
6. **Attack the sandbox.** When a plan includes a "code sandbox for asset enhancement", map what it
   can reach: secrets in env, other users' asset buckets, the platform network, egress, file writes
   back into the user's library, the agent's own tool list. The escape must be remote — a prompt,
   an uploaded file, a fetched page — never a precondition of the user's own machine.
7. **Attack model and key routing.** Is any model, provider key, endpoint or fallback chosen from
   user text, a project field or a tool output? Whether a cheaper model can be forced for
   platform-paid work, or a key can be exfiltrated to a proxy the platform operates, is the
   difference between a bug and a design. Record which key pays and which account is billed.
8. **Attack the OAuth surface, positively.** Dynamic client registration, redirect-URI policy,
   signed callback URLs, PKCE, token audience, scope handling, connector tokens, one-click
   authorisation. Prove that the *final* RFC 6749 §4.1.2.1 redirect carries the authorization code
   to an attacker origin. A URL parameter that is accepted and echoed into the next URL is not
   yet an open redirection: follow it through the consent step.

## Where the money is

- A spend or model control enforced only in prompt text, while the billing check lets several
  concurrent runs each spend the remaining balance.
- A foreign project, job or asset readable with the attacker's own token, including "expired"
  job records and public share URLs that are not unguessable.
- A sandbox that can read platform secrets or another user's upload because the tenancy is a
  directory name.
- A spend-to-own-API-key swap: platform-paid calls when the product promises the user's own key.
- A one-click connector or DCR flow that issues a token for an attacker-claimed client.

## Proof standard

Two owned accounts, A and B, on the same platform, with B's actions authored only by B. For every
claim: the exact request, the exact response, the server-side effect (credit balance delta from B's
own usage page, B's file bytes received by A) and a negative control where the same request against
an authorised object is accepted. Where the client-side app does not expose the boundary, retest in
a local/throwaway deployment. Never use another user's data, run paid operations on accounts you do
not own, or leave a dangling object you cannot delete.

## What does not pay

- Unauthenticated 302s, reflected parameters, missing security headers, permissive CORS on token
  endpoints — unless each is chained to a real grant of a token, an action or data.
- A sandbox escape that needs the victim to run the attacker's file on their own host.
- Prompt-only safety instructions failing where the program states the model is untrusted and the
  code-level controls held.
- Already-reported issues and "impacts only the reporter's own account".

## Self-check

For every candidate, name the channel that carries the attacker's decision into the tool call, the
code path that should have refused it, and the exact delta in dollars, credits, bytes or processes.
If any of the three is missing, it is a lead, not a finding.
