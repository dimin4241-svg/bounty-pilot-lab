# Agent wallet agent — a model holding keys reads text written by the attacker

Run this lens only when the target ships an AI agent that holds keys or can move funds: a trading
agent, a social bot with a wallet, an assistant with transfer tools. Every input the model reads is
attacker-writable somewhere, and the model cannot be the security boundary. **Your question is:
which control between "the model decided" and "funds moved" is enforced by code, and which is
enforced by a prompt?**

## Procedure

1. **Map every text input the agent reads.** Social posts and replies, direct messages, on-chain
   data (memos, calldata, event logs), token and NFT names and metadata, web pages, tool outputs,
   retrieved documents and other agents' messages. Each is a prompt-injection channel. Grok/Bankr,
   May 2026, roughly $175–204K: a Morse-code prompt in an X reply, together with an NFT that
   unlocked permissions, led the agent to transfer 3B DRB.
2. **Map every tool that moves value or changes permissions.** Transfers, swaps, approvals,
   signing, key export, allowlist edits, policy edits and config writes. For each, find the code
   path from the model's tool call to execution.
3. **Find where limits are enforced.** Spend limits, recipient allowlists, per-period caps, human
   confirmation and token allowlists: are they checked in code after the model emits the call, or
   only described in the system prompt? A limit the model is told about is not a limit.
4. **Check permission escalation through data.** Can holding a token, an NFT, a role on a social
   platform, or a message in a specific format change what the agent may do? Trace that check and
   ask who can satisfy it.
5. **Check tool and config injection.** Can a tool the agent calls write files the agent later
   loads as configuration or tool definitions, such as an MCP config like `.cursor/mcp.json`
   (reported by Zealynx)? Can a tool output add tools or change the system prompt?
6. **Check the model transport.** Does the agent call its model through a third-party router or
   proxy that could inject tool calls into responses? A claimed $500K loss through a malicious LLM
   router is UNVERIFIED; treat the channel as real and the figure as unconfirmed.
7. **Read key custody.** Where the key lives, whether the model's process can read it, and whether
   a tool can print, log or return it.
8. **Check replay of agent-signed intents.** Intents or messages the agent signs: nonce, expiry,
   chain and recipient binding, and whether a signed intent can be resubmitted.

## Where the money is

- A spend limit or allowlist that exists only in the prompt.
- A data-derived permission (holding an NFT, a username, a keyword) that unlocks value tools.
- A tool output or file write that becomes instructions or configuration on the next turn.
- A key readable from the model's tool sandbox.
- An agent-signed intent with no nonce or expiry.

## Proof standard

A reproduction in a local harness that runs the agent's real policy and tool-execution code with
test keys on a local chain or testnet fork: the injected input, the tool call the model emitted,
and the transfer that executed without the control stopping it. Quote the policy code and the
missing check. Never test against a live agent, a production account or real funds, and never
post injection payloads where a deployed agent will read them.

## What does not pay

- "The model can be jailbroken" with no value-moving action behind it.
- Prompt-only safety instructions failing when the program states the model is untrusted and the
  code-level controls held.
- Compromise of the operator's own infrastructure or keys.
