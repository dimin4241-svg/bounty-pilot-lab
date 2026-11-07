# Bridge and messaging agent — every message type, every field, bound or not

A bridge is a set of message types, and each type is its own authorization problem. The handler
that checks the source chain for a transfer often forgets it for a refund; the proof that binds
the amount often forgets the variant tag. **Your question is, per message type: which fields did
the verifier actually commit to, and which ones did the receiver merely read?**

This lens covers LayerZero v2 OApp/OFT, Wormhole, Axelar, CCIP, Hyperlane ISMs, Across, rollup
bridges and custom bridges. Where `integration-auth` asks who may call a callback, this lens builds
the full matrix for every message variant the bridge accepts, including the ones nobody sends.

## Procedure — the per-message-type binding matrix

1. **Enumerate message types.** Every variant tag, opcode, `msgType`, enum discriminator, export
   kind and payload version the receiver decodes, plus the paths with no tag at all: express or
   fast-path execution, retry, refund, recovery, escape hatch and admin replay. One row per type.
2. **For each row, fill these columns from quoted code:**
   - **Source binding:** is the source chain id / eid / domain checked, and against what?
   - **Sender identity:** is the sender taken from the authenticated envelope (the endpoint's
     `Origin`, the gateway's verified source address) or from inside the payload?
   - **Amount and asset binding:** does the proof or signature commit to the amount, the token
     and the decimals the receiver actually releases?
   - **Type/variant binding:** does the commitment cover the tag that selects the code path?
     Verus–Ethereum bridge, May 2026, $11.7M: the check proved an export object existed but not
     that it was a primary value export, so a crafted supplemental export passed the hash
     commitment checks.
   - **Replay domain:** nonce, chain id, contract address, and whether the nonce is consumed
     before or after the body runs.
   - **Fast-path authorization:** CrossCurve, Feb 2026, roughly $1.4–3M: `ReceiverAxelar`'s
     `expressExecute()` was callable by anyone and reached `_execute()` without gateway
     validation, with a confirmation threshold of 1.
   - **Failure, refund and retry:** a second call that arrives with half-updated state. NEAR
     Intents/Omni, Oct 2026, $3.87M, was a deposit/withdraw interaction bug; public mechanism
     detail is limited, so treat it as a pointer to read those paths, not as a template.
3. **For proof-based bridges, compare public inputs with what L1 processes.** List every value the
   settlement contract acts on and check each is a public input the proof constrains. Aztec
   Connect, Jun 2026: `numTxs = 1` hid a deposit so `decreasePendingDepositBalance` was skipped,
   and `escapeHatch` did not bind the private root to the public `oldDataRoot`.
4. **Read the live verifier configuration, not the setter.** DVN sets and thresholds, ISM modules,
   guardian sets, confirmation counts and peers, per chain, at a pinned block, with
   `bounty.py config-snapshot` (see `references/config-snapshot.md`). KelpDAO, Apr 2026, $292M: a
   1-of-1 LayerZero DVN fed by poisoned RPCs attested a forged `lzReceive` that released 116,500
   rsETH. A 1-of-1 verifier is a finding about the configuration, so cite it with the block.
5. **Do the threshold arithmetic.** Read how the quorum is computed: rounding of `2/3`, an
   off-by-one `>` versus `>=`, duplicate signers counted twice, stake weights read at a block an
   attacker can influence, and stake that can be flash-loaned or delegated into the set.
6. **Bound the damage.** Read rate limits, per-window caps and pausers that are live. They do not
   kill a finding, but they set its size and must appear in the impact figure.

## Where the money is

- A rarely used message type (refund, recovery, supplemental export, admin replay) that reuses the
  transfer handler's release code without its checks.
- A sender or source chain read from the payload while the envelope's authenticated copy is
  ignored.
- A fast path that any address can trigger before the slow path has verified anything.
- A proof whose public inputs omit a value the L1 contract branches on.
- A live verifier set of one, or a threshold the code computes lower than the docs claim.
- A nonce scoped per chain but not per contract, so a message replays on a sibling deployment.

## Proof standard

Quote the commitment (what is hashed, signed or proven) beside the code that consumes the message,
and name the field that is consumed but not committed. For configuration findings, give the
on-chain read with its block number. The strongest evidence is a local or fork test that delivers
a crafted message through the real endpoint or verifier contract and shows the release.

## What does not pay

- Compromise of validator, guardian or multisig keys (Shibarium, Sep 2025; IoTeX ioTube, Feb
  2026; AFX, Jul 2026) is usually out of bounty scope. Threshold arithmetic and stake-weight paths
  that an unprivileged actor reaches in code are in scope.
- A bridge operator misconfiguring its own deployment is admin behaviour unless the program lists
  the live configuration as an asset. Emit it as a LEAD tagged `likely-excluded` and name the clause.
