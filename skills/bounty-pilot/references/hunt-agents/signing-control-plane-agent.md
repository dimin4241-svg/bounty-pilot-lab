# Signing control plane — approved intent versus actual signature

This lens audits an **in-scope, off-chain signer/withdrawal control plane**. Its focus is distinct
from the user-facing `wallet` lens, smart-contract `classic` EIP-7702 semantics, and general
controller/worker `EAC-11` or `integration-auth` checks. Trace one authorized intent through
every intermediary to the bytes signed and transaction executed.

## Start with authorization and scope, not a hacked administrator

1. Name the real **remote or lower-privileged entry point** (tenant API, integrator token,
   in-scope webhook, queue producer, or ordinary user request). Record program exclusions.
   A compromised DevOps workstation, stolen HSM/EOA key, root container or administrator
   credentials are *not* an acceptable starting capability. Without a demonstrated
   independent low-privilege route, classify as LEAD/UNAVAILABLE, not CANDIDATE.
2. Trace **the same request ID**:
   `entry -> principal/session -> approval policy -> immutable job -> queue/retry ->
   worker -> HSM/MPC/EOA signer -> signed transaction -> execution`.
   Quote source `file:line` at each edge. Mark missing external implementations
   UNKNOWN; never assume production roles from local configuration.
3. At every handoff identify authenticated and attacker-controlled values. Compare the
   *exact* approved request, serialized job, signer request, signed domain/message and
   executed transaction. “Approved” in a log is not independent signer policy.

## Signing authorization matrix

Create one row per field with origin, authorization guard, signed representation,
execution-time consumer and whether a low-privileged actor can alter it:

- **Principal/tenant and wallet/account**: does a worker independently recheck the
  calling identity, ownership, account ID, and signer/key authorization?
- **Network and operation**: are chain ID, transaction family, target, delegate,
  selector, calldata, value, action type and policy version bound?
- **Asset/recipient/amount**: are token, decimals, destination, amount, limits,
  aggregate caps and transfer semantics enforced at the signer, not just the API?
- **Freshness**: are nonces, job IDs, authorization epoch, expiry, cancellation, retry
  and recovery bound so queued or restored jobs cannot regain privilege?
- **Cross-chain isolation**: can one tenant/worker/token request signatures from a
  different wallet group, privileged account or network?
- **Secondary routes**: compare manual, emergency, fallback, legacy, batch, migration,
  support and retry paths against the primary authorization decision.

For each discrepancy identify the **actual source writer and consumer**. The existence
of a validation function elsewhere is neither proof it runs nor proof it is bypassed.

## Special case: EIP-7702 delegated EOAs

Inspect authorization_list/type-4 construction, chain_id, EOA nonce and delegate
code identity; the service policy for issuing an EOA authorization; contract target
allowlists; batches or sequential-nonce pre-signing; delegation persistence after
the intended action; cancellation/revocation/rotation; and delegated privileges
over other accounts, token allowances and smart accounts.

**Never claim EIP-7702 allows unsigned delegations.** A valid EOA authorization
signature is mandatory. The bug candidate, if any, is a lower-privilege path that
persuades the signer to authorize a delegate, chain, nonce window or operation
outside policy, or causes authorized intent and actual signed bytes to differ.
A retained delegation alone is not a bug unless it violates a documented protection.

Canonical specification: https://eips.ethereum.org/EIPS/eip-7702

## Candidate, falsifier, and safe experiment

For each potential mechanism state: pinned commit; exact remote/low-privilege ingress;
source-anchored trust edges; attacker-controlled fields; the violated invariant;
policy-versus-signed-payload comparison; affected assets; and explicit scope decision.

Show **candidate and negative-control** with investigator-owned synthetic keys,
mock authorization/queue/worker/HSM services and a local EVM test. For example,
legitimate signer job accepted, but changed recipient, network, delegate, policy version
or revoked epoch rejected. A result is a finding only if the code actually accepts
the unauthorized variant, the entry is reachable, and measurable in-scope impact is
demonstrated. If not executed, record the blocker with command and output.

Disconfirm explicitly via signer-side rechecks, immutable payload binding,
independently enforced policy, unreachable entry, or effective revocation.
Keep SOURCE_CONFIRMED, POC_REPRODUCED and IMPACT_VERIFIED separate, never
convert lexical/path matches into exploits or severity claims. Preserve all ordinary
Bounty Pilot evidence, duplicate and independent-triage gates.

**Safety:** no use/validation of discovered keys, no production signer API calls,
no public network transaction, no real user or exchange accounts, no live Binance
probing. The lens is a passive local research guide.

## October 2026 Binance precedent: facts versus hypothesis

Binance's preliminary 30 October update linked its incident *possibly* to a
compromised DevOps laptop and service-container access allowing unauthorized
withdrawals; Binance stated it had found no evidence of leaked private keys.
TRM Labs' 29 October analysis describes EIP-7702 delegation involving 50
pre-signed authorizations alongside withdrawals on other chains. These are
different evidence classes, and Binance's final post-mortem is not yet published.
**Do not assert the precise root cause, signature authorization failure, or a
remotely exploitable bounty bug has been confirmed.**

Sources:
- https://www.binance.com/en/support/announcement/detail/c5a8729a97ac486d963784d96c5642d7
- https://www.trmlabs.com/resources/blog/north-korea-steals-usd-6-36-billion-from-binance-in-the-largest-hack-in-history
