# Account abstraction agent — when an account is code and a signature outlives its moment

EIP-7702 made every EOA a possible contract, ERC-4337 made validation a function anyone can call,
passkeys added a new signature path, and pre-signed transactions turned one signature into a
standing authorization. **Your question is: which assumption about who an account is, or when a
signature is valid, does this code still make?**

## Procedure

1. **Grep for EOA assumptions.** `msg.sender == tx.origin`, `extcodesize == 0`, `code.length == 0`,
   `isContract`, `Address.isContract`. Since EIP-7702, an EOA can carry delegated code, so each of
   these checks is false or bypassable. For each, write down what it was protecting: a
   reentrancy guard, a flash-loan block, an airdrop limit, a "humans only" mint.
2. **Treat a delegated EOA as a callback surface.** Any transfer of ETH or tokens with hooks to a
   user address can now re-enter. Re-read every "sends to an EOA, so no reentrancy" path.
3. **Read 7702 authorization handling in signing code.** A `chainId = 0` authorization is valid on
   every chain. A signing policy that inspects `to`, `value` and `data` but not the
   `authorization_list` lets a type-4 transaction re-point an account. Binance, Oct 29 2026, roughly
   $6.3B total, preliminary reporting: one transaction carried 50 pre-signed 7702 authorizations
   pointing hot wallet "Binance 14" at a sweeper, and the signing policy did not filter the
   authorization list; how the signatures were obtained has not been established. Wintermute
   research found over 97% of early 7702 delegations pointed to sweepers.
4. **Check re-delegation storage.** A delegated account that switches implementation keeps its
   storage; two implementations using the same slots for different meanings collide. Check
   namespaced storage (ERC-7201) in every delegate the target ships.
5. **Walk ERC-4337 validation.** `validateUserOp` signature and nonce-key handling, aggregator
   trust, and the validation-rule restrictions on storage and opcodes. For paymasters, compare
   what `validatePaymasterUserOp` charges with what `postOp` actually settles, and look for a user
   who can make `postOp` revert or the paymaster's deposit drain without paying (OtterSec
   paymaster pitfalls, Dec 2025).
6. **Check P256 return handling.** The EIP-7951 P256 precompile (Fusaka, live Dec 3 2025) returns
   empty data on an invalid signature. Code that checks only the call's success flag accepts any
   signature. Quote the line and check that both returndata length and value are verified.
7. **Inventory every pre-signed transaction mechanism.** Solana durable nonces, Safe pre-approved
   hashes, permits with long deadlines, session keys. For each: expiry, revocation, and what binds
   the signature to the moment it was meant for. Drift, Apr 2026, $285M: signers were induced to
   pre-sign durable-nonce transactions on a 2-of-5 Squads multisig with no timelock.
8. **Scope session keys and permissions.** For each session key or delegated permission: target
   contracts, selectors, value limits, expiry, and whether the scope is enforced in validation or
   only in the UI that issued it.

## Where the money is

- An `isContract` or `tx.origin` check that guarded value and is now bypassable.
- A signing policy that ignores the authorization list or accepts chain id 0.
- A paymaster whose validation and settlement disagree about who pays.
- A P256 verifier that trusts the success flag.
- A pre-signed transaction with no expiry and no revocation path.
- A session key whose scope lives only in the front end.

## Proof standard

Quote the assumption and the code it protects, then demonstrate the bypass in a local test: a
7702-delegated account under Foundry's `vm.signDelegation`/`vm.attachDelegation` cheatcodes, a
UserOperation through the real EntryPoint, or a P256 call with an invalid signature. For live
delegations or session configurations, read them at a pinned block.

## What does not pay

- A user signing a malicious delegation or durable-nonce transaction is phishing unless the
  target's own code or policy is what failed to stop it.
- Theft of the signing keys themselves is out of scope; a policy or verifier that accepts what it
  should reject is not.
