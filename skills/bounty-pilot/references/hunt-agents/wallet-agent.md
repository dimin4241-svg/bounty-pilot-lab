# Wallet agent — the gap between what is shown and what is signed

A wallet's whole job is that the user approves the thing they were shown. Every finding in this
class is one sentence: **the user saw A and signed B**, or **an origin that should not have been
able to ask, asked**.

This lens covers browser extensions, mobile wallets, desktop apps and the companion app of a
hardware device. It is not the dApp page that builds a transaction — that is `web-frontend`.

## Procedure

1. **Map every way a request enters.** The injected provider and its `postMessage` bridge, the
   content script's listener, the background or service worker's message handler, the WalletConnect
   or similar session channel, deep links and custom URL schemes, intents, a local HTTP or RPC
   port, a QR payload, an embedded webview's bridge, clipboard handlers, and the push channel.
   List them before reading any.
2. **For each entry, find where the origin is decided, and read that code.** The question is
   whether the origin the wallet *displays and authorises against* is the origin the request
   actually came from. Look for: an origin taken from the message body rather than the browser's
   own sender record, a sender record read at the top frame when the request came from an iframe,
   a missing frame identity check, a comparison by `startsWith`/`includes`/`indexOf` rather than
   a parsed host, a normalisation that strips something meaningful, and a permission cached
   against a value the page controls.
3. **Follow one request from entry to the approval screen and compare the two payloads.** What
   the user is shown is derived from the request somewhere; find that derivation and ask what it
   drops, truncates, re-encodes, or renders from a different field than the one that gets signed.
   The classic shapes: a decoded view built from a hint the dApp supplied, a long address
   displayed with an ellipsis, a token symbol or decimals taken from the request, a chain id
   displayed from one field and signed from another, an amount formatted with the wrong decimals,
   a batched call whose later elements are not rendered, a typed-data domain the screen omits.
4. **Read the blind-signing paths.** Where the wallet signs something it cannot decode — raw
   bytes, an unknown method, a hash, a message type with no renderer — and ask what the user was
   told instead. A "cannot decode, sign anyway" path is where clear-signing claims fail.
5. **Check the state the approval depends on between display and signature.** Can the page change
   the pending request after the screen is drawn, open a second request that replaces the first,
   or make the approved request execute with different parameters?
6. **Read the permission model's persistence.** What is remembered after one approval, keyed on
   what, for how long, and can a different origin inherit it: a permission stored per tab, per
   session, per account, or per a value the page supplies.
7. **Read the hardware boundary where there is one.** What the device itself shows versus what
   the companion app shows; which fields the device parses and which it trusts the host for;
   whether an unsupported type degrades to a hash the user cannot check.
8. **Check what the app accepts from outside the user's action.** A deep link that pre-fills a
   recipient, a scheme handler that opens a signing screen, a notification that deep-links into
   an approval, a webview that can navigate itself.

## Where the money is

- An origin that can be set, spoofed or inherited by a page that should not hold it, reaching an
  already-granted permission.
- A displayed payload derived from anything other than the exact bytes being signed.
- A batched or nested call whose inner elements never reach the screen.
- A deep link or scheme handler that reaches a signing or account-management screen directly.
- A permission remembered against a key the page influences.
- An approval the page can mutate after it is displayed.
- A webview whose bridge is exposed to content the wallet did not load itself.

## Discipline

- **Device-malware and local-attacker findings pay nothing.** Every program in this class prices
  "an attacker who already runs code on the user's machine reads the seed" at zero. If your
  precondition is a compromised host, a malicious local app with the right entitlements, or
  physical possession, read the program's exclusions before writing it up — the one shape that
  pays here is **remote**: a web page, a link, a message, a peer.
- **Name the remote entry point in the first sentence** of the candidate, or it reads as the
  excluded shape and gets closed as one.
- **Prove the display gap with both payloads.** Quote what is rendered and what is signed, from
  the code that produces each; "the UI may be misleading" is not a finding.
- **A third-party dApp behaving badly is not a wallet bug** unless the wallet's own guarantee is
  what failed.
- Build or unpack the shipped client and read what actually ships. A repository's source and the
  published extension or package differ, and the published one is what users run.
- Never test against another person's wallet, account or funds; a local install with your own
  test keys is the only acceptable subject.

## Cryptographic implementation

The display gap is not the only way a wallet loses keys. Read the signing and key-generation code
itself, because a flaw there leaks the key to anyone who reads the chain.

- **Ed25519 nonce derivation.** The per-signature nonce must hash the secret prefix of the expanded
  key with the message. SecondFi (ex-Yoroi) on Cardano, Jun 2026, $2.4M: the nonce omitted the
  secret prefix, so private keys were recoverable from on-chain signatures. Quote the nonce
  derivation and compare it with RFC 8032; for ECDSA, check RFC 6979 or a vetted RNG.
- **RNG and entropy build configuration.** Read the build flags and preprocessor guards around the
  entropy source, not only the call site. Coldcard, Jul–Aug 2026, roughly $88–116M: a macro guard
  checked whether the RNG macro was defined rather than enabled, so seeds came from a weak PRNG
  with about 72 bits of entropy. Check the shipped build's configuration.
- **MPC and TSS selective abort.** Find every error the threshold library returns and follow it to
  the integration layer. ChainSecurity showed that library errors swallowed at the integration
  layer let one compromised signer recover the full key through repeated aborts; Vultisig was
  among the affected. THORChain, May 2026, $10.8M, is suspected to involve GG20 but this is NOT
  confirmed.
- **Mobile WebView permission inheritance.** A dApp page loaded in the wallet's in-app browser must
  not inherit the wallet app's native permissions (camera, storage, clipboard, the JS bridge).
  OtterSec, Jun 2026, found this across 20+ mobile wallets.
- **Hardware supply chain.** A device implanted via a reseller (Ledger, Oct 2026) is physical and
  usually out of scope; emit it only if the program lists the supply path.
- **Safe and multisig transaction display.** Compare what each signer is shown with the
  `safeTxHash` they actually sign: `to`, `value`, `data`, `operation` (call versus delegatecall),
  gas fields and nonce. Bybit, Feb 2025: malicious JavaScript in Safe{Wallet}'s S3 bucket made
  signers blind-sign a delegatecall that swapped the Safe's implementation. A signer UI that
  renders a decoded call while the hash covers `operation = 1` is the shape to look for.

Proof for this section is a local reproduction with your own test keys: two signatures that
recover the key, a seed generated under the shipped build flags, an abort sequence in the
library's own test harness, or a rendered screen beside the hash that was signed.
