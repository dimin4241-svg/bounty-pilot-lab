# What has actually been exploited

A reading list of root causes that took real money, each with the shape to grep for. Use it to aim
lenses and to argue severity: a mechanism with a named precedent is much harder for triage to call
theoretical.

**Read the caveats.** Loss figures differ between trackers, and attributions get revised when
post-mortems land — treat every number here as approximate and cite the protocol's own post-mortem
in a report, never this file. This is a pattern library, not a source of record.

## The distribution matters more than any single entry

Across 2025–2026, **the largest losses were not broken Solidity.** Vendor tallies put the majority
of losses on stolen keys, compromised infrastructure and social engineering. The Bybit theft
(~$1.4B, February 2025, the largest ever) came from a supply-chain compromise of a third-party
multisig front end, and several large 2026 incidents started with a socially engineered developer.

Two 2026 tallies sharpen this. Hacken's Q3 2026 report put about 77% of the quarter's ~$1.18B in
losses (~$906.8M) on compromised suppliers, developer tools or other surfaces outside any audit's
scope ([CoinDesk](https://www.coindesk.com/tech/2026/10/18/crypto-audits-give-investors-false-sense-of-security-as-q3-hacks-cost-usd1-18-billion-hacken-says)).
CertiK's H1 2026 report counted code vulnerabilities as the most *frequent* cause (204 incidents)
but only about $152M of the value ([CertiK](https://www.certik.com/skynet-report/certik-hack3d-h1-2026-report)).
Many incidents, each modest: that is the contract-level bounty market, and it is also why the
deployed configuration around the code (below) deserves a pass of its own.

Two consequences for a hunter:

1. **Most contract-level money is in mid-size protocols**, not in the headline numbers. Do not
   calibrate your expectations on the biggest incidents; they are not bugs you can find by reading
   code.
2. **Many programs include web, API and infrastructure scope** with real payouts and far fewer
   competent competitors than the contract scope. Read the program's full scope before assuming it
   is a Solidity-only hunt.

## Signing control planes / EIP-7702 — Binance, October 2026

- **Official preliminary account.** Binance said on 30 October that its initial
  investigation suggested a compromised DevOps laptop, access to a service container
  and unauthorized withdrawal requests, with no evidence of private-key leakage.
  The final post-mortem has not been published.
  [Binance update](https://www.binance.com/en/support/announcement/detail/c5a8729a97ac486d963784d96c5642d7).
- **On-chain analysis, not a confirmed authorization root cause.** TRM Labs reports
  an Ethereum EIP-7702 delegation using 50 pre-signed authorizations during the
  29 October attack, alongside transfers on other networks.
  [TRM Labs](https://www.trmlabs.com/resources/blog/north-korea-steals-usd-6-36-billion-from-binance-in-the-largest-hack-in-history).
- **Bounty-worthy question.** Does an *in-scope lower-privilege* client have a route
  to get the signer to authorize an unintended delegate, network, wallet, recipient,
  amount, nonce window or replay? EIP-7702 still requires a valid EOA signature.
  A stolen employee machine or privileged service key alone is not a demonstrated
  low-privilege exploit and is often excluded.

→ Lens: `signing-control-plane`, plus `privileged-path` and `integration-auth`.
Never label Binance's final root cause as established.

## Access control and initialization

Measurably the hardest category for automated reviewers, and consistently the most expensive.

- **Config value that makes a guard vacuous.** Nomad bridge (~$190M, 2022): an upgrade left the
  trusted root at zero, so any forged proof verified. Grep: a guard comparing against a settable
  address/root/hash, and read it live — zero or default accepted is the finding.
- **Uninitialised implementation.** Parity multisig (2017, ~500k ETH frozen): a library left
  uninitialised, then destroyed. Still shipping today as UUPS implementations with no
  `_disableInitializers`.
- **Role reachable through a message.** Poly Network (~$611M, 2021): a crafted cross-chain message
  changed the keeper role.
- **Governance by spot balance.** Beanstalk (~$182M, 2022): flash-loaned voting power executed a
  malicious proposal in one transaction.
- **Supply-cap and limit bypass.** Venus (~$3.7M, 2026): a supply cap that could be stepped around.
  Caps are guards; attack them like guards.

→ Lens: `privileged-path`, `upgrade`.

## Arbitrary external call plus standing approvals

The most *repeated* production bug of the last few years, because every aggregator reinvents it.

- Routers and bridge adapters that take a target and calldata from the caller: LI.FI (2022 and
  again 2024), Socket (~$3.3M, 2024), and a long tail of zappers and swap helpers. Users' standing
  approvals are what turns a plumbing bug into a drain.
- Unconstrained `delegatecall`, including to a settable library or a registry-loaded module.
- Munchables (~$62M, 2024) is the insider variant: an upgradeable contract whose storage was
  pre-set so the "upgrade" handed over control.

→ Lens: `external-call`, `privileged-path`.

## Cross-chain and message verification

- **Verifying the envelope, not the contents.** Verus–Ethereum bridge (~$11.6M, 2026): the notarised
  state root and proofs verified correctly, but nothing checked that the stated transfer amount
  matched the payout. Same family: Wormhole (~$326M, 2022), where signature verification was
  bypassed by passing an unvalidated account.
- **Authenticating the messenger instead of the message.** A handler checks `msg.sender == endpoint`
  and then trusts a sender field that travelled inside the attacker's payload. The permissionless
  compose/queue mechanisms of modern messaging layers make the `msg.sender` check worthless for
  identity — read the framework's own source to learn who may make it call you.
- **Bridge infrastructure rather than bridge contracts.** KelpDAO (~$292M, 2026) involved a
  compromised messaging RPC. Out of contract scope, in scope on some programs. Blockaid's analysis
  adds the configuration half: the route was secured by a single DVN, so one compromised verifier
  was enough ([Blockaid](https://blockaid.io/blog/how-a-single-layerzero-dvn-compromise-drained-292m-from-kelpdao));
  see "Deployed configuration as the vulnerability" below.

→ Lens: `integration-auth`.

## Oracles and economic feasibility

- **Pricing off a pool the attacker can move.** Mango Markets (~$115M, 2022), Rhea Finance (~$7.6M,
  2026, oracle manipulated with seeded liquidity), Makina (~$4.1M, 2026, flash-loaned manipulation
  of Curve pool data). The code often looks fine; the finding is the *ratio* between pool depth and
  position cap, which only live data shows.
- **Read-only reentrancy into a price.** Sentiment (2023): a view function read mid-operation by a
  third protocol returned a broken value.
- **A constant that selects the wrong feed.** A hardcoded asset index or feed id that names one
  asset and selects another. Invisible in source review; one live read settles it.
- **Stale or fallback behaviour** is usually in the program's known-issues list — check before
  spending a pass on it.

→ Lens: `economics`, `live-reality`.

## Arithmetic, precision and compiler

- **Math-library overflow.** Cetus on Sui (~$223M, 2025): an overflow in the concentrated-liquidity
  math library. KyberSwap (~$48M, 2023): an intricate tick/precision edge in concentrated liquidity.
  Tick math, bit shifts, fixed-point helpers and curve invariants are where the big numbers live.
- **Rounding that favours the caller on both legs, amplified by batching.** Balancer v2 (Nov 2025,
  ~$95M by Balancer's own post-mortem, more counting forks): rounding in the upscaling of
  `EXACT_OUT` swaps in Composable Stable Pools, repeated inside one `batchSwap` at balances pushed
  to a few wei, moved the invariant and the BPT price. No access-control flaw was involved; early
  analyses that said otherwise were revised. Also the whole family of share-price and
  exchange-rate round trips. Write-ups: [OpenZeppelin](https://www.openzeppelin.com/news/understanding-the-balancer-v2-exploit),
  [Certora](https://www.certora.com/blog/breaking-down-the-balancer-hack). See "Rounding amplified
  by repetition" below for the 2025 siblings.
- **Donation / inflation attacks.** Direct transfers that move a share price so later deposits round
  to zero, or an attacker's shares inflate before redemption. ERC-4626 vaults, cToken-style markets,
  empty-market first depositors.
- **Compiler bugs are a real finding class.** Curve (~$70M, 2023): a malfunctioning reentrancy guard
  in specific Vyper versions. Truebit (~$26M, Jan 2026): an **old contract compiled with a pre-0.8 Solidity
  version and an unchecked addition** in the purchase price, so a crafted amount priced a mint
  at zero ([BlockSec](https://blocksec.com/blog/in-depth-analysis-the-truebit-incident)) — and an
  old contract nobody maintained that still held value (see "Abandoned but funded"). Both are found by
  checking the compiler version, not by reading the contract:
  ```sh
  python3 <skill-dir>/scripts/bounty.py solc-bugs --repo <checkout>
  ```

→ Lens: `economics`, `accounting`, plus the `solc-bugs` check in stage 1.

## Logic added later that breaks logic written earlier

- Euler (~$197M, 2023): a donate function, added later, broke an invariant the liquidation path
  depended on. Neither function is wrong alone.
- Penpie (~$27M, 2024): an attacker-registered market reached a reward path that trusted registry
  entries.
- Hundred Finance and the empty-market family: a market in a state the original design never had.

→ Lens: `delta`, `seam`, `accounting`.

## Solana and non-EVM account models

- Wormhole (2022) and Cashio (~$52M, 2022): a passed account whose owner, mint or type was never
  validated, so forged state was accepted — the "infinite mint" shape.
- Crema Finance (2022): a fake tick account supplied to a real instruction.
- Cetus (2025) is the Move/Sui reminder that non-EVM runtimes have their own arithmetic surface.

→ Lens: `anchor-account`, `economics`.

## The 2025–2026 additions

The sections below were added from 2025–2026 incident analyses. Each names its source; amounts are
approximate, and "preliminary" means the protocol had not published a final post-mortem when the
entry was written. Because this file and the lenses now describe these incidents, none of them is
a blind backtest case for this version of the skill; `holdout-2026.md` says which earlier version
each one can still measure.

## Deployed configuration as the vulnerability

The code was fine; the values it was deployed with were not. None of these appear in a diff, so
none of them were in an audit.

- **KelpDAO (Apr 2026, ~$292M):** a LayerZero route secured by a 1-of-1 DVN, so compromising one
  verifier forged the message ([Blockaid](https://blockaid.io/blog/how-a-single-layerzero-dvn-compromise-drained-292m-from-kelpdao)).
- **CrossCurve (Feb 2026):** a confirmation threshold of 1 combined with a publicly callable
  `expressExecute` ([Halborn](https://www.halborn.com/blog/post/explained-the-crosscurve-hack-february-2026)).
- **Bonzo Lend:** a pull oracle that accepted an update carrying zero valid signatures
  ([Bonzo incident report](https://bonzo.finance/blog/bonzo-lend-incident-report-oracle-provider-exploit)).
- **Drift:** a 2-of-5 multisig with no timelock and durable nonces, so pre-signed transactions
  stayed valid indefinitely ([Chainalysis](https://www.chainalysis.com/blog/lessons-from-the-drift-hack/)).
- **Troves (Oct 2026, initial loss ~8.6 BTC, preliminary):** a stale rebalancer
  permission that was never revoked ([KuCoin News](https://www.kucoin.com/news/flash/defi-protocol-troves-vault-hacked-initial-loss-of-8-6-btc)).

Shape: read the live values — verifier sets and thresholds, signer counts, timelock delays, role
members, oracle signer quorum, every permission granted to a contract that has since been replaced.

```sh
python3 <skill-dir>/scripts/bounty.py config-snapshot --rpc <url> --targets <addresses.json> --out <run>/config-snapshot.json
```

→ Lens: `live-reality`, `privileged-path`, `bridge-messaging`, `oracle-listing`; tool
`config-snapshot` (`references/config-snapshot.md`); `blind-spots.md` §16.

## Uncapped privileged mint

- **Resolv (Mar 2026, ~$25M):** a single compromised key could mint without any on-chain bound
  ([Sentora](https://sentora.com/research/articles/the-resolv-hack-25m-from-a-single-compromised-key)).
- **Echo eBTC and StablR (May 2026):** privileged mint paths abused in the same period
  ([BlockSec](https://blocksec.com/blog/defi-security-incidents-echo-protocol-stablr-more)).

Shape: a `mint`, `complete`, `finalize` or `fulfil` function gated **only** by a role, with no
on-chain cap, rate limit, oracle check or collateral check behind it. The key being stolen is out of
scope; the missing bound is a design fact, and on some programs a finding when a lower-trust role
(a relayer, a keeper, an operator hot key) holds the mint.

→ Lens: `privileged-path`, `impact-first`; `blind-spots.md` §23.

## Rounding amplified by repetition

One wei in the caller's favour is nothing; one wei per step inside a loop the caller controls,
at balances the caller pushed to a few wei, is the pool. Balancer v2 (Nov 2025) is the canonical
case (above). The same year added Bunni (Sep 2025), zkLend (Feb 2025) and Yearn yETH (Nov 2025)
to the family ([Halborn 2025 review](https://www.halborn.com/blog/post/year-in-review-the-biggest-defi-hacks-of-2025)).

Shape: every rounding direction that favours the caller, on a path the caller can repeat cheaply in
one transaction (`batchSwap`, multicall, a loop of deposit/withdraw), especially near empty or
near-zero balances.

```sh
python3 <skill-dir>/scripts/bounty.py rounding-map --repo <checkout> --out <run>/rounding-map.json
```

Then test the cheapest repetition with `templates/RepetitionDrift.t.sol`.

→ Lens: `accounting`, `economics`, `classic`, `seam`; tool `rounding-map`
(`references/rounding-map.md`); `blind-spots.md` §17.

## Silent patches and dependency N-days

- **Cosmos EVM chains (Aug 2026, ~$14.8M realized across several chains):** delegating from a
  locked or vesting balance subtracted from the spendable balance, so 0 − 1 wrapped to the maximum;
  the fix was pushed publicly without an advisory and chains still on the old module were drained
  in the following days ([The Hacker News](https://thehackernews.com/2026/08/cosmos-evm-flaw-exploited-after-cosmos.html),
  [BlockSec](https://blocksec.com/blog/defi-security-incidents-cosmos-evm-moonwell)).
- **Cetus (May 2025)** is the library form: the overflow sat in a shared math dependency
  (`integer-mate`), so every protocol pinning it carried the same bug (see "Arithmetic" above).
- **Liquid Network / Elements (Sep 2026, ~$320M reported):** on a range-proof cache hit the
  verification and minimum-value checks were skipped, so unbacked L-BTC was minted and pegged out
  (`blind-spots.md` §20) ([crypto.news](https://crypto.news/liquid-network-320-million-drain-cache-bug-unbacked-bitcoin/)).

Shape: a fork or a pinned dependency behind upstream, where upstream shipped a security fix —
often with an unremarkable commit message — that the fork never merged.

```sh
python3 <skill-dir>/scripts/bounty.py nday-scan --repo <checkout> --upstream <name>=<upstream-clone> --out <run>/nday-scan.json
```

→ Lens: `upstream-diff`, `delta`, `node-client`; tool `nday-scan` (`references/nday-scan.md`);
`blind-spots.md` §18.

## Abandoned but funded

- **Truebit (Jan 2026, ~$26M):** an old pre-0.8 contract still holding value (above).
- **Aztec Connect (Jun 2026):** a sunset rollup whose contracts still held funds
  ([BlockSec](https://blocksec.com/blog/efi-security-incidents-jaredfromsubway-aztec)).
- **Troves (Oct 2026):** a permission left on a component nobody maintained (above).

Shape: deprecated contracts, old proxies, previous versions and retired vaults that still hold a
balance, an approval or a role. They are often still in scope by address and absent from the
current source tree.

```sh
python3 <skill-dir>/scripts/bounty.py legacy-sweep --repo <checkout> --program <run>/program.json --out <run>/legacy-sweep.json
```

→ Lens: `live-reality`, `privileged-path`, `impact-first`; tool `legacy-sweep`
(`references/legacy-sweep.md`); `blind-spots.md` §19.

## A message exists is not a message means

The proof, signature or root verified; nothing checked that the fields the payout used were the
fields that were proven.

- **Verus–Ethereum (2026):** the transfer amount was never compared with the payout (above).
- **Aztec Connect (Jun 2026):** BlockSec's analysis centres on a `numTxs` field the contract relied
  on ([BlockSec](https://blocksec.com/blog/efi-security-incidents-jaredfromsubway-aztec)).
- **CrossCurve (Feb 2026):** a message accepted on one confirmation through a public execution
  path (above).

Shape: for every field the action reads, find the line that binds it to what was verified.

→ Lens: `integration-auth`, `bridge-messaging`, `zk-soundness`; `blind-spots.md` §21.

## Thin-liquidity collateral and signed-oracle abuse

- **Tectonic (Aug 2026, Cronos, ~$75–125M before a chain rollback):** a thinly traded collateral
  token pumped about 100x in minutes against a 20% collateral factor, then borrowed against across
  many markets ([Halborn](https://www.halborn.com/blog/post/explained-the-tectonic-hack-august-2026)).
- **Moonwell (Aug 2026, Base, ~$9.1M):** a 50% collateral factor on an illiquid token whose feed
  followed a pumped market, with the supply cap bypassed by transferring tokens straight to the
  market contract ([BlockSec](https://blocksec.com/blog/defi-security-incidents-cosmos-evm-moonwell)).
- **Ostium (Jul 2026, Arbitrum, ~$23.75M):** validly signed price reports carrying attacker-chosen
  timestamps, accepted through a trusted forwarder and looped in one batch
  ([BlockSec](https://blocksec.com/blog/defi-security-incidents-afx-trade-ostium)).
- **YieldBlox (Feb 2026, Stellar, ~$10M):** an oracle misconfiguration
  ([BlockSec](https://blocksec.com/blog/yieldblox-dao-incident-on-stellar-oracle-misconfiguration-enabled-a-10m-drain)).

Shape: a listed collateral whose market depth is small against its cap, and price updates signed
off chain whose freshness, source or signer set the contract does not fully check. Like Mango and
Rhea above, the finding is a ratio that only live data shows.

→ Lens: `oracle-listing`, `economics`, `live-reality`.

## Governance capture by purchase

- **BonkDAO (Jul 2026, Solana, ~$20M):** voting power bought on the market passed a proposal in a
  realm with a handful of voters and no timelock
  ([BlockSec](https://blocksec.com/blog/defi-security-incidents-afx-trade-ostium)).
- **Term Finance (Aug 2026, Ethereum, ~$8.47M):** quorum measured against a wrapped token's small
  supply, so a fraction of an ether bought most of the vote, and proposals presented as vetoes
  zeroed the timelock ([BlockSec](https://blocksec.com/blog/defi-security-incidents-cosmos-evm-moonwell)).
- **Astroport (Sep 2026, Neutron, ~$4.4M):** admin rights transferred by a proposal after the
  voting token was bought; secondary source only,
  [Blockhertz](https://blockhertz.com/blog/blockchain-security-report-october-2026).

Shape: Beanstalk without the flash loan. Compare the market cost of the voting power needed to pass
a proposal with the value the proposal can move, and check quorum, delay and veto against a buyer
who holds the tokens for the whole voting period.

→ Lens: `governance-capture`, `privileged-path`.

## Deploy and initialize in two transactions

- **Kinto (Jul 2025):** an initialization race on a proxy
  ([Halborn July 2025 review](https://www.halborn.com/blog/post/month-in-review-top-defi-hacks-of-july-2025)).

Shape: a proxy deployed in one transaction and initialized in another, so anyone can initialize it
first — or initialized it already, in a way the team never noticed.

```sh
python3 <skill-dir>/scripts/bounty.py init-race --repo <checkout> --out <run>/init-race.json
```

→ Lens: `upgrade`, `privileged-path`; tool `init-race`; `blind-spots.md` §22.

## Hooks, keepers and standing approvals

- **Cork (May 2025):** two independent flaws, one of them in a hook path, combined into one chain
  ([BlockSec](https://blocksec.com/blog/cork-protocol-incident-two-independent-flaws-combine-into-one-devastating-exploit-chain)).
- **rsETH Uniswap v4 hook and Safe module (Sep 2026, ~$7.73M from one user):**
  [KuCoin News](https://www.kucoin.com/news/flash/uniswap-v4-hook-exploited-in-attack-user-loses-7-73m-in-rseth).
- **jaredfromsubway (Jun 2026):** an MEV bot's contract and the authority it held; BlockSec covers
  the mechanism ([BlockSec](https://blocksec.com/blog/efi-security-incidents-jaredfromsubway-aztec)).

Shape: code that runs on someone else's call — a v4 hook, a keeper task, a Safe module, a bot's
callback — holding approvals or authority it uses without checking who triggered it.

→ Lens: `hooks-keepers`, `external-call`.

## ZK soundness

- **zkVM transcripts (Mar 2026):** OtterSec on zkVMs whose proofs did not faithfully bind the
  claimed statement ([OtterSec](https://osec.io/blog/zkvms-unfaithful-claims/)).
- **Zcash Orchard (2026):** a soundness bug in the Orchard circuit
  ([BlockSec](https://blocksec.com/blog/web3-security-zcash-orchard-soundness-bug-analysis)).
- **OpenVM:** soundness bugs found by zkSecurity ([zkSecurity](https://blog.zksecurity.xyz/posts/openvm-bugs/)).

These were found and paid as bounties or disclosures rather than exploited for loss, as far as the
sources say. → Lens: `zk-soundness`; adapter `adapters/zk.md`.

## Wallet cryptography

- **SecondFi (Jun 2026):** an Ed25519 implementation issue
  ([BlockSec](https://blocksec.com/blog/efi-security-incidents-jaredfromsubway-aztec)).
- **Coldcard (2026, ~$116M reported):** hardware-wallet randomness
  ([TRM Labs](https://www.trmlabs.com/resources/blog/the-largest-hardware-wallet-exploit-of-2026-inside-the-usd-116-million-coldcard-hack)).
- **MPC selective abort:** ChainSecurity's research on extracting keys from MPC wallets by
  aborting selectively and retrying ([ChainSecurity](https://www.chainsecurity.com/blog/please-try-again-stealing-keys-from-mpc-wallets-via-selective-abort-attacks/)).

Shape: nonce and randomness generation, retry-on-failure in a signing protocol, and any custom
curve code. → Lens: `wallet-app`, `signing-control-plane`.

## AI agents holding wallets

- **Grok / Bankr (May 2026):** an incident involving an AI agent connected to a wallet, recorded by
  the OECD AI incident monitor ([OECD.AI](https://oecd.ai/en/incidents/2026-05-04-4a73)).

Shape: an agent whose instructions can come from untrusted content and whose tools can sign or
transfer. Ask what the agent can be told to do by text it reads, and what bounds the wallet
enforces regardless. → Lens: `agent-wallet`.

## How to use this file

Pick the two or three classes that match the target's shape, run the corresponding lenses first, and
when you find something, check this file for the precedent — then write the precedent into the
report's impact section. "This is the Nomad class of defect" tells a triage engineer in six words
why the severity you claimed is the right one.

Do not cite a precedent you have not checked, and never imply a protocol was hacked when it was not.
