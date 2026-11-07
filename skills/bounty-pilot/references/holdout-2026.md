# Holdout cases — incidents after June 2026

A list of incidents from July 2026 onward that can serve as **blind backtest cases** for a model
whose training data ends before them. It follows `backtest.md` in full: open the case at the
pre-incident revision, hunt it, seal, and only then read the source and transcribe the truth.

**This file deliberately says nothing about any mechanism.** A backtest measures rediscovery only
if the hunter never saw the answer, and the leak is rarely deliberate — it is a one-line summary
read while setting up the case. So each row carries only the project, the date, the chain and the
source the operator scores against. Do not add a root cause, a bug class, an affected contract or a
loss mechanism to this file, ever; put them in the case's private `truth.json` after sealing.

## Rules for the two roles

- **The hunter must not open any source link below before sealing.** Nor search for the incident
  by name, nor read a news summary of it. The links are for the operator.
- **The operator uses the links only after the seal**, to write `truth.json` and decide pairs.
- **Lab 0.53 learned from these incidents, so they cannot measure it.** Its lenses,
  `hack-patterns.md` (bundled into every lens), `blind-spots.md` and the adapters describe their
  mechanisms; removing the mentions from one file does not unteach the others. Each row's **Blind
  for** column names the skill versions that predate any description of the case: run the case
  against a checkout of the commit that released that version (0.52.1 is `33c92d5`;
  `git log --oneline -- VERSION` lists the others), never against 0.53 or later.
- **To measure 0.53 or later, use incidents dated after its release.** Collect them the same way:
  project, date, chain and a source the operator alone reads, added here only after the version
  being measured was tagged. An incident the skill was edited in response to stops being blind
  for every later version.
- **Contamination is reduced, not excluded.** A model may have seen the protocol's code, its
  audits or a similar bug in an older fork. Note the model's stated training cutoff in the case
  README, as `backtest.md` asks.

## Which cases suit a source backtest

A source backtest needs an on-chain or node-code root cause that a reading of the pre-incident
revision could find. Pure key, infrastructure or off-chain-signer compromises are not source cases:
reading the repository cannot rediscover a stolen key. The **Case kind** column records only that
distinction, from what the cited sources make public at the level of "code or not code"; it says
nothing about which code. Where it is unclear, the case is marked `unclear` and the operator decides
after reading the source, before handing the case to a hunter.

| Project | Date | Chain | Case kind | Blind for | Source (operator only) |
| --- | --- | --- | --- | --- | --- |
| BonkDAO | 2026-07-06 | Solana | source | <= 0.52.1 | [BlockSec](https://blocksec.com/blog/defi-security-incidents-afx-trade-ostium) |
| Ostium | 2026-07-15 | Arbitrum | off-chain signer — not a source case | <= 0.52.1 | [BlockSec](https://blocksec.com/blog/defi-security-incidents-afx-trade-ostium) |
| AFX Trade | 2026-07-22 | unspecified in this file | off-chain signer — not a source case | <= 0.52.1 | [BlockSec](https://blocksec.com/blog/defi-security-incidents-afx-trade-ostium) |
| Cosmos EVM chains | 2026-08 | several Cosmos EVM chains | source (node code) | <= 0.52.1 | [The Hacker News](https://thehackernews.com/2026/08/cosmos-evm-flaw-exploited-after-cosmos.html), [BlockSec](https://blocksec.com/blog/defi-security-incidents-cosmos-evm-moonwell) |
| Term Finance | 2026-08-23 | Ethereum | source | <= 0.52.1 | [BlockSec](https://blocksec.com/blog/defi-security-incidents-cosmos-evm-moonwell) |
| Moonwell (MAMO) | 2026-08-27 | Base | source | <= 0.52.1 | [BlockSec](https://blocksec.com/blog/defi-security-incidents-cosmos-evm-moonwell) |
| Tectonic | 2026-08-30 | Cronos | source | <= 0.52.1 | [Halborn](https://www.halborn.com/blog/post/explained-the-tectonic-hack-august-2026) |
| Liquid Network | 2026-09-06 | Liquid (Elements) | source (node code) | none (in `caseforge-catalog.json` since before 0.53) | [crypto.news](https://crypto.news/liquid-network-320-million-drain-cache-bug-unbacked-bitcoin/) |
| Nostra | 2026-09-17 | Starknet | unclear | <= 0.52.1 | [Blockhertz](https://blockhertz.com/blog/blockchain-security-report-october-2026) (secondary) |
| Astroport | 2026-09-22 | Neutron | source | <= 0.52.1 | [Blockhertz](https://blockhertz.com/blog/blockchain-security-report-october-2026) (secondary) |
| NEAR Intents (Omni) | 2026-10-01 | NEAR | unclear | <= 0.52.1 | [The Block](https://theblock.co/news/ecosystems/2026-10-01-near-intents-halts-services-after-3-8-million-exploit-promises-full-compensation-417404) |
| MakerDaoBot | 2026-10 | unspecified in this file | unclear | <= 0.52.1 | none recorded here; find a primary source before using it |
| Troves | 2026-10-31 | Starknet | unclear | <= 0.52.1 | [KuCoin News](https://www.kucoin.com/news/flash/defi-protocol-troves-vault-hacked-initial-loss-of-8-6-btc) |

"Source" here means the cited coverage points at code rather than at a key or a server; it does not
mean the operator has confirmed a pinned pre-incident revision exists. Establish that first: a case
whose vulnerable revision you cannot check out is not a case.

## Preparing a case without reading the answer

1. From the project's repository alone — not from any write-up — pick the last tagged release or
   commit dated before the incident date in the table, and record it in the case README.
2. If the deployed revision at that date is not determinable from the repository and the chain,
   drop the case rather than reading a post-mortem to find it.
3. Run `backtest init` at that commit, hunt, and seal exactly as `backtest.md` describes.
4. Only then open the source, transcribe the truth and score. A case where the hunter saw the
   source, a summary, or a skill version that describes the incident before sealing is void;
   start another.

Report the raw rediscovered count per case and nothing more. Thirteen cases, several of them
unsuitable, cannot support a claim that the workflow improved (`AGENTS.md`, "No benchmark claims").
