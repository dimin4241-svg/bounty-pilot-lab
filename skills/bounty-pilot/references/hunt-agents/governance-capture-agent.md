# Governance capture agent — what it costs to pass a proposal, and what passing buys

Governance is an access-control system whose key is for sale. A DAO is captured when the cost of
passing a proposal is lower than the value the proposal can move. **Your question is: what is the
cheapest set of votes that passes an arbitrary payload, and what does that payload control?**

Programs differ sharply on "governance attacks": some exclude them, some pay for them only when a
code defect lowers the cost. Read the program's rules before pricing the result, and emit an
excluded shape as a LEAD tagged `likely-excluded` with the clause.

## Procedure

1. **Read the quorum and threshold denominators.** Quorum is a fraction of something: total
   supply, circulating supply, a wrapped token's supply, delegated supply, or votes cast. Find the
   line and name the denominator. Term Finance, Aug 2026, $8.47M: quorum was measured against the
   wrapped token's supply, so 0.5 ETH bought 90% of the votes.
2. **Read how voting power is snapshotted.** The block used (proposal creation, start, current),
   whether `getPastVotes` or a live balance is read, and whether power can be borrowed, flash
   loaned or moved between accounts within one block. Beanstalk, 2022, is the reference case for
   same-transaction flash-loaned voting power.
3. **Walk delegation edge cases.** Self-delegation on transfer, delegation to the zero address,
   checkpoints written twice in one block, delegated power that survives a transfer, and vote
   counting that sums balances instead of checkpoints.
4. **Compute cost-to-pass from live state.** Read supply, delegated supply and recent turnout at a
   pinned block, then compute the tokens needed to meet quorum and outvote a typical turnout, and
   their cost against measured liquidity. BonkDAO, Jul 2026, $20M: roughly $4.4M of BONK passed a
   proposal with only 7 voters and no timelock. Astroport/Neutron, Sep 2026, $4.4M: an admin
   transfer passed by proposal after buying NTRN.
5. **Compute value controllable after passing.** Treasury balances, admin roles, upgrade rights,
   minting rights and parameter setters the executor holds, read on chain. Net it against step 4.
6. **Compare the payload with the description.** Is the executed calldata hashed into the proposal
   id, and is the description? Can the payload be changed after voting starts? Does the UI decode
   the calldata or show the description only?
7. **Find timelock bypasses.** A proposal that changes the timelock delay, replaces the timelock,
   or calls a function the timelock does not guard. Term Finance also used veto-disguised
   proposals that zeroed the timelock delay.
8. **Read emergency and guardian powers.** Who can cancel, veto, fast-track or execute without a
   vote, and whether that role can itself be set by a proposal.

## Where the money is

- A quorum denominator smaller than the supply that actually votes.
- Voting power read at the current block, or snapshotted at a block the proposer chooses.
- A low-turnout DAO with no timelock whose executor holds more than the cost to pass.
- A proposal that edits the timelock or guardian in the same execution that uses it.
- A payload that is not bound to what voters were shown.

## Proof standard

The quorum and power lines quoted; live supply, delegated supply, turnout and treasury read at a
pinned block; the cost-to-pass and value-controllable figures with their inputs. The strongest
form is a fork test that acquires the votes, proposes, votes, waits out the live delay and executes
the payload, printing the treasury before and after.

## What does not pay

- "A whale could pass a bad proposal" with no defect that lowers the cost; that is how governance
  is meant to work.
- Many programs exclude governance attacks and attacks needing a majority of tokens. Check first.
- Guardian or multisig misuse by the trusted holders themselves is admin behaviour.
