# Cross-contract seam research: experimental v1

This branch introduces an **offline static reading queue**, not a vulnerability detector.
It reads a pinned Solidity compiler build-info JSON and emits typed cross-contract
call candidates, bounded paths, unresolved calls and state-write review prompts.

## Usage

```sh
python3 skills/bounty-pilot/scripts/cross_contract_seams.py \
  --build-info /private/pinned-build-info.json \
  --out /private/seams.json --max-depth 4
python3 -m unittest discover -s skills/bounty-pilot/tests -p test_cross_contract_seams.py
```

Never execute untrusted target code as part of this command. No RPC, target calls,
transactions, agent requests or model spend occur.

## Interpretation

- `edges`: compiler-typed candidate calls; overloads are not resolved.
- `unresolved_calls`: unknown interfaces, dynamic targets, address-typed calls and
  unsupported dispatch; **not** evidence that the code is safe.
- `state_write_sites`: AST assignments, not proof of storage ownership or final state.
- `leads`: questions for a human researcher, always `UNVERIFIED`.
- `limits.truncated`: budget exhaustion, making coverage incomplete.

## Remaining work (not implemented in v1)

1. Resolve interfaces, inheritance, overrides, proxy implementation and
   delegatecall storage context with explicit uncertainty annotations.
2. Attribute storage writes to actual contracts, handle increment/decrement,
   library calls and internal function transitive effects.
3. Add multi-user, multi-transaction transition models and cross-contract
   accounting/ownership invariants supplied from a documented protocol model.
4. Generate local candidate/control harnesses and execute only after explicit
   authorization on the isolated self-hosted Mac runner.
5. Build economic feasibility estimates from measured, pinned fork observations.
6. Run blind independent held-out tests before claiming detection uplift.

Do not assign High/Critical from static leads. No claim of improved discovery,
runtime reachability, exploitability or payment eligibility is made.
