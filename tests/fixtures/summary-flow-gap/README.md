# Fixtures: a summary flow that accepts what it cannot render

Real `trezor-firmware` source, copied verbatim with `git show <rev>:<path>`. Two bugs Trezor fixed
in firmware 2.12.5 (released 16 September 2026) and published as paid disclosures, each captured
before and after its fix:

| file | revision | state |
|---|---|---|
| `s1-pre.py` | `5a5305091^` | staking flow accepts `lockup.epoch` / `lockup.unix_timestamp` and never shows them |
| `s1-fixed.py` | `5a5305091` | `fix(solana): fall back to generic UI if stake lockup set` |
| `s2-pre.py` | `537b34f84^` | token transfer reads three ALT-capable accounts by value |
| `s2-partial.py` | `537b34f84` | `fix(core): solana transfer showing LUT address` — guards **one** of the three |
| `s2-fixed.py` | `cd6e7596b` | `fix(solana): fall back to generic UI for more ALT references` — guards all three |
| `instructions.py` | `cd6e7596b` | the generated instruction definitions that give each class its field list |

`instructions.py` is vendored once. The classes the two flows accept are byte-identical across all
of these revisions except `StakeProgramDelegateStakeInstruction` and
`AssociatedTokenAccountProgramCreateInstruction`, which differ only between `537b34f84^` and the
rest and not in any field the two checks read; `StakeProgramInitializeInstruction`, whose field list
drives the S1 case, hashes the same at every revision above.

`s2-partial.py` is the point of the set: a first fix that closed one of three identical holes is
what this generator has to keep reporting.
