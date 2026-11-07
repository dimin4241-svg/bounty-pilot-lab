# Adapter — ZK circuits, provers and verifiers

Route here when a repository contains circuits (`.circom`, Noir `Nargo.toml`, halo2 / gnark /
plonky2 / plonky3 / arkworks crates), a zkVM guest or host (SP1, RISC Zero, Jolt, OpenVM), a Cairo
program proved by a STARK prover, or an on-chain verifier contract (`Verifier.sol`, a generated
Groth16/PLONK/FFLONK verifier, a STARK verifier). This is a **soundness checklist**, not a full
methodology: it tells you which questions pay and which tools answer them, and it leaves the
cryptography to the specialists. Say in `coverage.md` which of the items below you could not
settle. The dispatched form is the `zk-soundness` lens (`hunt-agents/zk-soundness-agent.md`); add
`node-client` when the prover or sequencer itself is in scope.

The finding class is almost always one sentence: **a proof verifies for a statement that is false**
(soundness — theft, forged withdrawal, forged state root), or **a true statement cannot be proved**
(completeness — a liveness or freeze finding, usually lower on the ladder but real).

## Read these first, in this order

1. **The relation spec.** What does the protocol say the proof proves, in words? A paper, a spec,
   a doc comment on the top-level circuit. Write the relation down as a list of constraints you
   expect. Without it you are reading constraints with nothing to compare them against.
2. **The constraints, not the witness code.** In Circom, `<--` assigns without constraining and
   `<==` does both; in halo2, `assign_advice` places a value and only a gate or lookup constrains
   it. Diff the expected relation against what is actually constrained.
3. **The verifier and its public inputs.** Which public inputs does the on-chain verifier take,
   where does the contract get each one, and is each one bound to on-chain state the protocol
   then acts on?
4. **The transcript.** For any Fiat-Shamir proof: the exact order of everything absorbed before
   each challenge is squeezed.

## Soundness checklist

- **Transcript completeness and order.** Every public input, every commitment and the
  verification key (or its hash) must be absorbed **before** the challenge that depends on them.
  A value absorbed after its challenge, or never, lets a prover choose it adaptively.
- **Unconstrained witnesses.** Every `<--`, every hint, every `assign_advice` and every
  `unconstrained fn` (Noir) needs a constraint that pins it. A computed-but-unchecked inverse,
  bit decomposition or division remainder is the classic shape.
- **Range checks and field overflow.** Arithmetic is modulo p. A sum, product or comparison that
  "cannot overflow" in integers can wrap in the field; a bit decomposition without a check that
  the bits recombine below p aliases two values onto one. Check every `LessThan`/`Num2Bits` width.
- **Group, subgroup and curve membership.** Points from the prover must be on the curve and in the
  prime-order subgroup; extension-field elements must be in the intended subfield. Small-subgroup
  points have broken real verifiers.
- **Public input binding.** A nullifier, root, recipient, amount or chain id that is a public
  input must be compared by the contract against the value it then uses. A verifier that accepts
  a proof about root A while the contract pays out against root B is the bridge "envelope, not
  contents" bug in ZK form (`hack-patterns.md`).
- **Verification-key management.** Who can set or rotate the verifying key, whether old keys stay
  accepted, and whether a deprecated circuit whose key is still live is weaker than the current
  one. Read the deployed key, not the repository's.
- **Recursion and aggregation boundaries.** At each layer, what does the outer proof assert about
  the inner one: its key, its public inputs, its program id? An aggregation that checks "some
  valid proof" rather than "a proof of this program with these inputs" is the shape.
- **Nondeterministic hints in zkVMs.** Precompiles and host-supplied hints (`syscall` reads,
  memory-initialisation, accelerated ops) are prover-chosen. Each needs a constraint in the
  circuit that checks the hint, not a check in the host code.
- **Completeness bugs.** A valid input that no honest prover can prove — an edge-case range, a
  maximum-size batch, an empty tree — freezes whatever needs that proof. File it as a freeze with
  its persistence established (`impact-classes.md`), not as a soundness bug.

## Tools

- **circomspect** for Circom lints (unconstrained signals, `<--` without a matching constraint).
- **Picus**, **Ecne** and **ZKAP** for under-constraint detection: they look for two witnesses that
  satisfy the same public inputs. A reported pair is close to a proof of the bug.
- **halo2 `MockProver`** to show that a malicious witness satisfies every gate.
- **Differential and metamorphic fuzzing across prover implementations**: the same program proved
  by two zkVMs or two backends, or the same statement in two equivalent forms, should agree. A
  disagreement is a lead in one of them.

Use the target's pinned toolchain. A clean tool run covers only the constraints the tool models;
write down what it does not model (lookups, custom gates, recursion) rather than claiming coverage.

## Proof standard

A soundness finding needs a **concrete false statement that verifies**: the forged witness or
proof, the verifier accepting it (natively, or the on-chain verifier on a fork), and the protocol
action it unlocks. A completeness finding needs the valid input and the prover failing on it. An
under-constraint report from a tool without the protocol consequence is a lead, not a finding.

## Precedents worth reading

- OtterSec on zkVMs whose proofs did not faithfully bind the claimed statement (March 2026):
  [osec.io](https://osec.io/blog/zkvms-unfaithful-claims/).
- A soundness bug in the Zcash Orchard circuit, analysed by BlockSec (2026):
  [BlockSec](https://blocksec.com/blog/web3-security-zcash-orchard-soundness-bug-analysis).
- Soundness bugs found in OpenVM by zkSecurity:
  [zkSecurity](https://blog.zksecurity.xyz/posts/openvm-bugs/).

Read the write-up for the exact mechanism before citing one; `hack-patterns.md` carries them only
as pointers. For Circom-heavy targets, `integrations.md` lists `zksecurity/zk-skills`
`circom-auditor` as a bounded stage to delegate.
