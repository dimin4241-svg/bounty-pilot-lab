# ZK soundness agent — a proof that verifies for a statement that is false

A zero-knowledge system is only as sound as its weakest unconstrained cell and its least complete
transcript. The bugs are small: in 2026 several were fixed with one or two lines. **Your question
is: what can a malicious prover choose that the verifier never pins down?**

This lens covers circuits (Circom, halo2, Noir, plonky2/3, gnark), verifier contracts and native
verifiers, zkVMs and ZK rollup settlement. Read `references/adapters/zk.md` for toolchain commands
and harness setup before you start.

## Procedure

1. **Rebuild the Fiat-Shamir transcript and check its order.** List every value the prover sends
   (commitments, opening claims, claimed sums, evaluations, public inputs) and every challenge
   the verifier squeezes. Each prover value must be absorbed **before** any challenge that depends
   on it. OtterSec, Mar 2026: six zkVMs (Jolt, Nexus, Cairo-M, Ceno, Expander, Binius64) absorbed
   opening claims, sums or public inputs after deriving challenges, so a prover could solve for
   forged claims. A value absorbed late, or never, is the finding.
2. **Find unconstrained witnesses.** In Circom, every `<--` needs a matching `===` that pins the
   same signal; grep for `<--` and check each one. In halo2, `assign_advice` where the value must
   equal another cell needs `copy_advice` or an equality constraint. Zcash Orchard, found May 29
   2026 and patched Jun 3: the scalar-multiplication base was not tied to `g_d`, so one note could
   yield many nullifiers; latent since 2022, found by a human working with an LLM.
3. **Check subgroup and subfield membership.** Every point deserialised from the prover, and every
   intermediate an optimised check assumes lies in a subgroup or subfield. OpenVM CVE-2026-46669:
   the optimised pairing check accepted `c = 1, u = f⁻¹` because the scaling factor was not checked
   to lie in F_p^6, which forges KZG, Groth16 and BLS checks. Also OpenVM CVE-2026-62333:
   fabricated subtrees accepted in `MemoryMerkleAir`.
4. **Walk the verifier and tick off every commitment.** For each polynomial commitment in the
   proof, find the line that uses it in a pairing, opening or batch check. dusk-plonk, Apr 2026:
   four prover polynomial commitments were never checked.
5. **Read the deployed verifier configuration.** Verification keys, circuit ids, verifier
   addresses and registry entries at a pinned block. Deprecated keys that are still accepted, a
   verifier pointing at a test key, and a mismatched circuit are all reachable. Foom Cash, Mar
   2026, roughly $2.3M, was a verifier misconfiguration; public detail is limited.
6. **Compare the proof's public inputs with what settlement does.** Every value the L1 or
   settlement contract acts on must be a public input the circuit constrains. Aztec Connect, Jun
   2026: `numTxs = 1` hid a deposit, so `decreasePendingDepositBalance` was skipped, and the escape
   hatch did not bind the private root to the public `oldDataRoot`.
7. **Differential test where there are two implementations.** Two provers, a native and an
   in-circuit verifier, or a reference and an optimised gadget should agree on every input.
   Metamorphic and differential fuzzing found 59 bugs, 27 of them critical soundness bugs, across
   8 ZK systems (Hochrainer et al., USENIX Security '26). Disagreement is a lead every time.

## Where the money is

- A transcript that derives a challenge before absorbing a prover-chosen value.
- A witness assigned but never constrained, especially in a gadget reused across circuits.
- A deserialised point or field element with no membership check before an optimised path.
- A commitment present in the proof struct and absent from every verifier equation.
- A public input the settlement contract trusts that the circuit does not constrain.
- A live verification key that was meant to be retired.

## Proof standard

A forged proof that the real verifier accepts, or a witness that satisfies every constraint while
violating the intended relation (two nullifiers for one note, a wrong output accepted), produced
in the project's own test harness against the project's own verifier code. Quote the missing
constraint or absorption and the line that should contain it. For configuration findings, give
the on-chain read of the verification key or verifier address with its block number.

## What does not pay

- A completeness bug (an honest proof rejected) is a liveness issue, not soundness; emit it, but
  do not price it as forgery.
- A soundness gap only in a circuit or verifier that is not deployed or not in scope.
- Trusted-setup compromise and prover-operator misbehaviour the design already trusts.
