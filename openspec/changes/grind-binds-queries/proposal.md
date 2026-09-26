## Why

`docs/SECURITY_CLAIM.md` (2026-09-26) found deviation D1: the grinding nonce never enters the transcript state that the query indices are squeezed from. Every implementation agrees on this (`TranscriptRef`, `Poseidon2Transcript`, `FiatShamirScriptGen.emitGrindingCheck`, `VerifierProgram`), so it is a protocol weakness rather than a mismatch. An adversary who wants a different query set changes a cheap absorbed value, reads the new indices for one hash, keeps only states whose queries land well, and grinds once. The grind is a fixed 2^16 cost, not a multiplier per attempt, and its bits cannot be counted toward soundness: the honest figure is 88 bits conjectured / 44 proven for the system (the spend level), not the ~104 / ~106 in code comments.

## What Changes

- The grind digest becomes the transcript state. In both flavours, a successful grind check sets the state to H(state ‖ nonce) (SHA-256) or P(s ‖ [nonce, 0…])[0..8] (Poseidon2), and the query indices are squeezed from it. On failure the state is left as it was and the verifier rejects.
- The four implementations move together: the Dart transcripts (which the reference verifier, both provers and the native-kernel grind wrapper share), the script emitter, and the verifier AIR (which continues from the grind period instead of restoring the state before it).
- The nonce search is unchanged (smallest nonce meeting the target); the native kernels are untouched.
- A new negative test at proof level: a valid proof whose nonce is replaced by the next valid nonce is refused by the reference verifier, the script and the AIR. Before this change that mutation passed everywhere.
- The exported `templates/sp` verifier templates are regenerated; every existing proof, vector and localnet chain is invalid after this change.
- The `stark-prover` spec's security accounting names its assumption and counts the grind only because of this change.

## Capabilities

### Modified Capabilities

- `stark-prover`: "Parameter sets" (security accounting names the conjecture; the grind counts because the indices depend on the nonce) and "Transcript and hash flavours" (the grind digest is the state the indices come from).

## Measured numbers and bounds

- Soundness per level after the change, grind counted (`docs/SECURITY_CLAIM.md` §4): spend 102 conjectured / 58 proven; levels 1 and 2, 104 / 59; levels 3 and 4, 106 / 60; root 106 / 61. System: 102 / 58, set by the spend level. Before: 88 / 44.
- Script cost: zero opcodes net. The grind hash was computed and dropped; it is now kept. Verified by comparing the root slot's byte and op counts before and after (task 2.3).
- AIR cost: zero periods. The grind period already existed; the next squeeze chains from it instead of restarting from a saved digest (which saved a `fresh` restart, so the period count can only fall). Verified by the periods-used report (task 2.3).
- Proving time: unchanged; the search is the same.

## Non-functional contract

- **Untrusted input:** the nonce is proof data. A wrong nonce is refused before any index is derived, in every implementation.
- **Determinism:** the two provers still produce byte-identical proofs; the smallest-nonce rule is unchanged. Requirement kept.
- **Compatibility:** this is a consensus-level change to what the verifier accepts. There is no proof format version to bump (the proof codec carries none) and the wire protocol is unchanged, so the incompatibility is carried by the package: the next release is a major version (3.0.0), and the design record and CHANGELOG say why. Every sibling repo (pool-coordinator, libcloak, cloak-cli) upgrades together; none is on mainnet.
- **Failure behaviour:** a failed grind check leaves the transcript state unchanged and the verifier rejects, as before.

## Impact

- `lib/src/script_gen/fiat_shamir_script_gen.dart`, `lib/src/crypto/proof_hash.dart`, `lib/src/crypto/stark_prover_ref.dart`, `lib/src/recursion/verifier_program.dart`.
- `templates/sp/*.json` regenerated; `test/template_sync_test.dart`.
- New `test/grind_binds_queries_test.dart`; `test/stark_verifier_pieces_test.dart` gains the second-valid-nonce refusal.
- `openspec/specs/stark-prover/spec.md`, `docs/SECURITY_CLAIM.md` (D1 closed, numbers updated), `docs/ZK_SHIELDED_POOL_TSL1_DESIGN.md` §20, `CHANGELOG.md`.
- Localnet: the mined test and production chains under `../localnet` no longer verify against this code and must be re-mined when next needed.
