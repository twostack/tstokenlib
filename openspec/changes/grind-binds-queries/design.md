## 1. Where the state goes

Today, step 12 of the transcript (SECURITY_CLAIM §9) computes the grind digest and discards it; step 13 squeezes indices from the pre-nonce state S. After this change step 12 sets S' = H(S ‖ nonce) on success and step 13 squeezes from S'. Nothing else in the schedule moves.

Why the digest and not "absorb the nonce then squeeze": it is the same thing. Absorbing the nonce is H(S ‖ nonce) in the SHA-256 flavour and P(S ‖ chunk)[0..8] in the Poseidon2 flavour, which is exactly the digest the grind check already computes. Keeping it is one fewer hash than absorbing separately, and in the AIR it is the period that already exists.

## 2. Each implementation

- **`TranscriptRef.checkGrinding`** (SHA-256): compute h = SHA256(state ‖ nonce); if its first grindBytes bytes are zero, `state = h` and return true; otherwise return false with the state untouched. `grind` already returns via `checkGrinding` in the brute-force loop; on the native path it must call `checkGrinding` on the nonce the kernel returns so the state advances (and throw if the kernel's nonce does not grind, which would be a kernel bug).
- **`Poseidon2Transcript.checkGrinding`**: compute the full 8-lane digest d = P(state ‖ [nonce, 0, …])[0..8]; check lane 0's low 7·grindBytes bits; on success `state = d`. The native path of `grind` likewise runs `checkGrinding` on the returned nonce.
- **`StarkProverRef`**: it called `grind` and then `checkGrinding` again as an assertion. The second call would now advance the state twice; it goes, since `grind` cannot return a nonce that failed the check.
- **`FiatShamirScriptGen.emitGrindingCheck`**: roll `ts` (not pick), cat the nonce, SHA256, name the result `ts`, DUP, split off the zero prefix, drop the rest, EQUALVERIFY against zeros. The stack ends with the new `ts` where the old one was. Net opcodes: the PICK becomes a ROLL and a DUP is added; the old `ts` no longer has to be carried, so the later `dropAll` has one item fewer. Byte count is checked by the pieces test's size print and by the template regeneration.
- **`VerifierProgram`**: the grind period is `_absorb(nonce: true)` chained from `_cur`. Set `_cur = grind` instead of restoring `stateBeforeGrind`; the index squeezes then chain from it with no `fresh` restart, so the period count cannot rise. The digest of the grind period is already fully computed (its lane 0 feeds the bit check), so the constraint that binds the next period's low half to it is the ordinary chaining constraint.

## 3. What could go wrong

- One implementation left behind would fail loudly: the two-prover byte-identity tests, the script tests and the AIR tests all compare against the reference transcript, so any straggler fails on the first proof. The risk is a straggler in a path no test proves through; the grep in task 1.1 is the guard.
- The native grind wrapper returning without advancing the state would make native and Dart provers disagree; `test/stark_kernels_test.dart` compares them and is run with the kernels loaded.

## 4. Verification that the weakness is closed

The attack that worked before: take a valid proof, find the next nonce that also meets the grind target, substitute it. Before, every verifier accepted the proof (the nonce was checked, the indices did not depend on it). After, the reference verifier refuses it naming `query 0 index`, the script fails at the index comparison, and the AIR has no satisfying witness. The proof-level test uses the smallest AIR the prover tests already build, so it runs in well under a second.
