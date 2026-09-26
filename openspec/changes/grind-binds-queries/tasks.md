## 1. The transcripts

- [x] 1.1 Change `TranscriptRef.checkGrinding` and `Poseidon2Transcript.checkGrinding` to make the grind digest the state on success, and make both `grind` methods advance the state on the native path. Remove the double check in `StarkProverRef`. Verified: the grep lists exactly the design's sites; `test/stark_hash_flavour_test.dart` and `test/stark_kernels_test.dart` pass with the kernels loaded (33 tests across the fast STARK suites, 2 GPU skips). The three existing tests that re-checked a nonce after grinding now work on copies of the pre-grind state.
- [x] 1.2 Add `test/grind_binds_queries_test.dart`: both flavours, transcript level (two grinding nonces, two index sets; a miss leaves the state) and proof level (Poseidon2Air at 2^5, next grinding nonce refused at `query 0 index`). Mutation test done 2026-09-26: with `state = h` and `state = d` commented out, all four cases fail, the proof-level ones with "Actual: accepted"; restored, all pass.

## 2. Script and AIR

- [x] 2.1 `emitGrindingCheck` keeps the hash as `ts`. Verified: `test/stark_verifier_pieces_test.dart` passes, and its grinding case now also refuses the second valid nonce in script.
- [x] 2.2 `VerifierProgram` continues from the grind period. Verified: `test/verifier_air_test.dart` (8 tests) and `test/verifier_air_script_test.dart` pass; the new case shows the second-valid-nonce proof has no witness (constraint 57 fails at period 100 row 31, the first index squeeze).
- [x] 2.3 Templates regenerated with `dart run tool/export_templates.dart`; `test/template_sync_test.dart` passes (10 tests). Script bytes before and after: `pp1_sp_verifier.json` 504,184 and 504,184; `pp1_sp_k8.json` 65,443 and 65,443 (measured from the templates' hex). AIR: the ring-check program compiles to 368 periods (364 without); the squeeze after the grind chains from the grind period where it used to restart from a saved digest, which is the same period either way. The pool-aggregation dry run does not print a periods report, so that number was not re-measured.

## 3. Whole-system checks

- [x] 3.1 `test/pool_verifier_proof_test.dart`, `test/nullifier_aggregation_test.dart`, `test/pool_aggregation_test.dart`, `test/pool_round_v_test.dart`, `test/sp_token_test.dart`, `test/shielded_coordinator_test.dart`: 156 tests, all pass, 2 min 58 s. `dart analyze lib test tool` reports no errors outside `tool/scratch` (excluded, pre-existing).

## 4. Record

- [x] 4.1 `openspec/specs/stark-prover/spec.md` synced from the delta. `docs/SECURITY_CLAIM.md`: D1 marked fixed, section 4 counts the grind (102 / 58 system, 106 / 61 root), D3 narrowed, O1 closed, change log entry. `docs/ZK_SHIELDED_POOL_TSL1_DESIGN.md` §20 appended. `CHANGELOG.md` gains the 3.0.0 (unreleased) entry; `pubspec.yaml` is unchanged until the user calls the release. Comments in `pool_aggregator.dart` corrected (102 bits, 14-bit grind).
