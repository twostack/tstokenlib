## 1. Proof and job codec

- [ ] 1.1 Add `lib/src/crypto/proof_codec.dart` encoding a `StarkProof` of either flavour to bytes and back given `StarkParams` and the AIR's column counts; verify with a test that a spend proof and a Poseidon2 verifier proof round-trip and that the reference verifier accepts the decoded proofs.
- [ ] 1.2 Make decoding reject truncated and oversized inputs; verify with tests that cut and pad an encoding.
- [ ] 1.3 Define `NodeJob` (spend proofs, publics, level program identity, spend params, expected digest) with encode/decode; verify a round trip in the test.

## 2. Node prover interface

- [ ] 2.1 Add `NodeProver`, `LocalNodeProver` and `EdgeScheduler` (workers, per-node timeout, local fallback, verification of returned proofs against the re-derived AIR) in `lib/src/recursion/edge_proving.dart`; verify with a unit test using an in-process worker that returns a valid proof, one that returns a proof of a different node, and one that never returns.
- [ ] 2.2 Give `PoolAggregation.aggregate` an optional level-1 node prover and route level 1 through it; verify with `test/pool_aggregation_test.dart` that the local prover path yields the same root and publics as before and that a scheduler with one honest in-process worker yields the same root.

## 3. Measurement

- [ ] 3.1 Extend `tool/scratch/round_throughput.dart` with a mode where level 1 is proved by a simulated worker (same machine, timed separately) and record the coordinator's share in the design doc under a new section; verify the printed split matches level 1 versus levels 2 to 4 plus root.
- [ ] 3.2 Record job and result sizes in bytes in the same section.

## 4. Documentation

- [ ] 4.1 Add the "Edge proving of level 1 (built)" section to `docs/ZK_SHIELDED_POOL_DESIGN.md` and update the pool-aggregation spec's scenarios if the measured numbers differ from the proposal.
