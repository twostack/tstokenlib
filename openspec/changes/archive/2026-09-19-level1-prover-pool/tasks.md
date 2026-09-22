## 1. Proof and job codec

- [x] 1.1 Add `lib/src/crypto/proof_codec.dart` encoding a `StarkProof` of either flavour to bytes and back given `StarkParams` and the AIR's column counts; verify with a test that a spend proof and a Poseidon2 verifier proof round-trip and that the reference verifier accepts the decoded proofs.
- [x] 1.2 Make decoding reject truncated and oversized inputs; verify with tests that cut and pad an encoding.
- [x] 1.3 Define `NodeJob` (spend proofs, publics, level program identity, spend params, expected digest) with encode/decode; verify a round trip in the test.

## 2. Node prover interface

- [x] 2.1 Add `NodeProver`, `LocalNodeProver` and `ProverPool` (members, per-node timeout, local fallback, verification of returned proofs against the re-derived AIR) in `lib/src/recursion/prover_pool.dart`; verify with a unit test using an in-process member that returns a valid proof, one that returns a proof of a different node, and one that never returns.
- [x] 2.2 Give `PoolAggregation.aggregate` an optional level-1 node prover and route level 1 through it; verify with `test/pool_aggregation_test.dart` that the local prover path yields the same round as before and that a pool with one honest in-process member yields the same round.

## 3. Measurement

- [x] 3.1 Extend `tool/scratch/round_throughput.dart` with a mode where level 1 is proved by a simulated pool member (same machine, timed separately) and record the coordinator's share in the design doc under a new section; verify the printed split matches level 1 versus levels 2 to 4 plus root.
- [x] 3.2 Record job and result sizes in bytes in the same section.

## 4. Documentation

- [x] 4.1 Add the "A prover pool for level 1 (built)" section to `../../../../docs/LEGACY_ZK_SHIELDED_POOL_DESIGN.md` and update the pool-aggregation spec's scenarios if the measured numbers differ from the proposal.
- [x] 4.2 Reframe from "edge proving by wallets" to the coordinator's own prover pool: rename `edge_proving.dart` to `prover_pool.dart`, `EdgeScheduler` to `ProverPool`, workers to provers and members; reword the doc comments, the design-doc section and this change's artifacts; record why wallets do not fold nodes.
