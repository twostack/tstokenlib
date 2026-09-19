## Why

The blowup-32 proofs are now the most expensive per node: level 3 (two 2^20 nodes) takes 68 s, level 4 (one 2^19 node) 14 s and the root 15.5 s, 97 s of the 356 s round for four proofs, because their extensions and commitments run on 2^25 points. The level-1 cuts of this session (Poseidon2, row-block composition, the column store) did not touch what scales with the domain: the DEEP pass reads 190 columns of 128 MB, the trace and aux extensions run one thread per column, and the composition commitment is 32 limb columns at the full domain.

## What Changes

- The DEEP quotients of groups B and C are computed in one pass over the shared columns instead of two.
- The circle FFT parallelises within a column when the domain is large, so a 24-column extension uses every core.
- A stage profile of a blowup-32 node at 2^20 and 2^19 is recorded, and the level structure (2 x 2^20 + 2^19 + root at 2^19) is re-checked against the alternatives it enables.
- Target: levels 3 and 4 plus the root under 60 s (from 97 s), keeping proofs byte-identical.

## Capabilities

### New Capabilities

(none)

### Modified Capabilities
- `pool-aggregation`: the round-budget requirement gains the per-stage target for the blowup-32 nodes.

## Impact

- `native/stark_kernels/src/lib.rs` (DEEP kernel signature grows a second constant set; FFT gets an intra-column parallel path), `lib/src/crypto/stark_kernels.dart`, `lib/src/crypto/stark_prover.dart` (one DEEP call).
- Byte-identity tests in `test/stark_kernels_test.dart` cover both.
- Numbers to move: level 3 node 34 s, level 4 node 14.3 s, root 15.5 s; DEEP at 2^25 5.3 s; trace extension and Merkle 5.7 s; aux 5.5 s; composition commitment 8.2 s.
