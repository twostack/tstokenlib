## Why

This change was written as `blowup32-node-cost`, when levels 3 and 4 proved at
blowup 32 and their four proofs were 97 s of a 356 s round. Taking those levels
off the root's blowup (commit 68b8e2f) settled that: levels 3 and 4 and the root
are now 46.5 s, under the 60 s this change had set as its target, and the round
is 239.7 s. The premise is gone, so the change is re-aimed at what the stage
laps actually say now.

Summed over a round's 24 nodes and the root, with the GPU on:

| stage | round total | share |
| --- | --- | --- |
| composition values | 64.8 s | 27% |
| aux round | 29.3 s | 12% |
| composition LDE + merkle | 28.2 s | 12% |
| trace interpolation | 20.4 s | 9% |
| trace LDE + merkle | 18.0 s | 8% |
| DEEP quotients + circle fold | 17.7 s | 7% |
| FRI layers | 11.2 s | 5% |
| grinding | 10.9 s | 5% |
| oods | 8.8 s | 4% |
| preprocessed columns | 8.6 s | 4% |
| openings | 2.3 s | 1% |

Composition values is the largest stage at every level, and it is the one stage
no parameter reaches: its domain is 2^(logTrace + logExpand), fixed by the
constraint degree rather than the blowup, so it did not move when levels 3 and 4
halved. Grinding is a single-threaded Dart loop over nonces, about 2^16 hashes,
which is 10.9 s of the round for nothing.

## What Changes

- The DEEP quotients of groups B and C are computed in one pass over the shared
  columns instead of two.
- Grinding moves into the kernels and searches nonce blocks in parallel,
  returning the same smallest nonce so proofs stay byte-identical.
- The composition kernel's cost is profiled between its two halves (evaluating
  the columns onto the composition domain, and running the constraint program
  over the rows) so the next cut is aimed at the right one; the GPU spike moved
  the FFT but left this stage 14% slower reading shared buffers, which is the
  standing unexplained result from `gpu-kernels-spike`.
- The intra-column FFT parallelism is re-scoped to the CPU path only, since on
  this machine the FFT now runs on the GPU and a CPU-only coordinator is the
  case it serves.
- Target: the round under 210 s with every proof byte-identical to the Dart
  kernels'.

## Capabilities

### New Capabilities

(none)

### Modified Capabilities
- `pool-aggregation`: the round-budget requirement gains a stage-share target in
  place of the blowup-32 share it no longer needs.

## Impact

- `native/stark_kernels/src/lib.rs` (the DEEP kernel signature grows a second
  constant set; a grinding entry point; the FFT gets an intra-column parallel
  path), `lib/src/crypto/stark_kernels.dart`,
  `lib/src/script_gen/fiat_shamir_script_gen.dart` (the grind loop delegates),
  `lib/src/crypto/stark_prover.dart` (one DEEP call).
- Byte-identity tests in `test/stark_kernels_test.dart` cover all three.
- Numbers to move: composition values 64.8 s, DEEP 17.7 s, grinding 10.9 s;
  round 239.7 s.
