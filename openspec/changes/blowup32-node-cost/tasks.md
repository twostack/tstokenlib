## 1. Baseline

- [ ] 1.1 Add a mode to `tool/scratch/round_throughput.dart` (or a new scratch) that proves only levels 3 and 4 and the root from cached level-2 proofs and prints the stage laps; record the baseline (34 / 14.3 / 15.5 s) in a new design-doc section "Blowup-32 nodes (measured)".

## 2. Fused DEEP pass

- [ ] 2.1 Extend `sk_deep_quotients` to take a second constant set and produce both group quotients in one pass over the shared column sets (bump the ABI version and the Dart binding); verify with `test/stark_kernels_test.dart` that the fused kernel equals two Dart calls, including the accumulate path.
- [ ] 2.2 Use the fused call in `StarkProver` and verify the byte-identity suites pass (`test/stark_kernels_test.dart`, `test/stark_hash_flavour_test.dart`) and the node timing shows the DEEP stage down at 2^25.

## 3. FFT parallelism

- [ ] 3.1 Add intra-column parallelism to `evaluate` and `interpolate` for large domains with a threshold chosen from the column and thread counts; verify byte-identity and that a 24-column extension at 2^25 is faster in `tool/scratch/kernel_bench.dart 20 5 24`.

## 4. Measurement and decision

- [ ] 4.1 Re-run the round (`dart run tool/scratch/round_throughput.dart`) and record the new level-3, level-4 and root times and the round total in the design doc; verify the pool-aggregation spec's blowup-32 scenario holds or record the shortfall.
- [ ] 4.2 If the combined time is above 60 s, size the two level-structure alternatives from the design's open question with a dry run and write the follow-up proposal.
