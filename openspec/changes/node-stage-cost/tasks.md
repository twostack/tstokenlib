## 1. Baseline

- [ ] 1.1 Record the per-stage baseline in a new design-doc section "Node stages
  (measured)": the per-node lap table from design.md and the round totals from
  proposal.md, taken from `dart run tool/scratch/round_throughput.dart 16 nomem
  noscript` with the GPU on and off.

## 2. Fused DEEP pass

- [ ] 2.1 Extend `sk_deep_quotients` to take a second constant set and produce
  both group quotients in one pass over the shared column sets (bump the ABI
  version and the Dart binding); verify in `test/stark_kernels_test.dart` that
  the fused kernel equals two Dart calls, including the accumulate path.
- [ ] 2.2 Use the fused call in `StarkProver`, check the byte-identity suites
  (`test/stark_kernels_test.dart`, `test/stark_hash_flavour_test.dart`) and
  record the DEEP stage's new lap at each level.

## 3. Composition profile

- [ ] 3.1 Split the composition-values lap into evaluation and constraint-program
  halves at every level (and for both the reuse and the from-coefficients paths),
  with the GPU on and off, and record the four numbers in the design doc. Decide
  from them whether the next cut belongs in this change or a separate one, and
  write the decision into design.md.

## 4. Grinding

- [ ] 4.1 Add a kernel entry point that searches nonce blocks in parallel and
  returns the smallest nonce satisfying the predicate, for both hash flavours;
  `TranscriptRef.grind` delegates to it when the kernels are available.
- [ ] 4.2 Test that the kernel nonce equals the Dart loop's at a grind size
  whose smallest nonce falls outside the first block that the parallel search
  hands to a thread (the existing byte-identity suites grind 1 byte, where it
  never does), and record the round's grinding total.

## 5. FFT parallelism on the CPU path

- [ ] 5.1 Add intra-column parallelism to `evaluate` and `interpolate` for large
  domains with a threshold chosen from the column and thread counts; verify
  byte-identity and that a 24-column extension at 2^24 is faster with the GPU
  off in `tool/scratch/kernel_bench.dart`.

## 6. Measurement

- [ ] 6.1 Re-run the round and record the new stage totals and round time in the
  design doc; check the pool-aggregation spec's stage scenario holds or record
  the shortfall.
