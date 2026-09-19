## 1. Feature, context and field arithmetic

- [x] 1.1 Add the `metal` cargo feature (off by default) and dependency to `native/stark_kernels/Cargo.toml`; a `Gpu` context (device, command queue, library compiled from `src/kernels.metal`, pipelines) created once on first use; `sk_gpu_available` and `sk_gpu_enable` exports; ABI 5 in the crate and in `StarkKernels.abiVersion`; `STARK_KERNELS_GPU` read at load and `name` reporting `native+metal` when the switch took; a build note in the crate's README. Verify: the crate builds with and without the feature, and the byte-identity tests pass with the feature built and the switch off.
- [x] 1.2 MSL M31 `add`, `sub`, `mul` (the `mulhi` formulation), `pow5`, and a self-test kernel; a Rust test comparing 2^20 random operand pairs against the CPU `add`/`sub`/`mul`, skipped with a message when no device is present. End with the byte-identity tests.

## 2. Poseidon2 commitment on the GPU

- [x] 2.1 The width-16 Poseidon2 permutation kernel with the same external and internal layers and round-constant buffer as `v_permute`; a Rust test against `p2_permute` on 4,096 random states. End with the byte-identity tests.
- [x] 2.2 The leaves kernel (one thread per leaf, chain form over the 2k lanes `ev[j][i]`, `ev[j][M + i]`) and one dispatch per tree level; a Rust test that every level and the root equal `p2_leaves` + `merkle_above_p2` at 2^10, 2^14 and 2^16 leaves with k = 1, 3 and 79. End with the byte-identity tests.
- [x] 2.3 Route `sk_commit_columns_p2` through the GPU when the switch is on, with the evaluations in a shared buffer that becomes the `Stored` backing (`as_slice()` for every existing reader) and the tree written to `out_tree`; a Rust test that the stored columns and tree equal the CPU path's; then `test/stark_kernels_test.dart` with `STARK_KERNELS_GPU=1`. End with the byte-identity tests.

## 3. Circle FFT on the GPU

- [x] 3.1 Per-`m` twiddle buffers cached beside `tables`; the evaluate kernels (bit-reversal scatter of zero-padded coefficients, one dispatch per stage over all k columns, the final twin butterfly); a Rust test against `evaluate` at m = 8, 12, 16 and 20 with k = 1, 5 and 79 and with short (LDE) inputs. End with the byte-identity tests.
- [x] 3.2 The interpolate kernels (twin butterfly with `y_inv`, stages descending, the `n^-1` scale and bit reversal); a Rust test against `interpolate` at the same sizes and a round trip through both. End with the byte-identity tests.
- [x] 3.3 Route `sk_interpolate_columns`, `sk_evaluate_columns`, `sk_store_evaluate` and the evaluation inside `sk_commit_columns_p2` through the GPU when the switch is on. End with the byte-identity tests with the switch on.

## 4. Dart-side tests

- [x] 4.1 `test/stark_kernels_test.dart`: when `STARK_KERNELS_GPU=1` is set and `sk_gpu_available` reports a device, run the existing five comparisons with the switch on (proofs identical to the Dart prover's and to the CPU native path's); otherwise skip them with a printed reason. Verify the full suite is green with the switch on and off.

## 5. Measurement

- [x] 5.1 `tool/scratch/kernel_bench.dart` gains a `gpu` argument: at level-1 size (79 columns, 2^20 coefficients on 2^23, m = 22) record CPU and GPU seconds for evaluate, Poseidon2 commit and interpolate, and peak RSS for each; the six timings and the memory go in the "GPU kernels on Apple Silicon (measured)" section of `docs/ZK_SHIELDED_POOL_DESIGN.md`.
- [x] 5.2 `tool/scratch/node_prove.dart` with the switch on: the level-1 node's seconds and the prover's laps for trace interpolation, trace LDE + Merkle and composition LDE + Merkle against the CPU's 10.5 s node (0.8, 1.5, 2.2 s), and peak RSS against 8.7 GB; recorded in the same section, with the verdict against the bar (the three stages under 1.5 s together).
- [x] 5.3 If the node improves by at least 1.5x: `tool/scratch/round_throughput.dart 16` with the switch on, recording round seconds and the serial tail (levels 2 to 4 plus root, 171 s on the CPU) in the same section.

## 6. Documentation

- [x] 6.1 Add "GPU kernels on Apple Silicon (measured)" to `docs/ZK_SHIELDED_POOL_DESIGN.md`: what runs on the GPU and how it is switched on, the kernel and node numbers, memory, whether the spike passes its bar or why not, and the follow-on list (composition, DEEP, FRI, LogUp, the SHA256 root; a portable backend).
