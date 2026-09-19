## Context

The crate (`native/stark_kernels/src/lib.rs`, cdylib, ABI 4) holds every hot kernel as an exact port of the Dart code and is called from `lib/src/crypto/stark_kernels.dart` over `dart:ffi`; `ProverKernels.best` picks it when the library loads. Committed evaluations already stay in native memory behind a store id (`Stored { k, n, data: Vec<u32> }`), read in place by the composition, DEEP and opening kernels. The two kernels in scope are `sk_commit_columns_p2` (evaluate k coefficient columns onto the twin-layout domain of 2^(m+1), hash 2^m leaves of 2k lanes in Poseidon2 chain form, build the tree, store the evaluations) and the pair `interpolate`/`evaluate` (a twin butterfly with y inverses, then log(M) butterfly stages with per-stage x-inverse tables from `tables(m - l)`, a bit-reversal permutation and an n^-1 scale; evaluate is the same in reverse with shorter inputs zero-padded, which is the LDE). Threading is `std::thread::scope` over row blocks. See proposal.md for motivation.

This machine: Apple M3 Pro, 12 CPU cores (6 performance), 18 GPU cores, 36 GB unified memory, Metal 3, Xcode's `metal` compiler installed. Level-1 node size is 79 columns of 2^20 coefficients evaluated on 2^23 values (m = 22, 2^22 leaves), 2.65 GB of evaluations.

## Goals / Non-Goals

**Goals:**
- Poseidon2 commitment and circle FFT on the GPU, byte-identical, behind a feature and a run-time switch, with the CPU path untouched when either is off.
- One resident copy of the evaluations, in shared memory, that the CPU kernels read in place.
- Numbers: the three in-scope stages of a level-1 node, and the node itself, CPU against GPU.

**Non-Goals:**
- Composition, DEEP, FRI, LogUp or the SHA256 (root) commitment on the GPU; each is a follow-on change if this passes.
- Any backend but Metal; portability (CUDA, Vulkan, wgpu) is a separate decision once the numbers exist.
- Tuning beyond what the bar needs (threadgroup sizes, fused stages, avoiding the coefficient upload).

## Decisions

- **Metal Shading Language, compiled at run time.** Kernels live in `native/stark_kernels/src/kernels.metal`, embedded with `include_str!` and compiled with `newLibraryWithSource` when the GPU context is first used; no `.metallib` build step, no Xcode project. Alternative: `wgpu`/WGSL for portability, rejected because WGSL has no widening or 64-bit integer multiply and M31 arithmetic would be emulated in 16-bit limbs.
- **Binding: the `metal` crate** (gfx-rs), for the shortest path to a device, queue, library, pipeline and shared buffer; `objc2-metal` is the fallback if it does not build on Rust 1.84. Behind `[features] metal = ["dep:metal"]`, default off, and `#[cfg(all(target_os = "macos", feature = "metal"))]`; a build without the feature has no Metal symbol anywhere, so Linux and CI are unaffected. Build: `cargo build --release --features metal --manifest-path native/stark_kernels/Cargo.toml`.
- **A process-wide switch, not new entry points.** `sk_gpu_available() -> u32` and `sk_gpu_enable(on: u32) -> u32` (returns the effective state) are the only new exports; `sk_commit_columns_p2`, `sk_interpolate_columns`, `sk_evaluate_columns` and `sk_store_evaluate` route internally when the switch is on. The Dart side sets it from `STARK_KERNELS_GPU=1` at load and reports `name` as `native+metal` when it took, `native` otherwise, so every call site, the prover's `kernels:` plumbing and the tests are unchanged. Alternative: `sk_gpu_*` twins of each function, rejected as doubling the FFI surface for a spike. ABI 5, because the Dart side must not enable a switch an older library lacks.
- **M31 arithmetic without 64-bit.** `mul(a, b)`: `lo = a * b`, `hi = mulhi(a, b)`; since 2^32 = 2 mod p the product is `2 hi + lo`, reduced as `(lo & p) + (lo >> 31) + 2 hi` folded twice with `(r & p) + (r >> 31)`; results canonical in [0, p) exactly as the Rust `mul`. `add`, `sub`, `pow5` and the Poseidon2 external (M4 add chain) and internal (rotation diagonal) layers follow `v_permute` line for line, so the digests match without a translation layer. The round constants are one constant buffer uploaded once.
- **One thread per leaf, one dispatch per tree level.** A leaf thread gathers its 2k lanes from the evaluation buffer (column-major, stride n, the CPU layout) and runs the chain of `ceil(2k / 8)` permutations; every level above is one dispatch of `len / 2` threads. No atomics, no reductions: every write has a fixed position, which is what makes the result deterministic.
- **FFT as one dispatch per stage over all columns.** The grid is `(butterflies, k)`; the twiddle tables for each stage (`x_inv` of `tables(m - l)`, `y_inv` of `tables(m)`, and `x`/`y` for evaluate) are uploaded once per `m` and cached beside the CPU `tables` cache; the bit-reversal and the `n^-1` scale are one further dispatch each. This is the plain Cooley-Tukey layout, memory-bound; fusing stages through threadgroup memory is a follow-on if the numbers ask for it.
- **Shared buffers as the store's second backing.** `Stored.data` becomes an enum, heap `Vec<u32>` or a Metal buffer in `StorageModeShared`, with one `as_slice()` that every existing reader uses; a commit on the GPU keeps its evaluations in the buffer it computed them into, so the composition and DEEP kernels read GPU output in place and no stage holds two copies. The coefficient input from Dart is copied into a transient shared buffer (330 MB at level-1 size); avoiding that copy is left for later.
- **Watchdog.** macOS aborts command buffers that run for seconds. Each stage is its own dispatch and each command buffer holds at most one stage of one kernel, committed and waited on before the next; a level-1 commitment is therefore a few dozen short command buffers, not one long one.
- **Tests before size.** Every kernel is checked against its CPU port in Rust (`#[cfg(test)]`, skipped with a message when no device is present) at sizes from 2^8 to 2^16 first, because a wrong lane at 2^22 is undebuggable; then the Dart byte-identity suite runs with the switch on. The Metal shader debugger is not part of the plan.

## Risks / Trade-offs

- [Bandwidth-bound FFT] The M3 Pro's memory bandwidth (about 150 GB/s) is not far above what the 12 cores already see, so the FFT may gain only 2 to 3x while the hashing gains far more → the bar is set on the three stages together, and the design-doc section reports each kernel separately so a follow-on can choose.
- [`ulong` and `mulhi` throughput] Apple GPUs run 32-bit integer multiply below fp32 rate → measured, not assumed; the `mulhi` formulation avoids 64-bit entirely.
- [Command-buffer overhead] Dozens of small dispatches cost latency at small sizes → irrelevant at 2^22 and accepted at the test sizes.
- [Toolchain drift] `metal` crate versions and macOS SDKs move → the feature is off by default and the CPU path is what ships; a broken feature build cannot break the library.
- [Memory] A shared buffer of 2.65 GB plus the transient 330 MB upload beside the node's 8.7 GB peak → within the 36 GB here; the proposal's budget is "within 1 GB of today", checked in the node measurement.

## Open Questions

- Whether the coefficient columns should also live in shared buffers so the composition kernel's coefficient path (blowup 4) reads GPU memory directly; deferrable, nothing in this change depends on it.
