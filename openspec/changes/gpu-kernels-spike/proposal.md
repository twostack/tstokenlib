## Why

The prover's heavy stages are integer arithmetic over M31 with no data-dependent control flow, which is what a GPU is for, and this machine (Apple M3 Pro, 18 GPU cores, 36 GB unified memory, Metal 3) can run such kernels on the same memory the Rust crate already holds. The prover pool shrinks level 1 by adding machines, but the 171 s of levels 2 to 4 and the root are sequential and only shrink by making one prover faster; a GPU is the lever for that half. This is a spike: it answers whether Metal kernels for the two most self-contained stages are byte-identical and materially faster before anything larger is planned.

## What Changes

- An experimental Metal backend in `native/stark_kernels`, behind a cargo feature that is off by default, for two kernels: the Poseidon2 Merkle commitment (leaves over the twin layout and the tree above them) and the circle FFT (interpolation and evaluation, including the low-degree extension). Everything else stays on the CPU.
- A process-wide switch, set from the environment on the Dart side, that routes those kernels to the GPU when a device is present and the shaders compile; without a device, or with the feature not built, the existing CPU path runs and nothing else changes.
- Committed evaluations produced on the GPU live in shared (unified) memory and are read in place by the CPU kernels that follow, so the column store gains a second backing and no stage copies a column set.
- Proofs stay byte-identical: the existing native-versus-Dart comparisons are re-run with the GPU on, and the Rust crate gains GPU-versus-CPU tests for each kernel.
- Measurements at level-1 node size and a design-doc section that says whether the spike passes its bar.

Out of scope, to be planned only if this passes: the composition program, DEEP quotients, FRI folds, the LogUp aux columns and the SHA256 commitment of the root on the GPU; any backend other than Metal; production use on Linux coordinators.

## Capabilities

### New Capabilities
- none

### Modified Capabilities
- `native-kernels`: gains an optional GPU backend for the Poseidon2 commitment and the circle FFT, selectable at run time, with the same exact-port guarantee; the ABI version moves to 5.

## Impact

- `native/stark_kernels`: a `metal` cargo feature and dependency, `src/kernels.metal` (M31 arithmetic, Poseidon2, FFT stages), a GPU context created once per process, GPU tests; `Stored` gains a shared-buffer backing.
- `lib/src/crypto/stark_kernels.dart`: ABI 5, the `STARK_KERNELS_GPU` switch, the backend name reported as `native+metal`.
- `test/stark_kernels_test.dart`: the byte-identity suite runs with the GPU on when one is present, and is skipped with a reason when not.
- `tool/scratch/kernel_bench.dart`, `tool/scratch/node_prove.dart`, `tool/scratch/round_throughput.dart`: a GPU mode.
- Numbers to move: in the 10.5 s level-1 node, the stages in scope are trace interpolation 0.8 s, trace LDE + Merkle 1.5 s and composition LDE + Merkle 2.2 s, 4.5 s together; the bar is those three under 1.5 s, a node of about 7.5 s, and the same shape at levels 2 to 4 (a 21 s level-2 node, a 34 s level-3 node) so the round's serial tail moves from 171 s towards 130 s. Budgets: proofs identical byte for byte to the Dart prover's; the round stays under 10 minutes on this machine (it is 5.7 today); peak process memory for a level-1 node stays within 1 GB of today's 8.7 GB, since the GPU's copy of the evaluations replaces the heap copy rather than adding to it.
