# stark_kernels

Native kernels for the tstokenlib Circle-STARK prover: M31 circle FFT,
SHA256 Merkle commitments, DEEP quotients and FRI folds. Exact ports of the
Dart code in `lib/src/crypto/`, so proofs are byte-identical with or without
the library; the Dart side (`lib/src/crypto/stark_kernels.dart`) keeps the
transcript and the proof layout.

Build (Rust 1.84 or later, no external crates):

    cargo build --release --manifest-path native/stark_kernels/Cargo.toml

`StarkKernels.tryLoad()` finds `target/release/libstark_kernels.{dylib,so}` /
`stark_kernels.dll` under the working directory or its parents, or the path
in `$STARK_KERNELS_LIB`. When it is missing the prover silently falls back
to Dart (`DartKernels`). `test/stark_kernels_test.dart` checks every kernel
against the Dart implementation and compares whole proofs.
