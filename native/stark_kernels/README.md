# stark_kernels

Native kernels for the tstokenlib Circle-STARK prover: M31 circle FFT,
SHA256 Merkle commitments, DEEP quotients and FRI folds. Exact ports of the
Dart code in `lib/src/crypto/`, so proofs are byte-identical with or without
the library; the Dart side (`lib/src/crypto/stark_kernels.dart`) keeps the
transcript and the proof layout. It also hosts ML-KEM-768 (FIPS 203, the
RustCrypto `ml-kem` crate, the one external dependency) for the shielded
pool's note-encryption KEM: `sk_mlkem768_public_key`, `sk_mlkem768_encaps`,
`sk_mlkem768_decaps`, keys regenerated from a 64-byte seed on every call.
That part has no Dart fallback: `NoteKem` throws when the library is absent.

Build (Rust 1.84 or later; `zeroize` is pinned to 1.8.1 in `Cargo.lock` for
that toolchain, newer versions want Rust 1.85):

    cargo build --release --manifest-path native/stark_kernels/Cargo.toml

Two things about how the kernels are shaped. The Poseidon2 permutation runs
on 16 states at once in struct-of-arrays layout (`v_permute<N>`), with the
external matrix as the paper's add chain and the internal diagonal as
31-bit rotations, so the compiler vectorises every field operation; leaves
and tree levels are hashed 16 at a time. The composition program (the AIR's
constraints as a straight-line program) runs over 16 rows per op the same
way. Committed value columns never come back to Dart: `sk_commit_columns*`
keep them in a column store and return an id (`NativeColumns` on the Dart
side), and the composition, DEEP-quotient and opening steps read them
there (`sk_store_get`/`sk_store_read`); the Dart side releases them when
the proof is done (`sk_store_free`). ABI version 4.

`StarkKernels.tryLoad()` finds `target/release/libstark_kernels.{dylib,so}` /
`stark_kernels.dll` under the working directory or its parents, or the path
in `$STARK_KERNELS_LIB`. When it is missing the prover silently falls back
to Dart (`DartKernels`). `test/stark_kernels_test.dart` checks every kernel
against the Dart implementation and compares whole proofs.
