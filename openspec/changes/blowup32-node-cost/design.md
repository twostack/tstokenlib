## Context

Stage profile of the level-3 node (2^20, blowup 32, 18 queries, 79 columns, from the measured round): trace extension and Merkle 5.7 s, aux round 5.5 s, composition 5.2 s (coefficient path: the composition domain 2^23 is not the commitment domain 2^25, so the kernel extends 79 columns itself and runs the program), composition extension and Merkle 8.2 s (32 limb columns), DEEP 5.3 s, FRI 2.2 s. Level 4 at 2^19 is half of each. The kernels parallelise across columns (`par_fill_u32` one column per task) and the DEEP kernel walks the 79 shared columns twice (group B with the composition blocks, group C alone). See proposal.md for the target.

## Goals / Non-Goals

**Goals:**
- Cut what scales with the domain size, in the kernels, with no protocol change.
- Keep every proof byte-identical to the Dart kernels.

**Non-Goals:**
- Changing parameter sets or the level structure in this change (measured first, decided in a follow-up if the kernel cuts fall short).
- The composition split itself (the 32 columns are the protocol).

## Decisions

- **One DEEP pass.** The kernel takes both constant sets and computes, per row block, the B numerator (79 + 32 columns) and the C numerator (the same 79 columns at the shifted point) from one read of each shared column, then one batch inversion of both denominators. Saves 79 x 128 MB of reads and half the inversions at 2^25. Alternative: keep two calls and rely on cache, rejected: the columns are 10 GB, nothing stays cached.
- **Intra-column FFT parallelism.** For domains above 2^22 the butterfly layers above a threshold split the column into independent halves per thread (the first layers of the evaluate pass are independent per half; the last layers are strided and stay per-column). Alternative: more columns per task, no help when columns (24) are fewer than 2 x cores.
- **Composition commitment unchanged.** Its 8.2 s is 32 columns of extension plus Poseidon2 over 64 lanes per leaf; the FFT change applies to it, the hashing is already vectorised. If it stays the largest stage, the follow-up is a level-structure decision, recorded as an open question.
- **Measure before and after** with `tool/scratch/node_prove.dart 20 5 18 2` (a blowup-32 node over two level-2-shaped proofs is not what node_prove builds; add a `--verifier-inner` mode that verifies two verifier proofs, or time the nodes inside `round_throughput.dart`).

## Risks / Trade-offs

- [Thread oversubscription] Intra-column parallelism inside a per-column parallel fill could spawn cores x columns threads → the FFT decides once per call from the column count and thread count.
- [Fused DEEP complexity] Two numerators per row block double the live state → row blocks of 256 instead of 512 keep it in L1.
- [Falls short of 60 s] The kernel cuts may reach 70 to 75 s → the open question below is then decided with numbers.

## Open Questions

- If levels 3 and 4 plus the root stay above 60 s after the kernel cuts: replace levels 3 and 4 with one 2^21 node at blowup 32 (four level-2 proofs, one preprocessed commitment) or move level 3 to blowup 16 with 22 queries and level 4 to 2^20. Both change the plan and the fit; sized in a follow-up change.
