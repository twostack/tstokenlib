## Context

Stage laps per node from the 239.7 s round (`tool/scratch/round_throughput.dart
16 nomem noscript`, GPU on), in milliseconds. Levels 1 and 2 prove at blowup 8,
where the composition domain is the commitment domain and the kernel reads the
committed evaluations; levels 3 and 4 and the root prove at a higher blowup, so
the kernel evaluates the columns from coefficients first. The root is the only
SHA256 node, which is why its hashing stages stand out.

| stage | L1 x16 | L2 x4 | L3 x2 | L4 | root |
| --- | --- | --- | --- | --- | --- |
| trace interpolation | 785 | 1,468 | 639 | 309 | 384 |
| trace LDE + merkle | 539 | 1,108 | 1,040 | 522 | 2,378 |
| preprocessed columns | 946 | 1,924 | 1,663 | 871 | 3,219 |
| aux round | 974 | 1,965 | 1,424 | 696 | 2,323 |
| composition values | 2,278 | 4,332 | 3,717 | 1,764 | 1,855 |
| composition LDE + merkle | 904 | 1,763 | 1,458 | 723 | 3,044 |
| oods | 333 | 612 | 320 | 176 | 160 |
| DEEP + circle fold | 567 | 1,162 | 1,176 | 605 | 1,013 |
| FRI layers | 365 | 705 | 689 | 345 | 798 |
| grinding | 607 | 218 | 64 | 122 | 27 |
| openings | 112 | 112 | 3 | 3 | 4 |
| node | 7,411 | 15,370 | 12,238 | 6,143 | 15,214 |

Preprocessed columns is paid once per level, not once per node, since a level's
nodes share a cache key; every other row multiplies by the node count. See
proposal.md for the round totals that follow.

## Goals / Non-Goals

**Goals:**
- Cut the stages that dominate now, in the kernels, with no protocol change.
- Keep every proof byte-identical to the Dart kernels.

**Non-Goals:**
- Parameter and level-structure changes. That question is closed: commit 68b8e2f
  moved levels 3 and 4 to blowup 16 with 23 queries, which is what the earlier
  open question was asking for, and the peak node is now level 2 at 2^21 with
  blowup 8, where no parameter is left to take.
- The composition split itself (the 32 limb columns are the protocol).
- Memory. The round peaks at 15.4 GB and the candidates for going lower are
  recorded in the design doc, not here.

## Decisions

- **One DEEP pass.** The kernel takes both constant sets and computes, per row
  block, the B numerator (79 + 32 columns) and the C numerator (the same 79
  columns at the shifted point) from one read of each shared column, then one
  batch inversion of both denominators. Alternative: keep two calls and rely on
  cache, rejected because the columns are gigabytes and nothing stays cached.
  **Measured: 17.7 s to 15.5 s over a round, 12%, against the halving the
  wording implied.** Only the second read of the 79 shared columns is saved;
  the arithmetic is unchanged, since the fused pass still does 111 weighted
  multiply-adds for B and 79 for C, and the batch inversion it halves was
  never the cost. Worth keeping, not worth revisiting.
- **Grinding in the kernels, and still deterministic.** The proof carries the
  smallest nonce satisfying the predicate, so a parallel search must return that
  and not whichever thread finishes first: threads take disjoint nonce blocks in
  order, and the result is the smallest hit in the lowest block that has one.
  Alternative: a per-thread first-hit race, rejected because it would make
  proofs irreproducible.
- **Profile the composition kernel before cutting it.** It is 27% of the round
  and it has two halves that scale differently: evaluating 79 columns onto
  2^(t+3), and interpreting the recorded constraint program over those rows. The
  GPU spike left this stage 14% slower when its inputs are Metal shared buffers,
  which suggests the read pattern rather than the arithmetic is the cost. Task
  3.1 splits the lap before anything is optimised, because the two halves want
  opposite treatments.
  **Measured: the stage has three parts, not two.** Over a round with the GPU
  on: the constraint program 44.3 s, Dart-side setup 16.6 s, the extension
  4.9 s. The GPU regression is entirely the program half reading Metal shared
  buffers on the reuse path (26% at level 1, 16% at level 2); the
  from-coefficients levels are backend-independent because the kernel extends
  on the CPU either way. **Decision: both remaining cuts go to separate
  changes.** The program half needs the recorded program on the GPU, which
  this change said in advance it would not absorb. The Dart setup, which is
  the linear forms evaluated row by row over the composition domain plus the
  periodic columns and the divisor inversions, was in nobody's scope and is
  the cheaper of the two; it is recorded in the design doc with its numbers so
  a proposal can be written against it.
- **Intra-column FFT parallelism was tried and is not kept.** On a machine
  with the Metal backend the extension and interpolation stages already run on
  the GPU, so splitting a column across CPU threads buys nothing there. It was
  meant to serve a coordinator without a GPU. **Measured either side of the
  threshold (23 columns against 24 on a 12-core machine, 2^25 domain, GPU
  off): the extension is 9% faster per column (120.7 ms against 132.8), the
  interpolation 2.1x slower (380.8 against 182.8).** One column per thread
  lets a thread own a 128 MB column; splitting one column across twelve adds a
  barrier per stage and destroys that locality, and only the extension earns
  that back. The extension win does not reach the round either: the only
  commitment with fewer columns than this machine has cores is the aux one at
  20 columns, whose lap did not move (51.1 s to 51.0 s on the CPU path).
  A microbenchmark win that the round cannot see is not worth a second FFT
  scheme in the kernel, so both splits were reverted and the one-column-per-
  thread scheme stands. Making the interpolation benefit needs a persistent
  thread pool so stages synchronise without spawning, which is a piece of
  work in its own right and is not proposed here.

## Risks / Trade-offs

- [Fused DEEP complexity] Two numerators per row block double the live state, so
  row blocks of 256 instead of 512 keep it in L1.
- [Grinding determinism] The verifier accepts any nonce whose hash has the
  required leading zeros, and the nonce feeds nothing downstream (`checkGrinding`
  does not advance the transcript, and the query indices come from the state
  alone), so a parallel search that returns a later hit still produces a proof
  that verifies. It would differ from the Dart prover's in those 4 bytes, which
  `test/stark_kernels_test.dart` does compare. But that suite grinds 1 byte,
  where the smallest nonce is around 256 and sits in the first block of any
  split, so it would pass while production, grinding 2 bytes for a nonce around
  65,536, returned a different one. The new test must grind wide enough that the
  smallest nonce falls outside the first block.
- [Composition stays the largest] If the profile shows the cost is the constraint
  program rather than the evaluation, the cut is a GPU port of the program
  interpreter, which is a larger piece of work than this change should absorb;
  it would be proposed separately with the profile as its evidence.

## Open Questions

- Whether the root's SHA256 stages (trace and composition commitments, 5.4 s of
  its 15.2 s) are worth a vectorised SHA256 or a GPU port, given the root runs
  once per round and the on-chain verifier fixes the hash.
