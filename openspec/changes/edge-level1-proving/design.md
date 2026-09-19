## Context

`PoolAggregation.aggregate` proves every level inline (see the `aggregate` loop in `lib/src/recursion/pool_aggregator.dart`). A level-1 node's inputs are already explicit: `prog.witnessAll(proofs, shapes:)` and `prog.air(nodeDigest(digests))`, with `digests` computed from the spend AIRs alone (`statementDigest(air, const [])`). So the coordinator can compute a node's expected digest without proving it, which is what makes verifying a returned node possible. `StarkProof` has no byte encoding today; the only serialisation is the SHA-flavour unlocking script (`buildUnlock`), which is not a decoder. See proposal.md for motivation.

## Goals / Non-Goals

**Goals:**
- Level-1 proving behind an interface, with local and scheduled implementations that produce identical rounds.
- Verification of returned nodes as the trust boundary; no assumption about worker honesty.
- A codec for proofs and jobs that a later transport can carry unchanged.

**Non-Goals:**
- Network transport, worker discovery, incentives or payment for proving.
- Handing out levels 2 to 4 (they depend on level-1 results and are 5 proofs in total).
- Wallet-side spend proving (already the wallets' job).

## Decisions

- **Interface at the node, not the level.** `NodeProver` has one operation: prove one `NodeJob` to a `StarkProof` (async). `LocalNodeProver` wraps `StarkProver.prove`; `EdgeScheduler` fans jobs out to registered workers (each a `NodeProver`, possibly remote behind a codec) and falls back to a local prover per node. Alternative: an interface per level, rejected because only level 1 is worth distributing and the per-node shape is what workers need.
- **Verify by re-deriving the AIR.** The coordinator builds `prog.air(nodeDigest(...))` itself and runs `StarkVerifierRef(level.params, air, hash: p2).verify(proof)`; a worker cannot make the coordinator verify against a digest of the worker's choosing. Cost 0.1 s per node, 1.6 s per round.
- **Codec as lanes.** Encode a proof as a length-prefixed sequence of 32-bit words in the order the verifier reads it (roots, hints, OOD values, FRI roots, final coefficients, nonce, then per query the leaves, paths and inverses), parameterised by the `StarkParams` and AIR column counts so decoding knows every length. Alternative: JSON, rejected for size (a level-1 result is 327 KB of words) and because the lane order is already the on-chain convention.
- **Timeouts per node, not per round.** The scheduler awaits each node's future with `Future.timeout` and starts local proving on expiry; a late result is dropped (the future is already completed). Alternative: wait for all then fall back, rejected because one stalled worker would cost a full local level.
- **Aggregation API.** `aggregate(..., {NodeProver? level1})` keeps the current inline behaviour when null; the worker path is a second implementation, not a flag inside the loop.

## Risks / Trade-offs

- [Worker memory] A level-1 node peaks at about 9 GB; a laptop without it will fail or swap → the job carries the trace size so a worker can refuse before starting; refusal is a fast fallback.
- [Bandwidth] About 1 MB out and 327 KB back per node → acceptable for a wallet on a home connection; measured, not optimised, in this change.
- [Determinism] The proof uses randomness (zk is off for verifier nodes, but grinding and challenges follow the transcript) → identical rounds are checked on roots and publics, not proof bytes.

## Open Questions

- Whether the coordinator should ask two workers for the same node and take the first verified result; deferrable until a transport exists.
