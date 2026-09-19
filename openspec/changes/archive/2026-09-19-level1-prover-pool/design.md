## Context

`PoolAggregation.aggregate` proved every level inline (see the `aggregate` loop in `lib/src/recursion/pool_aggregator.dart`). A level-1 node's inputs are already explicit: `prog.witnessAll(proofs, shapes:)` and `prog.air(nodeDigest(digests))`, with `digests` computed from the spend AIRs alone (`statementDigest(air, const [])`). So the coordinator can compute a node's expected digest without proving it, which is what makes verifying a returned node possible. `StarkProof` had no byte encoding; the only serialisation was the SHA-flavour unlocking script (`buildUnlock`), which is not a decoder. See proposal.md for motivation.

This change was first framed as "edge proving": level-1 nodes folded by participants' wallets. That framing was dropped while it was being built (see the proposal): a node is indivisible, so a wallet would fold sixteen transfers' worth of work for its one transfer, and the round already meets its budget without any of this. The mechanism is the same; what it is for is the coordinator's own machines.

## Goals / Non-Goals

**Goals:**
- Level-1 proving behind an interface, with local and pooled implementations that produce identical rounds.
- Verification of returned nodes as the trust boundary, so pool membership needs no trust and can later extend beyond the coordinator's own machines.
- A codec for proofs and jobs that a later transport can carry unchanged.

**Non-Goals:**
- Network transport between the coordinator's machines, membership configuration (that is the coordinator service's), incentives or payment for proving.
- Handing out levels 2 to 4 (they depend on level-1 results and are 5 proofs in total).
- Wallet-side folding of nodes. Wallet-side spend proving is already the wallets' job and is unchanged.

## Decisions

- **Interface at the node, not the level.** `NodeProver` has one operation: prove one `NodeJob` to a `StarkProof` (async). `LocalNodeProver` wraps `StarkProver.prove`; `ProverPool` hands jobs to its members (each a `NodeProver`, possibly on another machine behind a codec) and falls back to a local prover per node. Alternative: an interface per level, rejected because only level 1 is worth distributing and the per-node shape is what a member needs.
- **Verify by re-deriving the AIR.** The coordinator builds `prog.air(nodeDigest(...))` itself and runs `StarkVerifierRef(level.params, air, hash: p2).verify(proof)`; a member cannot make the coordinator verify against a digest of the member's choosing. Cost 0.1 s per node, 1.6 s per round measured.
- **Codec as lanes.** Encode a proof as the sequence of 32-bit words in the order the verifier reads it (roots, hints, OOD values, FRI roots, final coefficients, nonce, then per query the index, leaves, paths and inverses), parameterised by the `StarkParams` and AIR column counts so decoding knows every length. Alternative: JSON, rejected for size (a level-1 result is 327 KB of words) and because the lane order is already the on-chain convention.
- **Timeouts per node, not per round.** The pool awaits each node's future with `Future.timeout` and starts local proving on expiry; a late result is dropped (the future is already completed). Alternative: wait for all then fall back, rejected because one stalled member would cost a full local level.
- **Aggregation API.** `aggregate(..., {NodeProver? level1})` keeps the inline behaviour when null; the pooled path is a second implementation, not a flag inside the loop. Taking an async prover makes `aggregate` and, above it, `ShieldedPoolTool.createAggregatedRoundTxn` return futures.
- **Who verifies (refined while building).** The spec requires the aggregation to fold only proofs it has verified, and the pool to verify before it decides whether to fall back, which would verify every node twice. `NodeProver` therefore carries `verifies`: a prover that has already checked its result against the job's digest (the local prover, the pool) says so, and `aggregate` repeats the check only for one that does not, falling back to proving the node itself. One verification per node either way, and a bare member handed straight to `aggregate` is still not trusted.
- **Assignment is round-robin, membership is configuration.** The pool takes a list and cycles through it; which machines are in the list is the coordinator service's configuration (`coordinator-service`), not discovery. Alternative: a policy that prefers a wallet with a transfer in the node, dropped with the wallet framing.

## Risks / Trade-offs

- [Member memory] A level-1 node peaks at about 9 GB; a machine without it will fail or swap → the job carries the trace size so a member can refuse before starting; refusal is a fast fallback.
- [Bandwidth] About 1 MB out and 327 KB back per node → trivial between the coordinator's machines; measured, not optimised, in this change.
- [Determinism] Level proofs are not zero-knowledge, so a node proved anywhere is byte-identical → identical rounds are checked proof for proof in the tests; if a level ever gains zk masking the check must move to roots and publics.

## Open Questions

- Whether the pool should ask two members for the same node and take the first verified result; deferrable until a transport exists.
