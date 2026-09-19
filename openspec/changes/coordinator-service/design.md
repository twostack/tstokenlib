## Context

The tool builds one round from a list of transfers and a ledger (`createAggregatedRoundTxn`, `createRoundTxn`); the reader rebuilds the ledger from transactions; padding and the aggregation plan exist. There is no process, queue, clock or configuration. The user's decision (session 9): direct-slot rounds and recursion are separate solutions shipped as different coordinator versions or one coordinator configured for one or the other. See proposal.md.

## Goals / Non-Goals

**Goals:**
- One class that owns the pool's lifecycle with a transport-free API, testable with a fake clock and an in-memory chain.
- The two modes behind one intake and one ledger.

**Non-Goals:**
- HTTP or P2P transport (for submitters and between the coordinator's own machines), authentication of submitters, fee policy, wallet software.
- Broadcasting to a node (a publish callback is the boundary).

## Decisions

- **Intake verifies proofs.** Verification with the reference verifier costs about 0.1 s per spend and rejects garbage before a round is built; the round builder trusts the intake (recorded as a spec change). Alternative: verify at round time, rejected because one bad proof would then fail a 6-minute round.
- **Pending state is a shadow ledger.** The pending round keeps a set of pending nullifiers and the pending vault delta; acceptance checks against ledger plus pending. On close, the tool applies the round to the real ledger.
- **Trigger = full or deadline.** Configured `roundDeadline` (from the first pending transfer) and the mode's capacity; a timer per pending round, no polling. Alternative: fixed block cadence, deferred until a node connection exists.
- **Idle worker.** After each round, a background task refills the padding stock to `paddingStock` and keeps the level programs compiled. Proving padding uses the machine while idle; it is interruptible per transfer. It does NOT keep all five preprocessed commitments resident: measured, they are 14.5 GB of a round's 30.3 GB peak (see the GPU section of the design doc), and the levels are proved in sequence so no two are needed at once. Keep the 8-lane preprocessed roots, which the statement digests need throughout, and let each level rebuild its own commitment when it starts; the cache should hold one or two entries, not eight.
- **Recovery through the reader.** The coordinator is given the genesis transaction and a source of round transactions (a callback returning the chain of state spends); it rebuilds with `PoolChainReader` and compares with any persisted snapshot. Alternative: persisting the ledger, rejected as the source of truth is the chain.
- **Level 1 through the pool.** The recursive-mode configuration lists the coordinator's level-1 provers (`NodeProver`s: this machine, plus members on machines the coordinator operates once a transport exists), and round building passes a `ProverPool` over them as `level1`. Membership is configuration, not discovery; a participant's server can be listed like any other member because the pool verifies every returned node. With no members listed the pool is empty and level 1 is proved here, the measured 5.9-minute round.
- **Mode as a sealed config.** `CoordinatorConfig.direct(k)` or `.recursive(plan)`; the service checks the pool's state script bytes against the generator for that mode at start.

## Risks / Trade-offs

- [Long rounds block intake] Building a recursive round takes minutes → intake continues into the next pending round while the current one proves (two pending sets).
- [Padding stock size] Each padding transfer is 64 KB and a second of proving; a stock of 256 covers an empty round → configurable, default 64.
- [Vault check at intake versus at close] A withdrawal accepted at intake may exceed the vault if a deposit's funding fails → deposits are accepted only with their funding input present.

## Open Questions

- Whether rejected transfers should be retried automatically in the next round (for example a double spend where the earlier transfer is later withdrawn); deferrable, default is no.
