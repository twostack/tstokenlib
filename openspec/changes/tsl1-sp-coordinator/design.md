## Context

See proposal.md for why. What the code gives this change, read on 2026-09-22:

- **The round as the fixture builds it** (`test/pool_chain_fixture.dart`, `test/pool_test_chain.dart`): witnesses proved per transfer, then `PoolAggregation.aggregate(publics, spendProofs, rootBefore:, rootAfter:, index:, paths:, ring:, nullifiers:, receiptTransfers:, level1:)` on trees advanced beforehand with `subtreeLeavesOf`, then `PoolRoundProof.root`, then `ShieldedPoolTool.buildSlotTxn` for Y_{N+1}, `createRoundTxn(prevWitness, prevRound, prevSlot, ..., newHeader, nextSlot, nextSlotTx:, receipts:, deposits:, withdrawals:, roundProof:, fee:)` and `createWitnessTxn(..., bundles:, receipts:, withdrawals:)`. The coordinator is that sequence with the trees taken from a `ShieldedLedger` copy and the header advanced by `PoolHeader.advance`.
- **Fees**: `createRoundTxn` takes a fee as a number because V signs the change; the localnet harness builds once, prices with `ShieldedPoolTool.feeFor(tx, satsPerKb:)`, and builds again. Y and the witness pay whatever their funding output holds beyond their 1-satoshi output, so the funding output has to be sized to the fee (the harness's splitter does that per transaction).
- **Deposits**: `ShieldedPoolTool.findDeposits(candidates, pp3Outpoint, minRefundAfter:)` recognises covenants naming a PP3 and returns each with its receipt; `createRoundTxn` refuses a deposit whose receipt does not match.
- **Intake pieces**: `ShieldedTransfer.decode`, `refusal()`, `depositRefusal()`, `receipt`, `verifyProof(spendP)`; `ShieldedLedger.roundsLeftInRing(root)`, `nullifiers.occupied`, `header.balance`; `ShieldedTransfer.padding(spendP)`.
- **The legacy coordinator** (`pool_coordinator.dart`): intake order, `_PendingRound` with its nullifier set and withdrawn total, the deadline through `CoordinatorClock` (with `FakeClock` for tests), one build at a time chained on a future, `ProverPool` for level 1, `runIdleWork`, `RejectReason`. All of that carries over; what goes is the mode, funding inputs, extra outputs, `PoolLedger` and the legacy reader.
- **Ricochet** (`../ricochet-dart-client`, `../go-ricochet`, surveyed 2026-09-22): payloads are opaque `Uint8List`, one per message, 10 MB a frame; a mailbox holds 1,000 messages until they are marked delivered; feeds are append-only and polled by sequence; a peer id is free to mint, so anyone can write to an inbox.

## Goals / Non-Goals

**Goals:**
- One coordinator class that runs the TSL1_SP pool from accepted transfers to the three transactions, with the same intake and scheduling the legacy one had.
- A message set the wallet and server repos can both build against, with nothing in it that assumes ricochet.
- The coordinator tested on the chain that is mined, at both scales, through the localnet harness.

**Non-Goals:**
- The transport, chain access, key storage and run loop: the server change.
- Persisting the pending round.
- Retiring the legacy tool and its script tests.

## Decisions

**`ShieldedCoordinator` in `lib/src/shielded_pool/shielded_coordinator.dart`, and the legacy coordinator deleted.** The pool core kept legacy types beside new ones so the legacy coordinator kept compiling; this change is the one that replaces it, so the old files go rather than gaining a third name. `PaddingSupply` gets a TSL1_SP twin over `ShieldedTransfer` (the legacy one stays with the legacy tool). Alternative: keep `PoolCoordinator` as the name. Rejected because the pool-core names are `Shielded*`, and a wallet author reading the exports should see one family.

**Intake order is cost order, and the pool's checks sit between the transfer's and the proof.** Size, decode and self-consistency come from the transfer type; then ring, nullifiers, deposit and balance, which are map lookups and one covenant parse; then the proof, at 20 ms. A submission that fails anything cheap never costs a verification. Alternative: verify first, as the legacy coordinator did. Rejected: an open inbox makes the 20 ms the attack surface.

**Deposits: the wallet sends the covenant transaction, and a deposit is good for one round.** The covenant names PP3_N, so it can only be spent by the round that spends PP3_N; once that round is closed, a covenant naming its PP3 is dead and the depositor has to refund and deposit again against PP3_{N+1}. The coordinator therefore matches a deposit against the tip's PP3 and refuses one naming a PP3 that a closed round spends, with a reason that says to resubmit. The margin `minRefundAfter` is configured (the harness uses 1,000 blocks); a refund that could be mined before the round would invalidate the round.

**Anchors are checked at intake against the ring and again at close.** Level 1 checks every real spend's anchor against the round's ring in-circuit, so a transfer whose anchor rotated out while it waited would fail aggregation minutes in. Dropping it at close with an expired reply costs nothing. With rounds closing at the deadline and a four-root ring, a transfer waits at most one round, so expiry only happens across a restart or a stalled coordinator.

**The coordinator applies its own round to its ledger before publishing.** The three transactions are built, then `ledger.apply(round, witness, Y)` runs the reader's checks; only if it applies are they stored and published. This turns the "a transfer can pass V and strand every reader" risk of the pool core into a pre-publish check for the one party that can still stop it: the coordinator. It costs about 0.7 s a production round (pool core measurement). Alternative: advance the ledger from what the coordinator knows it built. Rejected: that is trusting itself, and the check is cheap.

**Funding is an interface: `CoordinatorFunding.output(minValue)` returns a spendable P2PKH output (transaction, vout, signer, public key), and the coordinator asks for three per round.** Y's size is fixed for a pool (1,783,000 B at production), the round's and witness's are known after a dry build, so the coordinator prices with `feeFor` at the configured rate with a floor and asks for the exact value. The localnet harness's splitter becomes one implementation; the server's wallet another. Alternative: hand the coordinator a wallet. Rejected: the library stays transport- and wallet-free.

**Storing before publishing, in order.** `CoordinatorStore.roundBuilt(number, y, round, witness, snapshot)` is called before the first `publish`. A crash between the round's publish and the witness's would otherwise leave a round mined with no witness, which no one else can build (only the coordinator holds the witness's signer), and the pool frozen. The store makes the witness recoverable. Publishing is Y, round, witness, since each spends the one before; the transport may still deliver them out of order, but a node holds a child until its parent arrives.

**The protocol is plain data in `lib/src/shielded_pool/pool_protocol.dart`**, four classes with `encode`/`decode` in the style of `ShieldedTransfer`'s wire format: a version byte, a kind byte, then fields with explicit lengths, bounded before allocation, every failure a `ProtocolRefusal` naming the field. Reason numbers are an enum with fixed values, so a wallet built later still reads an older coordinator's refusals. Alternative: JSON. Rejected for the same reasons as the transfer's format, and because a submission embeds a 64 KB proof.

**The descriptor carries the layout, not the level programs.** `ShieldedPoolLayout.forArities(arities, nullifierLevel:, receiptSlots:)` is all a wallet needs to read the chain, and the spend parameters are all it needs to prove; the level parameters are the coordinator's business. A wallet checks the descriptor's txids by opening a ledger from them: an issuance that is not a pool's, or a witness that does not certify it, is refused there.

**The pending round is not persisted.** A restart loses it; the wallet notices by scanning the announced round for its notes and resubmits, which intake accepts since nothing was published. The alternative, persisting submissions, adds a store of proofs the coordinator would have to expire itself. The snapshot is taken after every witness, before publishing, so recovery is restore plus the rounds published since.

**Recovery refuses a chain that disagrees.** The reader refuses a triple that does not extend the snapshot's tip, and a coordinator that then finds a published round missing from the chain (its store has round N+1 but the chain gives it nothing after N) reports it rather than building round N+2 on a tip that may be orphaned. Re-publishing is the server's call.

**Bounds set before measuring, and what happens if they fail.** Intake under 50 ms: the parts measure 20 ms; if a production round's ring and nullifier checks push it over, the checks are wrong, not the bound. Round under 10 minutes: the plan measured 240 s with the GPU and 353 s without; a miss means the coordinator's own work (trees, apply, fee builds) grew past 4 minutes, which the round task times part by part. Recovery under 30 s: restore measured 9.4 s and a production apply 0.7 s; a miss goes back to the ledger, not here.

**Tests build rounds from the fixture's transfers.** `PoolChainFixture` already proves the transfers and exposes them; the coordinator test submits them, closes, and compares the three transactions it builds with the ones `PoolTestChain` builds by hand, then applies them with a reader. The aggregation at test parameters takes about 3 s a round, so the suite grows by under a minute. The localnet test gains a `POOL_COORDINATOR=1` path that mines the chain through the coordinator.

### What the apply changed (2026-09-22)

Recorded here because the code went a different way than the text above in these places.

- **The deposit margin is relative to a chain height the caller sets.** `minRefundAfter` as a configured absolute number cannot work across the pool's life; the coordinator has `depositMargin` (blocks) and a `chainHeight` the server updates, and matches a covenant against `chainHeight + depositMargin`. The harness sets the height once from the node.
- **Funding is asked for in two moments, and needs no owner key.** Y's output is asked for before anything is proved (its size is fixed, so that is what "refuse a round before proving when there is no funding" means); the round's and the witness's after a dry build of each with placeholder funding, since the witness's funding outpoint is locked into the round's PP2 and the round's size does not depend on it. A DER signature varies by a byte, so 8 bytes are added to each priced size. A round that fails after Y was funded leaves that output unspent; re-offering it is the funding source's business. `createRoundTxn` gained `ownerSigner` and `createWitnessTxn` `fundingSigner`/`fundingPubKey`, so a funding output may belong to a key other than the pool's owner.
- **Expiry is a re-check at close, not a caught aggregation failure.** Before padding, every accepted transfer's anchor and nullifiers are checked against the ledger again; the ones that fail are dropped with an expired reply. An aggregation that still fails is a build failure, and the round returns to pending. The reason: the aggregation does not say which transfer it failed on.
- **The "round the ledger refuses" scenario is driven through the tool, not the store.** The store is called after the apply, so it cannot tamper with what is applied; the test subclasses `ShieldedPoolTool` to build a witness with the bundles swapped, and the coordinator's apply refuses the round on outHash.
- **Tests compare headers and readers, not transaction bytes.** The coordinator's transactions differ from `PoolTestChain`'s in funding and signatures, so the tests check that the coordinator's ledger and a reader given its three transactions reach the fixture's headers, and that the reader's snapshot equals the coordinator's.
- **The localnet path funds from the node, one exact output per request,** rather than the splitter: `_NodeFunding` spends its change to pay exactly what the coordinator asked and mines it, which is what a server's wallet will do. The fixture gained `aggregate: false` and the harness a transfer cache (`POOL_PROOF_CACHE.transfers.json`), since a coordinator run needs only the spend proofs.
- **Per-stage timing is on the coordinator** (`RoundTiming`, `lastTiming`), so the round measurement and an operator read the same numbers.

## Risks / Trade-offs

- **An inbox of garbage costs 21 s per thousand proofs.** The cheap checks stop everything but a well-formed transfer with a valid-looking proof; a thousand of those cost 20 s of verification. → The bound is per submission; rate limiting is the server's.
- **The coordinator's memory at scale** is the ledger's (3.5 GB at 1,000 production rounds, pool core). → Noted there; nothing new here.
- **A deposit that misses its round** costs the depositor a refund and a second covenant. → The reply says so, and the wallet change can retry automatically. Deposits arriving while a round is in flight wait for the next tip, so the window is the round's build time.
- **The witness's signer is the coordinator's key alone.** A lost key after a round is published freezes the pool. → The store holds the witness before the round is published; key custody is the server's.
- **Three funding outputs a round, sized to the fee.** A funding source that returns one too small makes the transaction unmineable. → The coordinator checks the value it is handed before building, and refuses the round.

## Migration Plan

Additive for the pool; breaking for callers of the legacy coordinator, of which there are none outside its tests and `bin/pool_coordinator.dart`. The legacy tool keeps its tests. Rollback is reverting the change; nothing on chain changes.

## Open Questions

- None that change what gets built. The margin for `minRefundAfter` and the fee floor are configuration; the tasks use the harness's values.
