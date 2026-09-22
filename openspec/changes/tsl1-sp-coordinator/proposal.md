## Why

The pool core change gave the library a transfer, a ledger, a reader and a scanner for the TSL1_SP pool, but the coordinator in `lib/` (`PoolCoordinator`, its chain reader and `bin/pool_coordinator.dart`) still runs the legacy state-script pool: it takes legacy transfers with funding inputs and extra outputs, builds one state transaction a round, and cannot drive `ShieldedPoolTool`'s slot, round and witness. The standalone coordinator server and the CLI wallet (the next two changes, in their own repos) need two things from this library first: a coordinator that runs the TSL1_SP pool end to end, and an agreed set of messages a wallet and a coordinator exchange, so the two repos can be built against the same contract without either depending on the other.

## What Changes

- **The coordinator is rewritten for TSL1_SP.** It takes `ShieldedTransfer`s at intake, checks them in the order the transfer type fixes (size, decode, self-consistency, then the proof) plus what only the pool knows (the anchor is in the ring, the nullifiers are neither spent nor pending, the balance covers the round's withdrawals, a deposit's covenant names this pool's live PP3 and matches the transfer's receipt), keeps a `ShieldedLedger`, and closes a round into the three transactions the pool needs, in order: the next slot transaction Y, the round, and its witness. Padding pays the public padding note with an empty bundle. Level 1 still goes through the prover pool. Recovery restores a snapshot and reads the rounds since from the chain.
- **The coordinator's transactions are funded and priced.** Y, the round and the witness each spend a funding output the coordinator is given, priced from a dry build at a configured rate, as the localnet harness does today.
- **A wallet-to-coordinator protocol**, as plain data with versioned byte encodings and no transport: a submission (a transfer, with the deposit transaction when it backs one, under a wallet-chosen id), the coordinator's reply (accepted into round N, refused with a reason, or expired), a pool descriptor (what a wallet needs to open a ledger and build transfers: the issuance, witness 0 and Y_0 txids, the layout and spend parameters), and a round announcement (round number, header, the three txids). Every message is decoded as hostile input and fits ricochet's limits with room to spare.
- **BREAKING: the legacy coordinator is retired.** `PoolCoordinator`, `CoordinatorFile`, `PoolChainReader`, `bin/pool_coordinator.dart` and their tests go, and the two legacy tests that used the reader lose those assertions. The legacy tool, its `PoolTransfer` and `PaddingSupply` stay for the legacy script tests until the legacy pool is retired as a whole.

Not in this change: the server process (ricochet client, chain access, key storage, the run loop) and the CLI wallet, which are the next two changes in their own repos; fetching transactions from ARC, WhatsOnChain or a node; and the legacy pool's retirement.

Numbers to hold, each a requirement with a scenario that measures it: a submission is accepted or refused at intake in under 50 ms at production parameters (measured on the transfer: 0.11 ms to decode, 0.04 ms to check, 20 ms to verify the proof); a coordinator's round, from closing it to the witness being built, takes under 10 minutes of the 12-core machine at production (the coordinator's share of a 256-transfer round measured 173 s of 342 s before the GPU work; the pool core's CPU-only run aggregated a round in 353 s); a submission message encodes to under 128 KB (a transfer is under 100 KB, a deposit transaction about 1.5 KB); an announcement and a descriptor to under 4 KB each, inside ricochet's 10 MB frame; recovery of a coordinator with 1,000 rounds of history takes under 30 s from a snapshot (restore measured 9.4 s) plus the rounds since.

The specs also carry the non-functional contract: submissions come from anyone who knows the coordinator's address and are treated so; the coordinator learns nothing about a transfer beyond what the round publishes, and its replies and announcements reveal nothing per transfer; a wallet trusts nothing in an announcement it cannot check against the chain; encodings are versioned and canonical; a restart loses the pending round and nothing else.

## Capabilities

### New Capabilities
- `pool-protocol`: the messages a wallet and a TSL1_SP coordinator exchange, their encodings, sizes and the checks each side makes, independent of the transport that carries them.

### Modified Capabilities
- `pool-coordinator`: rewritten from the legacy pool's rounds (one state transaction, funding inputs, extra outputs, an in-library chain reader) to the TSL1_SP round (Y, round, witness), deposits by covenant, funded and priced transactions; its chain reader and note-data requirements move to `pool-ledger` and `pool-transfer`, which already state them.
- `coordinator-service`: intake takes `ShieldedTransfer`s and deposit covenants; the round trigger, idle work and prover pool lose the legacy mode language; recovery goes through the ledger's snapshot and the chain reader; the mode configuration requirement is removed (the pool has one mode since 2026-09-21); untrusted submissions, privacy, restart behaviour and performance bounds are added.

## Impact

- New code under `lib/src/shielded_pool/` (the coordinator, funding and publishing interfaces, the protocol messages); `lib/tstokenlib.dart` exports them.
- Removed: `lib/src/transaction/pool_coordinator.dart`, `lib/src/transaction/pool_chain_reader.dart`, `bin/pool_coordinator.dart`, `test/pool_coordinator_test.dart`, `test/pool_chain_reader_test.dart`; `test/pp1_sp_legacy_aggregated_test.dart` loses its reader assertions.
- `test/pool_localnet_test.dart` gains a second path that mines the chain through the coordinator rather than by hand, so the coordinator is tested against the node at both scales.
- No script, circuit or parameter changes, so no template re-export and no kernel work.
- Consumers: the coordinator server builds on the coordinator and the protocol; the CLI wallet on the protocol, the transfer and the ledger.
