## 1. The protocol

- [x] 1.1 Move every message to format version 3; add the 16-byte random id to catch-up requests and echo it in replies, keeping the constructors source-compatible (the id optional, random by default). Verify pool-protocol "Another version is refused" and "A reply echoes its request's id" (`test/pool_protocol_test.dart`, `test/pool_catch_up_test.dart`).
- [x] 1.2 Add the refusal form of the catch-up reply with its four reasons. Verify "Every reason round trips".
- [x] 1.3 Add the round kind, sharing the head's body codec. Verify "A round request is one round" and "A round after later rounds are mined".
- [x] 1.4 Add the mined-round notice (kind 7), carrying the txids and the witness's place but no transactions (slimmed after libcloak's review, from 792,214 B). Verify "A notice round trips" and "A notice stays small", and record its size at test parameters (141 B) in the design record.
- [x] 1.5 Update the existing version 2 catch-up tests' byte offsets and version pins for version 3. Verify the whole of `test/pool_protocol_test.dart` passes.
- [x] 1.6 Mutation fuzz of the new messages: verify "Mutated version 3 messages" (10,000).

## 2. The ledger

- [x] 2.1 Factor the round reading out of `apply` into a static `_read`, and build `ShieldedLedger.readLeaves` on it. Verify "Leaves agree with the ledger" and "Another round's witness", and that every existing ledger, fold and evidence test still passes.
- [x] 2.2 Add `ShieldedLedger.frontierAt`, making `frontier()` its tip case. Verify "The frontier one round back".

## 3. The responder and the fixture

- [x] 3.1 Write `PoolCatchUpResponder` and `CatchUpSource` (with `placed` for a notice, which needs no transactions): published ranges only, answers pinned to the last mined round, and a refusal for everything else, including a failing source. Verify "Not mined yet", "A source that fails", "Head and frontier agree below the ledger's round" and "Block roots up to the last mined round".
- [x] 3.2 Add `PoolTestChain.descriptor()`, `.catchUpSource()` and `.responder()` for wallets' fake pools. Verify through the responder tests above, which run on it.

## 4. Record and run

- [x] 4.1 Add a dated section to `docs/ZK_SHIELDED_POOL_TSL1_DESIGN.md`: version 3, the id, the refusals, the round kind and its privacy cost, the notice, `readLeaves`, and the sizes. Verify the section exists.
- [x] 4.2 Run `dart analyze lib test` (no new issues) and the full suite. Verify all pass, and report the output.
