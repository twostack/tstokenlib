## 1. The lineage gate

- [x] 1.1 On localnet, forge a round carrying the pool's tokenId with a header of the forger's choosing, give it a witness and mine it; verify pool-evidence "A forged round carrying the pool's tokenId" (the check refuses, naming the step that caught it) in `test/pool_lineage_attack_test.dart`, guarded by `POOL_LOCALNET=1`. Write the checker enough to run this first.
- [x] 1.2 Record the attempt and its result in the design record as a dated section. **If the forged round passes, stop this change**, record what passed, and size a multi-round proven-round check before any other task is started.

## 2. The invariant

- [x] 2.1 Assert in `AggregationTree` that `leavesAppended` is a power of two, throwing with the count; verify pool-aggregation "The plans in use", "A plan that would straddle" (300 transfers, 608 leaves) and "A round always appends its whole block" in `test/pool_aggregation_test.dart`.
- [x] 2.2 Make `ShieldedCoordinator.open` and `recover` refuse a plan whose leaf count disagrees with the tree being restored, naming both; verify it in `test/shielded_coordinator_test.dart`.

## 3. The block root and the fold

- [x] 3.1 Expose the round's block root on `ShieldedLedger` (the tree node at level log2(leaves), index N) and the block level on `ShieldedPoolLayout`; verify pool-ledger "A round's block root" against the fixture's round 2.
- [x] 3.2 Implement the upper frontier and the fold on `NoteCommitmentTree`: fold a block root, update a path from it, and report the computed root; verify pool-ledger "A path kept current by folding", "A fold that does not match" and "Thirty-two bytes a round".
- [x] 3.3 Verify pool-ledger "Folding a thousand blocks" against a directly built tree of 1,000 blocks of 512 leaves, and measure one fold plus one path update; record the number in the design record and check it against the 1 ms bound.

## 4. The descriptor and the announcement

- [x] 4.1 Add the leaf count, the tokenId and the genesis header to `PoolDescriptor`, and the block root to `PoolAnnouncement`, at protocol format version 2; verify pool-protocol "A descriptor a wallet can act on alone", "An announcement carries its block root" and the three scenarios the requirement already had.
- [x] 4.2 Verify pool-protocol "A descriptor stays small" (production, under 512 B) and re-run the protocol's existing untrusted-input and round-trip scenarios at version 2, including that a version 1 message is refused.

## 4b. Catch-up

- [x] 4.3 Add the catch-up request and reply at protocol version 2 (block roots over a range, the frontier, a head proof), with the published range set in the descriptor; verify pool-protocol "Three kinds of request", "A head proof checks out", "A frontier reproduces the root", "Block roots in a range", "A range outside the published set" and "A reply carries no asker".
- [x] 4.4 Verify pool-protocol "Catch-up replies are bounded", "A reply that claims too many roots" and "Mutated catch-up messages" (10,000 mutated), and measure a head proof at test parameters against the fixture's chain; record the size in the design record.

## 5. Proven rounds and proven notes

- [x] 5.1 Implement `lib/src/shielded_pool/pool_evidence.dart`: the proven-round check (witness spends the round's PP1 and PP2, PP1 carries the descriptor's tokenId, the header parses) and the proven-note check (the opening commits under `pk_d`, the path reaches the round's root); verify pool-evidence "A round of the test chain", "A witness that spends another round", "Another pool's tokenId", "A note of the test chain", "An opening that is not the holder's" and "A path to another root".
- [x] 5.2 Document beside the check what a proven round does and does not establish, with the result of task 1.1; verify by review against pool-evidence "What a proven round does and does not establish".
- [x] 5.3 Verify pool-evidence "Mutated evidence" (10,000 mutated rounds, witnesses, openings, positions and paths), "Checking makes no requests", "Two parties agree" and "Nothing left after a failure".
- [x] 5.4 Measure a proven-round and proven-note pair at test parameters; verify "Check cost" (under 20 ms) and record it in the design record.

- [x] 5.5 Route every read of a PP1 in the library through the body check (`ShieldedLedger._pp1Header`, the tool's `prevPP1`, the coordinator's tip read), and make `open` take the pool's tokenId and genesis header and refuse a triple that does not carry them; verify pool-ledger "A forged round offered to a ledger", "A round cannot be applied over a real tip anyway", "A forged genesis" and "The test pool opens", reusing the forgery from `test/pool_lineage_attack_test.dart`.
- [x] 5.6 Add a doc comment to `PP1SpLockBuilder.parse` saying it reads by offset, is not a security boundary, and that a reader of chain data must go through `PoolEvidence`; verify by review.

## 6. The testing library

- [x] 6.1 Add `lib/testing.dart` exporting `PoolChainFixture` and its plans, and move the fixture out of `test/` to where it can be exported without carrying test-only code into `lib/`; verify the existing suites still pass unchanged and that a scratch package outside tstokenlib can import and build the fixture.

## 7. Docs and the suite

- [x] 7.1 Write the dated section in the design record: the block-root geometry with its table, the invariant and its three enforcement points, why a folded root needs no attestation, the one-hop claim and the attack's result, the protocol's version 2 fields, and every measurement from groups 3, 4 and 5.
- [x] 7.2 Run `dart analyze` (0 errors) and the full suite, and report the counts.
