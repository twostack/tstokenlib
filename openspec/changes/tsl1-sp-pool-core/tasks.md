## 1. The transfer

- [ ] 1.1 Add `ShieldedTransfer` in `lib/src/shielded_pool/shielded_transfer.dart` (proof, 56 publics, bundle bytes, optional `PoolWithdrawal`, optional 36-byte deposit outpoint), with a `padding` constructor that pays `paddingNote` twice with an empty bundle; verify with a new `test/shielded_transfer_test.dart` that a real and a padding transfer hold what pool-transfer "Contents" says.
- [ ] 1.2 Implement the self-consistency check (null, or the first failing reason) for every rule in pool-transfer "Self-consistency"; verify one test per rule that each refusal names its reason, including bundle-names-another-commitment, withdrawal-for-the-wrong-amount and empty-bundle-on-a-real-transfer, and that none of them needs the proof verified.
- [ ] 1.3 Implement the deposit shape check and the receipt a deposit transfer implies; verify the two pool-transfer "Deposit shape" scenarios, and that the receipt of the fixture's 500 deposit equals the one `pool_round_v_test` puts at output 5.
- [ ] 1.4 Implement the wire format from design.md (version, flags, publics, length-prefixed `ProofCodec` proof and bundle, withdrawal record, deposit outpoint); verify round trip at test parameters with the decoded proof still verifying, and refusal of an unknown version, a truncated encoding and a trailing byte.
- [ ] 1.5 Extend `tool/scratch/spend_submission_size.dart` to encode a production `ShieldedTransfer` with two hybrid bundles and a withdrawal; record the encoded size (expected about 67 KB, bound 100 KB) and the proving time in `docs/ZK_SHIELDED_POOL_TSL1_DESIGN.md`.

## 2. Reading a round

- [ ] 2.1 Add a static reader to `PP1SpUnlockBuilder` returning the ROUND unlock's pushes by name, so the bundles push index lives beside the code that writes it; verify on witness 1 of the test chain that the bundles push decodes (`PoolOutHash.decodeBundles`) to the fixture's bundles.
- [ ] 2.2 Parse the root statement from round N+1's input 2 unlock: exactly `PoolStatement.numPublics` minimal script numbers, refusing anything else; verify on round 1 and round 2 of the test chain that each transfer's pinned lanes equal the fixture's publics, and that an unlock with one push missing is refused.
- [ ] 2.3 Give the reader the pool's `AggregationTree` and `PoolStatement` without compiling level programs (fall back to `PoolAggregation(dryRun: true)` if the tree cannot stand alone); verify that `subtreeLeavesOf` over lanes rebuilt from bundles gives the fixture's leaves, and measure construction at production shape in `tool/scratch/reader_setup_probe.dart`, recording the time in the design doc.

## 3. The test chain as it will be mined

- [ ] 3.1 Change `test/pool_chain_fixture.dart`: round 1's deposit note and round 2's 200 change note go to one wallet address, other outputs to other addresses; bundles are `NoteEncryption.encrypt` results (two per transfer, output order); padding transfers pay `paddingNote` with an empty bundle; the fixture exposes each round's transfers as `ShieldedTransfer`s and the wallet's keys and diversifier. Verify every transfer passes 1.2, and `test/pool_round_v_test.dart` passes (11 tests).
- [ ] 3.2 Verify the localnet run still mines the test chain through ARC (`POOL_LOCALNET=1 dart test test/pool_localnet_test.dart`), deleting the stale proof cache first, since the bundles and padding changed.

## 4. The ledger

- [ ] 4.1 Add `copy()` to `NoteCommitmentTree`; verify a copy advances independently of its original.
- [ ] 4.2 Add `ShieldedLedger` in `lib/src/shielded_pool/shielded_ledger.dart`, opened from the issuance, witness 0 and Y_0; verify pool-ledger "Genesis" on the test chain.
- [ ] 4.3 Implement applying (round, witness, next Y) in two phases, on copies, committing only when every check in pool-ledger "Applying a round" holds; verify "Honest round" for rounds 1 and 2, "Bundle swapped in the witness", "Round does not extend the tip", a nullifier already present, a receipt that is not the deposit's, and a balance off by one, each leaving the ledger's header and roots unchanged.

## 5. The chain reader and snapshots

- [ ] 5.1 Add `ShieldedChainReader` over the issuance, witness 0, Y_0 and the (round, witness, next Y) triples, reporting padding flags, withdrawals, receipts and the last round applied; verify "Reader agrees with the builder" and "Stops at a bad round" on the test chain.
- [ ] 5.2 Implement ledger snapshots (header, tip transactions, leaves in order, nullifiers in order; restore replays and checks the roots against the header); verify "Restart" (snapshot after round 1, restore, apply round 2, same header), and that a snapshot with one leaf altered is refused on restore.
- [ ] 5.3 Measure in `tool/scratch/ledger_apply_probe.dart`: applying one production round from the localnet production dump (target under 5 s on one core), and restoring a snapshot of 1,000 synthetic rounds (512,000 leaves; if over 10 s, add the frontier and node map to the snapshot, and update design.md); record both in the design doc.

## 6. Scanning and paths

- [ ] 6.1 Add `ShieldedNoteScanner` (ivk, diversifiers, optional nk) over rounds the ledger accepted; verify "Wallet finds its deposit" (500 at leaf 0 in round 1), "Stranger finds nothing", and "Spent after round 2" (500 spent in round 2, the 200 change note found) on the test chain.
- [ ] 6.2 Add Merkle paths against the current root and the rounds-left-in-ring query; verify "Path to the current root" (after round 2, leaf 0) and "Anchor ageing out" (a root four rounds old is out of the ring), the latter with headers advanced in a unit test.
- [ ] 6.3 Measure scanning one production round for one diversifier (512 hybrid bundles) in `tool/scratch/scan_cost_probe.dart`; record it in the design doc.

## 7. Surface, re-measurement and record

- [ ] 7.1 Export `ShieldedTransfer`, `ShieldedLedger`, `ShieldedChainReader`, `ShieldedNoteScanner` and the types a wallet needs to use them (`PoolHeader`, `PoolWithdrawal`, `PoolReceipt`, `PoolWalletKeys`, `NoteAddress`, `NotePlaintext`, `NoteBundle`) from `lib/tstokenlib.dart`, not the legacy types; verify `dart analyze lib test bin` has no errors and a test importing only `package:tstokenlib/tstokenlib.dart` can decode a transfer and read the test chain.
- [ ] 7.2 Re-run the production chain on localnet through node RPC with the new fixture (`POOL_BROADCAST=rpc POOL_PRODUCTION=1`, fresh proof cache, about 13 minutes of proving), and apply it with the reader; record the new witness sizes (expected about +0.92 MB each) in the design doc, and re-measure `docs/pool_round_anatomy.html` from the new dumps.
- [ ] 7.3 Write the dated "pool core" section in `docs/ZK_SHIELDED_POOL_TSL1_DESIGN.md`: the transfer and its wire format, why commitments come from bundles and what a mismatched bundle does, the reader's inputs, snapshots and scanning, with the numbers from 1.5, 2.3, 5.3, 6.3 and 7.2.
- [ ] 7.4 Run `dart analyze lib test bin` (0 errors) and the full suite (`dart test`), and report the counts.
