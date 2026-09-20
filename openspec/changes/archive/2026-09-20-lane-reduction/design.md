## Context

The wide root's public lanes are each transfer's 56 lanes padded to 7 chunks, plus 3 round chunks (`AggregationTree.widePublics`); the root derives each spend's statement digest from its lanes in-circuit and the level-1 digests from those. The state script's aggregated per-transfer section reads the anchor (ring check, now waived for two-dummy transfers), nullifiers, amount, outHash, flags and asset; it never reads the commitments. The chain reader's aggregated path reads commitments from the lanes to rebuild the tree. See proposal.md for the numbers.

## Goals / Non-Goals

**Goals:**
- 32 lanes per transfer on chain in aggregated mode with the same security: every dropped lane is checked inside a proof instead.
- Direct-slot mode untouched.

**Non-Goals:**
- Changing the spend circuit's 56 public inputs (wallets keep proving the same statement).
- Reducing outHash or nullifier lanes.

## Decisions

- **Anchor check at level 1, ring as a round chunk.** The ring (4 x 8 lanes) enters the wide publics once per round; the root includes it in the level-1 digest derivation; each level-1 node takes the ring as part of its public input and pins every real spend's anchor to one of the four. Alternative: check anchors in the root, rejected because the root is the tight trace (10,473 of 16,384 periods) and level 1 has slack only if the ring check is cheap; sized first (task 1.1).
- **Commitments as witness of the root, bound by digests.** The root already receives the leaves as witness for the tree update; today they are also public lanes. With commitments in the level-1 digest (which covers each spend's full 56-lane statement), the root derives the same digest from the reduced lanes plus the witness commitments, so a substituted commitment breaks the digest. No new constraint, one fewer chunk source.
- **Reader reads commitments from bundles, attributed by outHash; padding pays a fixed public note.** Every note-data bundle carries its commitment (`NoteBundle.cm`); the reader rebuilds the subtree from them and checks rootAfter, which is what makes bundles a trustworthy source (the proof appended the true commitments, so wrong ones fail the check). The reader attributes extra outputs to transfers by outHash: walking the transfers in order, each takes the shortest run of remaining outputs whose serialisation hashes to its outHash, so a transfer's note-data output is found without delimiters and a transfer with no extras takes none. Padding transfers carry no note data, so they could not supply commitments that way: decided (with the user) that every padding transfer pays its two zero-value outputs to one constant public note (`PoolTransfer.paddingNote`: zero address, zero randomness), whose commitment `PoolTransfer.paddingCm` the reader fills in for a transfer whose lanes read as padding. It costs nothing on chain and keeps padding synchronous; the note is spendable once, for nothing. The alternative, bundles on padding transfers, was about 1.5 KB per padding transfer and an asynchronous padding path for the KEM. A non-padding transfer without a note-data output is refused by the reader, since it has nowhere to take the commitments from; wallets are already required to publish one (pool-coordinator, Note data on chain). Alternative for the commitments: an OP_RETURN, rejected as bytes the state script would not bind.
- **Lane layout.** Reduced lanes in the order nf1, nf2, publicOut lo/hi, outHash, real1, real2, asset (exactly 32 = 4 chunks), so per-transfer chunk arithmetic in the root and the script is a constant. This is the spend statement's chunk order with chunks 0, 3 and 4 removed, so the root's pinned periods and the free (witness) periods interleave in statement order and the transcript replay is unchanged (`AggregationTree.freeChunks`, `PoolPublicInputs.toReducedLanes`).
- **Ring as four more round chunks, absorbed into every level-1 digest.** The level-1 node's public input stays one 8-lane digest: the ring's four chunks continue the node's digest chain after the spend digests (`VerifierProgram.nodeDigest(digests, ring:)`), so no AIR change was needed and the check costs four periods per node. The selector-bit form (bits sum to real1 OR real2, selected root equals that flag times the anchor) is 37 VM rows and four hints per spend. Measured: level 1 at 16 spends uses 31,876 of 32,768 periods, so the 15-spend fallback was not needed.
- **The issuer's message follows the mode.** The state script's Rabin check hashes the lanes it reads, so in aggregated mode the issuer signs SHA256 of the 32 reduced lanes (`IssuerAuth.message(publics, aggregated: true)`, `PP1SpScriptGen.issuerMessage`); the amount, asset, outHash and nullifiers it authorises are all among them.

## Measured outcome

The root slot moved as proposed, the state script did not. For the 256-transfer plan (`tool/scratch/root_script_size.dart throughput`, `tool/scratch/state_script_size.dart`): the root verifier slot is 647,463 ops and 1,592,510 bytes against 883,000 ops and 2.2 MB, about 1,230 ops per transfer against 2,156 (four pinned chunks at 281 ops each plus 32 lanes at 3.4; the proposal's 1,050 assumed a lower per-chunk cost). The state script's per-transfer section went from 3,432 to 3,348 ops and 5.9 to 5.75 KB: the anchor check and 24 lanes' bytes were 84 ops, and the rest is the two nullifier insertions (two depth-32 Merkle paths each), which no lane change touches. So the proposal's "a third off the state script" and "about 400 transfers per round" were wrong; the state script still binds the round, at about 298 transfers (1,420 fixed ops plus 3,348 per transfer under 1,000,000) against 290. The delta spec records the measured figures. What the change buys is the root script (27% smaller, 0.6 MB less per round) and 6,112 fewer public lanes per round, which is also what the prover's root has to pin.

## Risks / Trade-offs

- [Level-1 fit] 16 spends x a 4-way 8-lane comparison may not fit 2^20 → measured in task 1.1; fallback is 15 spends per node and a 15 x 4 x 2 x 2 plan (240 transfers).
- [Two lane formats] Direct-slot mode keeps 56 lanes → the generator's aggregated flag already switches the layout; the reader too.
- [Wallet visibility] Commitments no longer appear as lanes → wallets scan bundles (they do already).

## Open Questions

- Whether the ring should shrink to two roots once anchors are checked in-circuit (fewer chunks, less anchor tolerance for slow wallets); deferrable.
