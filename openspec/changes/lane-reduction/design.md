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
- **Reader reads commitments from bundles.** Every note-data bundle carries its commitment (`NoteBundle.cm`); the reader rebuilds the subtree from them and checks rootAfter; padding transfers carry bundles too (zero-value notes) or the reader takes their positions as their bundles' commitments. Alternative: keep commitments in an OP_RETURN, rejected as bytes the state script would not bind.
- **Lane layout.** Reduced lanes in the order nf1, nf2, publicOut lo/hi, outHash, real1, real2, asset (exactly 32 = 4 chunks), so per-transfer chunk arithmetic in the root and the script is a constant.

## Risks / Trade-offs

- [Level-1 fit] 16 spends x a 4-way 8-lane comparison may not fit 2^20 → measured in task 1.1; fallback is 15 spends per node and a 15 x 4 x 2 x 2 plan (240 transfers).
- [Two lane formats] Direct-slot mode keeps 56 lanes → the generator's aggregated flag already switches the layout; the reader too.
- [Wallet visibility] Commitments no longer appear as lanes → wallets scan bundles (they do already).

## Open Questions

- Whether the ring should shrink to two roots once anchors are checked in-circuit (fewer chunks, less anchor tolerance for slow wallets); deferrable.
