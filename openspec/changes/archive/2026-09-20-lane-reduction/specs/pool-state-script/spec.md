## MODIFIED Requirements

### Requirement: Per-transfer checks
For every transfer the script SHALL check that its lanes are canonical, that the signed public amount moves the vault only for BSV, that a mint or gated transfer carries a valid issuer authorisation (Rabin signature over the lanes), that each real input's nullifier is inserted into the sorted nullifier set (non-membership then insertion, both proved by Merkle paths) and that SHA256 of its extra outputs equals its outHash lanes. In direct-slot mode the script SHALL also check that the anchor is in the ring unless neither input is real; in aggregated mode a transfer has 32 lanes, the anchor check is the proof's (against the ring the round chunks carry, which the script SHALL check equals its own ring), and the commitments reach the tree only through the root proof.

#### Scenario: Double spend
- **WHEN** a transfer's nullifier is already in the set
- **THEN** the non-membership proof fails and the round is rejected

#### Scenario: Anchor waived for padding and deposits
- **WHEN** a direct-slot transfer's real flags are both zero and its anchor is not in the ring
- **THEN** the transfer is still accepted

#### Scenario: Aggregated ring
- **WHEN** an aggregated round's chunks carry a ring different from the state's
- **THEN** the round is rejected

### Requirement: Size limits
The state script and the round's unlocking data SHALL keep every script under 1,000,000 ops and the transaction under 10 MB; at 32 lanes per transfer the state script binds at about 300 transfers per round (its per-transfer cost is the two nullifier insertions, not the lanes).

#### Scenario: Round at plan size
- **WHEN** a 256-transfer aggregated round is assembled
- **THEN** the root verifier slot is about 650,000 ops and 1.6 MB and the transaction under 10 MB
