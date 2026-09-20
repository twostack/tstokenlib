# pool-state-script Specification

## Purpose
The PP1_SP locking script that is the pool on chain: a state output holding the header (commitment-root ring, nullifier-set root, tree size, vault) that every round must advance correctly, with the transfers checked either in per-transfer verifier slots (direct mode) or through one aggregated verifier slot (aggregated mode).

## Requirements

### Requirement: Header
The state output SHALL carry the pool's token id, the issuer's Rabin key hash, a phase, a ring of the four most recent commitment roots (ring[0] current), the tree size and the nullifier-set root. A round SHALL rotate the new root into the ring, add the round's leaves to the size and replace the nullifier root.

#### Scenario: Header after a round
- **WHEN** a round appends 32 leaves and inserts nullifiers
- **THEN** the next state's ring[0] is the new commitment root, size is 32 larger and the nullifier root is the set's new root

### Requirement: Two modes, two coordinators
The generator SHALL produce either the direct-slot script (k verifier slots and one append slot per round, up to 11 transfers) or the aggregated script (one verifier slot for the round's root proof, a fixed transfer count); these are separate solutions shipped as separate coordinator configurations, never one script that accepts both.

#### Scenario: Aggregated round shape
- **WHEN** the generator is in aggregated mode for 256 transfers
- **THEN** a round transaction is the state input, one slot input and the deposits' funding inputs, and the unlocking script supplies all 256 transfers' lanes

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

### Requirement: Nullifier set
The nullifier set SHALL be a sorted Merkle set of depth 32 over SHA256 leaves (value, next) such that non-membership of a value is shown by the low leaf around it, and insertion creates a leaf at the next free index; a dummy input SHALL insert nothing.

#### Scenario: Dummy inserts nothing
- **WHEN** a transfer's second input is a dummy
- **THEN** the nullifier root after the transfer accounts only for the first input

### Requirement: Outputs bound by the covenant
The script SHALL bind the transaction's outputs (the next state, the slot results, the vault amount, the transfers' extra outputs) through the sighash preimage, so a round cannot redirect value.

#### Scenario: Vault overdraw
- **WHEN** the transfers withdraw more BSV than the vault holds
- **THEN** the script rejects

### Requirement: Size limits
The state script and the round's unlocking data SHALL keep every script under 1,000,000 ops and the transaction under 10 MB; at 32 lanes per transfer the state script binds at about 300 transfers per round (its per-transfer cost is the two nullifier insertions, not the lanes).

#### Scenario: Round at plan size
- **WHEN** a 256-transfer aggregated round is assembled
- **THEN** the root verifier slot is about 650,000 ops and 1.6 MB and the transaction under 10 MB
