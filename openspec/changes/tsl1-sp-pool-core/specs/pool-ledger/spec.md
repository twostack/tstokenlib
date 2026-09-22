## Purpose

The TSL1_SP pool's state as a coordinator or a wallet holds it (the header, the commitment tree, the nullifier tree and the chain tip the next round spends), rebuilt from mined transactions alone, and the way a wallet finds, proves and tracks its own notes in it.

## ADDED Requirements

### Requirement: Ledger state
A ledger SHALL hold the pool's current header, its note commitment tree, its nullifier tree, and the tip the next round must spend: slot transaction Y_N, round N and witness N. A ledger opened from a pool's issuance and witness 0 SHALL hold the genesis header, an empty commitment tree and an empty nullifier tree, and its roots SHALL equal the genesis header's.

#### Scenario: Genesis
- **WHEN** a ledger is opened from an issuance and its witness
- **THEN** its size is 0, its roots are the genesis header's, and its tip is round 0, witness 0 and Y_0

### Requirement: Applying a round
Given round N+1, witness N+1 and the slot transaction Y_{N+1} that round N+1's PP3 pins, a ledger SHALL advance only if every one of these holds, and otherwise SHALL be left unchanged and name the first that fails:
- round N+1 spends the tip's Y_N output 0 at input 2 and round N output 3 at input 3, and witness N+1 spends round N+1's outputs 1 and 2;
- the new header is the one round N+1's PP1 output carries;
- the per-transfer lanes are read from the root proof's statement at the bottom of round N+1's input 2 unlock, in the statement layout of the pool's verifier;
- the bundles are the ones witness N+1 carries, their hashes combine to the new header's outHash, and every transfer's outHash lanes match its bundle and its withdrawal, the withdrawals being round N+1's withdrawal outputs in order;
- every transfer's commitments come from its bundle, or are the padding note's for a padding transfer with an empty bundle, and are placed at the leaf positions the aggregation gives them;
- every real nullifier is inserted, and none was already present;
- the rebuilt commitment tree and nullifier tree reach the new header's roots, its size is the old size plus the round's leaves, its ring is the old ring rotated with the new root first, and its balance is the old balance minus the sum of the transfers' public amounts;
- round N+1's receipts are exactly the deposit transfers' first commitments and values, in receipt order.

#### Scenario: Honest round
- **WHEN** a ledger applies a round and witness the tool built from well-formed transfers
- **THEN** its header equals the round's new header and its roots match

#### Scenario: Bundle swapped in the witness
- **WHEN** a witness carries a bundle other than the one a transfer's outHash commits to
- **THEN** the round is refused and the ledger keeps its previous state

#### Scenario: Round does not extend the tip
- **WHEN** a round spends a PP3 other than the tip's
- **THEN** it is refused as belonging to another chain or another point in this one

### Requirement: Chain reader
A reader SHALL rebuild a ledger from a pool's issuance, witness 0, and every (round, witness, next slot) triple since, in order, using no other input, and SHALL reach the same header bytes, commitment root, nullifier root and balance as the ledger that built the rounds. It SHALL flag each padding transfer, report each round's withdrawals and receipts, and stop at the first triple it refuses, reporting the last round it applied.

#### Scenario: Reader agrees with the builder
- **WHEN** a reader applies the two rounds of the test chain as mined
- **THEN** its header bytes, roots and balance equal those the builder advanced to

#### Scenario: Stops at a bad round
- **WHEN** round 2 of the test chain is given with a witness whose bundles do not match its outHash
- **THEN** the reader applies round 1, refuses round 2, and reports round 1 as its last

### Requirement: Snapshot
A ledger SHALL serialise to bytes and restore to an equal ledger (header, both trees, tip), so a coordinator or wallet can restart without re-reading every round. A restored ledger SHALL apply the next round exactly as the original would.

#### Scenario: Restart
- **WHEN** a ledger is serialised after round 1, restored, and given round 2
- **THEN** it reaches the same header as a ledger that never stopped

### Requirement: Note scanning
Given an incoming viewing key, a scanner SHALL return, for each round applied, the notes addressed to that key: the plaintext, the commitment, its leaf position, and the round it arrived in. It SHALL only decrypt bundles the ledger accepted (so their hash chain to the header's outHash is checked), SHALL discard a note whose plaintext does not reproduce its commitment, and SHALL return no note for a key the round did not pay. Given the nullifier key as well, it SHALL report a note spent from the round its nullifier enters the tree.

#### Scenario: Wallet finds its deposit
- **WHEN** the depositor scans round 1 of the test chain with the deposit note's viewing key
- **THEN** it finds one note of 500 at leaf position 0

#### Scenario: Stranger finds nothing
- **WHEN** another key scans the same round
- **THEN** no note is returned

#### Scenario: Spent after round 2
- **WHEN** the depositor scans round 2 with its nullifier key
- **THEN** the 500 note is reported spent in round 2 and the 200 change note is found

### Requirement: Merkle paths for spending
For any leaf the ledger holds, the ledger SHALL give its Merkle path against the current commitment root. A spend proved against that root SHALL stay acceptable to the pool for as long as the root is in the header's ring, the current round and the three after it, because the ring is what the next rounds check anchors against; the ledger SHALL say how many more rounds a given root stays in the ring.

#### Scenario: Path to the current root
- **WHEN** a wallet asks for the path of leaf 0 after round 2
- **THEN** the path and the leaf reproduce the header's current commitment root

#### Scenario: Anchor ageing out
- **WHEN** a root was current four rounds ago
- **THEN** the ledger reports it no longer in the ring, so a spend anchored to it would be refused
