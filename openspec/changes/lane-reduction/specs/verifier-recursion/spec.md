## MODIFIED Requirements

### Requirement: Wide root
In wide mode the root program SHALL take every transfer's reduced public lanes (nullifiers, public amount, outHash, real flags, asset: 32 lanes) followed by the round chunks (root before, root after, first subtree index, and the ring of four anchors) as its public input, derive the level-1 statement digests from those lanes and the ring in-circuit, and verify the top inner proof against them. The anchors and commitments of the transfers SHALL NOT be part of the on-chain statement.

#### Scenario: Public lanes are the statement
- **WHEN** the verifier slot's unlocking script supplies the wide publics
- **THEN** the same lanes are what the state script reads as the round's transfers

#### Scenario: Ring is a round input
- **WHEN** the round chunks carry a ring that is not the pool's current ring
- **THEN** the state script rejects the round

### Requirement: In-circuit tree update
The wide root SHALL prove that appending the round's commitments as whole subtrees (32 leaves each, empty leaves for padding positions) to the commitment tree at the given index takes the root from rootBefore to rootAfter, where the commitments are witness values bound to the level-1 statement digests rather than public lanes.

#### Scenario: Wrong rootAfter
- **WHEN** the round chunks claim a rootAfter that does not result from the appended leaves
- **THEN** no witness satisfies the program

#### Scenario: Substituted commitment
- **WHEN** the root's witness carries a commitment that is not the one the level-1 node verified
- **THEN** the level-1 digest does not match and no witness satisfies the program

## ADDED Requirements

### Requirement: Level-1 anchor check
A level-1 node SHALL check that every real-input spend it verifies has its anchor among the round's ring of four roots, and its statement digest SHALL cover the ring and every spend's anchor and commitments.

#### Scenario: Stale anchor
- **WHEN** a spend's anchor is older than the ring
- **THEN** no level-1 witness includes it
