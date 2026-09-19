## MODIFIED Requirements

### Requirement: Chain reader
A reader SHALL rebuild the ledger from the genesis transaction and the round transactions alone (publics from the slot unlocks, cross-checked against the results), reaching the same header, tree root, nullifier root and vault as the coordinator, and flagging padding transfers. In aggregated mode the reader SHALL take the round's commitments from the note-data outputs (each bundle carries its commitment) rather than from the public lanes, and SHALL check that the tree it rebuilds reaches the round's rootAfter.

#### Scenario: Reader agreement
- **WHEN** a reader applies the rounds the coordinator built
- **THEN** its ledger's header bytes equal the coordinator's

#### Scenario: Commitments from bundles
- **WHEN** an aggregated round's note-data outputs are read
- **THEN** the commitments they carry rebuild the subtree whose root matches the round's rootAfter
