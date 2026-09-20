## MODIFIED Requirements

### Requirement: Chain reader
A reader SHALL rebuild the ledger from the genesis transaction and the round transactions alone (publics from the slot unlocks, cross-checked against the results), reaching the same header, tree root, nullifier root and vault as the coordinator, and flagging padding transfers. In aggregated mode the reader SHALL take the round's commitments from the note-data outputs (each bundle carries its commitment; a transfer's extra outputs are the run of outputs its outHash commits to) rather than from the public lanes, take a padding transfer's two commitments as the padding note's constant, and SHALL check that the tree it rebuilds reaches the round's rootAfter.

#### Scenario: Reader agreement
- **WHEN** a reader applies the rounds the coordinator built
- **THEN** its ledger's header bytes equal the coordinator's

#### Scenario: Commitments from bundles
- **WHEN** an aggregated round's note-data outputs are read
- **THEN** the commitments they carry, with the padding constant for padding transfers, rebuild the subtree whose root matches the round's rootAfter

### Requirement: Padding supply
The tool SHALL keep a stock of padding transfers, fill it ahead of time on request, and fill a short aggregated round from it, proving any shortfall on the spot; a short round without a supply SHALL be refused. A running coordinator SHALL refill the stock between rounds. A padding transfer SHALL pay its two zero-value outputs to the one public padding note (zero address and randomness), so its commitments are a constant every reader knows.

#### Scenario: Stock consumed
- **WHEN** three padding transfers are needed and two are in stock
- **THEN** one is proved on the spot and the stock is empty afterwards

#### Scenario: Refilled while idle
- **WHEN** the coordinator is idle after a round that used padding
- **THEN** the stock is refilled to its configured level

#### Scenario: Padding leaves
- **WHEN** a reader applies an aggregated round with padding transfers
- **THEN** it places the padding note's commitment at each of their leaf positions and reaches the round's rootAfter
