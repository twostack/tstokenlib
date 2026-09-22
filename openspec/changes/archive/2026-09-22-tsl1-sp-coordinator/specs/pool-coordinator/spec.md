## MODIFIED Requirements

### Requirement: Issuance and genesis
The tool SHALL create a pool's issuance (the TSL1 token transaction carrying the genesis header, whose PP3 pins Y_0), the slot transaction Y_0 carrying the verifier for the genesis header, and witness 0, which certifies Y_0; and the coordinator SHALL open its ledger from those three, reaching the genesis header with empty trees.

#### Scenario: Fresh pool
- **WHEN** a pool is issued and its coordinator opened
- **THEN** the coordinator's ledger has size 0, the genesis header, and the issuance, witness 0 and Y_0 as its tip

### Requirement: Rounds
Given the transfers accepted into a round, the coordinator SHALL fill the round to the plan's size with padding, prove the aggregation with the ledger's trees and ring, and build three transactions in order: the slot transaction Y_{N+1} carrying the new header, round N+1 spending the tip's Y at input 2, its PP3 at input 3, Y_{N+1}'s anchor at input 4 and each deposit covenant after, with the receipts then the withdrawals as its output tail; and witness N+1 carrying the round's bundles. The coordinator SHALL apply the three to its own ledger with the same checks a reader makes and SHALL NOT publish a round its ledger refuses. A running coordinator SHALL have verified every transfer's proof at intake, so the round builder does not verify spend proofs again.

#### Scenario: A round from the test chain's transfers
- **WHEN** the coordinator closes a round of the fixture's round-1 transfers and deposit
- **THEN** it builds Y_1, round 1 and witness 1, its ledger reaches header 1, and a reader given the three reaches the same header

#### Scenario: Extra outputs mismatch
- **WHEN** a transfer's bundle or withdrawal does not hash to its outHash
- **THEN** the transfer is refused at intake, before any proving

#### Scenario: Verified at intake
- **WHEN** a transfer reaches the round builder through the coordinator's intake
- **THEN** its proof was verified once, at intake

#### Scenario: A round the ledger refuses is not published
- **WHEN** the built round does not apply to the coordinator's ledger
- **THEN** nothing is published, the ledger is unchanged, and the failure names the check

### Requirement: Padding supply
The coordinator SHALL keep a stock of padding transfers, fill it ahead of time on request, and fill a short round from it, proving any shortfall on the spot; a short round without a supply SHALL be refused. A padding transfer SHALL pay its two zero-value outputs to the one public padding note (zero address and randomness) with an empty bundle, so its commitments are a constant every reader knows.

#### Scenario: Stock consumed
- **WHEN** three padding transfers are needed and two are in stock
- **THEN** one is proved on the spot and the stock is empty afterwards

#### Scenario: Refilled while idle
- **WHEN** the coordinator is idle after a round that used padding
- **THEN** the stock is refilled to its configured level

#### Scenario: Padding leaves
- **WHEN** a reader applies a round the coordinator padded
- **THEN** it places the padding note's commitment at each padding transfer's leaf positions and reaches the round's header

## REMOVED Requirements

### Requirement: Chain reader
**Reason**: The TSL1_SP reader is specified by `pool-ledger` (Chain reader, Applying a round), which the coordinator now uses for its own recovery.
**Migration**: Readers use the ledger and chain reader of `pool-ledger`; the legacy reader is deleted with the legacy coordinator.

### Requirement: Note data on chain
**Reason**: In TSL1_SP the bundles ride in the witness, not in round outputs; `pool-transfer` (Contents) and `pool-ledger` (Note scanning) state where they are and how a wallet finds its notes.
**Migration**: None on chain; the legacy pool's note-data outputs go with the legacy pool.

## ADDED Requirements

### Requirement: Deposits by covenant
A deposit SHALL reach a round as a transfer of the deposit shape together with the mined transaction holding the depositor's covenant. The coordinator SHALL accept the deposit only if the covenant names the pool's live PP3 (the tip round's output 3), its receipt equals the transfer's receipt (first commitment and value), and its refund height is at least the configured margin ahead; SHALL refuse it, naming the reason, otherwise; SHALL take at most the plan's receipt slots (8) into a round; and SHALL refuse a deposit whose covenant names a PP3 the pending or an in-flight round spends, telling the wallet to deposit against the new tip.

#### Scenario: The fixture's deposit
- **WHEN** the fixture's deposit transfer arrives with its covenant transaction
- **THEN** it is accepted, and the round carries its receipt at output 5 and the covenant at input 5

#### Scenario: A deposit for the previous round
- **WHEN** a covenant naming the PP3 of a round already closed arrives
- **THEN** it is refused as targeting a spent round

#### Scenario: A receipt that is not the transfer's
- **WHEN** a covenant's commitment differs from the transfer's first output commitment
- **THEN** it is refused as not matching the transfer

### Requirement: Funding and fees
Each of Y, the round and the witness SHALL spend one funding output the coordinator is given, and the coordinator SHALL price each from its own size at the configured rate (satoshis per kB) with a floor, ask for an output of at least the value that covers it, and build the transaction again with the exact fee, since the round's size does not depend on its fee. A coordinator without funding SHALL refuse to close a round before proving anything.

#### Scenario: Priced from size
- **WHEN** a round is built at 1 sat/kB
- **THEN** each of its three transactions pays at least its size times the rate and at least the floor

#### Scenario: No funding
- **WHEN** the funding source cannot supply an output
- **THEN** the round is refused before aggregation, and the pending transfers stay pending

### Requirement: Publishing order
The coordinator SHALL hand the three transactions to its store before publishing any of them, and SHALL publish Y first, then the round, then the witness, since the round spends Y's anchor and the witness spends the round.

#### Scenario: Stored before published
- **WHEN** a round is closed
- **THEN** the store receives Y, the round and the witness before the first publish call, and the publish calls come in that order
