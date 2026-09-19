# pool-coordinator Specification

## Purpose
The tool that runs a pool: issues and opens it, collects transfers into rounds, keeps the ledger (tree, nullifier set, vault, header), builds the round transactions, and the reader that rebuilds the same ledger from the chain.

## Requirements

### Requirement: Issuance and genesis
The tool SHALL create the issuance transaction and the genesis transaction (the first state output with an empty tree, empty nullifier set and the initial vault), signed by the operator with the Rabin identity binding of TSL1.

#### Scenario: Fresh pool
- **WHEN** genesis is created
- **THEN** the ledger starts with size 0, the empty ring and an empty nullifier set

### Requirement: Rounds
Given submitted transfers (publics, proof, extra outputs, optional issuer authorisation) the tool SHALL check each transfer's outHash against its extra outputs, insert the real nullifiers, append the commitments as whole subtrees, compute the vault after the round, prove the aggregation (aggregated mode) and assemble the round transaction with the funding inputs of deposits signed. A running coordinator SHALL have verified every transfer's proof at intake, so the round builder does not verify spend proofs again.

#### Scenario: Extra outputs mismatch
- **WHEN** a transfer's extra outputs do not hash to its outHash
- **THEN** the round is refused before any proving

#### Scenario: Verified at intake
- **WHEN** a transfer reaches the round builder through the coordinator's intake
- **THEN** its proof was verified once, at intake


### Requirement: Padding supply
The tool SHALL keep a stock of padding transfers, fill it ahead of time on request, and fill a short aggregated round from it, proving any shortfall on the spot; a short round without a supply SHALL be refused. A running coordinator SHALL refill the stock between rounds.

#### Scenario: Stock consumed
- **WHEN** three padding transfers are needed and two are in stock
- **THEN** one is proved on the spot and the stock is empty afterwards

#### Scenario: Refilled while idle
- **WHEN** the coordinator is idle after a round that used padding
- **THEN** the stock is refilled to its configured level


### Requirement: Chain reader
A reader SHALL rebuild the ledger from the genesis transaction and the round transactions alone (publics from the slot unlocks, cross-checked against the results), reaching the same header, tree root, nullifier root and vault as the coordinator, and flagging padding transfers.

#### Scenario: Reader agreement
- **WHEN** a reader applies the rounds the coordinator built
- **THEN** its ledger's header bytes equal the coordinator's

### Requirement: Note data on chain
Each transfer's extra outputs SHALL begin with its note-data output (the ciphertext bundles of its output notes), so wallets scan rounds for their notes, followed by any payouts.

#### Scenario: Wallet scan
- **WHEN** a wallet scans a round with its incoming viewing key
- **THEN** it recovers the plaintexts of notes addressed to it and nothing else
