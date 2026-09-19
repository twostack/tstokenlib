## MODIFIED Requirements

### Requirement: Padding supply
The tool SHALL keep a stock of padding transfers, fill it ahead of time on request, and fill a short aggregated round from it, proving any shortfall on the spot; a short round without a supply SHALL be refused. A running coordinator SHALL refill the stock between rounds.

#### Scenario: Stock consumed
- **WHEN** three padding transfers are needed and two are in stock
- **THEN** one is proved on the spot and the stock is empty afterwards

#### Scenario: Refilled while idle
- **WHEN** the coordinator is idle after a round that used padding
- **THEN** the stock is refilled to its configured level

### Requirement: Rounds
Given submitted transfers (publics, proof, extra outputs, optional issuer authorisation) the tool SHALL check each transfer's outHash against its extra outputs, insert the real nullifiers, append the commitments as whole subtrees, compute the vault after the round, prove the aggregation (aggregated mode) and assemble the round transaction with the funding inputs of deposits signed. A running coordinator SHALL have verified every transfer's proof at intake, so the round builder does not verify spend proofs again.

#### Scenario: Extra outputs mismatch
- **WHEN** a transfer's extra outputs do not hash to its outHash
- **THEN** the round is refused before any proving

#### Scenario: Verified at intake
- **WHEN** a transfer reaches the round builder through the coordinator's intake
- **THEN** its proof was verified once, at intake
