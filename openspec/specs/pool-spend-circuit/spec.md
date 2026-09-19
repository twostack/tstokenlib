# pool-spend-circuit Specification

## Purpose
The spend statement a wallet proves: two input notes in, two output notes out, one asset, a signed public amount, nullifiers and commitments, all as an AIR over a Poseidon2 hash chain of 2^12 rows. Every transfer in the pool (spend, deposit, withdrawal, mint, burn, padding) is an instance of it.

## Requirements

### Requirement: Notes and commitments
A note SHALL consist of a diversified address (pk_d), a value, a randomness rho, a commitment randomness rcm and an asset id (four public lanes). Its commitment SHALL be the Poseidon2 hash of those fields, and SHALL be what the commitment tree stores.

#### Scenario: Same note, different rcm
- **WHEN** two notes differ only in rcm
- **THEN** their commitments differ

### Requirement: Key hierarchy
From a spending key sk the circuit SHALL derive the incoming viewing key ivk and the nullifier key nk in-circuit; pk_d SHALL be H(ivk, d) for a diversifier d and a nullifier SHALL be H(nk, rho). A wallet MAY hand out ivk (to detect incoming notes) or ovk (to recover outgoing notes) without revealing sk.

#### Scenario: Viewing key cannot spend
- **WHEN** a party holds ivk but not sk
- **THEN** it can derive addresses and decrypt incoming notes but cannot produce a valid nullifier

### Requirement: Membership under an anchor
Each real input note SHALL be proved to sit in the commitment tree (depth 32) under the anchor given as a public input, and both real inputs SHALL share that anchor.

#### Scenario: Two anchors
- **WHEN** the two real inputs are under different roots
- **THEN** no witness can be built

### Requirement: Dummy inputs
A dummy input SHALL have value zero and no membership proof; its real flag (a public input pinned to the circuit) SHALL be zero. A dummy declared real SHALL fail the anchor pin and a real note declared dummy SHALL fail the zero-value pins. A transfer with two dummies is a deposit, a mint or padding.

#### Scenario: Deposit
- **WHEN** both inputs are dummies and the public amount is negative
- **THEN** the outputs are funded by the transaction's transparent inputs

### Requirement: Value balance and range
The circuit SHALL enforce inputs = outputs + publicOut in the one asset, with every value range-checked to 56 bits (two 28-bit limbs) and publicOut signed (negative for value entering the pool).

#### Scenario: Overflow attempt
- **WHEN** an output value does not fit the range check
- **THEN** no proof can be produced

### Requirement: One asset per transfer
The asset id SHALL be a public input pinned to the asset registers that both commitments and both output notes carry; a mint (negative publicOut) of a non-BSV asset and any transfer of a gated asset SHALL carry the issuer's authorisation on chain.

#### Scenario: Mixed assets
- **WHEN** an output note's asset differs from the inputs' asset
- **THEN** no witness can be built

### Requirement: Public inputs
The public inputs SHALL be 56 lanes: anchor (8), nullifier 1 (8), nullifier 2 (8), commitment 1 (8), commitment 2 (8), publicOut low and high limbs (2), outHash (8, SHA256 of the transfer's extra outputs masked to 31-bit lanes), real flags (2) and asset (4). The verifier SHALL absorb them into the transcript, so a proof is bound to its recipients through outHash without the circuit reading it.

#### Scenario: Recipient swap
- **WHEN** the extra outputs of a withdrawal are replaced after proving
- **THEN** outHash no longer matches and the state script rejects the round

### Requirement: Padding transfers
A transfer with no real input and publicOut zero SHALL be a padding transfer; it changes no balance and inserts no nullifier, and only its two zero-value commitments reach the tree.

#### Scenario: Recognised on chain and by readers
- **WHEN** a transfer's real flags are both zero and its public amount is zero
- **THEN** the chain reader flags it as padding
