## Purpose

The unit a wallet hands to a TSL1_SP coordinator and the coordinator puts in a round: one spend proof with everything a round needs to carry it, checkable on its own before any pool state is consulted, and encoded so it can cross a process or network boundary.

## ADDED Requirements

### Requirement: Contents
A transfer SHALL carry its spend proof over the pool's spend parameters, its 56 public lanes, the ciphertext bundle of its output notes, a withdrawal (payee key hash and amount) when it takes BSV out of the pool, and, when it backs a deposit, the outpoint of the deposit covenant it backs. The bundle SHALL be the note bundle of output 1 followed by the note bundle of output 2, or empty for a padding transfer.

#### Scenario: Round trip of a real transfer
- **WHEN** a transfer with a withdrawal is built by a wallet
- **THEN** it holds the proof, the publics, a bundle of two note bundles, and the withdrawal, and no deposit outpoint

#### Scenario: Padding carries no bundle
- **WHEN** a padding transfer is built
- **THEN** its bundle is empty

### Requirement: Self-consistency
A transfer SHALL be accepted as well formed only if all of these hold, and SHALL be refused naming the first that fails: its outHash lanes equal the lanes of SHA-256 over its withdrawal record (when it has one) followed by SHA-256 of its bundle; it has a withdrawal exactly when its asset is BSV and its public amount is positive, for exactly that amount; its public amount is zero for any asset other than BSV; a non-empty bundle parses as exactly two note bundles whose commitments are the publics' first and second output commitments in that order; an empty bundle belongs only to a padding transfer (no real input, public amount zero) whose two output commitments are the padding note's. These checks SHALL NOT need the proof to be verified or any pool state.

#### Scenario: Bundle names another commitment
- **WHEN** a transfer's first note bundle carries a commitment other than its first output commitment
- **THEN** it is refused as a bundle that does not match the proof, before its proof is verified

#### Scenario: Withdrawal for the wrong amount
- **WHEN** a transfer taking 300 out carries a withdrawal of 301
- **THEN** it is refused

#### Scenario: Empty bundle on a real transfer
- **WHEN** a transfer with a real input has an empty bundle
- **THEN** it is refused, because readers could not place its commitments

### Requirement: Deposit shape
A transfer backing a deposit SHALL have two dummy inputs, the BSV asset, a negative public amount whose magnitude is the deposit's value, and the deposited note as its first output; its receipt SHALL be the first output commitment and that value. A transfer claiming a deposit outpoint without this shape SHALL be refused.

#### Scenario: Deposit with a real input
- **WHEN** a transfer names a deposit outpoint but spends a real note
- **THEN** it is refused, since the root proof refuses a receipt backed by a transfer with a real input

#### Scenario: Receipt of a deposit
- **WHEN** a deposit transfer of 500 is well formed
- **THEN** its receipt names its first output commitment and 500 satoshis

### Requirement: Wire format
A transfer SHALL encode to bytes and decode back to an equal transfer, given only the pool's spend parameters. The encoding SHALL begin with a format version and SHALL be refused on decode when the version is unknown, when any length runs past the end, or when bytes remain after the last field. At production spend parameters a transfer with two hybrid bundles SHALL encode to under 100 KB.

#### Scenario: Round trip
- **WHEN** a transfer is encoded and the bytes decoded with the same spend parameters
- **THEN** the decoded transfer equals the original, field by field, and its proof still verifies

#### Scenario: Truncated bytes
- **WHEN** the last byte of an encoding is dropped
- **THEN** decoding fails rather than returning a transfer

#### Scenario: Production size
- **WHEN** a production-parameter transfer with two hybrid note bundles is encoded
- **THEN** the encoding is under 100 KB (measured: 63,512 B proof, 224 B publics, 3,654 B bundle)
