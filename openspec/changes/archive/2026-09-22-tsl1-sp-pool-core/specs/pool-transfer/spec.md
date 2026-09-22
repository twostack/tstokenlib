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

### Requirement: Untrusted input
A transfer decoded from bytes SHALL be treated as hostile: anyone who knows a coordinator's address can send one. Decoding SHALL refuse an encoding over 100 KB before reading it; SHALL check every length against the bytes that remain and against its field's own bound before allocating for it (the proof's length SHALL equal the length the spend parameters fix, the bundle SHALL be at most two note bundles of the largest kind, 6,054 B); and SHALL end in either a transfer or a refusal naming the field, never any other failure. The self-consistency checks SHALL run before the proof is verified and SHALL use only hashing and parsing, no key agreement and no proving arithmetic, so a refused transfer costs its receiver far less than a verification.

#### Scenario: Oversized message
- **WHEN** a 7 MB byte string arrives as a transfer
- **THEN** it is refused as too large without being parsed

#### Scenario: Lying length field
- **WHEN** an encoding declares a bundle of 4 GB
- **THEN** it is refused on that field without allocating for it

#### Scenario: Random bytes
- **WHEN** 10,000 random byte strings and 10,000 single-byte mutations of a valid encoding are decoded
- **THEN** each ends in a transfer or a named refusal, and none raises any other error

#### Scenario: Cheap refusal
- **WHEN** a production transfer with a mismatched bundle is decoded and checked
- **THEN** it is refused in under 5 ms, before any proof verification starts

### Requirement: No secrets in a transfer
A transfer SHALL carry nothing that is not either published by the round that includes it or protected by the spend proof's zero knowledge: no spending, viewing or nullifier key, no note plaintext, no diversifier and no address of the sender. The anchor lane is the one value it carries that the round does not publish; it names a commitment root, which every wallet already sees.

#### Scenario: Encoding holds no key material
- **WHEN** a wallet's transfer is encoded
- **THEN** the encoding contains no run of bytes equal to the wallet's spending key, viewing keys, nullifier key, the spent notes' rho or rcm, or the diversifier it used

### Requirement: Format compatibility
The first byte of a transfer's encoding SHALL be its format version. A decoder SHALL refuse a version it does not know rather than attempt to read it, and a change to the encoding SHALL bump the version, so a coordinator and a wallet built at different times either agree on a transfer's meaning or refuse it.

#### Scenario: Newer version
- **WHEN** a decoder of version 1 is given an encoding whose first byte is 2
- **THEN** it refuses it as an unknown version
