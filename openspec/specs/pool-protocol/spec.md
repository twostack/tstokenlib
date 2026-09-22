# pool-protocol Specification

## Purpose

The messages a wallet and a TSL1_SP coordinator exchange: what a wallet submits, what the coordinator answers, and what it publishes about the pool and each round, as versioned byte encodings that any transport can carry and either side decodes as hostile input.

## Requirements

### Requirement: Message kinds
The protocol SHALL have four messages. A submission carries one transfer in the pool-transfer wire format, the raw deposit transaction when the transfer backs a deposit, and a 16-byte submission id the wallet chooses. A reply carries the submission id it answers and one outcome: accepted, with the number of the round the transfer is pending for; refused, with a numbered reason and a sentence; or expired, when a transfer accepted earlier could not be included. A descriptor carries what a wallet needs to open a ledger and build transfers for the pool: the network, the txids of the issuance, witness 0 and Y_0, the aggregation arities, the nullifier level, the receipt slots a round has, and the spend parameters. An announcement carries a round's number, its 236-byte header, and the txids of the round, its witness and the slot transaction the round pins, so a reader has the triple it applies.

#### Scenario: A deposit submission
- **WHEN** a wallet submits a transfer backing a deposit
- **THEN** the submission carries the transfer, the deposit transaction and the wallet's id, and decodes to the same three

#### Scenario: A reply to a refused transfer
- **WHEN** the coordinator refuses a submission
- **THEN** the reply carries the submission's id, the outcome refused, the reason's number and its sentence, and nothing else

#### Scenario: An announcement has what a reader applies
- **WHEN** round 2 of the test chain is announced
- **THEN** the announcement names round 2's txid, witness 2's txid and Y_2's txid, and carries header 2's bytes

### Requirement: Encoding
Every message SHALL begin with a format version byte and its kind, SHALL encode canonically so that equal messages give identical bytes, and SHALL be refused on decode when the version is unknown, when any length runs past the end, or when bytes remain after the last field. A submission's transfer SHALL be decoded by the pool-transfer decoder with the descriptor's spend parameters.

#### Scenario: Round trip of every kind
- **WHEN** a submission, a reply, a descriptor and an announcement built from the test chain are encoded and decoded
- **THEN** each decodes to an equal message, and encoding the result gives the same bytes

#### Scenario: Newer version
- **WHEN** a decoder of version 1 is given a message whose first byte is 2
- **THEN** it refuses it as an unknown version

### Requirement: Untrusted input
A message decoded from bytes SHALL be treated as hostile: a coordinator's inbox can be written by anyone who knows its address, and a wallet reads announcements from a feed anyone can name. Decoding SHALL refuse a submission over 128 KB and any other message over 4 KB before reading it, SHALL check every length against the bytes that remain and its field's own bound before allocating for it, and SHALL end in either a message or a refusal naming the field, never any other failure. A submission's deposit transaction SHALL be at most 4 KB.

#### Scenario: Oversized submission
- **WHEN** a 1 MB byte string arrives as a submission
- **THEN** it is refused as too large without being parsed

#### Scenario: Random bytes
- **WHEN** 10,000 random byte strings and 10,000 single-byte mutations of a valid message of each kind are decoded
- **THEN** each ends in a message or a named refusal, and none raises any other error

### Requirement: No secrets in a message
A submission SHALL carry nothing a transfer does not already carry, plus a deposit transaction, which the chain publishes once it is mined. The submission id SHALL be random, not derived from any key or note. A reply SHALL name nothing about the transfer beyond the outcome. A descriptor and an announcement SHALL carry only what the chain publishes.

#### Scenario: Submission holds no key material
- **WHEN** a wallet's submission is encoded
- **THEN** the encoding contains no run of bytes equal to the wallet's spending key, viewing keys, nullifier key, the spent notes' rho or rcm, or the diversifier it used

### Requirement: Nothing in a message is trusted
A descriptor and an announcement SHALL be treated by a wallet as pointers to the chain, not as facts: the ledger the wallet opens from the descriptor's txids and applies the announced triples to refuses anything that does not rebuild the announced header, so a coordinator that announces a header its round does not carry is caught when the round is read. A reply's accepted outcome SHALL be treated as a promise, not a fact: a wallet learns its transfer was included by finding its notes in the announced round.

#### Scenario: A lying announcement
- **WHEN** an announcement carries round 2's txids with round 1's header
- **THEN** a wallet applying the triple refuses it, since the round's PP1 carries another header

### Requirement: Transport fit
Each message SHALL be one payload, so a transport that carries opaque byte payloads of up to 10 MB with no ordering guarantee between senders can carry it. A submission SHALL encode to under 128 KB at production parameters and every other message to under 4 KB, measured on the test chain and the production transfer.

#### Scenario: Sizes
- **WHEN** a production submission with a deposit transaction, and the test chain's descriptor, announcements and replies, are encoded
- **THEN** the submission is under 128 KB and each other message under 4 KB (measured 2026-09-22, `tool/scratch/protocol_size_probe.dart`: a production deposit submission 68,972 B; a descriptor 115 B, an announcement 338 B, a reply at most 84 B)

### Requirement: Decoding cost
Decoding any message and, for a submission, checking its transfer's self-consistency SHALL take under 5 ms at production parameters, so an inbox of a thousand messages is emptied in seconds before any proof is verified.

#### Scenario: A production submission
- **WHEN** a production submission is decoded and its transfer checked
- **THEN** it takes under 5 ms, before any proof verification starts (measured 2026-09-22: 0.53 ms, of which 0.45 ms decodes the transfer and the deposit transaction)
