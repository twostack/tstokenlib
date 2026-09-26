# pool-protocol Specification

## Purpose

The messages a wallet and a TSL1_SP coordinator exchange: what a wallet submits, what the coordinator answers, and what it publishes about the pool and each round, as versioned byte encodings that any transport can carry and either side decodes as hostile input.

## Requirements

### Requirement: Message kinds
The protocol SHALL have six messages, four of them here and the two catch-up messages below. A submission carries one transfer in the pool-transfer wire format, the raw deposit transaction when the transfer backs a deposit, and a 16-byte submission id the wallet chooses. A reply carries the submission id it answers and one outcome: accepted, with the number of the round the transfer is pending for; refused, with a numbered reason and a sentence; or expired, when a transfer accepted earlier could not be included.

A descriptor carries what a wallet needs to open a ledger, build transfers for the pool, and check that a round is this pool's: the network, the txids of the issuance, witness 0 and Y_0, the aggregation arities, the nullifier level, the receipt slots a round has, the spend parameters, **the number of leaves a round appends, the pool's tokenId, and the genesis header in full**. The last three are there because a wallet does not look anything up: a txid it cannot resolve tells it nothing, the leaf count is what its whole path arithmetic rests on, and the tokenId is what a round has to carry before the wallet will believe it belongs to this pool.

An announcement carries a round's number, its 236-byte header, the txids of the round, its witness and the slot transaction the round pins, so a reader has the triple it applies, **and the round's 32-byte block root**, so a party keeping a path current needs nothing else from that round.

#### Scenario: A deposit submission
- **WHEN** a wallet submits a transfer backing a deposit
- **THEN** the submission carries the transfer, the deposit transaction and the wallet's id, and decodes to the same three

#### Scenario: A reply to a refused transfer
- **WHEN** the coordinator refuses a submission
- **THEN** the reply carries the submission's id, the outcome refused, the reason's number and its sentence, and nothing else

#### Scenario: An announcement has what a reader applies
- **WHEN** round 2 of the test chain is announced
- **THEN** the announcement names round 2's txid, witness 2's txid and Y_2's txid, and carries header 2's bytes

#### Scenario: An announcement carries its block root
- **WHEN** round 2 of the test chain is announced
- **THEN** the announcement carries a 32-byte block root equal to the one the ledger reports for round 2

#### Scenario: A descriptor a wallet can act on alone
- **WHEN** a descriptor for the test pool is decoded
- **THEN** it states 32 leaves a round, the pool's tokenId and the genesis header in full, and a ledger opens from it without any lookup

#### Scenario: A descriptor stays small
- **WHEN** a descriptor for the production plan is encoded
- **THEN** it is under 512 bytes

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
A submission SHALL carry nothing a transfer does not already carry, plus a deposit transaction, which the coordinator or the depositor publishes on the chain. The submission id SHALL be random, not derived from any key or note. A reply SHALL name nothing about the transfer beyond the outcome. A descriptor and an announcement SHALL carry only what the chain publishes.

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

### Requirement: Catch-up messages
The protocol SHALL carry a fifth and sixth message: a **catch-up request** naming one of three things, and its **reply**. The three are the pool's **block roots** over a round range, the pool's **current frontier** (the round it stands at, that round's block root, and the complete left subtrees above the block level, 32 bytes each, at most one per level: 23 nodes and 736 bytes at production parameters, whatever the pool's age), and a **head proof**: the tip round, its witness, and the witness's merkle branch with the hash of the block holding it.

None of the three is trusted. A block root is checked by folding it and matching the round's `cmRoot`; a frontier by computing the tree's root from it and matching a proven `cmRoot`; a head proof by the rules in `pool-evidence`. A pool is therefore a convenient server for them and never an authority, and a wallet that obtains any of the three elsewhere reaches the same verdict.

Block roots are also carried one at a time on the announcement, so a wallet already reading the feed needs no request. The request exists because an announcement is 370 bytes where a block root is 32, and a wallet catching up over thousands of rounds should not pay eleven times over for headers it already has or does not want.

#### Scenario: Three kinds of request
- **WHEN** each of the three catch-up requests is encoded and decoded
- **THEN** each decodes to an equal request, and an unknown kind byte is refused naming it

#### Scenario: A head proof checks out
- **WHEN** a head proof for round 2 of the test chain is decoded and given to `pool-evidence`
- **THEN** the round is reported proven and its `cmRoot` matches the ledger's

#### Scenario: A frontier reproduces the root
- **WHEN** the frontier reply for a round of the test chain is decoded and a follower is built from it
- **THEN** the follower's commitment root equals that round's `cmRoot`, and it folds the next round as a follower that had folded every round since the genesis

#### Scenario: Block roots in a range
- **WHEN** block roots for rounds 1 to 2 are requested on the test chain
- **THEN** the reply carries two 32-byte roots in round order, and folding them in order reaches round 2's `cmRoot`

### Requirement: A catch-up request carries nothing about the asker
A block-root request SHALL name a round range drawn from a set the descriptor publishes, and the protocol SHALL refuse a range outside it, naming the range. A request derived from what a wallet holds, such as the round it was last current at, is a fingerprint across repeated catch-ups; a published set makes every wallet's request one of a handful. A request's id SHALL be drawn at random for that request, and a reply SHALL carry nothing about the asker beyond echoing that id.

#### Scenario: A range outside the published set
- **WHEN** a request names a range the descriptor does not publish
- **THEN** it is refused, naming the range, and no roots are served

#### Scenario: A reply carries no asker
- **WHEN** any catch-up reply is encoded
- **THEN** it holds nothing derived from who asked: no address, no round the asker named beyond what it asked for, and no id other than the request's own random one

### Requirement: Catch-up replies are bounded
A catch-up reply SHALL bound its size before allocation. A block-root reply SHALL be refused above a configured number of roots (default 65,536, about 2 MB, more than a year of a pool closing a round every ten minutes), a frontier reply above the tree's depth, and a head proof's two transactions above the chain's own 10 MB per-transaction limit each, since a larger transaction cannot be mined and so cannot be part of a head proof.

#### Scenario: A reply that claims too many roots
- **WHEN** a block-root reply declares more roots than the bound
- **THEN** it is refused before allocation, naming the count and the bound

#### Scenario: Mutated catch-up messages
- **WHEN** 10,000 random and mutated catch-up requests and replies are decoded
- **THEN** each one either decodes to a message or is refused with a named field and reason, and none throws an unnamed error

### Requirement: Protocol version 3
Every message SHALL begin with format version 3. A message of any other version SHALL be refused, naming the version, before any other field is read. Version 3 adds the catch-up request id, the refusal form of a catch-up reply, the round kind, and the mined-round notice; a version 2 catch-up request has no id to answer to.

#### Scenario: Another version is refused
- **WHEN** a message of each kind is re-encoded with version 2 or 4
- **THEN** each is refused with the field `version`

### Requirement: Catch-up requests carry an id their replies echo
A catch-up request SHALL carry a 16-byte id, drawn at random for that request and derived from nothing the wallet holds, and every reply SHALL carry the id of the request it answers. Two requests SHALL NOT share an id. The id lets a wallet send several requests at once and route each reply, as it routes submission replies by submission id.

#### Scenario: A reply echoes its request's id
- **WHEN** a frontier request with a given id is encoded, decoded and answered
- **THEN** the decoded request and the decoded reply both carry that id, and two requests built without one carry different ids

### Requirement: A catch-up request the pool will not answer is refused
A pool SHALL answer every catch-up request it can read, with the answer or a refusal naming one of four reasons:
- `notServed`: a kind the pool does not serve.
- `unpublishedRange`: a block-root range the descriptor does not publish.
- `notYet`: nothing mined to answer from, or a round past the last mined one.
- `unavailable`: the pool cannot answer now.

The refusal SHALL also carry a sentence for a person. A pool whose chain access fails SHALL refuse with `unavailable` rather than stay silent.

#### Scenario: Every reason round trips
- **WHEN** a refusal of each reason for each kind is encoded and decoded
- **THEN** each decodes to an equal reply naming its kind, reason and sentence, and an unknown reason number is refused with the field `reason`

#### Scenario: Not mined yet
- **WHEN** the test chain's responder has no round mined and is asked for the head, the frontier, round 1 and a published block-root range
- **THEN** each is refused with `notYet`, echoing the request's id

#### Scenario: A source that fails
- **WHEN** the responder's source throws while reading a mined round
- **THEN** the head and round requests are refused with `unavailable`, and the sentence names the failure

### Requirement: Catch-up answers stand at the last mined round
A pool SHALL answer a head, a frontier and a block-root range at or below its last mined round (every round up to it mined), never at a round it has published but not seen mined. A block-root reply SHALL serve the published range from its first round up to the last mined round.

#### Scenario: Head and frontier agree below the ledger's round
- **WHEN** the test chain's responder has round 1 mined and round 2 applied, and is asked for the head and then the frontier
- **THEN** both stand at round 1, the head carries round 1 and witness 1, and a follower built from the frontier reaches round 1's `cmRoot`

#### Scenario: Block roots up to the last mined round
- **WHEN** the descriptor publishes runs of 4, rounds 1 and 2 are mined, and rounds 1 to 4 are asked for
- **THEN** the reply serves rounds 1 and 2, and a request for rounds 2 to 5 is refused with `unpublishedRange`, naming the range

### Requirement: A mined round by number
The protocol SHALL carry a fourth catch-up kind naming one mined round, answered as a head is: the round and witness transactions whole, the hash of the block holding the witness, the witness's index there, and its merkle branch. A request for a round past the last mined one SHALL be refused with `notYet`. Which round a wallet asks for follows from what it did, so the request tells the pool that the peer cares about that round. This is harmless for the round the same peer submitted into, and a link otherwise. A submitter SHALL be able to learn its round without asking (the mined-round notice), and this kind SHALL be documented as the recovery path.

#### Scenario: A round after later rounds are mined
- **WHEN** the test chain has rounds 1 and 2 mined and round 1 is asked for
- **THEN** the reply carries round 1 and witness 1, and its branch computes the block's merkle root for witness 1

#### Scenario: A round request is one round
- **WHEN** a round request names round 0, or names a count
- **THEN** it is refused, naming `from` or `count`

### Requirement: A submitter is sent its mined round
The protocol SHALL carry a seventh message, the mined-round notice. It names one or more (at most 256) of the recipient's accepted submission ids that the round took in, the round's number, the round's and the witness's txids, and the witness's block hash, index and merkle branch. It SHALL carry no transactions: a notice goes to every submitter of every round, and at production a round's two transactions are about 2.6 MB. A wallet that needs them asks for the round by number from the identity it submitted with. The notice SHALL be sent only to the peer that submitted those ids, which the pool already knows took part in the round. Nothing in it is trusted: its branch is checked against the wallet's own header, its txids against the round's announcement.

#### Scenario: A notice round trips
- **WHEN** a notice for round 2 naming two submission ids is encoded and decoded
- **THEN** it names the same ids and round and the txids of round 2 and witness 2, its branch computes the block's merkle root, and it is under 4,096 bytes; a notice naming no ids is refused

#### Scenario: A notice stays small
- **WHEN** a notice names one id and carries a 20-deep branch, as a block of a million transactions has
- **THEN** it encodes under 1,024 bytes, and a decoder refuses anything over the notice's bound as too large

### Requirement: New catch-up messages are bounded
A round reply SHALL be bounded as a head proof is: each transaction at most the chain's 10 MB, the branch at most 40 nodes, the whole under `PoolMessage.maxCatchUp`. A notice SHALL be bounded by its fields: at most 256 ids and 40 branch nodes, about 5.5 KB in all. Each bound is checked before allocation.

#### Scenario: Mutated version 3 messages
- **WHEN** 10,000 single-byte mutations of a round request, a refusal, a round reply and a notice are decoded
- **THEN** each either decodes to a message or is refused with a named field, and none throws an unnamed error
